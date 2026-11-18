module LibP2P.DHT.KeyBindingSpec (spec) where

import Control.Concurrent.STM (atomically, modifyTVar')
import qualified Data.ByteString as BS
import Data.Either (isLeft)
import Data.IORef (modifyIORef', newIORef, readIORef)
import Data.Maybe (maybeToList)
import Data.Time (getCurrentTime)
import LibP2P.Crypto.Ed25519 (generateKeyPair)
import LibP2P.Crypto.Key (KeyPair (..))
import LibP2P.Crypto.PeerId (peerIdBytes, fromPublicKey)
import LibP2P.Crypto.Protobuf (encodePublicKey)
import LibP2P.DHT (DHTNode (..), Validator (..))
import LibP2P.DHT.API (getValue)
import LibP2P.DHT.DHTSpec (localPid, mkPeerId, mkTestNode)
import LibP2P.DHT.Distance (peerIdToKey)
import LibP2P.DHT.Message
import LibP2P.DHT.RoutingTable (insertPeer)
import LibP2P.DHT.Types
import LibP2P.DHT.Validator (pkValidator)
import Test.Hspec

spec :: Spec
spec = describe "GET_VALUE request-key binding" $ do
  it "should reject a valid unrelated public-key record when queried for another peer" $ do
    wanted <- publicKeyRecord
    unrelated <- publicKeyRecord
    valValidate pkValidator (recKey unrelated) (recValue unrelated) `shouldBe` Right ()
    (result, requests) <- lookupRecords pkValidator (recKey wanted) [unrelated]
    result `shouldSatisfy` isLeft
    map msgType requests `shouldBe` [GetValue]

  it "should reject a mismatched record before invoking the validator" $ do
    let validator = Validator
          (\_ _ -> error "validator must not receive an unrelated record")
          (\_ _ -> error "selector must not receive an unrelated record")
    (result, _) <- lookupRecords validator "wanted" [DHTRecord "other" "value" ""]
    result `shouldSatisfy` isLeft

  it "should select a matching public-key record when an unrelated answer arrives first" $ do
    wanted <- publicKeyRecord
    unrelated <- publicKeyRecord
    (result, requests) <- lookupRecords pkValidator (recKey wanted) [unrelated, wanted]
    result `shouldBe` Right wanted
    map msgType requests `shouldBe` [GetValue, GetValue]
    map msgKey requests `shouldBe` replicate 2 (recKey wanted)

  it "should not generate a repair from an unrelated answer after a matching answer" $ do
    wanted <- publicKeyRecord
    unrelated <- publicKeyRecord
    (result, requests) <- lookupRecords pkValidator (recKey wanted) [wanted, unrelated]
    result `shouldBe` Right wanted
    map msgType requests `shouldBe` [GetValue, GetValue]

  it "should validate, select and repair matching records using the requested raw key" $ do
    let key = "/example/requested"
        old = DHTRecord key "old" ""
        best = DHTRecord key "best" ""
        validator = Validator
          (\k _ -> if k == key then Right () else Left "wrong validation key")
          (\k _ -> if k == key then Right 1 else Left "wrong selection key")
    (result, requests) <- lookupRecords validator key [old, best]
    result `shouldBe` Right best
    let repairs = filter ((== PutValue) . msgType) requests
    map msgKey repairs `shouldBe` [key]
    map msgRecord repairs `shouldBe` [Just best]

publicKeyRecord :: IO DHTRecord
publicKeyRecord = do
  Right kp <- generateKeyPair
  pure $ DHTRecord ("/pk/" <> peerIdBytes (fromPublicKey (kpPublic kp)))
    (encodePublicKey (kpPublic kp)) ""

-- Each responder reveals only the next peer, making answer order deterministic.
lookupRecords
  :: Validator -> BS.ByteString -> [DHTRecord]
  -> IO (Either String DHTRecord, [DHTMessage])
lookupRecords validator key records = do
  node <- mkTestNode localPid
  calls <- newIORef []
  let peers = take (length records) [mkPeerId (BS.singleton i) | i <- [10 ..]]
      nextPeers = map Just (drop 1 peers) ++ [Nothing]
      responses = zipWith3 response peers records nextPeers
      send pid request = do
        modifyIORef' calls (request :)
        pure $ case msgType request of
          GetValue -> maybe (Left "unknown peer") wireRoundTrip (lookup pid responses)
          PutValue -> wireRoundTrip request
          _ -> Left "unexpected RPC"
  now <- getCurrentTime
  let seed = mkPeerId (BS.singleton 10)
      entry = BucketEntry seed (peerIdToKey seed) [] now NotConnected
  atomically $ modifyTVar' (dhtRoutingTable node) (fst . insertPeer entry)
  result <- getValue (node { dhtSendRequest = send }) validator key
  requests <- reverse <$> readIORef calls
  pure (result, requests)
  where
    response pid record nextPeer = (pid, emptyDHTMessage
      { msgType = GetValue
      , msgKey = key
      , msgRecord = Just record
      , msgCloserPeers =
          [DHTPeer (peerIdBytes next) [] NotConnected | next <- maybeToList nextPeer]
      })
    wireRoundTrip = decodeFramed maxDHTMessageSize . encodeFramed
