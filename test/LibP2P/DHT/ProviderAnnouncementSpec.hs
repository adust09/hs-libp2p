module LibP2P.DHT.ProviderAnnouncementSpec (spec) where

import Control.Concurrent.Async (cancel, mapConcurrently, wait, waitCatch, withAsync)
import Control.Concurrent.STM
import Control.Exception (IOException, bracket, tryJust)
import Control.Monad (forever)
import Data.Either (isLeft)
import qualified Data.Map.Strict as Map
import Data.Time (getCurrentTime)
import LibP2P.Crypto.PeerId (PeerId (..), peerIdBytes)
import LibP2P.DHT
import LibP2P.DHT.API (provide)
import LibP2P.DHT.DHTSpec (localPid, mkTestNode)
import LibP2P.DHT.Distance (peerIdToKey)
import LibP2P.DHT.Message
import LibP2P.DHT.RoutingTable (insertPeer)
import LibP2P.DHT.Types
import LibP2P.EofStream (mkEofStreamPair)
import LibP2P.Multiaddr (Multiaddr (..))
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.MultistreamSelect.Negotiation (StreamIO (..))
import System.IO.Error (isEOFError)
import System.Timeout (timeout)
import Test.Hspec

spec :: Spec
spec = describe "send-only ADD_PROVIDER" $ do
  it "should emit no response when receiving a provider announcement" $
    bracket (mkTestNode localPid) stopDHTNode $ \node -> do
      (client, server) <- mkEofStreamPair
      writeFramedMessage client announcement
      streamClose client
      within (handleDHTRequest node server remotePid address)
      streamClose server
      within (collectReplies client) `shouldReturn` []
      providers <- getProviders node "content-key"
      map peProvider providers `shouldBe` [remotePid]

  it "should preserve response alignment when FIND_NODE and GET_PROVIDERS follow an announcement" $
    bracket (mkTestNode localPid) stopDHTNode $ \node -> do
      (client, server) <- mkEofStreamPair
      mapM_ (writeFramedMessage client)
        [announcement, request FindNode, request GetProviders]
      streamClose client
      within (handleDHTRequest node server remotePid address)
      streamClose server
      responses <- within (collectReplies client)
      map msgType responses `shouldBe` [FindNode, GetProviders]
      let providers = concatMap msgProviderPeers responses
      map dhtPeerId providers `shouldBe` [peerIdBytes remotePid]

  it "should finish provide when a remote accepts ADD_PROVIDER without replying" $
    bracket (mkTestNode localPid) stopDHTNode $ \node -> do
      (client, remote) <- mkEofStreamPair
      session <- newPeerSession (Just client)
      now <- getCurrentTime
      let entry = BucketEntry remotePid (peerIdToKey remotePid) [address] now Connected
      atomically $ do
        writeTVar (dhtStreams node) (Map.singleton remotePid session)
        modifyTVar' (dhtRoutingTable node) (fst . insertPeer entry)
      let receiver = do
            Right query <- readFramedMessage remote maxDHTMessageSize
            msgType query `shouldBe` FindNode
            writeFramedMessage remote (request FindNode)
            Right message <- readFramedMessage remote maxDHTMessageSize
            msgType message `shouldBe` AddProvider
            atomically retry
      withAsync receiver $ \_ ->
        withAsync (provide node [address] "content-key") $ \publisher ->
          timeout 1000000 (wait publisher) `shouldReturn` Just ()

  it "should serialize concurrent announcements and RPCs on one cached stream" $
    bracket (mkTestNode localPid) stopDHTNode $ \node -> do
      (client, remote) <- mkEofStreamPair
      session <- newPeerSession (Just client)
      atomically $ writeTVar (dhtStreams node) (Map.singleton remotePid session)
      received <- newTVarIO ([] :: [MessageType])
      let receiver = forever $ do
            Right message <- readFramedMessage remote maxDHTMessageSize
            atomically $ modifyTVar' received (msgType message :)
            case msgType message of
              AddProvider -> pure ()
              _ -> writeFramedMessage remote message
          send kind = case kind of
            AddProvider -> dhtSendMessage node remotePid announcement
            _ -> do
              result <- dhtSendRequest node remotePid (request kind)
              pure $ case result of
                Right response | msgType response == kind -> Right ()
                _ -> Left "response did not match its request"
          kinds = concat (replicate 10 [AddProvider, FindNode, GetProviders])
      withAsync receiver $ \_ -> do
        timeout 2000000 (mapConcurrently send kinds)
          `shouldReturn` Just (replicate (length kinds) (Right ()))
        timeout 1000000 (atomically $ readTVar received >>= check . ((== 30) . length))
          `shouldReturn` Just ()

  it "should propagate cancellation without retrying an interrupted announcement" $
    bracket (mkTestNode localPid) stopDHTNode $ \node -> do
      (client, _) <- mkEofStreamPair
      entered <- newEmptyTMVarIO
      let blocked = client { streamWrite = \_ -> do
            atomically $ putTMVar entered ()
            atomically retry }
      session <- newPeerSession (Just blocked)
      atomically $ writeTVar (dhtStreams node) (Map.singleton remotePid session)
      withAsync (dhtSendMessage node remotePid announcement) $ \sender -> do
        timeout 1000000 (atomically $ takeTMVar entered) `shouldReturn` Just ()
        cancel sender
        result <- waitCatch sender
        result `shouldSatisfy` isLeft

  it "should reject request/announcement API misuse before sending bytes" $
    bracket (mkTestNode localPid) stopDHTNode $ \node -> do
      dhtSendRequest node remotePid announcement
        `shouldReturn` Left "ADD_PROVIDER requires dhtSendMessage"
      dhtSendMessage node remotePid (request FindNode)
        `shouldReturn` Left "only ADD_PROVIDER is send-only"
      sessions <- readTVarIO (dhtStreams node)
      Map.null sessions `shouldBe` True

within :: IO a -> IO a
within action = withAsync action $ \worker -> do
  result <- timeout 2000000 (wait worker)
  maybe (fail "DHT operation timed out") pure result

collectReplies :: StreamIO -> IO [DHTMessage]
collectReplies stream = do
  result <- tryJust (\err -> if isEOFError err then Just err else Nothing)
    (readFramedMessage stream maxDHTMessageSize)
    :: IO (Either IOException (Either String DHTMessage))
  case result of
    Left _ -> pure []
    Right (Left err) -> fail err
    Right (Right response) -> (response :) <$> collectReplies stream

request :: MessageType -> DHTMessage
request kind = emptyDHTMessage { msgType = kind, msgKey = "content-key" }

announcement :: DHTMessage
announcement = (request AddProvider)
  { msgProviderPeers = [DHTPeer (peerIdBytes remotePid) [] Connected] }

remotePid :: PeerId
remotePid = PeerId "remote"

address :: Multiaddr
address = Multiaddr [IP4 0x7f000001, TCP 4001]
