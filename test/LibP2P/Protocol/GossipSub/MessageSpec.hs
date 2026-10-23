module LibP2P.Protocol.GossipSub.MessageSpec (spec) where

import Test.Hspec

import Control.Concurrent.STM
import qualified Data.ByteString as BS
import Data.List (isInfixOf)
import Data.Word (Word8)
import LibP2P.Protocol.GossipSub.Types
import LibP2P.Protocol.GossipSub.Message
import LibP2P.MultistreamSelect.Negotiation (StreamIO (..), mkByteStreamIO)

-- | Create a bidirectional in-memory stream pair for testing.
mkStreamPair :: IO (StreamIO, StreamIO)
mkStreamPair = do
  q1 <- newTQueueIO :: IO (TQueue Word8)
  q2 <- newTQueueIO :: IO (TQueue Word8)
  let streamA = mkByteStreamIO
        (\bs -> mapM_ (\b -> atomically (writeTQueue q1 b)) (BS.unpack bs))
        (atomically (readTQueue q2))
        (pure ())
      streamB = mkByteStreamIO
        (\bs -> mapM_ (\b -> atomically (writeTQueue q2 b)) (BS.unpack bs))
        (atomically (readTQueue q1))
        (pure ())
  pure (streamA, streamB)

spec :: Spec
spec = do
  describe "GossipSub.Message" $ do
    describe "RPC encode/decode round-trip" $ do
      it "full RPC with subs, publish, and control" $ do
        let rpc = RPC
              { rpcSubscriptions =
                  [ SubOpts True "blocks"
                  , SubOpts False "tx"
                  ]
              , rpcPublish =
                  [ PubSubMessage
                      { msgFrom      = Just (BS.pack [1, 2, 3])
                      , msgData      = BS.pack [0xDE, 0xAD]
                      , msgSeqNo     = Just (BS.pack [0, 0, 0, 0, 0, 0, 0, 1])
                      , msgTopic     = "blocks"
                      , msgSignature = Just (BS.pack [0xAA, 0xBB])
                      , msgKey       = Just (BS.pack [0xCC, 0xDD])
                      }
                  ]
              , rpcControl = Just ControlMessage
                  { ctrlIHave = [IHave "blocks" [BS.pack [1], BS.pack [2]]]
                  , ctrlIWant = [IWant [BS.pack [3]]]
                  , ctrlGraft = [Graft "blocks"]
                  , ctrlPrune = [Prune "tx" [] (Just 60)]
                  , ctrlIDontWant = [IDontWant [BS.pack [4]]]
                  }
              }
        let encoded = encodeRPC rpc
        decodeRPC encoded `shouldBe` Right rpc

      it "empty RPC" $ do
        let encoded = encodeRPC emptyRPC
        decodeRPC encoded `shouldBe` Right emptyRPC

      it "RPC with subscriptions only" $ do
        let rpc = emptyRPC
              { rpcSubscriptions =
                  [ SubOpts True "topic1"
                  , SubOpts True "topic2"
                  , SubOpts False "topic3"
                  ]
              }
        let encoded = encodeRPC rpc
        decodeRPC encoded `shouldBe` Right rpc

      it "RPC with publish only" $ do
        let msg = PubSubMessage
              { msgFrom      = Just (BS.pack [10, 20])
              , msgData      = BS.pack [1, 2, 3, 4, 5]
              , msgSeqNo     = Just (BS.pack [0, 0, 0, 0, 0, 0, 0, 42])
              , msgTopic     = "events"
              , msgSignature = Nothing
              , msgKey       = Nothing
              }
            rpc = emptyRPC { rpcPublish = [msg] }
        let encoded = encodeRPC rpc
        decodeRPC encoded `shouldBe` Right rpc

    describe "Control message round-trips" $ do
      it "IHAVE with topic and message IDs" $ do
        let ctrl = emptyControlMessage
              { ctrlIHave = [IHave "blocks" [BS.pack [1, 2], BS.pack [3, 4]]] }
            rpc = emptyRPC { rpcControl = Just ctrl }
        decodeRPC (encodeRPC rpc) `shouldBe` Right rpc

      it "IWANT with message IDs" $ do
        let ctrl = emptyControlMessage
              { ctrlIWant = [IWant [BS.pack [5, 6], BS.pack [7, 8]]] }
            rpc = emptyRPC { rpcControl = Just ctrl }
        decodeRPC (encodeRPC rpc) `shouldBe` Right rpc

      it "GRAFT with topic" $ do
        let ctrl = emptyControlMessage
              { ctrlGraft = [Graft "blocks", Graft "tx"] }
            rpc = emptyRPC { rpcControl = Just ctrl }
        decodeRPC (encodeRPC rpc) `shouldBe` Right rpc

      it "PRUNE with peer exchange and backoff" $ do
        let px = PeerExchangeInfo (BS.pack [1, 2, 3]) (Just (BS.pack [4, 5]))
            ctrl = emptyControlMessage
              { ctrlPrune = [Prune "blocks" [px] (Just 60)] }
            rpc = emptyRPC { rpcControl = Just ctrl }
        decodeRPC (encodeRPC rpc) `shouldBe` Right rpc

      it "PRUNE without backoff" $ do
        let ctrl = emptyControlMessage
              { ctrlPrune = [Prune "blocks" [] Nothing] }
            rpc = emptyRPC { rpcControl = Just ctrl }
        decodeRPC (encodeRPC rpc) `shouldBe` Right rpc

      it "IDONTWANT with message IDs" $ do
        let ctrl = emptyControlMessage
              { ctrlIDontWant =
                  [IDontWant [BS.pack [1, 2], BS.pack [3, 4]]] }
            rpc = emptyRPC { rpcControl = Just ctrl }
        decodeRPC (encodeRPC rpc) `shouldBe` Right rpc

      it "encodes IDONTWANT with the v1.2 protobuf field numbers" $ do
        let rpc = emptyRPC
              { rpcControl = Just emptyControlMessage
                  { ctrlIDontWant = [IDontWant [BS.pack [1, 2]]] }
              }
            vector = BS.pack
              [ 0x1a, 0x06       -- RPC.control, 6 bytes
              , 0x2a, 0x04       -- ControlMessage.idontwant, 4 bytes
              , 0x0a, 0x02, 1, 2 -- ControlIDontWant.messageIDs
              ]
        encodeRPC rpc `shouldBe` vector
        decodeRPC vector `shouldBe` Right rpc

    describe "PubSubMessage" $ do
      it "round-trips with all fields" $ do
        let msg = PubSubMessage
              { msgFrom      = Just (BS.pack [1, 2, 3])
              , msgData      = BS.pack [4, 5, 6]
              , msgSeqNo     = Just (BS.pack [0, 0, 0, 0, 0, 0, 0, 7])
              , msgTopic     = "test-topic"
              , msgSignature = Just (BS.pack [0xAA])
              , msgKey       = Just (BS.pack [0xBB])
              }
        decodePubSubMessage (encodePubSubMessageBS msg) `shouldBe` Right msg

      it "round-trips with minimal fields" $ do
        let msg = PubSubMessage
              { msgFrom      = Nothing
              , msgData      = BS.empty
              , msgSeqNo     = Nothing
              , msgTopic     = "t"
              , msgSignature = Nothing
              , msgKey       = Nothing
              }
        decodePubSubMessage (encodePubSubMessageBS msg) `shouldBe` Right msg

    describe "Framed encoding" $ do
      it "encode/decode round-trip with framing" $ do
        let rpc = emptyRPC
              { rpcSubscriptions = [SubOpts True "test"]
              , rpcPublish = [PubSubMessage Nothing (BS.pack [1]) Nothing "test" Nothing Nothing]
              }
        let framed = encodeFramed rpc
        decodeFramed maxRPCSize framed `shouldBe` Right rpc

      it "rejects oversized messages" $ do
        let rpc = emptyRPC
              { rpcPublish = [PubSubMessage Nothing (BS.replicate 100 0xFF) Nothing "t" Nothing Nothing]
              }
        let framed = encodeFramed rpc
        case decodeFramed 10 framed of
          Left err -> err `shouldSatisfy` \e -> "too large" `isInfixOf` e
          Right _  -> expectationFailure "should reject oversized message"

    describe "Stream I/O" $ do
      it "write + read round-trip over stream" $ do
        let rpc = emptyRPC
              { rpcSubscriptions = [SubOpts True "stream-test"]
              , rpcControl = Just emptyControlMessage
                  { ctrlGraft = [Graft "stream-test"] }
              }
        (clientStream, serverStream) <- mkStreamPair
        writeRPCMessage clientStream rpc
        result <- readRPCMessage serverStream maxRPCSize
        result `shouldBe` Right rpc
