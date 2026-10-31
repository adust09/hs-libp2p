module LibP2P.NAT.AutoNAT.V2.MessageSpec (spec) where

import Control.Concurrent.STM (TQueue, atomically, newTQueueIO, readTQueue, writeTQueue)
import qualified Data.ByteString as BS
import Data.Word (Word8)
import LibP2P.MultistreamSelect.Negotiation (StreamIO (..), mkByteStreamIO)
import LibP2P.NAT.AutoNAT.V2.Message
import Test.Hspec

mkStreamPair :: IO (StreamIO, StreamIO)
mkStreamPair = do
  leftToRight <- newTQueueIO :: IO (TQueue Word8)
  rightToLeft <- newTQueueIO :: IO (TQueue Word8)
  let stream leftQueue rightQueue = mkByteStreamIO
        (mapM_ (atomically . writeTQueue leftQueue) . BS.unpack)
        (atomically (readTQueue rightQueue))
        (pure ())
  pure
    ( stream leftToRight rightToLeft
    , stream rightToLeft leftToRight
    )

roundTrips :: AutoNATV2Message -> Expectation
roundTrips message = decodeAutoNATV2Message (encodeAutoNATV2Message message)
  `shouldBe` Right message

spec :: Spec
spec = do
  describe "AutoNAT v2 protobuf codec" $ do
    it "encodes a dial request with the specified fixed64 nonce layout" $ do
      let message = V2DialRequest DialRequestV2
            { drv2Addrs = ["a"]
            , drv2Nonce = 0x0102030405060708
            }
      encodeAutoNATV2Message message `shouldBe` BS.pack
        [ 0x0a, 0x0c
        , 0x0a, 0x01, 0x61
        , 0x11, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01
        ]

    it "round-trips every dial-request stream message" $ do
      mapM_ roundTrips
        [ V2DialRequest DialRequestV2
            { drv2Addrs = ["first", "second"]
            , drv2Nonce = 42
            }
        , V2DialDataRequest DialDataRequestV2
            { ddrv2AddrIdx = 1
            , ddrv2NumBytes = 30000
            }
        , V2DialDataResponse (BS.replicate 4000 7)
        , V2DialResponse DialResponseV2
            { drsv2Status = ResponseOK
            , drsv2AddrIdx = 1
            , drsv2DialStatus = DialStatusBackError
            }
        ]

    it "preserves unknown statuses so the client can reject them" $ do
      let message = V2DialResponse DialResponseV2
            { drsv2Status = ResponseStatusUnknown 777
            , drsv2AddrIdx = 0
            , drsv2DialStatus = DialStatusUnknown 888
            }
      roundTrips message

    it "rejects messages containing multiple oneof fields" $ do
      let dialRequest = BS.drop 2 . encodeAutoNATV2Message $
            V2DialRequest (DialRequestV2 [] 1)
          dialResponse = BS.drop 2 . encodeAutoNATV2Message $
            V2DialResponse (DialResponseV2 ResponseOK 0 DialStatusOK)
          malformed = BS.concat
            [ BS.pack [0x0a, fromIntegral (BS.length dialRequest)]
            , dialRequest
            , BS.pack [0x12, fromIntegral (BS.length dialResponse)]
            , dialResponse
            ]
      decodeAutoNATV2Message malformed `shouldSatisfy` isLeft

    it "round-trips dial-back messages and the empty OK response" $ do
      let dialBack = DialBackV2 0x1122334455667788
      decodeDialBackV2 (encodeDialBackV2 dialBack) `shouldBe` Right dialBack
      decodeDialBackResponseV2 encodeDialBackResponseV2 `shouldBe` Right ()

  describe "AutoNAT v2 framed I/O" $ do
    it "writes and reads all message variants on one stream" $ do
      (sender, receiver) <- mkStreamPair
      let messages =
            [ V2DialRequest (DialRequestV2 ["addr"] 9)
            , V2DialDataRequest (DialDataRequestV2 0 30000)
            , V2DialDataResponse (BS.replicate 4000 0)
            , V2DialResponse (DialResponseV2 ResponseOK 0 DialStatusOK)
            ]
      mapM_ (writeAutoNATV2Message sender) messages
      results <- mapM (const (readAutoNATV2Message receiver)) messages
      results `shouldBe` fmap Right messages

    it "rejects an oversized frame before reading its body" $ do
      (sender, receiver) <- mkStreamPair
      let oversizedLength = BS.pack [0x81, 0x40]
      -- 8193 encoded as uvarint.
      streamWrite sender oversizedLength
      result <- readAutoNATV2Message receiver
      result `shouldSatisfy` isLeft

isLeft :: Either a b -> Bool
isLeft (Left _) = True
isLeft _ = False
