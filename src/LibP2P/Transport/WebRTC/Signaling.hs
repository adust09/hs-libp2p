-- | Relay-carried signaling messages for standard libp2p WebRTC.
--
-- Protocol: /webrtc-signaling/0.0.1
-- Wire format: uvarint-length-prefixed protobuf.
module LibP2P.Transport.WebRTC.Signaling (
  SignalingMessage (..),
  signalingProtocolId,
  maxSignalingMessageSize,
  encodeSignalingMessage,
  decodeSignalingMessage,
  writeSignalingMessage,
  readSignalingMessage,
) where

import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as BL
import Data.Text (Text)
import Data.Text.Encoding qualified as Text
import Data.Text.Lazy qualified as TL
import LibP2P.Core.Varint (decodeUvarint, encodeUvarint)
import LibP2P.MultistreamSelect.Negotiation (StreamIO (..), readExactBounded)
import Proto3.Wire.Decode (ParseError (..), Parser (..), RawMessage, at, one, parse)
import Proto3.Wire.Decode qualified as Decode
import Proto3.Wire.Encode qualified as Encode
import Proto3.Wire.Types (FieldNumber (..))

-- | Signaling protocol negotiated on the relayed libp2p stream.
signalingProtocolId :: Text
signalingProtocolId = "/webrtc-signaling/0.0.1"

-- | Bound SDP offers/answers and candidate JSON to one MiB.
maxSignalingMessageSize :: Int
maxSignalingMessageSize = 1024 * 1024

data SignalingMessage
  = SDPOffer !Text
  | SDPAnswer !Text
  | ICECandidate !Text
  deriving (Show, Eq)

encodeSignalingMessage :: SignalingMessage -> ByteString
encodeSignalingMessage message = BL.toStrict $ Encode.toLazyByteString $
  Encode.uint32 (FieldNumber 1) messageType
    <> Encode.byteString (FieldNumber 2) (Text.encodeUtf8 contents)
 where
  (messageType, contents) = case message of
    SDPOffer value -> (0, value)
    SDPAnswer value -> (1, value)
    ICECandidate value -> (2, value)

decodeSignalingMessage :: ByteString -> Either ParseError SignalingMessage
decodeSignalingMessage = parse signalingParser

signalingParser :: Parser RawMessage SignalingMessage
signalingParser = do
  messageType <- at (one Decode.uint32 0) (FieldNumber 1)
  rawData <- at (one Decode.byteString BS.empty) (FieldNumber 2)
  contents <- case Text.decodeUtf8' rawData of
    Left err -> parserError ("signaling data is not UTF-8: " <> show err)
    Right value -> pure value
  case messageType of
    0 -> pure (SDPOffer contents)
    1 -> pure (SDPAnswer contents)
    2 -> pure (ICECandidate contents)
    _ -> parserError ("unknown signaling message type: " <> show messageType)

parserError :: String -> Parser RawMessage value
parserError message = Parser $ const $ Left $ WireTypeError (TL.pack message)

writeSignalingMessage :: StreamIO -> SignalingMessage -> IO ()
writeSignalingMessage stream message =
  streamWrite stream (encodeUvarint (fromIntegral (BS.length payload)) <> payload)
 where
  payload = encodeSignalingMessage message

readSignalingMessage :: StreamIO -> IO (Either String SignalingMessage)
readSignalingMessage stream = do
  prefix <- readVarintBytes stream
  case decodeUvarint prefix of
    Left err -> pure (Left ("signaling length: " <> err))
    Right (size, _) -> readPayload size
 where
  readPayload size
    | size > fromIntegral maxSignalingMessageSize =
        pure (Left "signaling message exceeds one MiB")
    | otherwise = do
        result <- readExactBounded stream maxSignalingMessageSize (fromIntegral size)
        pure $ case result of
          Left err -> Left ("signaling read: " <> err)
          Right payload -> case decodeSignalingMessage payload of
            Left err -> Left ("signaling protobuf: " <> show err)
            Right message -> Right message

readVarintBytes :: StreamIO -> IO ByteString
readVarintBytes stream = go [] (0 :: Int)
 where
  go bytes count
    | count >= 10 = pure (BS.pack (reverse bytes))
    | otherwise = do
        byte <- streamReadByte stream
        if byte < 0x80
          then pure (BS.pack (reverse (byte : bytes)))
          else go (byte : bytes) (count + 1)
