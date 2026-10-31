-- | AutoNAT v2 protobuf messages and framed stream I/O.
module LibP2P.NAT.AutoNAT.V2.Message
  ( AutoNATV2Message (..)
  , DialRequestV2 (..)
  , DialDataRequestV2 (..)
  , DialResponseV2 (..)
  , DialStatusV2 (..)
  , ResponseStatusV2 (..)
  , DialBackV2 (..)
  , encodeAutoNATV2Message
  , decodeAutoNATV2Message
  , encodeDialBackV2
  , decodeDialBackV2
  , encodeDialBackResponseV2
  , decodeDialBackResponseV2
  , writeAutoNATV2Message
  , readAutoNATV2Message
  , writeDialBackV2
  , readDialBackV2
  , writeDialBackResponseV2
  , readDialBackResponseV2
  , autoNATV2DialProtocolId
  , autoNATV2DialBackProtocolId
  , maxAutoNATV2MessageSize
  , maxAutoNATV2DialBackMessageSize
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import Data.Text (Text)
import Data.Word (Word32, Word64)
import LibP2P.Core.Varint (decodeUvarint, encodeUvarint)
import LibP2P.MultistreamSelect.Negotiation (StreamIO (..), readExactBounded)
import Proto3.Wire.Decode (ParseError, Parser, RawMessage, at, embedded, one, parse, repeated)
import qualified Proto3.Wire.Decode as Decode
import Proto3.Wire.Encode (MessageBuilder)
import qualified Proto3.Wire.Encode as Encode
import Proto3.Wire.Types (FieldNumber (..))

-- | Protocol used for one AutoNAT v2 reachability request.
autoNATV2DialProtocolId :: Text
autoNATV2DialProtocolId = "/libp2p/autonat/2/dial-request"

-- | Protocol used by the server to return the request nonce.
autoNATV2DialBackProtocolId :: Text
autoNATV2DialBackProtocolId = "/libp2p/autonat/2/dial-back"

-- | go-libp2p's bound for request, response, and dial-data messages.
maxAutoNATV2MessageSize :: Int
maxAutoNATV2MessageSize = 8192

-- | go-libp2p's bound for dial-back messages.
maxAutoNATV2DialBackMessageSize :: Int
maxAutoNATV2DialBackMessageSize = 1024

-- | One message on the dial-request protocol stream.
data AutoNATV2Message
  = V2DialRequest !DialRequestV2
  | V2DialResponse !DialResponseV2
  | V2DialDataRequest !DialDataRequestV2
  | V2DialDataResponse !ByteString
  deriving (Show, Eq)

-- | Priority-ordered addresses and the nonce expected on dial-back.
data DialRequestV2 = DialRequestV2
  { drv2Addrs :: ![ByteString]
  , drv2Nonce :: !Word64
  }
  deriving (Show, Eq)

-- | Cost the client must upload before a cross-IP dial-back.
data DialDataRequestV2 = DialDataRequestV2
  { ddrv2AddrIdx :: !Word32
  , ddrv2NumBytes :: !Word64
  }
  deriving (Show, Eq)

-- | Outcome of dialing the selected address.
data DialStatusV2
  = DialStatusUnused
  | DialStatusError
  | DialStatusBackError
  | DialStatusOK
  | DialStatusUnknown !Word32
  deriving (Show, Eq)

-- | Outcome of serving the request itself.
data ResponseStatusV2
  = ResponseInternalError
  | ResponseRequestRejected
  | ResponseDialRefused
  | ResponseOK
  | ResponseStatusUnknown !Word32
  deriving (Show, Eq)

-- | Final response on the dial-request stream.
data DialResponseV2 = DialResponseV2
  { drsv2Status :: !ResponseStatusV2
  , drsv2AddrIdx :: !Word32
  , drsv2DialStatus :: !DialStatusV2
  }
  deriving (Show, Eq)

-- | Nonce delivered over the fresh dial-back connection.
newtype DialBackV2 = DialBackV2
  { dbv2Nonce :: Word64
  }
  deriving (Show, Eq)

encodeAutoNATV2Message :: AutoNATV2Message -> ByteString
encodeAutoNATV2Message message = BL.toStrict . Encode.toLazyByteString $
  case message of
    V2DialRequest request -> Encode.embedded (FieldNumber 1) (encodeDialRequest request)
    V2DialResponse response -> Encode.embedded (FieldNumber 2) (encodeDialResponse response)
    V2DialDataRequest request -> Encode.embedded (FieldNumber 3) (encodeDialDataRequest request)
    V2DialDataResponse bytes -> Encode.embedded (FieldNumber 4) (encodeDialDataResponse bytes)

encodeDialRequest :: DialRequestV2 -> MessageBuilder
encodeDialRequest request =
  foldMap (Encode.byteString (FieldNumber 1)) (drv2Addrs request)
    <> Encode.fixed64 (FieldNumber 2) (drv2Nonce request)

encodeDialDataRequest :: DialDataRequestV2 -> MessageBuilder
encodeDialDataRequest request =
  Encode.uint32 (FieldNumber 1) (ddrv2AddrIdx request)
    <> Encode.uint64 (FieldNumber 2) (ddrv2NumBytes request)

encodeDialDataResponse :: ByteString -> MessageBuilder
encodeDialDataResponse = Encode.byteString (FieldNumber 1)

encodeDialResponse :: DialResponseV2 -> MessageBuilder
encodeDialResponse response =
  Encode.uint32 (FieldNumber 1) (responseStatusToWord (drsv2Status response))
    <> Encode.uint32 (FieldNumber 2) (drsv2AddrIdx response)
    <> Encode.uint32 (FieldNumber 3) (dialStatusToWord (drsv2DialStatus response))

decodeAutoNATV2Message :: ByteString -> Either String AutoNATV2Message
decodeAutoNATV2Message bytes = do
  fields <- firstParseError (parse messageParser bytes)
  case fields of
    (Just request, Nothing, Nothing, Nothing) -> Right (V2DialRequest request)
    (Nothing, Just response, Nothing, Nothing) -> Right (V2DialResponse response)
    (Nothing, Nothing, Just request, Nothing) -> Right (V2DialDataRequest request)
    (Nothing, Nothing, Nothing, Just response) -> Right (V2DialDataResponse response)
    _ -> Left "AutoNAT v2 message must contain exactly one message field"

messageParser
  :: Parser RawMessage
       ( Maybe DialRequestV2
       , Maybe DialResponseV2
       , Maybe DialDataRequestV2
       , Maybe ByteString
       )
messageParser = (,,,)
  <$> at (embedded dialRequestParser) (FieldNumber 1)
  <*> at (embedded dialResponseParser) (FieldNumber 2)
  <*> at (embedded dialDataRequestParser) (FieldNumber 3)
  <*> at (embedded dialDataResponseParser) (FieldNumber 4)

dialRequestParser :: Parser RawMessage DialRequestV2
dialRequestParser = DialRequestV2
  <$> at (repeated Decode.byteString) (FieldNumber 1)
  <*> at (one Decode.fixed64 0) (FieldNumber 2)

dialDataRequestParser :: Parser RawMessage DialDataRequestV2
dialDataRequestParser = DialDataRequestV2
  <$> at (one Decode.uint32 0) (FieldNumber 1)
  <*> at (one Decode.uint64 0) (FieldNumber 2)

dialDataResponseParser :: Parser RawMessage ByteString
dialDataResponseParser = at (one Decode.byteString BS.empty) (FieldNumber 1)

dialResponseParser :: Parser RawMessage DialResponseV2
dialResponseParser = DialResponseV2
  <$> at (fmap responseStatusFromWord (one Decode.uint32 0)) (FieldNumber 1)
  <*> at (one Decode.uint32 0) (FieldNumber 2)
  <*> at (fmap dialStatusFromWord (one Decode.uint32 0)) (FieldNumber 3)

encodeDialBackV2 :: DialBackV2 -> ByteString
encodeDialBackV2 dialBack = BL.toStrict . Encode.toLazyByteString $
  Encode.fixed64 (FieldNumber 1) (dbv2Nonce dialBack)

decodeDialBackV2 :: ByteString -> Either String DialBackV2
decodeDialBackV2 bytes = firstParseError $ parse parser bytes
  where
    parser = DialBackV2 <$> at (one Decode.fixed64 0) (FieldNumber 1)

-- | DialBackResponse has one enum field whose only valid value is OK=0.
encodeDialBackResponseV2 :: ByteString
encodeDialBackResponseV2 = BS.empty

decodeDialBackResponseV2 :: ByteString -> Either String ()
decodeDialBackResponseV2 bytes = do
  status <- firstParseError $ parse parser bytes
  if status == 0
    then Right ()
    else Left ("unknown AutoNAT v2 dial-back status: " <> show status)
  where
    parser = at (one Decode.uint32 0) (FieldNumber 1)

writeAutoNATV2Message :: StreamIO -> AutoNATV2Message -> IO ()
writeAutoNATV2Message stream = writeFramed stream . encodeAutoNATV2Message

readAutoNATV2Message :: StreamIO -> IO (Either String AutoNATV2Message)
readAutoNATV2Message stream =
  readFramed stream maxAutoNATV2MessageSize decodeAutoNATV2Message

writeDialBackV2 :: StreamIO -> DialBackV2 -> IO ()
writeDialBackV2 stream = writeFramed stream . encodeDialBackV2

readDialBackV2 :: StreamIO -> IO (Either String DialBackV2)
readDialBackV2 stream =
  readFramed stream maxAutoNATV2DialBackMessageSize decodeDialBackV2

writeDialBackResponseV2 :: StreamIO -> IO ()
writeDialBackResponseV2 stream = writeFramed stream encodeDialBackResponseV2

readDialBackResponseV2 :: StreamIO -> IO (Either String ())
readDialBackResponseV2 stream =
  readFramed stream maxAutoNATV2DialBackMessageSize decodeDialBackResponseV2

writeFramed :: StreamIO -> ByteString -> IO ()
writeFramed stream payload = streamWrite stream $
  encodeUvarint (fromIntegral (BS.length payload)) <> payload

readFramed
  :: StreamIO
  -> Int
  -> (ByteString -> Either String a)
  -> IO (Either String a)
readFramed stream maxSize decoder = do
  prefix <- readVarintBytes stream
  case decodeUvarint prefix of
    Left err -> pure (Left ("AutoNAT v2 varint decode error: " <> err))
    Right (lengthWord, _)
      | lengthWord > fromIntegral maxSize ->
          pure (Left "AutoNAT v2 message exceeds the size limit")
      | otherwise -> do
          payload <- readExactBounded stream maxSize (fromIntegral lengthWord)
          pure $ payload >>= decoder

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

responseStatusToWord :: ResponseStatusV2 -> Word32
responseStatusToWord ResponseInternalError = 0
responseStatusToWord ResponseRequestRejected = 100
responseStatusToWord ResponseDialRefused = 101
responseStatusToWord ResponseOK = 200
responseStatusToWord (ResponseStatusUnknown value) = value

responseStatusFromWord :: Word32 -> ResponseStatusV2
responseStatusFromWord 0 = ResponseInternalError
responseStatusFromWord 100 = ResponseRequestRejected
responseStatusFromWord 101 = ResponseDialRefused
responseStatusFromWord 200 = ResponseOK
responseStatusFromWord value = ResponseStatusUnknown value

dialStatusToWord :: DialStatusV2 -> Word32
dialStatusToWord DialStatusUnused = 0
dialStatusToWord DialStatusError = 100
dialStatusToWord DialStatusBackError = 101
dialStatusToWord DialStatusOK = 200
dialStatusToWord (DialStatusUnknown value) = value

dialStatusFromWord :: Word32 -> DialStatusV2
dialStatusFromWord 0 = DialStatusUnused
dialStatusFromWord 100 = DialStatusError
dialStatusFromWord 101 = DialStatusBackError
dialStatusFromWord 200 = DialStatusOK
dialStatusFromWord value = DialStatusUnknown value

firstParseError :: Either ParseError a -> Either String a
firstParseError = either (Left . show) Right
