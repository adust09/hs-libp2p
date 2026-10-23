-- | GossipSub RPC message encoding/decoding (protobuf).
--
-- Wire format from specs/pubsub (rpc.proto):
--   Message framing: [uvarint length][protobuf RPC]
--   RPC fields: subscriptions(1), publish(2), control(3)
--   SubOpts: subscribe(1), topicid(2)
--   Message: from(1), data(2), seqno(3), topic(4), signature(5), key(6)
--   ControlMessage: ihave(1), iwant(2), graft(3), prune(4), idontwant(5)
--   ControlIHave: topicID(1), messageIDs(2)
--   ControlIWant: messageIDs(1)
--   ControlIDontWant: messageIDs(1)
--   ControlGraft: topicID(1)
--   ControlPrune: topicID(1), peers(2), backoff(3)
--   PeerInfo: peerID(1), signedPeerRecord(2)
--
-- Uses proto3-wire, same pattern as DHT/Message.hs and Relay/Message.hs.
module LibP2P.Protocol.GossipSub.Message
  ( -- * Protobuf encode/decode (no framing)
    encodeRPC
  , decodeRPC
    -- * Sub-message encode/decode (exported for testing)
  , encodePubSubMessage
  , decodePubSubMessage
  , encodeControlMessage
  , decodeControlMessage
    -- * Wire framing (uvarint length prefix)
  , encodeFramed
  , decodeFramed
    -- * Serialization helpers
  , encodePubSubMessageBS
    -- * Stream I/O helpers
  , writeRPCMessage
  , readRPCMessage
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import Data.Text (Text)
import qualified Data.Text.Lazy as TL
import Data.Word (Word64)
import Proto3.Wire.Decode (Parser, RawMessage, ParseError, at, one, optional, repeated, embedded, embedded', parse)
import qualified Proto3.Wire.Decode as Decode
import Proto3.Wire.Encode (MessageBuilder)
import qualified Proto3.Wire.Encode as Encode
import Proto3.Wire.Types (FieldNumber (..))
import LibP2P.Core.Varint (encodeUvarint, decodeUvarint)
import LibP2P.MultistreamSelect.Negotiation (StreamIO (..), readExactBounded)
import LibP2P.Protocol.GossipSub.Types

-- Encoding helpers

optBytes :: Word -> Maybe ByteString -> MessageBuilder
optBytes _ Nothing  = mempty
optBytes n (Just v) = Encode.byteString (FieldNumber (fromIntegral n)) v

optText :: Word -> Maybe Text -> MessageBuilder
optText _ Nothing  = mempty
optText n (Just v) = Encode.text (FieldNumber (fromIntegral n)) (TL.fromStrict v)

optUint64 :: Word -> Maybe Word64 -> MessageBuilder
optUint64 _ Nothing  = mempty
optUint64 n (Just v) = Encode.uint64 (FieldNumber (fromIntegral n)) v

optEmbedded :: Word -> (a -> MessageBuilder) -> Maybe a -> MessageBuilder
optEmbedded _ _ Nothing  = mempty
optEmbedded n f (Just v) = Encode.embedded (FieldNumber (fromIntegral n)) (f v)

repEmbedded :: Word -> (a -> MessageBuilder) -> [a] -> MessageBuilder
repEmbedded n enc = foldMap (\x -> Encode.embedded (FieldNumber (fromIntegral n)) (enc x))

nonEmpty :: ByteString -> Maybe ByteString
nonEmpty bs
  | BS.null bs = Nothing
  | otherwise  = Just bs

nonEmptyText :: Text -> Maybe Text
nonEmptyText t
  | t == ""   = Nothing
  | otherwise = Just t

-- Encoding

-- | Encode a PubSubMessage sub-message.
encodePubSubMessage :: PubSubMessage -> MessageBuilder
encodePubSubMessage msg =
     optBytes 1 (msgFrom msg)
  <> optBytes 2 (nonEmpty (msgData msg))
  <> optBytes 3 (msgSeqNo msg)
  <> Encode.text (FieldNumber 4) (TL.fromStrict (msgTopic msg))
  <> optBytes 5 (msgSignature msg)
  <> optBytes 6 (msgKey msg)

-- | Encode a SubOpts sub-message.
encodeSubOpts :: SubOpts -> MessageBuilder
encodeSubOpts sub =
     Encode.bool (FieldNumber 1) (subSubscribe sub)
  <> Encode.text (FieldNumber 2) (TL.fromStrict (subTopicId sub))

-- | Encode an IHave sub-message.
encodeIHave :: IHave -> MessageBuilder
encodeIHave (IHave topic mids) =
     optText 1 (nonEmptyText topic)
  <> foldMap (\mid -> Encode.byteString (FieldNumber 2) mid) mids

-- | Encode an IWant sub-message.
encodeIWant :: IWant -> MessageBuilder
encodeIWant (IWant mids) =
  foldMap (\mid -> Encode.byteString (FieldNumber 1) mid) mids

-- | Encode an IDONTWANT sub-message.
encodeIDontWant :: IDontWant -> MessageBuilder
encodeIDontWant (IDontWant mids) =
  foldMap (\mid -> Encode.byteString (FieldNumber 1) mid) mids

-- | Encode a Graft sub-message.
encodeGraft :: Graft -> MessageBuilder
encodeGraft (Graft topic) =
  optText 1 (nonEmptyText topic)

-- | Encode a PeerExchangeInfo sub-message.
encodePeerExchangeInfo :: PeerExchangeInfo -> MessageBuilder
encodePeerExchangeInfo px =
     optBytes 1 (nonEmpty (pxPeerId px))
  <> optBytes 2 (pxSignedPeerRecord px)

-- | Encode a Prune sub-message.
encodePrune :: Prune -> MessageBuilder
encodePrune prn =
     optText 1 (nonEmptyText (pruneTopic prn))
  <> repEmbedded 2 encodePeerExchangeInfo (prunePeers prn)
  <> optUint64 3 (pruneBackoff prn)

-- | Encode a ControlMessage sub-message.
encodeControlMessage :: ControlMessage -> MessageBuilder
encodeControlMessage ctrl =
     repEmbedded 1 encodeIHave (ctrlIHave ctrl)
  <> repEmbedded 2 encodeIWant (ctrlIWant ctrl)
  <> repEmbedded 3 encodeGraft (ctrlGraft ctrl)
  <> repEmbedded 4 encodePrune (ctrlPrune ctrl)
  <> repEmbedded 5 encodeIDontWant (ctrlIDontWant ctrl)

-- | Encode an RPC message to protobuf (no framing).
encodeRPC :: RPC -> ByteString
encodeRPC rpc = BL.toStrict $ Encode.toLazyByteString $
     repEmbedded 1 encodeSubOpts (rpcSubscriptions rpc)
  <> repEmbedded 2 encodePubSubMessage (rpcPublish rpc)
  <> optEmbedded 3 encodeControlMessage (rpcControl rpc)

-- Decoding

-- | Decode PubSubMessage from protobuf.
pubSubMessageParser :: Parser RawMessage PubSubMessage
pubSubMessageParser = PubSubMessage
  <$> at (optional Decode.byteString) (FieldNumber 1)
  <*> at (one Decode.byteString BS.empty) (FieldNumber 2)
  <*> at (optional Decode.byteString) (FieldNumber 3)
  <*> at (one (TL.toStrict <$> Decode.text) "") (FieldNumber 4)
  <*> at (optional Decode.byteString) (FieldNumber 5)
  <*> at (optional Decode.byteString) (FieldNumber 6)

-- | Decode a PubSubMessage from raw bytes.
decodePubSubMessage :: ByteString -> Either ParseError PubSubMessage
decodePubSubMessage = parse pubSubMessageParser

-- | Encode a PubSubMessage to ByteString (used for signature computation).
encodePubSubMessageBS :: PubSubMessage -> ByteString
encodePubSubMessageBS msg = BL.toStrict $ Encode.toLazyByteString $ encodePubSubMessage msg

-- | Decode SubOpts from protobuf.
subOptsParser :: Parser RawMessage SubOpts
subOptsParser = SubOpts
  <$> at (one Decode.bool False) (FieldNumber 1)
  <*> at (one (TL.toStrict <$> Decode.text) "") (FieldNumber 2)

-- | Decode IHave from protobuf.
ihaveParser :: Parser RawMessage IHave
ihaveParser = IHave
  <$> at (one (TL.toStrict <$> Decode.text) "") (FieldNumber 1)
  <*> at (repeated Decode.byteString) (FieldNumber 2)

-- | Decode IWant from protobuf.
iwantParser :: Parser RawMessage IWant
iwantParser = IWant
  <$> at (repeated Decode.byteString) (FieldNumber 1)

-- | Decode IDONTWANT from protobuf.
idontwantParser :: Parser RawMessage IDontWant
idontwantParser = IDontWant
  <$> at (repeated Decode.byteString) (FieldNumber 1)

-- | Decode Graft from protobuf.
graftParser :: Parser RawMessage Graft
graftParser = Graft
  <$> at (one (TL.toStrict <$> Decode.text) "") (FieldNumber 1)

-- | Decode PeerExchangeInfo from protobuf.
peerExchangeInfoParser :: Parser RawMessage PeerExchangeInfo
peerExchangeInfoParser = PeerExchangeInfo
  <$> at (one Decode.byteString BS.empty) (FieldNumber 1)
  <*> at (optional Decode.byteString) (FieldNumber 2)

-- | Decode Prune from protobuf.
pruneParser :: Parser RawMessage Prune
pruneParser = Prune
  <$> at (one (TL.toStrict <$> Decode.text) "") (FieldNumber 1)
  <*> at (repeated (embedded' peerExchangeInfoParser)) (FieldNumber 2)
  <*> at (optional Decode.uint64) (FieldNumber 3)

-- | Decode ControlMessage from protobuf.
controlMessageParser :: Parser RawMessage ControlMessage
controlMessageParser = ControlMessage
  <$> at (repeated (embedded' ihaveParser)) (FieldNumber 1)
  <*> at (repeated (embedded' iwantParser)) (FieldNumber 2)
  <*> at (repeated (embedded' graftParser)) (FieldNumber 3)
  <*> at (repeated (embedded' pruneParser)) (FieldNumber 4)
  <*> at (repeated (embedded' idontwantParser)) (FieldNumber 5)

-- | Decode a ControlMessage from raw bytes.
decodeControlMessage :: ByteString -> Either ParseError ControlMessage
decodeControlMessage = parse controlMessageParser

-- | Decode RPC from protobuf.
rpcParser :: Parser RawMessage RPC
rpcParser = RPC
  <$> at (repeated (embedded' subOptsParser)) (FieldNumber 1)
  <*> at (repeated (embedded' pubSubMessageParser)) (FieldNumber 2)
  <*> at (embedded controlMessageParser) (FieldNumber 3)

-- | Decode an RPC from raw bytes.
decodeRPC :: ByteString -> Either ParseError RPC
decodeRPC = parse rpcParser

-- Wire framing

-- | Encode an RPC with uvarint length prefix.
encodeFramed :: RPC -> ByteString
encodeFramed rpc =
  let payload = encodeRPC rpc
      lenPrefix = encodeUvarint (fromIntegral (BS.length payload))
  in lenPrefix <> payload

-- | Decode an RPC from uvarint-length-prefixed bytes.
decodeFramed :: Int -> ByteString -> Either String RPC
decodeFramed maxSize bs = do
  (len, rest) <- decodeUvarint bs
  let msgLen = fromIntegral len :: Int
  if msgLen > maxSize
    then Left $ "GossipSub RPC too large: " ++ show msgLen ++ " > " ++ show maxSize
    else if BS.length rest < msgLen
      then Left "GossipSub RPC truncated"
      else case decodeRPC (BS.take msgLen rest) of
        Left err -> Left $ "GossipSub protobuf decode error: " ++ show err
        Right rpc -> Right rpc

-- Stream I/O helpers

-- | Write a framed RPC to a stream.
writeRPCMessage :: StreamIO -> RPC -> IO ()
writeRPCMessage stream rpc = streamWrite stream (encodeFramed rpc)

-- | Read a framed RPC from a stream.
readRPCMessage :: StreamIO -> Int -> IO (Either String RPC)
readRPCMessage stream maxSize = do
  varintBytes <- readVarintBytes stream
  case decodeUvarint varintBytes of
    Left err -> pure (Left $ "GossipSub varint decode error: " ++ err)
    Right (len, _) -> do
      let msgLen = fromIntegral len :: Int
      if msgLen > maxSize
        then pure (Left $ "GossipSub RPC too large: " ++ show msgLen ++ " > " ++ show maxSize)
        else do
          payloadOrErr <- readExactBounded stream maxSize msgLen
          case payloadOrErr of
            Left err -> pure (Left $ "GossipSub read error: " ++ err)
            Right payload -> case decodeRPC payload of
              Left err -> pure (Left $ "GossipSub protobuf decode error: " ++ show err)
              Right rpc -> pure (Right rpc)

-- | Read unsigned varint bytes (up to 10).
readVarintBytes :: StreamIO -> IO ByteString
readVarintBytes stream = go [] (0 :: Int)
  where
    go acc n
      | n >= 10 = pure (BS.pack (reverse acc))
      | otherwise = do
          b <- streamReadByte stream
          if b < 0x80
            then pure (BS.pack (reverse (b : acc)))
            else go (b : acc) (n + 1)
