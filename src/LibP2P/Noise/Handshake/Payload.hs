module LibP2P.Noise.Handshake.Payload
  ( -- * Noise handshake payload types
    NoisePayload(..)
  , NoiseExtensions(..)
    -- * Errors
  , PayloadDecodeError(..)
    -- * Smart constructor
  , buildHandshakePayload
  , buildInlinedExtensions
    -- * Encoder and decoder
  , encodeNoisePayload
  , decodeNoisePayload
    -- * Static key signing
  , signStaticKey
  , verifyStaticKey
    -- * libp2p-noise early data getters
  , getStreamMuxers
  )
where

import Data.ByteString (ByteString)
import Proto3.Wire.Decode (Parser, RawMessage, at, text, byteString, optional)
import Data.Text (Text)
import qualified Data.Text.Lazy as TL
import qualified Data.ByteString.Lazy as BL
import Proto3.Wire (FieldNumber(FieldNumber))
import Proto3.Wire.Decode (repeated, embedded, parse, ParseError)
import Proto3.Wire.Encode (MessageBuilder)
import qualified Proto3.Wire.Encode as Encode
import LibP2P.Crypto.Key (KeyPair(..), PrivateKey, PublicKey, sign, verify)
import LibP2P.Crypto.Protobuf (encodePublicKey)
import LibP2P.MultistreamSelect.Negotiation (ProtocolId)
import qualified Data.List.NonEmpty as NE
import Data.List.NonEmpty (NonEmpty)

-- | Noise handshake payload (protobuf-encoded in messages 2 and 3).
data NoisePayload = NoisePayload
  { npIdentityKey :: !ByteString -- ^ Serialized PublicKey protobuf
  , npIdentitySig :: !ByteString -- ^ Signature over "noise-libp2p-static-key:" || static_pubkey
  , npExts :: !(Maybe NoiseExtensions) -- ^ Extensions
  }
  deriving (Show, Eq)

-- | Gets the supplied inlined muxer list.
getStreamMuxers :: NoisePayload -> Maybe (NonEmpty ProtocolId)
getStreamMuxers payload = do
  exts <- npExts payload
  nExtStreamMuxers exts

-- | Errors that can occur when decoding the handshake payload
data PayloadDecodeError
  = ParseError ParseError -- ^ The payload does not conform to the protobuf spec
  | MissingKey -- ^ Missing serialized public key
  | MissingSig -- ^ Missing signature over "noise-libp2p-static-key:" || static_pubkey
  deriving (Show, Eq)

data NoiseExtensions = NoiseExtensions
  { nExtWebTransportCertHashes :: ![ByteString]
  , nExtStreamMuxers :: !(Maybe (NonEmpty ProtocolId))
  }
  deriving (Show, Eq)

-- | Noise handshake payload protobuf message as would be received from the wire
data NoisePayloadMessage = NoisePayloadMessage
  { npmIdentityKey :: !(Maybe ByteString)
  , npmIdentitySig :: !(Maybe ByteString)
  , npmExts :: !(Maybe NoiseExtensions)
  }
  deriving (Show, Eq)

-- | The prefix for the signed data in Noise handshake.
noiseStaticKeyPrefix :: ByteString
noiseStaticKeyPrefix = "noise-libp2p-static-key:"

-- | Sign the Noise static public key with the identity private key.
signStaticKey :: PrivateKey -> ByteString -> Either String ByteString
signStaticKey sk noiseStaticPubKey =
  let payload = noiseStaticKeyPrefix <> noiseStaticPubKey
   in sign sk payload

-- | Verify a signature over the Noise static public key.
verifyStaticKey :: PublicKey -> ByteString -> ByteString -> Bool
verifyStaticKey pk noiseStaticPubKey sig =
  let payload = noiseStaticKeyPrefix <> noiseStaticPubKey
   in verify pk payload sig

buildInlinedExtensions :: [ProtocolId] -> Maybe NoiseExtensions
buildInlinedExtensions [] = Nothing
buildInlinedExtensions streamMuxers = Just $ NoiseExtensions [] (NE.nonEmpty streamMuxers)

-- | Build a handshake payload from an identity key pair, Noise static pubkey, and optional list of supported muxers.
buildHandshakePayload :: KeyPair -> ByteString -> Maybe NoiseExtensions -> Either String NoisePayload
buildHandshakePayload identityKP noiseStaticPub exts = do
  identSig <-
    either (Left . ("buildHandshakePayload: " <>)) Right $
      signStaticKey (kpPrivate identityKP) noiseStaticPub
  Right (NoisePayload (encodePublicKey (kpPublic identityKP)) identSig exts)

--- | Encode a NoisePayload as a protobuf message.
encodeNoisePayload :: NoisePayload -> ByteString
encodeNoisePayload (NoisePayload identKey identSig noiseExts) =
  BL.toStrict $ Encode.toLazyByteString $ payloadBuilder
  where
    payloadBuilder :: MessageBuilder
    payloadBuilder =
      optBytes 1 (Just identKey)
      <> optBytes 2 (Just identSig)
      <> maybe mempty (Encode.embedded 4 . extBuilder) noiseExts

    extBuilder :: NoiseExtensions -> MessageBuilder
    extBuilder (NoiseExtensions certHashes muxers) =
      repBytes 1 certHashes
      <> repText 2 (maybe [] NE.toList muxers)

    optBytes :: Word -> Maybe ByteString -> MessageBuilder
    optBytes _ Nothing  = mempty
    optBytes n (Just v) = Encode.byteString (FieldNumber (fromIntegral n)) v

    repBytes :: Word -> [ByteString] -> MessageBuilder
    repBytes n = foldMap (Encode.byteString (FieldNumber (fromIntegral n)))

    repText :: Word -> [Text] -> MessageBuilder
    repText n = foldMap (Encode.text (FieldNumber (fromIntegral n)) . TL.fromStrict)

--- | Decode a NoisePayload from protobuf bytes.
decodeNoisePayload :: ByteString -> Either PayloadDecodeError NoisePayload
decodeNoisePayload bytes = do
  (NoisePayloadMessage mIdKey mIdSig exts) <-
    case parse noisePayloadMessageParser bytes of
      Left e -> Left $ ParseError e
      Right x -> Right x
  idKey <- maybe (Left MissingKey) Right mIdKey
  idSig <- maybe (Left MissingSig) Right mIdSig
  Right $ NoisePayload {npIdentityKey = idKey, npIdentitySig = idSig, npExts = exts}

--- | Parser for a NoiseExtensions message
noiseExtensionsParser :: Parser RawMessage NoiseExtensions
noiseExtensionsParser = NoiseExtensions
  <$> at (repeated byteString) (FieldNumber 1)
  <*> at (NE.nonEmpty <$> repeated (TL.toStrict <$> text)) (FieldNumber 2)

--- | Parser for a NoisePayload message
noisePayloadMessageParser :: Parser RawMessage NoisePayloadMessage
noisePayloadMessageParser = NoisePayloadMessage
  <$> at (optional byteString) (FieldNumber 1)
  <*> at (optional byteString) (FieldNumber 2)
  <*> at (embedded noiseExtensionsParser) (FieldNumber 4)
