-- | Noise XX handshake for libp2p secure channels.
--
-- Implements the Noise_XX_25519_ChaChaPoly_SHA256 handshake pattern
-- with libp2p-specific payload injection (identity key + signature).
--
-- Uses cacophony for the core Noise protocol state machine.
module LibP2P.Noise.Handshake
  ( -- * Handshake types
    HandshakeResult (..)
  , NoisePayload (..)
  , HandshakeState (..)
    -- * Payload encoding
  , encodeNoisePayload
  , encodeNoisePayloadWithCerthashes
  , decodeNoisePayload
  , decodeNoiseCerthashes
  , buildHandshakePayload
    -- * Static key signing
  , signStaticKey
  , verifyStaticKey
    -- * Handshake lifecycle
  , initHandshakeInitiator
  , initHandshakeResponder
  , writeHandshakeMsg
  , readHandshakeMsg
  , sessionComplete
    -- * Remote static key extraction
  , getRemoteNoiseStaticKey
    -- * Convenience
  , performFullHandshake
  , performFullHandshakeWithSessions
    -- * Re-exports for payload decoding
  , decodePublicKey
  ) where

import Crypto.Noise
  ( HandshakeRole (..)
  , NoiseResult (..)
  , NoiseState
  , convert
  , defaultHandshakeOpts
  , handshakeComplete
  , noiseState
  , readMessage
  , remoteStaticKey
  , setLocalEphemeral
  , setLocalStatic
  , writeMessage
  )
import Crypto.Noise.Cipher.ChaChaPoly1305 (ChaChaPoly1305)
import Crypto.Noise.DH (dhGenKey, dhPubToBytes)
import qualified Crypto.Noise.DH as DH
import Crypto.Noise.DH.Curve25519 (Curve25519)
import Crypto.Noise.HandshakePatterns (noiseXX)
import Crypto.Noise.Hash.SHA256 (SHA256)
import Data.Bits (shiftL, shiftR, (.&.), (.|.))
import Data.ByteArray (ScrubbedBytes)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word64)
import LibP2P.Core.Varint (decodeUvarint, encodeUvarint)
import LibP2P.Crypto.Key
  ( KeyPair (..)
  , PrivateKey (..)
  , PublicKey (..)
  , verify
  )
import qualified LibP2P.Crypto.Key as Key
import LibP2P.Crypto.PeerId (PeerId, fromPublicKey)
import LibP2P.Crypto.Protobuf (decodePublicKey, encodePublicKey)
import LibP2P.Noise.Session (NoiseSession, mkNoiseSession)

-- | Type alias for the Noise state with our fixed cipher suite.
type CacophonyState = NoiseState ChaChaPoly1305 Curve25519 SHA256

-- | Opaque handshake state wrapping cacophony's NoiseState.
newtype HandshakeState = HandshakeState
  { hsNoiseState :: CacophonyState
  }

-- | Result of a successful Noise handshake.
data HandshakeResult = HandshakeResult
  { hrRemotePeerId :: !PeerId
  , hrRemotePublicKey :: !PublicKey
  }
  deriving (Show, Eq)

-- | Noise handshake payload (protobuf-encoded in messages 2 and 3).
data NoisePayload = NoisePayload
  { npIdentityKey :: !ByteString -- ^ Serialized PublicKey protobuf
  , npIdentitySig :: !ByteString -- ^ Signature over "noise-libp2p-static-key:" || static_pubkey
  }
  deriving (Show, Eq)

-- | The prefix for the signed data in Noise handshake.
noiseStaticKeyPrefix :: ByteString
noiseStaticKeyPrefix = "noise-libp2p-static-key:"

-- | Sign the Noise static public key with the identity private key.
signStaticKey :: PrivateKey -> ByteString -> Either String ByteString
signStaticKey sk noiseStaticPubKey =
  let payload = noiseStaticKeyPrefix <> noiseStaticPubKey
   in Key.sign sk payload

-- | Verify a signature over the Noise static public key.
verifyStaticKey :: PublicKey -> ByteString -> ByteString -> Bool
verifyStaticKey pk noiseStaticPubKey sig =
  let payload = noiseStaticKeyPrefix <> noiseStaticPubKey
   in verify pk payload sig

-- | Build a handshake payload from an identity key pair and Noise static pubkey.
buildHandshakePayload :: Key.KeyPair -> ByteString -> Either String NoisePayload
buildHandshakePayload identityKP noiseStaticPub = do
  identSig <-
    either (Left . ("buildHandshakePayload: " <>)) Right $
      signStaticKey (kpPrivate identityKP) noiseStaticPub
  Right (NoisePayload (encodePublicKey (kpPublic identityKP)) identSig)

-- | Encode a NoisePayload as a minimal protobuf message.
encodeNoisePayload :: NoisePayload -> ByteString
encodeNoisePayload (NoisePayload identKey identSig) =
  -- Field 1: tag 0x0a (field 1, wire type 2 = length-delimited)
  BS.singleton 0x0a
    <> encodeUvarint (fromIntegral (BS.length identKey))
    <> identKey
    -- Field 2: tag 0x12 (field 2, wire type 2 = length-delimited)
    <> BS.singleton 0x12
    <> encodeUvarint (fromIntegral (BS.length identSig))
    <> identSig

-- | Encode a Noise payload with libp2p WebTransport certificate hashes.
encodeNoisePayloadWithCerthashes :: NoisePayload -> [ByteString] -> ByteString
encodeNoisePayloadWithCerthashes payload [] = encodeNoisePayload payload
encodeNoisePayloadWithCerthashes payload hashes =
  encodeNoisePayload payload <> lengthDelimitedField 4 extensions
  where
    extensions = BS.concat (map (lengthDelimitedField 1) hashes)

-- | Decode WebTransport certificate hashes from Noise payload extensions.
decodeNoiseCerthashes :: ByteString -> Either String [ByteString]
decodeNoiseCerthashes = fmap concat . collectOuterExtensions

collectOuterExtensions :: ByteString -> Either String [[ByteString]]
collectOuterExtensions input
  | BS.null input = Right []
  | otherwise = do
      (tag, rest) <- decodeUvarint input
      let fieldNum = tag `shiftR` 3
          wireType = tag .&. 0x7
      if fieldNum == 4 && wireType == 2
        then do
          (extension, trailing) <- parseLengthDelimited rest
          hashes <- collectCerthashes extension
          (hashes :) <$> collectOuterExtensions trailing
        else skipExtensionField wireType rest >>= collectOuterExtensions

collectCerthashes :: ByteString -> Either String [ByteString]
collectCerthashes input
  | BS.null input = Right []
  | otherwise = do
      (tag, rest) <- decodeUvarint input
      let fieldNum = tag `shiftR` 3
          wireType = tag .&. 0x7
      if fieldNum == 1 && wireType == 2
        then do
          (hash, trailing) <- parseLengthDelimited rest
          (hash :) <$> collectCerthashes trailing
        else skipExtensionField wireType rest >>= collectCerthashes

lengthDelimitedField :: Word64 -> ByteString -> ByteString
lengthDelimitedField fieldNumber bytes =
  encodeUvarint ((fieldNumber `shiftL` 3) .|. 2)
    <> encodeUvarint (fromIntegral (BS.length bytes))
    <> bytes

parseLengthDelimited :: ByteString -> Either String (ByteString, ByteString)
parseLengthDelimited input = do
  (len, rest) <- decodeUvarint input
  let fieldLen = fromIntegral len :: Int
  if BS.length rest < fieldLen
    then Left "protobuf length-delimited field is truncated"
    else Right (BS.take fieldLen rest, BS.drop fieldLen rest)

skipExtensionField :: Word64 -> ByteString -> Either String ByteString
skipExtensionField 0 input = snd <$> decodeUvarint input
skipExtensionField 1 input = skipExtensionFixed 8 input
skipExtensionField 2 input = snd <$> parseLengthDelimited input
skipExtensionField 5 input = skipExtensionFixed 4 input
skipExtensionField wireType _ =
  Left $ "unsupported protobuf wire type " <> show wireType

skipExtensionFixed :: Int -> ByteString -> Either String ByteString
skipExtensionFixed size input
  | BS.length input < size = Left "protobuf fixed-width field is truncated"
  | otherwise = Right (BS.drop size input)

-- | Decode a NoisePayload from protobuf bytes.
--
-- Protobuf does not constrain field order on the wire, so fields are
-- dispatched by number in a loop rather than matched in a fixed
-- sequence. Unknown fields are skipped according to their wire type
-- (go-libp2p already emits an extensions message as field 4, and other
-- implementations may add more). Both identity_key (field 1) and
-- identity_sig (field 2) must be present; on duplicates the last
-- occurrence wins, per protobuf merge semantics.
decodeNoisePayload :: ByteString -> Either String NoisePayload
decodeNoisePayload bs0 = do
  (mKey, mSig) <- go (Nothing, Nothing) bs0
  identKey <- maybe (Left "decodeNoisePayload: missing identity_key (field 1)") Right mKey
  identSig <- maybe (Left "decodeNoisePayload: missing identity_sig (field 2)") Right mSig
  Right (NoisePayload identKey identSig)
  where
    go
      :: (Maybe ByteString, Maybe ByteString)
      -> ByteString
      -> Either String (Maybe ByteString, Maybe ByteString)
    go acc@(mKey, mSig) input
      | BS.null input = Right acc
      | otherwise = do
          (tag, rest) <- decodeUvarint input
          let fieldNum = tag `shiftR` 3
              wireType = tag .&. 0x7
          case (fieldNum, wireType) of
            (1, 2) -> do
              (v, rest') <- lengthDelimited rest
              go (Just v, mSig) rest'
            (2, 2) -> do
              (v, rest') <- lengthDelimited rest
              go (mKey, Just v) rest'
            (_, wt) -> do
              rest' <- skipField wt rest
              go acc rest'

    lengthDelimited :: ByteString -> Either String (ByteString, ByteString)
    lengthDelimited input = do
      (len, rest) <- decodeUvarint input
      let fieldLen = fromIntegral len :: Int
      if BS.length rest < fieldLen
        then Left "decodeNoisePayload: not enough bytes for field"
        else Right (BS.take fieldLen rest, BS.drop fieldLen rest)

    skipField :: Word64 -> ByteString -> Either String ByteString
    skipField 0 input = snd <$> decodeUvarint input
    skipField 1 input = skipFixed 8 input
    skipField 2 input = snd <$> lengthDelimited input
    skipField 5 input = skipFixed 4 input
    skipField wt _ = Left $ "decodeNoisePayload: unsupported wire type " <> show wt

    skipFixed :: Int -> ByteString -> Either String ByteString
    skipFixed n input
      | BS.length input < n = Left "decodeNoisePayload: not enough bytes for field"
      | otherwise = Right (BS.drop n input)

-- | Initialize a handshake state for the initiator role.
-- Returns (HandshakeState, noiseStaticPublicKey).
initHandshakeInitiator :: Key.KeyPair -> IO (HandshakeState, ByteString)
initHandshakeInitiator _identityKP = do
  noiseStaticKP <- dhGenKey :: IO (DH.KeyPair Curve25519)
  noiseEphemeralKP <- dhGenKey :: IO (DH.KeyPair Curve25519)
  let noiseStaticPub = convert (dhPubToBytes (snd noiseStaticKP)) :: ByteString
  let opts = setLocalStatic (Just noiseStaticKP)
           . setLocalEphemeral (Just noiseEphemeralKP)
           $ defaultHandshakeOpts InitiatorRole ""
  let ns = noiseState opts noiseXX :: CacophonyState
  pure (HandshakeState ns, noiseStaticPub)

-- | Initialize a handshake state for the responder role.
-- Returns (HandshakeState, noiseStaticPublicKey).
initHandshakeResponder :: Key.KeyPair -> IO (HandshakeState, ByteString)
initHandshakeResponder _identityKP = do
  noiseStaticKP <- dhGenKey :: IO (DH.KeyPair Curve25519)
  noiseEphemeralKP <- dhGenKey :: IO (DH.KeyPair Curve25519)
  let noiseStaticPub = convert (dhPubToBytes (snd noiseStaticKP)) :: ByteString
  let opts = setLocalStatic (Just noiseStaticKP)
           . setLocalEphemeral (Just noiseEphemeralKP)
           $ defaultHandshakeOpts ResponderRole ""
  let ns = noiseState opts noiseXX :: CacophonyState
  pure (HandshakeState ns, noiseStaticPub)

-- | Write a handshake message with the given payload.
-- Returns (ciphertext, updatedState).
writeHandshakeMsg :: HandshakeState -> ByteString -> Either String (ByteString, HandshakeState)
writeHandshakeMsg hs payload =
  let sb = convert payload :: ScrubbedBytes
   in case writeMessage sb (hsNoiseState hs) of
        NoiseResultMessage ct ns' ->
          Right (convert ct, HandshakeState ns')
        NoiseResultException ex ->
          Left $ "writeHandshakeMsg: " <> show ex
        NoiseResultNeedPSK _ ->
          Left "writeHandshakeMsg: unexpected PSK request"

-- | Read a handshake message and extract the decrypted payload.
-- Returns (plaintext, updatedState).
readHandshakeMsg :: HandshakeState -> ByteString -> Either String (ByteString, HandshakeState)
readHandshakeMsg hs ciphertext =
  let sb = convert ciphertext :: ScrubbedBytes
   in case readMessage sb (hsNoiseState hs) of
        NoiseResultMessage pt ns' ->
          Right (convert pt, HandshakeState ns')
        NoiseResultException ex ->
          Left $ "readHandshakeMsg: " <> show ex
        NoiseResultNeedPSK _ ->
          Left "readHandshakeMsg: unexpected PSK request"

-- | Extract the remote party's Noise static public key from the handshake state.
-- Returns Just after the remote static key has been transmitted (msg2 for initiator,
-- msg3 for responder in XX pattern).
getRemoteNoiseStaticKey :: HandshakeState -> Maybe ByteString
getRemoteNoiseStaticKey hs =
  convert . dhPubToBytes <$> remoteStaticKey (hsNoiseState hs)

-- | Check whether the handshake is complete.
sessionComplete :: HandshakeState -> Bool
sessionComplete = handshakeComplete . hsNoiseState

-- | Perform a full 3-message XX handshake between two peers.
-- Returns the remote PeerId as seen by each side.
performFullHandshake :: Key.KeyPair -> Key.KeyPair -> IO (Either String (PeerId, PeerId))
performFullHandshake aliceIdentity bobIdentity = do
  (aliceInit, aliceNoiseStaticPub) <- initHandshakeInitiator aliceIdentity
  (bobInit, bobNoiseStaticPub) <- initHandshakeResponder bobIdentity
  pure $ do
    -- Message 1: Alice → Bob (empty payload)
    (msg1, aliceState1) <- writeHandshakeMsg aliceInit BS.empty
    (_payload1, bobState1) <- readHandshakeMsg bobInit msg1

    -- Message 2: Bob → Alice (Bob's identity payload)
    bobPayload <- encodeNoisePayload <$> buildHandshakePayload bobIdentity bobNoiseStaticPub
    (msg2, bobState2) <- writeHandshakeMsg bobState1 bobPayload
    (payload2, aliceState2) <- readHandshakeMsg aliceState1 msg2

    -- Decode Bob's identity
    bobNP <- decodeNoisePayload payload2
    bobPubKey <- decodePublicKey (npIdentityKey bobNP)
    let bobRemotePeerId = fromPublicKey bobPubKey

    -- Verify Bob's identity_sig: binds identity key to Noise static key
    case getRemoteNoiseStaticKey aliceState2 of
      Nothing -> Left "performFullHandshake: remote Noise static key unavailable after msg2"
      Just remoteNoisePub ->
        if not (verifyStaticKey bobPubKey remoteNoisePub (npIdentitySig bobNP))
          then Left "performFullHandshake: Bob's identity signature verification failed"
          else Right ()

    -- Message 3: Alice → Bob (Alice's identity payload)
    alicePayload <- encodeNoisePayload <$> buildHandshakePayload aliceIdentity aliceNoiseStaticPub
    (msg3, _aliceFinal) <- writeHandshakeMsg aliceState2 alicePayload
    (payload3, bobFinal) <- readHandshakeMsg bobState2 msg3

    -- Decode Alice's identity
    aliceNP <- decodeNoisePayload payload3
    alicePubKey <- decodePublicKey (npIdentityKey aliceNP)
    let aliceRemotePeerId = fromPublicKey alicePubKey

    -- Verify Alice's identity_sig: binds identity key to Noise static key
    case getRemoteNoiseStaticKey bobFinal of
      Nothing -> Left "performFullHandshake: remote Noise static key unavailable after msg3"
      Just remoteNoisePub ->
        if not (verifyStaticKey alicePubKey remoteNoisePub (npIdentitySig aliceNP))
          then Left "performFullHandshake: Alice's identity signature verification failed"
          else Right ()

    Right (bobRemotePeerId, aliceRemotePeerId)

-- | Perform a full handshake and return transport sessions for both sides.
performFullHandshakeWithSessions :: Key.KeyPair -> Key.KeyPair -> IO (Either String (NoiseSession, NoiseSession))
performFullHandshakeWithSessions aliceIdentity bobIdentity = do
  (aliceInit, aliceNoiseStaticPub) <- initHandshakeInitiator aliceIdentity
  (bobInit, bobNoiseStaticPub) <- initHandshakeResponder bobIdentity
  pure $ do
    -- Message 1: Alice → Bob (empty payload)
    (msg1, aliceState1) <- writeHandshakeMsg aliceInit BS.empty
    (_payload1, bobState1) <- readHandshakeMsg bobInit msg1

    -- Message 2: Bob → Alice (Bob's identity payload)
    bobPayload <- encodeNoisePayload <$> buildHandshakePayload bobIdentity bobNoiseStaticPub
    (msg2, bobState2) <- writeHandshakeMsg bobState1 bobPayload
    (payload2, aliceState2) <- readHandshakeMsg aliceState1 msg2

    -- Verify Bob's identity_sig
    bobNP <- decodeNoisePayload payload2
    bobPubKey <- decodePublicKey (npIdentityKey bobNP)
    case getRemoteNoiseStaticKey aliceState2 of
      Nothing -> Left "performFullHandshakeWithSessions: remote Noise static key unavailable after msg2"
      Just remoteNoisePub ->
        if not (verifyStaticKey bobPubKey remoteNoisePub (npIdentitySig bobNP))
          then Left "performFullHandshakeWithSessions: Bob's identity signature verification failed"
          else Right ()

    -- Message 3: Alice → Bob (Alice's identity payload)
    alicePayload <- encodeNoisePayload <$> buildHandshakePayload aliceIdentity aliceNoiseStaticPub
    (msg3, aliceFinal) <- writeHandshakeMsg aliceState2 alicePayload
    (payload3, bobFinal) <- readHandshakeMsg bobState2 msg3

    -- Verify Alice's identity_sig
    aliceNP <- decodeNoisePayload payload3
    alicePubKey <- decodePublicKey (npIdentityKey aliceNP)
    case getRemoteNoiseStaticKey bobFinal of
      Nothing -> Left "performFullHandshakeWithSessions: remote Noise static key unavailable after msg3"
      Just remoteNoisePub ->
        if not (verifyStaticKey alicePubKey remoteNoisePub (npIdentitySig aliceNP))
          then Left "performFullHandshakeWithSessions: Alice's identity signature verification failed"
          else Right ()

    -- Convert to transport sessions
    Right (mkNoiseSession (hsNoiseState aliceFinal), mkNoiseSession (hsNoiseState bobFinal))
