-- | Noise XX handshake for libp2p secure channels.
--
-- Implements the Noise_XX_25519_ChaChaPoly_SHA256 handshake pattern
-- with libp2p-specific payload injection (identity key + signature).
--
-- Uses cacophony for the core Noise protocol state machine.
module LibP2P.Noise.Handshake
  ( -- * Handshake types
    HandshakeResult (..)
  , HandshakeState (..)
  , InlinedNegotiationResult (..)
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
import Data.ByteArray (ScrubbedBytes)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import LibP2P.Crypto.Key (PublicKey (..))
import qualified LibP2P.Crypto.Key as Key
import LibP2P.Crypto.PeerId (PeerId, fromPublicKey)
import LibP2P.Crypto.Protobuf (decodePublicKey)
import LibP2P.Noise.Session (NoiseSession, mkNoiseSession)
import LibP2P.Noise.Handshake.Payload
  ( NoisePayload (..)
  , buildHandshakePayload
  , decodeNoisePayload
  , encodeNoisePayload
  , verifyStaticKey
  )
import LibP2P.MultistreamSelect.Negotiation (ProtocolId)

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
  , hrNegotiatedMuxer :: !InlinedNegotiationResult
  }
  deriving (Show, Eq)

data InlinedNegotiationResult
  = Selected !ProtocolId
  | Fallback
  | NoOverlap
  deriving (Show, Eq)

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
    bobPayload <- encodeNoisePayload <$> buildHandshakePayload bobIdentity bobNoiseStaticPub Nothing
    (msg2, bobState2) <- writeHandshakeMsg bobState1 bobPayload
    (payload2, aliceState2) <- readHandshakeMsg aliceState1 msg2

    -- Decode Bob's identity
    bobNP <-
      case decodeNoisePayload payload2 of
        Left e -> Left $ show e
        Right x -> Right x
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
    alicePayload <- encodeNoisePayload <$> buildHandshakePayload aliceIdentity aliceNoiseStaticPub Nothing
    (msg3, _aliceFinal) <- writeHandshakeMsg aliceState2 alicePayload
    (payload3, bobFinal) <- readHandshakeMsg bobState2 msg3

    -- Decode Alice's identity
    aliceNP <-
      case decodeNoisePayload payload3 of
        Left e -> Left $ show e
        Right x -> Right x
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
    bobPayload <- encodeNoisePayload <$> buildHandshakePayload bobIdentity bobNoiseStaticPub Nothing
    (msg2, bobState2) <- writeHandshakeMsg bobState1 bobPayload
    (payload2, aliceState2) <- readHandshakeMsg aliceState1 msg2

    -- Verify Bob's identity_sig
    bobNP <-
      case decodeNoisePayload payload2 of
        Left e -> Left $ show e
        Right x -> Right x
    bobPubKey <- decodePublicKey (npIdentityKey bobNP)
    case getRemoteNoiseStaticKey aliceState2 of
      Nothing -> Left "performFullHandshakeWithSessions: remote Noise static key unavailable after msg2"
      Just remoteNoisePub ->
        if not (verifyStaticKey bobPubKey remoteNoisePub (npIdentitySig bobNP))
          then Left "performFullHandshakeWithSessions: Bob's identity signature verification failed"
          else Right ()

    -- Message 3: Alice → Bob (Alice's identity payload)
    alicePayload <- encodeNoisePayload <$> buildHandshakePayload aliceIdentity aliceNoiseStaticPub Nothing
    (msg3, aliceFinal) <- writeHandshakeMsg aliceState2 alicePayload
    (payload3, bobFinal) <- readHandshakeMsg bobState2 msg3

    -- Verify Alice's identity_sig
    aliceNP <-
      case decodeNoisePayload payload3 of
        Left e -> Left $ show e
        Right x -> Right x
    alicePubKey <- decodePublicKey (npIdentityKey aliceNP)
    case getRemoteNoiseStaticKey bobFinal of
      Nothing -> Left "performFullHandshakeWithSessions: remote Noise static key unavailable after msg3"
      Just remoteNoisePub ->
        if not (verifyStaticKey alicePubKey remoteNoisePub (npIdentitySig aliceNP))
          then Left "performFullHandshakeWithSessions: Alice's identity signature verification failed"
          else Right ()

    -- Convert to transport sessions
    Right (mkNoiseSession (hsNoiseState aliceFinal), mkNoiseSession (hsNoiseState bobFinal))
