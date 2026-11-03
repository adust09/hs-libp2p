{- | Noise authentication for libp2p WebTransport sessions.

WebTransport uses Noise only on the first session stream to authenticate
peer identities and bind the server's TLS certificate hashes. The resulting
Noise transport cipher is deliberately discarded: subsequent WebTransport
streams are protected by QUIC TLS and are not double-encrypted.
-}
module LibP2P.Noise.WebTransport (
  performWebTransportInitiator,
  performWebTransportResponder,
) where

import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import LibP2P.Core.Binary (readWord16BE)
import LibP2P.Crypto.Key (KeyPair, PublicKey)
import LibP2P.Crypto.PeerId (fromPublicKey)
import LibP2P.Crypto.Protobuf qualified as Protobuf
import LibP2P.MultistreamSelect.Negotiation (StreamIO (..))
import LibP2P.Noise.Framing (encodeFrame)
import LibP2P.Noise.Handshake (
  HandshakeResult (..),
  HandshakeState,
  NoisePayload (..),
  buildHandshakePayload,
  decodeNoiseCerthashes,
  decodeNoisePayload,
  encodeNoisePayload,
  encodeNoisePayloadWithCerthashes,
  getRemoteNoiseStaticKey,
  initHandshakeInitiator,
  initHandshakeResponder,
  readHandshakeMsg,
  verifyStaticKey,
  writeHandshakeMsg,
 )

{- | Authenticate an outbound WebTransport session and return the remote peer
plus the certificate hashes bound into the responder's Noise payload.
-}
performWebTransportInitiator ::
  KeyPair -> StreamIO -> IO (HandshakeResult, [ByteString])
performWebTransportInitiator identity stream = do
  (initial, staticKey) <- initHandshakeInitiator identity
  state1 <- sendFirstMessage stream initial
  (remotePayload, state2) <- receiveIdentityMessage "initiator" stream state1
  result <- verifyRemoteIdentity "initiator" state2 remotePayload
  localPayload <- buildEncodedPayload identity staticKey []
  sendFinalMessage "initiator" stream state2 localPayload
  hashes <-
    either (fail . ("initiator decode extensions: " <>)) pure $
      decodeNoiseCerthashes remotePayload
  pure (result, hashes)

{- | Authenticate an inbound WebTransport session. The supplied certificate
multihashes are sent in the responder's signed Noise payload.
-}
performWebTransportResponder ::
  KeyPair -> [ByteString] -> StreamIO -> IO HandshakeResult
performWebTransportResponder identity certificateHashes stream = do
  (initial, staticKey) <- initHandshakeResponder identity
  state1 <- receiveFirstMessage stream initial
  localPayload <- buildEncodedPayload identity staticKey certificateHashes
  state2 <- sendIdentityMessage "responder" stream state1 localPayload
  (remotePayload, finalState) <- receiveIdentityMessage "responder" stream state2
  verifyRemoteIdentity "responder" finalState remotePayload

sendFirstMessage :: StreamIO -> HandshakeState -> IO HandshakeState
sendFirstMessage stream state = do
  (message, next) <-
    either (fail . ("initiator msg1 write: " <>)) pure $
      writeHandshakeMsg state BS.empty
  writeFramedMessage stream message
  pure next

receiveFirstMessage :: StreamIO -> HandshakeState -> IO HandshakeState
receiveFirstMessage stream state = do
  message <- readFramedMessage stream
  (_, next) <-
    either (fail . ("responder msg1 read: " <>)) pure $
      readHandshakeMsg state message
  pure next

sendIdentityMessage ::
  String -> StreamIO -> HandshakeState -> ByteString -> IO HandshakeState
sendIdentityMessage role stream state payload = do
  (message, next) <-
    either (fail . ((role <> " msg2 write: ") <>)) pure $
      writeHandshakeMsg state payload
  writeFramedMessage stream message
  pure next

sendFinalMessage :: String -> StreamIO -> HandshakeState -> ByteString -> IO ()
sendFinalMessage role stream state payload = do
  (message, _) <-
    either (fail . ((role <> " msg3 write: ") <>)) pure $
      writeHandshakeMsg state payload
  writeFramedMessage stream message

receiveIdentityMessage ::
  String -> StreamIO -> HandshakeState -> IO (ByteString, HandshakeState)
receiveIdentityMessage role stream state = do
  message <- readFramedMessage stream
  either (fail . ((role <> " handshake read: ") <>)) pure $
    readHandshakeMsg state message

buildEncodedPayload ::
  KeyPair -> ByteString -> [ByteString] -> IO ByteString
buildEncodedPayload identity staticKey hashes = do
  payload <-
    either (fail . ("Noise identity payload: " <>)) pure $
      buildHandshakePayload identity staticKey
  pure $
    if null hashes
      then encodeNoisePayload payload
      else encodeNoisePayloadWithCerthashes payload hashes

verifyRemoteIdentity ::
  String -> HandshakeState -> ByteString -> IO HandshakeResult
verifyRemoteIdentity role state bytes = do
  payload <-
    either (fail . ((role <> " decode payload: ") <>)) pure $
      decodeNoisePayload bytes
  publicKey <-
    either (fail . ((role <> " decode public key: ") <>)) pure $
      Protobuf.decodePublicKey (npIdentityKey payload)
  verifyIdentitySignature role state publicKey payload
  pure
    HandshakeResult
      { hrRemotePeerId = fromPublicKey publicKey
      , hrRemotePublicKey = publicKey
      }

verifyIdentitySignature ::
  String -> HandshakeState -> PublicKey -> NoisePayload -> IO ()
verifyIdentitySignature role state publicKey payload =
  case getRemoteNoiseStaticKey state of
    Nothing -> fail $ role <> ": remote Noise static key unavailable"
    Just remoteStatic
      | verifyStaticKey publicKey remoteStatic (npIdentitySig payload) -> pure ()
      | otherwise -> fail $ role <> ": identity signature verification failed"

writeFramedMessage :: StreamIO -> ByteString -> IO ()
writeFramedMessage stream message =
  either fail (streamWrite stream) (encodeFrame message)

readFramedMessage :: StreamIO -> IO ByteString
readFramedMessage stream = do
  lengthBytes <- readExact stream 2
  let size = fromIntegral (readWord16BE lengthBytes)
  readExact stream size

readExact :: StreamIO -> Int -> IO ByteString
readExact stream wanted = go BS.empty wanted
 where
  go acc 0 = pure acc
  go acc remaining = do
    chunk <- streamReadChunk stream remaining
    if BS.null chunk
      then fail "WebTransport Noise stream closed unexpectedly"
      else go (acc <> chunk) (remaining - BS.length chunk)
