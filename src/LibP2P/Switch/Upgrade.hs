-- | Connection upgrade pipeline for the Switch.
--
-- Transforms a raw transport connection into a fully upgraded
-- (secure + multiplexed) Connection by executing a 4-step pipeline:
--   1. multistream-select: negotiate security protocol ("/noise")
--   2. Noise XX handshake: encrypted channel + remote PeerId
--   3. multistream-select: negotiate muxer ("/yamux/1.0.0")
--   4. Yamux session init: multiplexed streams
--
-- Implements the connection upgrading pipeline.
module LibP2P.Switch.Upgrade
  ( -- * Streaming handshake
    performStreamHandshake
    -- * Encrypted StreamIO
  , noiseSessionToStreamIO
    -- * Yamux → MuxerSession adapter
  , yamuxToMuxerSession
    -- * Full upgrade pipeline
  , upgradeAs
  , upgradeAsWithConfig
  , upgradeOutbound
  , upgradeInbound
    -- * Helpers (exported for testing)
  , readExact
  , readFramedMessage
  , writeFramedMessage
  ) where

import Control.Concurrent.Async (async, cancel, race, waitCatch)
import Control.Concurrent.STM (atomically, isEmptyTQueue, newTVarIO, retry)
import Control.Exception (SomeException, catch)
import Control.Monad (unless)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import Data.Word (Word8)
import LibP2P.Core.Binary (readWord16BE)
import LibP2P.Crypto.Key (KeyPair (..))
import LibP2P.Crypto.PeerId (fromPublicKey)
import LibP2P.Yamux.Frame (maxStreamWindowSize)
import LibP2P.Yamux.Session (closeSession, keepaliveLoop, newSessionWithConfig, recvLoop, sendLoop)
import qualified LibP2P.Yamux.Session as Yamux
import LibP2P.Yamux.Stream (streamRead)
import qualified LibP2P.Yamux.Stream as YS
import LibP2P.Yamux.Types (SessionRole (..), YamuxConfig, YamuxSession (ysessSendCh), YamuxStream, defaultYamuxConfig)
import LibP2P.MultistreamSelect.Negotiation
  ( NegotiationResult (..)
  , StreamIO (..)
  , negotiateInitiator
  , negotiateResponder
  , readExactBounded
  )
import LibP2P.Noise.Framing (chunkPlaintext, encodeFrame)
import LibP2P.Noise.Handshake
  ( HandshakeResult (..)
  , buildHandshakePayload
  , decodeNoisePayload
  , encodeNoisePayload
  , getRemoteNoiseStaticKey
  , initHandshakeInitiator
  , initHandshakeResponder
  , readHandshakeMsg
  , verifyStaticKey
  , writeHandshakeMsg
  )
import LibP2P.Noise.Session
  ( NoiseSession
  , decryptMessage
  , encryptMessage
  , mkNoiseSession
  )
import LibP2P.Switch.Types
  ( ConnState (..)
  , Connection (..)
  , Direction (..)
  , MuxerSession (..)
  )
import LibP2P.Transport
  ( ConnectionEndpoint (..)
  , NativeMuxer (..)
  , RawConnection (..)
  )
import System.Timeout (timeout)
import qualified LibP2P.Crypto.Protobuf as Proto
import qualified LibP2P.Noise.Handshake as HS

-- | Read exactly n bytes from a StreamIO.
--
-- Exception-style wrapper over 'readExactBounded' for the Noise frame
-- reader and the yamux read callback, which expect failures as
-- exceptions. Defence in depth against remote memory exhaustion: the
-- request size is bounded by maxStreamWindowSize (callers must validate
-- lengths against flow control before reading).
readExact :: StreamIO -> Int -> IO ByteString
readExact stream n =
  either fail pure
    =<< readExactBounded stream (fromIntegral maxStreamWindowSize) n

-- | Read a 2-byte-BE-length-prefixed Noise frame from a StreamIO.
readFramedMessage :: StreamIO -> IO ByteString
readFramedMessage stream = do
  lenBytes <- readExact stream 2
  let len = fromIntegral (readWord16BE lenBytes) :: Int
  if len == 0
    then pure BS.empty
    else readExact stream len

-- | Write a 2-byte-BE-length-prefixed Noise frame to a StreamIO.
-- Fails (instead of truncating the length prefix) if the message exceeds
-- the 65535-byte Noise message cap.
writeFramedMessage :: StreamIO -> ByteString -> IO ()
writeFramedMessage stream msg =
  either fail (streamWrite stream) (encodeFrame msg)

-- | Perform a Noise XX handshake over a StreamIO using framed messages.
-- Returns (NoiseSession, HandshakeResult) with the remote PeerId.
performStreamHandshake
  :: KeyPair -> Direction -> StreamIO -> IO (NoiseSession, HandshakeResult)
performStreamHandshake identityKP dir stream = case dir of
  Outbound -> performInitiatorHandshake identityKP stream
  Inbound  -> performResponderHandshake identityKP stream

-- | Initiator (dialer) side of the Noise XX handshake.
--
-- Message flow:
--   1. Initiator → Responder: e (empty payload)
--   2. Responder → Initiator: e, ee, s, es (responder identity payload)
--   3. Initiator → Responder: s, se (initiator identity payload)
performInitiatorHandshake :: KeyPair -> StreamIO -> IO (NoiseSession, HandshakeResult)
performInitiatorHandshake identityKP stream = do
  (hsState0, noiseStaticPub) <- initHandshakeInitiator identityKP

  -- Message 1: → (empty payload)
  (msg1, hsState1) <- either (fail . ("initiator msg1 write: " <>)) pure $
    writeHandshakeMsg hsState0 BS.empty
  writeFramedMessage stream msg1

  -- Message 2: ← (responder's identity payload)
  msg2 <- readFramedMessage stream
  (payload2, hsState2) <- either (fail . ("initiator msg2 read: " <>)) pure $
    readHandshakeMsg hsState1 msg2

  -- Decode responder's identity
  remoteNP <- either (fail . ("initiator decode payload: " <>)) pure $
    decodeNoisePayload payload2
  remotePubKey <- either (fail . ("initiator decode pubkey: " <>)) pure $
    Proto.decodePublicKey (HS.npIdentityKey remoteNP)
  let remotePeerId = fromPublicKey remotePubKey

  -- Verify identity_sig: binds identity key to Noise static key
  case getRemoteNoiseStaticKey hsState2 of
    Nothing -> fail "performInitiatorHandshake: remote Noise static key unavailable after msg2"
    Just remoteNoisePub ->
      if not (verifyStaticKey remotePubKey remoteNoisePub (HS.npIdentitySig remoteNP))
        then fail "performInitiatorHandshake: identity signature verification failed"
        else pure ()

  -- Message 3: → (initiator's identity payload)
  identPayload <- either (fail . ("initiator payload build: " <>)) pure $
    encodeNoisePayload <$> buildHandshakePayload identityKP noiseStaticPub
  (msg3, hsStateFinal) <- either (fail . ("initiator msg3 write: " <>)) pure $
    writeHandshakeMsg hsState2 identPayload
  writeFramedMessage stream msg3

  let noiseSession = mkNoiseSession (HS.hsNoiseState hsStateFinal)
  pure (noiseSession, HandshakeResult remotePeerId remotePubKey)

-- | Responder (listener) side of the Noise XX handshake.
performResponderHandshake :: KeyPair -> StreamIO -> IO (NoiseSession, HandshakeResult)
performResponderHandshake identityKP stream = do
  (hsState0, noiseStaticPub) <- initHandshakeResponder identityKP

  -- Message 1: ← (empty payload)
  msg1 <- readFramedMessage stream
  (_payload1, hsState1) <- either (fail . ("responder msg1 read: " <>)) pure $
    readHandshakeMsg hsState0 msg1

  -- Message 2: → (responder's identity payload)
  identPayload <- either (fail . ("responder payload build: " <>)) pure $
    encodeNoisePayload <$> buildHandshakePayload identityKP noiseStaticPub
  (msg2, hsState2) <- either (fail . ("responder msg2 write: " <>)) pure $
    writeHandshakeMsg hsState1 identPayload
  writeFramedMessage stream msg2

  -- Message 3: ← (initiator's identity payload)
  msg3 <- readFramedMessage stream
  (payload3, hsStateFinal) <- either (fail . ("responder msg3 read: " <>)) pure $
    readHandshakeMsg hsState2 msg3

  -- Decode initiator's identity
  remoteNP <- either (fail . ("responder decode payload: " <>)) pure $
    decodeNoisePayload payload3
  remotePubKey <- either (fail . ("responder decode pubkey: " <>)) pure $
    Proto.decodePublicKey (HS.npIdentityKey remoteNP)
  let remotePeerId = fromPublicKey remotePubKey

  -- Verify identity_sig: binds identity key to Noise static key
  case getRemoteNoiseStaticKey hsStateFinal of
    Nothing -> fail "performResponderHandshake: remote Noise static key unavailable after msg3"
    Just remoteNoisePub ->
      if not (verifyStaticKey remotePubKey remoteNoisePub (HS.npIdentitySig remoteNP))
        then fail "performResponderHandshake: identity signature verification failed"
        else pure ()

  let noiseSession = mkNoiseSession (HS.hsNoiseState hsStateFinal)
  pure (noiseSession, HandshakeResult remotePeerId remotePubKey)

-- | Create an encrypted StreamIO from a NoiseSession and raw StreamIO.
--
-- Uses separate IORefs for send/recv session state (each direction's
-- CipherState is independent in Noise). A read buffer (IORef ByteString)
-- bridges Noise's message-boundary decryption with StreamIO's byte-level reads.
noiseSessionToStreamIO
  :: IORef NoiseSession    -- ^ Send session state
  -> IORef NoiseSession    -- ^ Recv session state
  -> IORef ByteString      -- ^ Read buffer (decrypted but unconsumed bytes)
  -> StreamIO              -- ^ Raw (unencrypted) StreamIO
  -> StreamIO
noiseSessionToStreamIO sendRef recvRef bufRef rawIO = StreamIO
  { streamWrite = encryptAndWrite sendRef rawIO
  , streamReadByte = decryptAndReadByte recvRef bufRef rawIO
  , streamReadChunk = decryptAndReadChunk recvRef bufRef rawIO
  , streamClose = pure ()  -- Encryption layer does not own the connection
  }

-- | Encrypt plaintext and write as framed Noise messages.
-- A Noise message is capped at 65535 bytes, so plaintext is split into
-- chunks of at most 65519 bytes (65535 minus the 16-byte AEAD tag) and
-- each chunk is encrypted and framed as its own Noise transport message.
encryptAndWrite :: IORef NoiseSession -> StreamIO -> ByteString -> IO ()
encryptAndWrite sendRef rawIO plaintext =
  mapM_ encryptChunk (chunkPlaintext plaintext)
  where
    encryptChunk chunk = do
      sess <- readIORef sendRef
      case encryptMessage sess chunk of
        Left err -> fail $ "encryptAndWrite: " <> err
        Right (ct, sess') -> do
          writeIORef sendRef sess'
          writeFramedMessage rawIO ct

-- | Read Noise frames from the raw stream until one decrypts to a
-- non-empty plaintext, and return that plaintext. A transport message
-- with an empty plaintext (a frame carrying only the AEAD tag) is
-- legal — some implementations send it as a keepalive — and a
-- zero-length frame carries no Noise message at all; both yield zero
-- application bytes, so reading continues at the next frame.
nextPlaintext :: IORef NoiseSession -> StreamIO -> IO ByteString
nextPlaintext recvRef rawIO = do
  ct <- readFramedMessage rawIO
  if BS.null ct
    then nextPlaintext recvRef rawIO -- zero-length frame: no message to decrypt
    else do
      sess <- readIORef recvRef
      case decryptMessage sess ct of
        Left err -> fail $ "nextPlaintext: decrypt failed: " <> err
        Right (pt, sess') -> do
          writeIORef recvRef sess'
          if BS.null pt
            then nextPlaintext recvRef rawIO -- empty transport message (keepalive)
            else pure pt

-- | Read and decrypt a byte from the Noise channel: pop the buffer if
-- it has bytes, otherwise decrypt the next frame and buffer the rest.
decryptAndReadByte :: IORef NoiseSession -> IORef ByteString -> StreamIO -> IO Word8
decryptAndReadByte recvRef bufRef rawIO = do
  buf <- readIORef bufRef
  bs <- if BS.null buf then nextPlaintext recvRef rawIO else pure buf
  writeIORef bufRef (BS.tail bs)
  pure (BS.head bs)

-- | Chunk-level read from the Noise channel: hand back up to @n@ bytes
-- of the buffered plaintext (a decrypted frame is already a chunk),
-- decrypting the next frame only when the buffer is empty. Bytes
-- beyond @n@ stay buffered for the next read.
decryptAndReadChunk :: IORef NoiseSession -> IORef ByteString -> StreamIO -> Int -> IO ByteString
decryptAndReadChunk recvRef bufRef rawIO n = do
  buf <- readIORef bufRef
  bs <- if BS.null buf then nextPlaintext recvRef rawIO else pure buf
  let (front, rest) = BS.splitAt n bs
  writeIORef bufRef rest
  pure front

-- | Bounded window given to the send loop to flush the GoAway frame
-- before the transport is closed underneath it.
goAwayFlushTimeoutUs :: Int
goAwayFlushTimeoutUs = 200000

-- | Wrap a YamuxSession as a MuxerSession.
-- Starts sendLoop, recvLoop and keepaliveLoop as background threads.
-- The MuxerSession provides open/accept stream operations that
-- produce StreamIO-compatible streams.
--
-- The supplied close action closes the underlying transport; muxClose
-- runs it after sending GoAway and stopping the session loops, so
-- closing a connection actually releases the socket.
yamuxToMuxerSession :: YamuxSession -> IO () -> IO MuxerSession
yamuxToMuxerSession yamuxSess closeTransport = do
  -- Start background loops
  sendLoopA <- async (sendLoop yamuxSess)
  recvLoopA <- async (recvLoop yamuxSess)
  -- A failed keepalive means the peer went silent without closing the
  -- transport, so recvLoop is still blocked on a read that will never
  -- return. Stopping it is what makes muxAcceptStream fail and the
  -- Switch tear the connection down.
  keepaliveA <- async $ do
    result <- keepaliveLoop yamuxSess
    case result of
      Left _ -> cancel recvLoopA
      Right () -> pure ()
  pure MuxerSession
    { muxOpenStream = do
        result <- Yamux.openStream yamuxSess
        case result of
          Right stream -> yamuxStreamToStreamIO stream
          Left err -> fail $ "muxOpenStream: " <> show err
    , muxAcceptStream = do
        -- Fail the accept as soon as the receive loop dies (remote
        -- GoAway followed by EOF, transport error, or local close), so
        -- the Switch's stream accept loop exits and tears down the
        -- connection instead of blocking forever.
        result <- race (waitCatch recvLoopA) (Yamux.acceptStream yamuxSess)
        case result of
          Left _ -> fail "muxAcceptStream: session terminated"
          Right (Right stream) -> yamuxStreamToStreamIO stream
          Right (Left err) -> fail $ "muxAcceptStream: " <> show err
    , muxClose = do
        -- Queue GoAway, give the send loop a bounded window to flush
        -- it, then stop the loops and close the underlying transport.
        closeSession yamuxSess
        _ <- timeout goAwayFlushTimeoutUs $ atomically $ do
          empty <- isEmptyTQueue (ysessSendCh yamuxSess)
          unless empty retry
        cancel keepaliveA
        cancel sendLoopA
        cancel recvLoopA
        closeTransport `catch` \(_ :: SomeException) -> pure ()
    }

-- | Convert a YamuxStream to StreamIO with a read buffer.
-- Yamux delivers data in chunks via streamRead; an IORef buffer holds
-- the bytes a byte- or chunk-level read did not consume.
yamuxStreamToStreamIO :: YamuxStream -> IO StreamIO
yamuxStreamToStreamIO yamuxStream = do
  readBuf <- newIORef BS.empty
  let -- Buffered bytes if any, otherwise the next yamux chunk.
      nextChunk = do
        buf <- readIORef readBuf
        if BS.null buf
          then do
            result <- streamRead yamuxStream
            case result of
              Left err -> fail $ "yamuxStreamRead: " <> show err
              Right chunk
                | BS.null chunk -> fail "yamuxStreamRead: empty chunk"
                | otherwise -> pure chunk
          else pure buf
  pure StreamIO
    { streamWrite = \bs -> do
        result <- YS.streamWrite yamuxStream bs
        case result of
          Right () -> pure ()
          Left err -> fail $ "yamuxStreamWrite: " <> show err
    , streamReadByte = do
        chunk <- nextChunk
        writeIORef readBuf (BS.tail chunk)
        pure (BS.head chunk)
    , streamReadChunk = \n -> do
        chunk <- nextChunk
        let (front, rest) = BS.splitAt n chunk
        writeIORef readBuf rest
        pure front
    , streamClose = do
        _ <- YS.streamClose yamuxStream  -- Sends FIN flag
        pure ()
    }

-- | Upgrade a raw connection, taking every role from the direction.
--
-- Pipeline: mss(/noise) -> Noise XX -> mss(/yamux/1.0.0) -> Yamux.
-- 'Outbound' runs the initiator/client side of all three, 'Inbound' the
-- responder/server side. go-libp2p derives the same way
-- (@isServer := dir == network.DirInbound@ in its upgrader), which is
-- what lets a TCP simultaneous connect flip roles: the peer that must
-- act as the server passes 'Inbound' even though it called connect().
upgradeAs :: Direction -> KeyPair -> RawConnection -> IO Connection
upgradeAs = upgradeAsWithConfig defaultYamuxConfig

-- | Like 'upgradeAs', with an explicit Yamux configuration. A native
-- multiplexer (QUIC) does not run Yamux, so the configuration is unused there.
upgradeAsWithConfig :: YamuxConfig -> Direction -> KeyPair -> RawConnection -> IO Connection
upgradeAsWithConfig yamuxConfig dir identityKP rawConn = case rcEndpoint rawConn of
  ByteStreamEndpoint rawIO -> upgradeByteStream yamuxConfig dir identityKP rawConn rawIO
  NativeMuxerEndpoint native -> nativeToConnection dir rawConn native

upgradeByteStream :: YamuxConfig -> Direction -> KeyPair -> RawConnection -> StreamIO -> IO Connection
upgradeByteStream yamuxConfig dir identityKP rawConn rawIO = do
  let isServer = dir == Inbound
      negotiate = if isServer then negotiateResponder else negotiateInitiator
      role = if isServer then "upgradeInbound" else "upgradeOutbound"

  -- Step 1: multistream-select -> "/noise"
  secResult <- negotiate rawIO ["/noise"]
  case secResult of
    Accepted _ -> pure ()
    NoProtocol -> fail (role <> ": /noise negotiation failed")

  -- Step 2: Noise XX handshake
  (noiseSess, HandshakeResult remotePeerId _remotePK) <-
    performStreamHandshake identityKP dir rawIO

  -- Step 3: Create encrypted StreamIO
  sendRef <- newIORef noiseSess
  recvRef <- newIORef noiseSess
  bufRef  <- newIORef BS.empty
  let encryptedIO = noiseSessionToStreamIO sendRef recvRef bufRef rawIO

  -- Step 4: multistream-select -> "/yamux/1.0.0" (over encrypted channel)
  muxResult <- negotiate encryptedIO ["/yamux/1.0.0"]
  case muxResult of
    Accepted _ -> pure ()
    NoProtocol -> fail (role <> ": /yamux/1.0.0 negotiation failed")

  -- Step 5: Initialize Yamux session (client = odd IDs, server = even)
  let yamuxWrite = streamWrite encryptedIO
      yamuxRead  = \n -> readExact encryptedIO n
  yamuxSess <- newSessionWithConfig yamuxConfig (if isServer then RoleServer else RoleClient) yamuxWrite yamuxRead
  muxer <- yamuxToMuxerSession yamuxSess (rcClose rawConn)

  stateVar <- newTVarIO ConnOpen
  pure Connection
    { connPeerId     = remotePeerId
    , connDirection  = dir
    , connLocalAddr  = rcLocalAddr rawConn
    , connRemoteAddr = rcRemoteAddr rawConn
    , connSecurity   = "/noise"
    , connMuxer      = "/yamux/1.0.0"
    , connSession    = muxer
    , connState      = stateVar
    }

nativeToConnection :: Direction -> RawConnection -> NativeMuxer -> IO Connection
nativeToConnection dir rawConn native = do
  stateVar <- newTVarIO ConnOpen
  let muxer = MuxerSession
        { muxOpenStream = nativeOpenStream native
        , muxAcceptStream = nativeAcceptStream native
        , muxClose = nativeClose native
        }
  pure Connection
    { connPeerId = nativePeerId native
    , connDirection = dir
    , connLocalAddr = rcLocalAddr rawConn
    , connRemoteAddr = rcRemoteAddr rawConn
    , connSecurity = nativeSecurity native
    , connMuxer = nativeMuxerProtocol native
    , connSession = muxer
    , connState = stateVar
    }

-- | Upgrade an outbound (dialer) raw connection.
upgradeOutbound :: KeyPair -> RawConnection -> IO Connection
upgradeOutbound = upgradeAs Outbound

-- | Upgrade an inbound (listener) raw connection.
upgradeInbound :: KeyPair -> RawConnection -> IO Connection
upgradeInbound = upgradeAs Inbound
