module LibP2P.Protocol.Ping.PingSpec (spec) where

import Control.Concurrent.Async (async, cancel, forConcurrently, wait)
import Control.Concurrent.STM
  ( TMVar
  , TQueue
  , atomically
  , newEmptyTMVarIO
  , newTQueueIO
  , newTVarIO
  , putTMVar
  , readTQueue
  , readTVar
  , tryReadTMVar
  , writeTQueue
  )
import Control.Exception (finally, throwIO, try)
import Data.Bits (xor)
import qualified Data.ByteString as BS
import Data.IORef (IORef, modifyIORef', newIORef, readIORef, writeIORef)
import qualified Data.Map.Strict as Map
import Data.Word (Word8)
import LibP2P.Crypto.Ed25519 (generateKeyPair)
import LibP2P.Crypto.Key (kpPublic)
import LibP2P.Crypto.PeerId (PeerId (..), fromPublicKey)
import LibP2P.Multiaddr (Multiaddr (..))
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.MultistreamSelect.Negotiation
  ( NegotiationResult (..)
  , StreamIO (..)
  , mkByteStreamIO
  , negotiateResponder
  )
import LibP2P.Protocol.Ping
import LibP2P.Switch (newSwitch)
import LibP2P.Switch.ResourceManager
  ( MemoryAccount (..)
  , ResourceScope (..)
  , ResourceUsage (..)
  , getOrCreatePeerScope
  , reserveConnection
  )
import LibP2P.Switch.Types
  ( ConnState (..)
  , Connection (..)
  , Direction (..)
  , MuxerSession (..)
  , Switch (..)
  )
import System.IO.Error (mkIOError, eofErrorType)
import System.Timeout (timeout)
import Test.Hspec

-- | Create a closable stream pair where the writer can signal EOF.
mkClosableStreamPair :: IO (StreamIO, IO (), StreamIO)
mkClosableStreamPair = do
  qAtoB <- newTQueueIO :: IO (TQueue (Maybe Word8))
  qBtoA <- newTQueueIO :: IO (TQueue (Maybe Word8))
  closedA <- newEmptyTMVarIO :: IO (TMVar ())
  closedB <- newEmptyTMVarIO :: IO (TMVar ())
  let writeQ q closed bs = do
        c <- atomically $ tryReadTMVar closed
        case c of
          Just () -> throwIO (mkIOError eofErrorType "stream closed" Nothing Nothing)
          Nothing -> mapM_ (\b -> atomically $ writeTQueue q (Just b)) (BS.unpack bs)
      readQ q = do
        mv <- atomically $ readTQueue q
        case mv of
          Just b  -> pure b
          Nothing -> throwIO (mkIOError eofErrorType "EOF" Nothing Nothing)
      closeWriter q closed = atomically $ do
        putTMVar closed ()
        writeTQueue q Nothing
      streamA = mkByteStreamIO (writeQ qAtoB closedA) (readQ qBtoA) (closeWriter qAtoB closedA)
      streamB = mkByteStreamIO (writeQ qBtoA closedB) (readQ qAtoB) (closeWriter qBtoA closedB)
  pure (streamA, closeWriter qAtoB closedA, streamB)

-- | Wrap a StreamIO so every write chunk is recorded (most recent first).
recordWrites :: IORef [BS.ByteString] -> StreamIO -> StreamIO
recordWrites ref s = s
  { streamWrite = \bs -> modifyIORef' ref (bs :) >> streamWrite s bs }

-- | Wrap a StreamIO so closing it flips the flag (before delegating).
recordClose :: IORef Bool -> StreamIO -> StreamIO
recordClose ref s = s { streamClose = writeIORef ref True >> streamClose s }

-- | Stream opener that counts how many streams have been handed out.
countingOpen :: IORef Int -> StreamIO -> IO StreamIO
countingOpen ref stream = modifyIORef' ref (+ 1) >> pure stream

-- | A Switch whose only role here is stream resource accounting for
-- the ping initiator ('sendPing' reserves stream slots through it).
mkTestSwitch :: IO Switch
mkTestSwitch = do
  Right kp <- generateKeyPair
  let pid = fromPublicKey (kpPublic kp)
  newSwitch pid kp

-- | Build an outbound Connection whose muxer runs the given stream opener.
-- This is what lets tests drive the real 'sendPing' initiator path.
mkPingConnection :: Switch -> IO StreamIO -> IO Connection
mkPingConnection sw openStream = do
  stateVar <- newTVarIO ConnOpen
  connScope <- atomically $
    reserveConnection (swResourceMgr sw) (PeerId "ping-remote") Outbound
  ownedScope <- either (fail . show) pure connScope
  pure Connection
    { connPeerId     = PeerId "ping-remote"
    , connDirection  = Outbound
    , connLocalAddr  = Multiaddr [IP4 0x7f000001, TCP 0]
    , connRemoteAddr = Multiaddr [IP4 0x7f000001, TCP 4001]
    , connSecurity   = "/noise"
    , connMuxer      = "/yamux/1.0.0"
    , connSession    = MuxerSession
        { muxOpenStream = \account -> do
            stream <- openStream
            pure stream
              { streamClose = streamClose stream
                  `finally` atomically (maClose account)
              }
        , muxAcceptStream = fail "test connection: no inbound streams"
        , muxClose        = pure ()
        }
    , connState      = stateVar
    , connResourceScope = ownedScope
    }

-- | Outbound ping streams currently reserved against a peer's resource
-- scope (a session holds exactly one while open, zero after close).
readPeerOutboundStreams :: Switch -> PeerId -> IO Int
readPeerOutboundStreams sw pid = atomically $ do
  scope <- getOrCreatePeerScope (swResourceMgr sw) pid
  ruStreamsOutbound <$> readTVar (rsUsage scope)

-- | Read exactly n bytes from a stream.
readNBytes :: StreamIO -> Int -> IO BS.ByteString
readNBytes stream n = BS.pack <$> mapM (const (streamReadByte stream)) [1..n]

-- | Responder that accepts the ping protocol and runs the echo loop.
pingResponder :: StreamIO -> IO ()
pingResponder stream = do
  negResult <- negotiateResponder stream [pingProtocolId]
  negResult `shouldBe` Accepted pingProtocolId
  handlePing stream (PeerId "initiator")

spec :: Spec
spec = do
  describe "Ping responder (handlePing)" $ do
    it "handlePing echoes 32 bytes" $ do
      (streamA, closeA, streamB) <- mkClosableStreamPair
      handler <- async $ handlePing streamB (PeerId "test-peer")
      let payload = BS.pack [1..32]
      streamWrite streamA payload
      response <- readNBytes streamA pingSize
      response `shouldBe` payload
      closeA
      wait handler

    it "handlePing echoes multiple pings on same stream" $ do
      (streamA, closeA, streamB) <- mkClosableStreamPair
      handler <- async $ handlePing streamB (PeerId "test-peer")
      -- Ping 1
      let payload1 = BS.pack [1..32]
      streamWrite streamA payload1
      resp1 <- readNBytes streamA pingSize
      resp1 `shouldBe` payload1
      -- Ping 2 (different data)
      let payload2 = BS.pack [33..64]
      streamWrite streamA payload2
      resp2 <- readNBytes streamA pingSize
      resp2 `shouldBe` payload2
      closeA
      wait handler

    it "handlePing exits on stream close" $ do
      (_streamA, closeA, streamB) <- mkClosableStreamPair
      handler <- async $ handlePing streamB (PeerId "test-peer")
      closeA
      -- Handler should exit gracefully (not hang or crash)
      wait handler

    it "handlePing closes its side of the stream after the loop exits" $ do
      -- ping.md: the listening peer SHOULD exit the loop and close the
      -- stream once the dialing peer closes its write side.
      (_streamA, closeA, streamB) <- mkClosableStreamPair
      closedRef <- newIORef False
      handler <- async $ handlePing (recordClose closedRef streamB) (PeerId "test-peer")
      closeA
      wait handler
      closed <- readIORef closedRef
      closed `shouldBe` True

    it "handlePing exits without echoing when the final read is short" $ do
      (streamA, closeA, streamB) <- mkClosableStreamPair
      handler <- async $ handlePing streamB (PeerId "test-peer")
      -- One byte short of a full ping payload, then EOF (ping.md: the
      -- payload is exactly 32 bytes; a truncated read must not be echoed).
      streamWrite streamA (BS.pack [1..31])
      closeA
      wait handler
      -- The responder must not have written anything back: reading from
      -- its side either blocks (timeout) or hits the EOF it signalled by
      -- closing the stream — never an echoed byte.
      echoed <- timeout 100000 (try (streamReadByte streamA))
      case echoed of
        Nothing            -> pure ()  -- no data, read blocked
        Just (Left (_ :: IOError)) -> pure ()  -- EOF from responder close
        Just (Right b)     -> expectationFailure $
          "responder echoed a byte from a short read: " ++ show b

  describe "Ping initiator (sendPing)" $ do
    it "sendPing round-trips against handlePing and returns a non-negative RTT" $ do
      (streamA, _closeA, streamB) <- mkClosableStreamPair
      sw <- mkTestSwitch
      conn <- mkPingConnection sw (pure streamA)
      responder <- async $ pingResponder streamB
      result <- sendPing sw conn
      case result of
        Left err -> expectationFailure $ "sendPing failed: " ++ show err
        Right (PingResult rtt) -> rtt `shouldSatisfy` (>= 0)
      -- Regression for #163: sendPing must close the stream, so the
      -- responder's echo loop sees EOF and exits on its own.
      done <- timeout 1000000 (wait responder)
      done `shouldBe` Just ()

    it "sendPing closes the ping stream after the ping completes" $ do
      (streamA, _closeA, streamB) <- mkClosableStreamPair
      closedRef <- newIORef False
      sw <- mkTestSwitch
      conn <- mkPingConnection sw (pure (recordClose closedRef streamA))
      responder <- async $ pingResponder streamB
      result <- sendPing sw conn
      case result of
        Left err -> expectationFailure $ "sendPing failed: " ++ show err
        Right _  -> pure ()
      closed <- readIORef closedRef
      closed `shouldBe` True
      done <- timeout 1000000 (wait responder)
      done `shouldBe` Just ()

    it "two pings on one session reuse a single stream and close it at the end" $ do
      -- ping.md: the dialing peer MUST NOT keep more than one outbound
      -- ping stream per peer, and MAY send further payloads on the same
      -- stream.
      (streamA, _closeA, streamB) <- mkClosableStreamPair
      opensRef <- newIORef (0 :: Int)
      closedRef <- newIORef False
      sw <- mkTestSwitch
      conn <- mkPingConnection sw (countingOpen opensRef (recordClose closedRef streamA))
      responder <- async $ pingResponder streamB
      result <- withPingSession sw conn $ \sess -> do
        r1 <- ping sess
        r2 <- ping sess
        pure (r1, r2)
      case result of
        Left err -> expectationFailure $ "ping session failed to open: " ++ show err
        Right (r1, r2) -> do
          case r1 of
            Left err -> expectationFailure $ "ping 1 failed: " ++ show err
            Right (PingResult rtt1) -> rtt1 `shouldSatisfy` (>= 0)
          case r2 of
            Left err -> expectationFailure $ "ping 2 failed: " ++ show err
            Right (PingResult rtt2) -> rtt2 `shouldSatisfy` (>= 0)
      opens <- readIORef opensRef
      opens `shouldBe` 1
      closed <- readIORef closedRef
      closed `shouldBe` True
      done <- timeout 1000000 (wait responder)
      done `shouldBe` Just ()

    it "10 concurrent pings on one session serialize onto the single stream and all succeed" $ do
      -- ping.md: the dialing peer MUST NOT keep more than one outbound
      -- ping stream per peer. Concurrent callers must queue on the
      -- session's one stream, one exchange at a time — without
      -- serialization their 32-byte payloads interleave on the wire and
      -- the echoes no longer match.
      (streamA, _closeA, streamB) <- mkClosableStreamPair
      opensRef <- newIORef (0 :: Int)
      sw <- mkTestSwitch
      conn <- mkPingConnection sw (countingOpen opensRef streamA)
      responder <- async $ pingResponder streamB
      result <- withPingSession sw conn $ \sess ->
        forConcurrently [1 .. 10 :: Int] $ \_ -> ping sess
      case result of
        Left err -> expectationFailure $ "ping session failed to open: " ++ show err
        Right results -> do
          length results `shouldBe` 10
          mapM_
            (\r -> case r of
               Right (PingResult rtt) -> rtt `shouldSatisfy` (>= 0)
               Left err -> expectationFailure $ "concurrent ping failed: " ++ show err)
            results
      opens <- readIORef opensRef
      opens `shouldBe` 1
      -- withPingSession closed the stream, so the responder exits on EOF.
      done <- timeout 1000000 (wait responder)
      done `shouldBe` Just ()

    it "ping fails on a session that has been closed" $ do
      (streamA, _closeA, streamB) <- mkClosableStreamPair
      sw <- mkTestSwitch
      conn <- mkPingConnection sw (pure streamA)
      responder <- async $ pingResponder streamB
      opened <- openPingSession sw conn
      case opened of
        Left err -> expectationFailure $ "ping session failed to open: " ++ show err
        Right sess -> do
          closePingSession sess
          result <- ping sess
          case result of
            Left (PingStreamError _) -> pure ()
            other -> expectationFailure $
              "expected Left PingStreamError, got: " ++ show other
      done <- timeout 1000000 (wait responder)
      done `shouldBe` Just ()

    it "closePingSession closes the stream and releases its reservation exactly once" $ do
      -- A session holds exactly one stream reservation against the
      -- peer's resource scope; closing the session must release it, and
      -- a double close must not close the stream (or release the
      -- reservation) a second time.
      (streamA, _closeA, streamB) <- mkClosableStreamPair
      closeCountRef <- newIORef (0 :: Int)
      let countingClose s =
            s { streamClose = modifyIORef' closeCountRef (+ 1) >> streamClose s }
      sw <- mkTestSwitch
      conn <- mkPingConnection sw (pure (countingClose streamA))
      responder <- async $ pingResponder streamB
      opened <- openPingSession sw conn
      case opened of
        Left err -> expectationFailure $ "ping session failed to open: " ++ show err
        Right sess -> do
          reservedOpen <- readPeerOutboundStreams sw (connPeerId conn)
          reservedOpen `shouldBe` 1
          closePingSession sess
          closePingSession sess
          closes <- readIORef closeCountRef
          closes `shouldBe` 1
          reservedClosed <- readPeerOutboundStreams sw (connPeerId conn)
          reservedClosed `shouldBe` 0
      done <- timeout 1000000 (wait responder)
      done `shouldBe` Just ()

    it "withPingSession closes the session when the action throws" $ do
      (streamA, _closeA, streamB) <- mkClosableStreamPair
      closedRef <- newIORef False
      sw <- mkTestSwitch
      conn <- mkPingConnection sw (pure (recordClose closedRef streamA))
      responder <- async $ pingResponder streamB
      outcome <- try $ withPingSession sw conn $ \_sess ->
        throwIO (userError "boom") :: IO ()
      case outcome of
        Left (_ :: IOError) -> pure ()  -- the action's exception propagates
        Right (r :: Either PingError ()) -> expectationFailure $
          "expected the exception to propagate, got: " ++ show r
      -- The session (and its stream) must still have been closed, so
      -- the responder's echo loop sees EOF and exits on its own.
      closed <- readIORef closedRef
      closed `shouldBe` True
      done <- timeout 1000000 (wait responder)
      done `shouldBe` Just ()

    it "a ping after a timed-out ping on the same session is rejected" $ do
      -- A late echo from the slow responder would corrupt the next
      -- exchange, so a failed ping closes the session: the session must
      -- reject further pings instead of reusing the poisoned stream.
      (streamA, _closeA, streamB) <- mkClosableStreamPair
      sw <- mkTestSwitch
      conn <- mkPingConnection sw (pure streamA)
      responder <- async $ do
        negResult <- negotiateResponder streamB [pingProtocolId]
        negResult `shouldBe` Accepted pingProtocolId
        -- Swallow the payload and never echo.
        _ <- readNBytes streamB pingSize
        pure ()
      opened <- openPingSession sw conn
      case opened of
        Left err -> expectationFailure $ "ping session failed to open: " ++ show err
        Right sess -> do
          first <- pingWithTimeout 200000 sess
          first `shouldBe` Left PingTimeout
          second <- ping sess
          case second of
            Left (PingStreamError _) -> pure ()
            other -> expectationFailure $
              "expected Left PingStreamError after a timed-out ping, got: " ++ show other
      wait responder

    it "pingWithTimeout returns Left PingTimeout and closes the stream when no echo arrives" $ do
      (streamA, _closeA, streamB) <- mkClosableStreamPair
      closedRef <- newIORef False
      sw <- mkTestSwitch
      conn <- mkPingConnection sw (pure (recordClose closedRef streamA))
      responder <- async $ do
        negResult <- negotiateResponder streamB [pingProtocolId]
        negResult `shouldBe` Accepted pingProtocolId
        -- Swallow the payload and never echo.
        _ <- readNBytes streamB pingSize
        pure ()
      opened <- openPingSession sw conn
      case opened of
        Left err -> expectationFailure $ "ping session failed to open: " ++ show err
        Right sess -> do
          result <- pingWithTimeout 200000 sess
          result `shouldBe` Left PingTimeout
          closed <- readIORef closedRef
          closed `shouldBe` True
      wait responder

    it "sendPing returns Left PingMismatch and closes the stream when the echo is corrupted" $ do
      (streamA, _closeA, streamB) <- mkClosableStreamPair
      closedRef <- newIORef False
      sw <- mkTestSwitch
      conn <- mkPingConnection sw (pure (recordClose closedRef streamA))
      responder <- async $ do
        negResult <- negotiateResponder streamB [pingProtocolId]
        negResult `shouldBe` Accepted pingProtocolId
        payload <- readNBytes streamB pingSize
        -- Corrupt the first byte before echoing (ping.md: the echo MUST
        -- match the sent payload).
        let corrupted = BS.cons (BS.head payload `xor` 0xFF) (BS.tail payload)
        streamWrite streamB corrupted
      result <- sendPing sw conn
      wait responder
      result `shouldBe` Left PingMismatch
      closed <- readIORef closedRef
      closed `shouldBe` True

    it "sendPing returns Left PingStreamError on mid-payload EOF" $ do
      (streamA, _closeA, streamB) <- mkClosableStreamPair
      sw <- mkTestSwitch
      conn <- mkPingConnection sw (pure streamA)
      responder <- async $ do
        negResult <- negotiateResponder streamB [pingProtocolId]
        negResult `shouldBe` Accepted pingProtocolId
        payload <- readNBytes streamB pingSize
        -- Echo only half the payload, then close: the initiator must
        -- surface a stream error instead of hanging or succeeding.
        streamWrite streamB (BS.take 16 payload)
        streamClose streamB
      result <- sendPing sw conn
      wait responder
      case result of
        Left (PingStreamError _) -> pure ()
        other -> expectationFailure $
          "expected Left PingStreamError, got: " ++ show other

    it "sendPing returns Left PingStreamError and closes the stream when the responder rejects the protocol" $ do
      (streamA, _closeA, streamB) <- mkClosableStreamPair
      closedRef <- newIORef False
      sw <- mkTestSwitch
      conn <- mkPingConnection sw (pure (recordClose closedRef streamA))
      -- Responder speaks multistream-select but supports no protocols, so
      -- it answers "na" to /ipfs/ping/1.0.0 and keeps waiting for further
      -- proposals (which never come) — hence cancel, not wait.
      responder <- async $ negotiateResponder streamB []
      result <- sendPing sw conn
      cancel responder
      case result of
        Left (PingStreamError _) -> pure ()
        other -> expectationFailure $
          "expected Left PingStreamError, got: " ++ show other
      closed <- readIORef closedRef
      closed `shouldBe` True

    it "sendPing writes a fresh random 32-byte payload per ping, unframed" $ do
      let runRecordedPing = do
            (streamA, _closeA, streamB) <- mkClosableStreamPair
            writesRef <- newIORef ([] :: [BS.ByteString])
            sw <- mkTestSwitch
            conn <- mkPingConnection sw (pure (recordWrites writesRef streamA))
            responder <- async $ pingResponder streamB
            result <- sendPing sw conn
            case result of
              Left err -> expectationFailure $ "sendPing failed: " ++ show err
              Right _  -> pure ()
            -- sendPing closed the stream, so the responder exits on EOF.
            wait responder
            readIORef writesRef
      chunks1 <- runRecordedPing
      -- The initiator writes exactly two chunks: the pipelined
      -- multistream header + protocol proposal (one write, per the
      -- multistream-select SHOULD), and the ping payload (most recent
      -- first).
      length chunks1 `shouldBe` 2
      let payload1 = head chunks1
      -- ping.md: the payload is 32 raw bytes — no varint prefix, no
      -- framing. A length-prefixed write would be 33+ bytes here.
      BS.length payload1 `shouldBe` pingSize
      -- A second ping must use a freshly generated random payload.
      chunks2 <- runRecordedPing
      let payload2 = head chunks2
      BS.length payload2 `shouldBe` pingSize
      payload2 `shouldNotBe` payload1

  describe "Ping responder stream cap" $ do
    -- ping.md: "The listening peer SHOULD accept at most two streams
    -- per peer since cross-stream behavior is non-linear and stream
    -- writes occur asynchronously."
    it "accepts two concurrent ping streams from the same peer, both echo" $ do
      limiter <- newPingLimiter
      let peer = PeerId "capped-peer"
      (dialer1, close1, listener1) <- mkClosableStreamPair
      (dialer2, close2, listener2) <- mkClosableStreamPair
      h1 <- async $ handlePingLimited limiter listener1 peer
      h2 <- async $ handlePingLimited limiter listener2 peer
      let payload1 = BS.pack [1..32]
          payload2 = BS.pack [33..64]
      streamWrite dialer1 payload1
      resp1 <- readNBytes dialer1 pingSize
      resp1 `shouldBe` payload1
      streamWrite dialer2 payload2
      resp2 <- readNBytes dialer2 pingSize
      resp2 `shouldBe` payload2
      close1
      close2
      wait h1
      wait h2

    it "resets the third concurrent ping stream from a peer while the first two stay usable" $ do
      limiter <- newPingLimiter
      let peer = PeerId "capped-peer"
      (dialer1, close1, listener1) <- mkClosableStreamPair
      (dialer2, close2, listener2) <- mkClosableStreamPair
      (dialer3, _close3, listener3) <- mkClosableStreamPair
      h1 <- async $ handlePingLimited limiter listener1 peer
      h2 <- async $ handlePingLimited limiter listener2 peer
      -- Prove both slots are held before opening the third stream.
      streamWrite dialer1 (BS.pack [1..32])
      _ <- readNBytes dialer1 pingSize
      streamWrite dialer2 (BS.pack [33..64])
      _ <- readNBytes dialer2 pingSize
      -- The third stream must be refused: the handler returns without
      -- serving the echo loop and closes its side of the stream.
      h3 <- async $ handlePingLimited limiter listener3 peer
      done3 <- timeout 1000000 (wait h3)
      done3 `shouldBe` Just ()
      streamWrite dialer3 (BS.pack [65..96])
      echoed <- try (readNBytes dialer3 pingSize)
      case echoed of
        Left (_ :: IOError) -> pure ()  -- EOF from the reset
        Right bs -> expectationFailure $
          "third ping stream was served, echoed: " ++ show bs
      -- The first two streams keep echoing after the refusal.
      let payload1' = BS.pack [97..128]
          payload2' = BS.pack [129..160]
      streamWrite dialer1 payload1'
      resp1 <- readNBytes dialer1 pingSize
      resp1 `shouldBe` payload1'
      streamWrite dialer2 payload2'
      resp2 <- readNBytes dialer2 pingSize
      resp2 `shouldBe` payload2'
      close1
      close2
      wait h1
      wait h2

    it "closing a ping stream frees a slot for a new stream from the same peer" $ do
      limiter <- newPingLimiter
      let peer = PeerId "capped-peer"
      (dialer1, close1, listener1) <- mkClosableStreamPair
      (dialer2, close2, listener2) <- mkClosableStreamPair
      h1 <- async $ handlePingLimited limiter listener1 peer
      h2 <- async $ handlePingLimited limiter listener2 peer
      streamWrite dialer1 (BS.pack [1..32])
      _ <- readNBytes dialer1 pingSize
      streamWrite dialer2 (BS.pack [33..64])
      _ <- readNBytes dialer2 pingSize
      -- Close the first stream; once its handler exits, the slot is free.
      close1
      wait h1
      (dialer3, close3, listener3) <- mkClosableStreamPair
      h3 <- async $ handlePingLimited limiter listener3 peer
      let payload3 = BS.pack [65..96]
      streamWrite dialer3 payload3
      resp3 <- readNBytes dialer3 pingSize
      resp3 `shouldBe` payload3
      close2
      close3
      wait h2
      wait h3

    it "caps ping streams per peer, not globally" $ do
      limiter <- newPingLimiter
      let peerA = PeerId "peer-a"
          peerB = PeerId "peer-b"
      (dialerA1, closeA1, listenerA1) <- mkClosableStreamPair
      (dialerA2, closeA2, listenerA2) <- mkClosableStreamPair
      hA1 <- async $ handlePingLimited limiter listenerA1 peerA
      hA2 <- async $ handlePingLimited limiter listenerA2 peerA
      -- Peer A holds both of its slots.
      streamWrite dialerA1 (BS.pack [1..32])
      _ <- readNBytes dialerA1 pingSize
      streamWrite dialerA2 (BS.pack [33..64])
      _ <- readNBytes dialerA2 pingSize
      -- A stream from peer B is still served.
      (dialerB, closeB, listenerB) <- mkClosableStreamPair
      hB <- async $ handlePingLimited limiter listenerB peerB
      let payloadB = BS.pack [65..96]
      streamWrite dialerB payloadB
      respB <- readNBytes dialerB pingSize
      respB `shouldBe` payloadB
      closeA1
      closeA2
      closeB
      wait hA1
      wait hA2
      wait hB

    it "the handler registered by registerPingHandler enforces the per-peer cap" $ do
      sw <- mkTestSwitch
      registerPingHandler sw
      protos <- atomically $ readTVar (swProtocols sw)
      handler <- maybe (fail "ping handler not registered") pure
        (Map.lookup pingProtocolId protos)
      conn <- mkPingConnection sw (fail "test connection: no outbound streams")
      (dialer1, close1, listener1) <- mkClosableStreamPair
      (dialer2, close2, listener2) <- mkClosableStreamPair
      (dialer3, _close3, listener3) <- mkClosableStreamPair
      h1 <- async $ handler conn listener1
      h2 <- async $ handler conn listener2
      streamWrite dialer1 (BS.pack [1..32])
      _ <- readNBytes dialer1 pingSize
      streamWrite dialer2 (BS.pack [33..64])
      _ <- readNBytes dialer2 pingSize
      h3 <- async $ handler conn listener3
      done3 <- timeout 1000000 (wait h3)
      done3 `shouldBe` Just ()
      streamWrite dialer3 (BS.pack [65..96])
      echoed <- try (readNBytes dialer3 pingSize)
      case echoed of
        Left (_ :: IOError) -> pure ()
        Right bs -> expectationFailure $
          "third ping stream was served, echoed: " ++ show bs
      close1
      close2
      wait h1
      wait h2

  describe "Ping registration" $ do
    it "registerPingHandler adds handler to switch" $ do
      Right kp <- generateKeyPair
      let pid = fromPublicKey (kpPublic kp)
      sw <- newSwitch pid kp
      registerPingHandler sw
      protos <- atomically $ readTVar (swProtocols sw)
      Map.member pingProtocolId protos `shouldBe` True
