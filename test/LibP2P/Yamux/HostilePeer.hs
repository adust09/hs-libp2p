-- | Hostile-peer test harness for Yamux (issue #171).
--
-- Runs our session implementation on one side and gives the test raw
-- byte-level control of the other side, so tests can inject arbitrary
-- frames (including ones our own sender never emits) and decode every
-- frame the session writes.
--
-- This replaces the symmetric self-pair harness for adversarial and
-- state-machine tests: with two of our sessions wired together, any
-- frame shape a conformant-but-differently-written peer may send is
-- structurally unreachable.
--
-- The transport is a chunk-based in-memory pipe that can be closed:
-- closing the inject direction makes the session's next read throw an
-- EOF IOError once the buffered bytes run out, exactly like the
-- production readExact-over-socket wiring in Switch.Upgrade.
module LibP2P.Yamux.HostilePeer
  ( HostilePeer (..)
  , withHostilePeer
  , withHostilePeerWithConfig
  , injectFrame
  , expectFrame
  , expectBytes
  , acceptWithin
  , awaitState
  , awaitTrue
  , awaitRemoteGoAway
  ) where

import Control.Concurrent.Async (withAsync)
import Control.Concurrent.STM
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import LibP2P.Yamux.Frame
import LibP2P.Yamux.Session
import LibP2P.Yamux.Types
import System.Timeout (timeout)
import Test.Hspec

-- | Our session under test plus raw byte access to both directions.
data HostilePeer = HostilePeer
  { hpSession :: YamuxSession
  -- ^ The session under test (recvLoop/sendLoop already running)
  , hpInject :: ByteString -> IO ()
  -- ^ Write raw bytes into the session's receive side
  , hpCloseInject :: IO ()
  -- ^ Signal transport EOF on the session's receive side: after the
  -- already-injected bytes are consumed, the session's read throws
  , hpNextFrame :: IO (YamuxHeader, ByteString)
  -- ^ Decode the next frame the session wrote (header + Data payload)
  , hpRecvRaw :: Int -> IO ByteString
  -- ^ Read exactly n raw bytes the session wrote (byte-exact asserts)
  }

-- | One direction of the in-memory transport: a queue of chunks, a
-- leftover buffer for partially consumed chunks, and a closed flag.
data Pipe = Pipe
  { pipeChunks :: TQueue ByteString
  , pipeLeftover :: TVar ByteString
  , pipeClosed :: TVar Bool
  }

newPipe :: IO Pipe
newPipe = Pipe <$> newTQueueIO <*> newTVarIO BS.empty <*> newTVarIO False

pipeWrite :: Pipe -> ByteString -> IO ()
pipeWrite p bs
  | BS.null bs = pure ()
  | otherwise = atomically $ writeTQueue (pipeChunks p) bs

pipeClose :: Pipe -> IO ()
pipeClose p = atomically $ writeTVar (pipeClosed p) True

-- | Read exactly n bytes, blocking until they arrive. Throws an
-- IOError on EOF before n bytes are available, mirroring the
-- production transport read (readExact fails on a short read).
pipeRead :: Pipe -> Int -> IO ByteString
pipeRead p n = go [] n
  where
    go acc 0 = pure (BS.concat (reverse acc))
    go acc want = do
      mChunk <- atomically $ do
        leftover <- readTVar (pipeLeftover p)
        if not (BS.null leftover)
          then do
            writeTVar (pipeLeftover p) BS.empty
            pure (Just leftover)
          else do
            mc <- tryReadTQueue (pipeChunks p)
            case mc of
              Just c -> pure (Just c)
              Nothing -> do
                closed <- readTVar (pipeClosed p)
                if closed then pure Nothing else retry
      case mChunk of
        Nothing -> ioError (userError "pipeRead: transport EOF mid-read")
        Just c
          | BS.length c <= want -> go (c : acc) (want - BS.length c)
          | otherwise -> do
              let (use, rest) = BS.splitAt want c
              atomically $ writeTVar (pipeLeftover p) rest
              go (use : acc) 0

-- | Run an action against a session wired to a raw byte peer.
withHostilePeer :: SessionRole -> (HostilePeer -> IO a) -> IO a
withHostilePeer = withHostilePeerWithConfig defaultYamuxConfig

-- | Like 'withHostilePeer', with an explicit session configuration.
-- The keepalive loop is not started; tests that need it run it themselves.
withHostilePeerWithConfig :: YamuxConfig -> SessionRole -> (HostilePeer -> IO a) -> IO a
withHostilePeerWithConfig config role action = do
  toSession <- newPipe
  fromSession <- newPipe
  sess <- newSessionWith config role (pipeWrite fromSession) (pipeRead toSession)
  let nextFrame = do
        hdrBytes <- pipeRead fromSession headerSize
        case decodeHeader hdrBytes of
          Left err -> fail ("frame recorder: " <> err)
          Right hdr -> do
            payload <-
              if yhType hdr == FrameData && yhLength hdr > 0
                then pipeRead fromSession (fromIntegral (yhLength hdr))
                else pure BS.empty
            pure (hdr, payload)
  withAsync (sendLoop sess) $ \_ ->
    withAsync (recvLoop sess) $ \_ ->
      action
        HostilePeer
          { hpSession = sess
          , hpInject = pipeWrite toSession
          , hpCloseInject = pipeClose toSession
          , hpNextFrame = nextFrame
          , hpRecvRaw = pipeRead fromSession
          }

-- | Inject a frame (header plus optional Data payload) as raw bytes.
injectFrame :: HostilePeer -> YamuxHeader -> ByteString -> IO ()
injectFrame hp hdr payload = hpInject hp (encodeHeader hdr <> payload)

-- | Read the session's next outbound frame, failing loudly after 1s
-- instead of hanging the suite.
expectFrame :: HostilePeer -> IO (YamuxHeader, ByteString)
expectFrame hp = do
  mFrame <- timeout 1000000 (hpNextFrame hp)
  case mFrame of
    Just frame -> pure frame
    Nothing -> fail "expected an outbound frame within 1s, got none"

-- | Assert that the session's next outbound bytes are exactly the
-- given ones (byte-exact golden assertion), failing after 1s.
expectBytes :: HostilePeer -> ByteString -> Expectation
expectBytes hp expected = do
  mGot <- timeout 1000000 (hpRecvRaw hp (BS.length expected))
  case mGot of
    Just got -> got `shouldBe` expected
    Nothing -> expectationFailure "expected outbound bytes within 1s, got none"

-- | Accept an inbound stream, failing loudly after 1s.
acceptWithin :: HostilePeer -> IO YamuxStream
acceptWithin hp = do
  mRes <- timeout 1000000 (acceptStream (hpSession hp))
  case mRes of
    Just (Right s) -> pure s
    Just (Left err) -> fail ("acceptStream: " <> show err)
    Nothing -> fail "acceptStream timed out after 1s"

-- | Block until the stream reaches the given state, failing after 1s.
awaitState :: YamuxStream -> StreamState -> Expectation
awaitState stream expected = do
  result <- timeout 1000000 $ atomically $ do
    st <- readTVar (ysState stream)
    check (st == expected)
  case result of
    Just () -> pure ()
    Nothing -> do
      actual <- readTVarIO (ysState stream)
      expectationFailure $
        "expected stream state " <> show expected <> " but stuck at " <> show actual

-- | Block until the TVar becomes True, failing after 1s.
awaitTrue :: TVar Bool -> Expectation
awaitTrue var = do
  result <- timeout 1000000 $ atomically (readTVar var >>= check)
  case result of
    Just () -> pure ()
    Nothing -> expectationFailure "expected TVar to become True within 1s"

-- | Block until the session records a remote GoAway with the given
-- code, failing after 1s.
awaitRemoteGoAway :: YamuxSession -> GoAwayCode -> Expectation
awaitRemoteGoAway sess expected = do
  result <- timeout 1000000 $ atomically $ do
    got <- readTVar (ysessRemoteGoAway sess)
    check (got == Just expected)
  case result of
    Just () -> pure ()
    Nothing -> do
      actual <- readTVarIO (ysessRemoteGoAway sess)
      expectationFailure $
        "expected remote GoAway " <> show (Just expected) <> " but got " <> show actual
