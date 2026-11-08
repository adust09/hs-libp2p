module LibP2P.Transport.WebRTCStreamSpec (spec) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.Async (cancel, poll, wait, waitCatch, withAsync)
import Control.Concurrent.STM
import Control.Exception (IOException, SomeException, bracket, catch, uninterruptibleMask_)
import Control.Monad (when)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Either (isLeft)
import Data.List (isPrefixOf)
import Data.Maybe (isNothing)
import LibP2P.Core.Varint (encodeUvarint)
import LibP2P.MultistreamSelect.Negotiation (StreamIO (..))
import LibP2P.Transport.WebRTC.Stream
import System.IO.Error (ioeGetErrorString, isEOFError)
import System.Timeout (timeout)
import Test.Hspec

data Fixture = Fixture
  { fixtureStream :: StreamIO
  , fixtureIncoming :: TQueue (Maybe ByteString)
  , fixtureOutgoing :: TQueue ByteString
  , fixtureClosed :: TVar Bool
  , fixtureReleased :: TVar Int
  }

spec :: Spec
spec = describe "WebRTC stream controls" $ do
  framingSpec
  finSpec
  resetSpec
  stopSendingSpec
  closeSpec
  failureSpec
  shutdownSpec
  duplexSpec

framingSpec :: Spec
framingSpec = do
  it "should assemble fragmented frames and preserve partial application reads" $
    withFixture $ \fixture -> do
      let bytes = message Nothing (BS.replicate 130 0x61)
      mapM_ (push fixture . BS.singleton) (BS.unpack bytes)
      readBytes fixture 1 `shouldReturn` "a"
      readBytes fixture 129 `shouldReturn` BS.replicate 129 0x61
  it "should ignore unknown flags without losing their payload" $
    withFixture $ \fixture -> do
      push fixture (message (Just 9) "ok")
      readBytes fixture 2 `shouldReturn` "ok"
  it "should reject a frame whose encoded size exceeds 16 KiB" $
    withFixture $ \fixture -> do
      push fixture (encodeUvarint 16384)
      within (streamReadByte (fixtureStream fixture)) `shouldThrow` isFrameError
  it "should reject a length that would overflow the size calculation" $
    withFixture $ \fixture -> do
      push fixture (BS.replicate 9 0xff <> BS.singleton 1)
      within (streamReadByte (fixtureStream fixture)) `shouldThrow` isFrameError
  it "should report a truncated protobuf payload as a framing error" $
    withFixture $ \fixture -> do
      push fixture (BS.pack [3, 0x12, 4, 0x61])
      within (streamReadByte (fixtureStream fixture)) `shouldThrow` isFrameError

finSpec :: Spec
finSpec = do
  it "should acknowledge FIN without waiting for an application read" $
    withFixture $ \fixture -> do
      push fixture fin
      nextSent fixture `shouldReturn` finAck
      within (streamReadByte (fixtureStream fixture)) `shouldThrow` isEOFError
  it "should drain a data-bearing FIN before reporting EOF" $
    withFixture $ \fixture -> do
      push fixture (message (Just 0) "last")
      nextSent fixture `shouldReturn` finAck
      readBytes fixture 2 `shouldReturn` "la"
      readBytes fixture 2 `shouldReturn` "st"
      within (streamReadByte (fixtureStream fixture)) `shouldThrow` isEOFError
  it "should process coalesced data and FIN frames without dropping bytes" $
    withFixture $ \fixture -> do
      push fixture (message Nothing "last" <> fin)
      readBytes fixture 4 `shouldReturn` "last"
      within (streamReadByte (fixtureStream fixture)) `shouldThrow` isEOFError
      nextSent fixture `shouldReturn` finAck
  it "should keep writes open after receiving FIN" $
    withFixture $ \fixture -> do
      push fixture fin
      nextSent fixture `shouldReturn` finAck
      streamWrite (fixtureStream fixture) "response"
      nextSent fixture `shouldReturn` message Nothing "response"

resetSpec :: Spec
resetSpec = do
  it "should wake a blocked reader with reset when RESET_STREAM arrives" $
    withFixture $ \fixture -> do
      push fixture resetStream
      within (streamReadByte (fixtureStream fixture)) `shouldThrow` (hasMessage "WebRTC stream reset")
  it "should discard payload carried by RESET_STREAM and retain the read error" $
    withFixture $ \fixture -> do
      push fixture (message (Just 2) "discard")
      within (streamReadByte (fixtureStream fixture)) `shouldThrow` (hasMessage "WebRTC stream reset")
      within (streamReadByte (fixtureStream fixture)) `shouldThrow` (hasMessage "WebRTC stream reset")
  it "should keep the independent write side usable after RESET_STREAM" $
    withFixture $ \fixture -> do
      push fixture resetStream
      within (streamReadByte (fixtureStream fixture)) `shouldThrow` (hasMessage "WebRTC stream reset")
      streamWrite (fixtureStream fixture) "reply"
      nextSent fixture `shouldReturn` message Nothing "reply"

stopSendingSpec :: Spec
stopSendingSpec = do
  it "should reject writes after STOP_SENDING without responding with RESET_STREAM" $
    withFixture $ \fixture -> do
      push fixture (stopSending <> fin)
      nextSent fixture `shouldReturn` finAck
      streamWrite (fixtureStream fixture) "late" `shouldThrow` (hasMessage "WebRTC peer stopped receiving")
      atomically (tryReadTQueue (fixtureOutgoing fixture)) `shouldReturn` Nothing
  it "should deliver payload while processing a combined STOP_SENDING" $
    withFixture $ \fixture -> do
      push fixture (message (Just 1) "readable")
      readBytes fixture 8 `shouldReturn` "readable"
      streamWrite (fixtureStream fixture) "late" `shouldThrow` (hasMessage "WebRTC peer stopped receiving")
  it "should ignore unsolicited FIN_ACK without closing either half" $
    withFixture $ \fixture -> do
      push fixture (message (Just 3) "readable")
      readBytes fixture 8 `shouldReturn` "readable"
      streamWrite (fixtureStream fixture) "writable"
      nextSent fixture `shouldReturn` message Nothing "writable"

closeSpec :: Spec
closeSpec = do
  it "should wait for FIN_ACK and keep receiving until the remote FIN" $
    withFixture $ \fixture -> do
      withAsync (streamClose (fixtureStream fixture)) $ \closer -> do
        nextSent fixture `shouldReturn` fin
        (isNothing <$> poll closer) `shouldReturn` True
        readTVarIO (fixtureClosed fixture) `shouldReturn` False
        push fixture finAck
        within $ wait closer
      push fixture (message Nothing "after half-close")
      readBytes fixture 16 `shouldReturn` "after half-close"
      push fixture fin
      nextSent fixture `shouldReturn` finAck
      awaitRelease fixture
  it "should force channel shutdown when FIN_ACK does not arrive within the bound" $
    withFixtureTimeout 100000 $ \fixture -> do
      within $ streamClose (fixtureStream fixture)
      nextSent fixture `shouldReturn` fin
      readTVarIO (fixtureClosed fixture) `shouldReturn` True
      awaitRelease fixture
  it "should send FIN and release the channel only once across repeated closes" $
    withFixture $ \fixture -> do
      withAsync (streamClose (fixtureStream fixture)) $ \closer -> do
        nextSent fixture `shouldReturn` fin
        push fixture (finAck <> fin)
        within $ wait closer
      nextSent fixture `shouldReturn` finAck
      streamClose (fixtureStream fixture)
      awaitRelease fixture
      atomically (tryReadTQueue (fixtureOutgoing fixture)) `shouldReturn` Nothing
  it "should reject data writes after locally closing the write half" $
    withFixture $ \fixture -> do
      withAsync (streamClose (fixtureStream fixture)) $ \closer -> do
        nextSent fixture `shouldReturn` fin
        streamWrite (fixtureStream fixture) "late" `shouldThrow` (hasMessage "WebRTC write side closed")
        push fixture finAck
        within $ wait closer

failureSpec :: Spec
failureSpec = do
  it "should retain final payload when sending its FIN_ACK fails" $
    withFixtureChannel 2000000 failingSender $ \fixture -> do
      push fixture (message (Just 0) "final")
      readBytes fixture 5 `shouldReturn` "final"
      within (streamReadByte (fixtureStream fixture)) `shouldThrow` isEOFError
      awaitRelease fixture
  it "should release the channel when a data write fails" $
    withFixtureChannel 2000000 failingSender $ \fixture -> do
      streamWrite (fixtureStream fixture) "data" `shouldThrow` anyIOException
      awaitRelease fixture
  it "should release the channel when a caller cancels FIN_ACK waiting" $
    withFixture $ \fixture -> do
      withAsync (streamClose (fixtureStream fixture)) $ \closer -> do
        nextSent fixture `shouldReturn` fin
        cancel closer
      awaitRelease fixture
  where
    failingSender channel = channel { dcSend = \_ -> fail "scripted send failure" }

shutdownSpec :: Spec
shutdownSpec = do
  it "should unblock an in-flight send before freeing a timed-out channel" $ do
    entered <- newEmptyTMVarIO
    stopped <- newTVarIO False
    let blocked channel = channel
          { dcSend = \_ -> do
              atomically $ putTMVar entered ()
              atomically $ readTVar stopped >>= check
              fail "scripted send interrupted"
          , dcShutdown = atomically (writeTVar stopped True) >> dcShutdown channel
          }
    withFixtureChannel 100000 blocked $ \fixture ->
      withAsync (streamWrite (fixtureStream fixture) "data") $ \writer -> do
        within $ atomically $ takeTMVar entered
        within $ streamClose (fixtureStream fixture)
        outcome <- within $ waitCatch writer
        outcome `shouldSatisfy` isLeft
        awaitRelease fixture

  it "should shut down foreign FIN writes before joining their uncancellable worker" $ do
    stopped <- newTVarIO False
    let blocked channel = channel
          { dcSend = \_ -> uninterruptibleMask_ $ atomically $ readTVar stopped >>= check
          , dcShutdown = atomically (writeTVar stopped True) >> dcShutdown channel
          }
    withFixtureChannel 100000 blocked $ \fixture ->
      withAsync (threadDelay 2000000 >> atomically (writeTVar stopped True)) $ \_ -> do
        within $ streamClose (fixtureStream fixture)
        awaitRelease fixture

duplexSpec :: Spec
duplexSpec =
  it "should exchange the final response after bidirectional half-close" $
    withDuplex $ \left right -> do
      streamWrite left "request"
      within $ streamClose left
      within (streamReadChunk right 7) `shouldReturn` "request"
      within (streamReadByte right) `shouldThrow` isEOFError
      streamWrite right "response"
      within $ streamClose right
      within (streamReadChunk left 8) `shouldReturn` "response"
      within (streamReadByte left) `shouldThrow` isEOFError

withFixture :: (Fixture -> IO a) -> IO a
withFixture = withFixtureTimeout 2000000

withFixtureTimeout :: Int -> (Fixture -> IO a) -> IO a
withFixtureTimeout closeTimeout = withFixtureChannel closeTimeout id

withFixtureChannel :: Int -> (ChannelIO -> ChannelIO) -> (Fixture -> IO a) -> IO a
withFixtureChannel closeTimeout transform = bracket acquire release
  where
    acquire = do
      incoming <- newTQueueIO
      outgoing <- newTQueueIO
      closed <- newTVarIO False
      released <- newTVarIO 0
      let channel = testChannel incoming (writeTQueue outgoing) closed released
      stream <- channelToStreamIO closeTimeout (transform channel)
      pure $ Fixture stream incoming outgoing closed released
    release fixture = do
      atomically $ writeTVar (fixtureClosed fixture) True
      streamClose (fixtureStream fixture) `catch` \(_ :: SomeException) -> pure ()
      awaitRelease fixture

testChannel
  :: TQueue (Maybe ByteString) -> (ByteString -> STM ()) -> TVar Bool -> TVar Int -> ChannelIO
testChannel incoming send closed released = ChannelIO
  { dcSend = \bytes -> atomically $ do
      stopped <- readTVar closed
      when stopped $ throwSTM (userError "test data channel closed")
      send bytes
  , dcReceive = atomically $ readTQueue incoming `orElse` do
      readTVar closed >>= check
      pure Nothing
  , dcShutdown = atomically $ writeTVar closed True
  , dcClose = atomically $ do
      writeTVar closed True
      modifyTVar' released (+ 1)
  }

withDuplex :: (StreamIO -> StreamIO -> IO a) -> IO a
withDuplex action = do
  leftQueue <- newTQueueIO
  rightQueue <- newTQueueIO
  closed <- newTVarIO False
  leftReleased <- newTVarIO 0
  rightReleased <- newTVarIO 0
  let left = testChannel leftQueue (writeTQueue rightQueue . Just) closed leftReleased
      right = testChannel rightQueue (writeTQueue leftQueue . Just) closed rightReleased
      acquire = (,) <$> channelToStreamIO 2000000 left <*> channelToStreamIO 2000000 right
      release (a, b) = do
        atomically $ writeTVar closed True
        streamClose a `catch` \(_ :: SomeException) -> pure ()
        streamClose b `catch` \(_ :: SomeException) -> pure ()
  bracket acquire release (uncurry action)

push :: Fixture -> ByteString -> IO ()
push fixture = atomically . writeTQueue (fixtureIncoming fixture) . Just

nextSent :: Fixture -> IO ByteString
nextSent = within . atomically . readTQueue . fixtureOutgoing

readBytes :: Fixture -> Int -> IO ByteString
readBytes fixture = within . streamReadChunk (fixtureStream fixture)

awaitRelease :: Fixture -> IO ()
awaitRelease fixture = do
  within $ atomically $ readTVar (fixtureReleased fixture) >>= check . (> 0)
  readTVarIO (fixtureReleased fixture) `shouldReturn` 1

within :: IO a -> IO a
within action = withAsync action $ \worker -> do
  result <- timeout 1000000 (wait worker)
  maybe (fail "WebRTC stream operation timed out") pure result

message :: Maybe Word -> ByteString -> ByteString
message flag payload =
  let flags = maybe BS.empty (\value -> BS.pack [8, fromIntegral value]) flag
      bytes = flags <> BS.singleton 0x12 <> encodeUvarint (fromIntegral (BS.length payload)) <> payload
  in encodeUvarint (fromIntegral (BS.length bytes)) <> bytes

fin, stopSending, resetStream, finAck :: ByteString
fin = BS.pack [2, 8, 0]
stopSending = BS.pack [2, 8, 1]
resetStream = BS.pack [2, 8, 2]
finAck = BS.pack [2, 8, 3]

hasMessage :: String -> IOException -> Bool
hasMessage messageText = (== messageText) . ioeGetErrorString

isFrameError :: IOException -> Bool
isFrameError exception = any (`isPrefixOf` ioeGetErrorString exception)
  ["WebRTC stream frame", "WebRTC stream message"]
