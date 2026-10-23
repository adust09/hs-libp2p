module LibP2P.NAT.Relay.LimitSpec (spec) where

import Control.Concurrent.STM (atomically, newTVarIO)
import Control.Exception (try)
import Control.Monad (replicateM)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.IORef (IORef, modifyIORef', newIORef, readIORef, writeIORef)
import Data.Word (Word8, Word64)
import LibP2P.Crypto.Ed25519 (generateKeyPair)
import LibP2P.Crypto.Key (kpPublic)
import LibP2P.Crypto.PeerId (PeerId (..), fromPublicKey)
import LibP2P.Multiaddr (Multiaddr (..))
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.MultistreamSelect.Negotiation (StreamIO (..), mkMemoryStreamPair)
import LibP2P.NAT.Relay.Limit
  ( RelayCircuitExhausted (..)
  , enforceRelayCircuitLimit
  )
import LibP2P.Switch (newSwitch)
import LibP2P.Switch.Connection
  ( StreamOpenError (..)
  , newStream
  , newStreamAllowingLimited
  )
import LibP2P.Switch.ResourceManager (reserveConnection)
import LibP2P.Switch.Types
  ( ConnState (..)
  , Connection (..)
  , Direction (..)
  , MuxerSession (..)
  , Switch (..)
  )
import LibP2P.Transport (RelayCircuitLimit (..))
import System.Timeout (timeout)
import Test.Hspec

spec :: Spec
spec = do
  describe "enforceRelayCircuitLimit" $ do
    it "should not send a write that does not fit" $ do
      (local, remote, written) <- cappedWriteStream 4
      streamWrite local "hello" `shouldThrow` (== RelayCircuitDataExhausted)
      readIORef written `shouldReturn` BS.empty
      streamReadByte local `shouldThrow` (== RelayCircuitDataExhausted)
      pending <- timeout 100000 (streamReadByte remote)
      pending `shouldBe` Nothing

    it "should deliver a write that fills the cap and refuse the next" $ do
      (local, remote, written) <- cappedWriteStream 4
      streamWrite local "ab"
      streamWrite local ""
      streamWrite local "cd"
      readIORef written `shouldReturn` "abcd"
      got <- readN remote 4
      got `shouldBe` "abcd"
      streamWrite local "e" `shouldThrow` (== RelayCircuitDataExhausted)
      readIORef written `shouldReturn` "abcd"

    it "should not consume a byte past the read cap" $ do
      (local, consumed) <- cappedReadStream 4
      chunk <- streamReadChunk local 10
      chunk `shouldBe` "hell"
      readIORef consumed `shouldReturn` 4
      streamReadByte local `shouldThrow` (== RelayCircuitDataExhausted)
      readIORef consumed `shouldReturn` 4

    it "should count each direction against its own cap" $ do
      (local, remote) <- pairWith (Just 4)
      streamWrite remote "wxyz"
      got <- streamReadChunk local 4
      got `shouldBe` "wxyz"
      streamWrite local "abcd"
      streamWrite local "e" `shouldThrow` (== RelayCircuitDataExhausted)

    it "should treat 0 and an omitted limit as unlimited" $ do
      (zero, _) <- pairWith (Just 0)
      streamWrite zero (BS.replicate 8 0x61)
      (local, _) <- mkMemoryStreamPair
      omitted <- enforceRelayCircuitLimit Nothing local
      streamWrite omitted "hello world"

    it "should fail a blocked read when the duration elapses" $ do
      (local, _) <- mkMemoryStreamPair
      limited <- enforceRelayCircuitLimit (Just oneSecond) local
      outcome <- timeout 3000000 (tryByte limited)
      case outcome of
        Nothing -> expectationFailure "duration limit did not fire"
        Just (Left e) -> e `shouldBe` RelayCircuitDurationExhausted
        Just (Right _) -> expectationFailure "read returned a byte past the duration"

  describe "newStream on a relay-limited connection" $ do
    it "should refuse without opening a mux stream" $ do
      (sw, conn, opened) <- limitedConn (Just fourBytes)
      result <- newStream sw conn
      case result of
        Left err -> err `shouldBe` StreamLimitedConnection
        Right _ -> expectationFailure "opened a stream on a limited connection"
      readIORef opened `shouldReturn` False

    it "should open when the caller opts in" $ do
      (sw, conn, opened) <- limitedConn (Just fourBytes)
      result <- newStreamAllowingLimited sw conn
      openedStream result opened

    it "should open when the advertised limit is inactive" $ do
      (sw, conn, opened) <- limitedConn (Just inactive)
      result <- newStream sw conn
      openedStream result opened

oneSecond :: RelayCircuitLimit
oneSecond = RelayCircuitLimit (Just 1) Nothing

fourBytes :: RelayCircuitLimit
fourBytes = RelayCircuitLimit Nothing (Just 4)

inactive :: RelayCircuitLimit
inactive = RelayCircuitLimit (Just 0) (Just 0)

tryByte :: StreamIO -> IO (Either RelayCircuitExhausted Word8)
tryByte stream = try (streamReadByte stream)

openedStream :: Either StreamOpenError StreamIO -> IORef Bool -> IO ()
openedStream result opened = do
  case result of
    Left err -> expectationFailure (show err)
    Right _ -> pure ()
  readIORef opened `shouldReturn` True

pairWith :: Maybe Word64 -> IO (StreamIO, StreamIO)
pairWith bytes = do
  (local, remote) <- mkMemoryStreamPair
  limited <- enforceRelayCircuitLimit (Just (RelayCircuitLimit Nothing bytes)) local
  pure (limited, remote)

cappedWriteStream :: Word64 -> IO (StreamIO, StreamIO, IORef ByteString)
cappedWriteStream cap = do
  (local, remote) <- mkMemoryStreamPair
  written <- newIORef BS.empty
  limited <- enforceRelayCircuitLimit (Just (RelayCircuitLimit Nothing (Just cap)))
    (countingWrite written local)
  pure (limited, remote, written)

countingWrite :: IORef ByteString -> StreamIO -> StreamIO
countingWrite written inner = inner
  { streamWrite = \bs -> do
      modifyIORef' written (<> bs)
      streamWrite inner bs
  }

cappedReadStream :: Word64 -> IO (StreamIO, IORef Int)
cappedReadStream cap = do
  (local, remote) <- mkMemoryStreamPair
  streamWrite remote "hello!!"
  consumed <- newIORef 0
  limited <- enforceRelayCircuitLimit (Just (RelayCircuitLimit Nothing (Just cap)))
    (countingRead consumed local)
  pure (limited, consumed)

countingRead :: IORef Int -> StreamIO -> StreamIO
countingRead consumed inner = inner
  { streamReadChunk = \n -> do
      bs <- streamReadChunk inner n
      modifyIORef' consumed (+ BS.length bs)
      pure bs
  , streamReadByte = do
      b <- streamReadByte inner
      modifyIORef' consumed (+ 1)
      pure b
  }

readN :: StreamIO -> Int -> IO ByteString
readN stream n = BS.pack <$> replicateM n (streamReadByte stream)

limitedConn
  :: Maybe RelayCircuitLimit
  -> IO (Switch, Connection, IORef Bool)
limitedConn budget = do
  Right kp <- generateKeyPair
  sw <- newSwitch (fromPublicKey (kpPublic kp)) kp
  opened <- newIORef False
  conn <- mkConn sw budget opened
  pure (sw, conn, opened)

mkConn :: Switch -> Maybe RelayCircuitLimit -> IORef Bool -> IO Connection
mkConn sw budget opened = do
  stateVar <- newTVarIO ConnOpen
  scope <- atomically $
    reserveConnection (swResourceMgr sw) (PeerId "remote") Outbound
  owned <- either (fail . show) pure scope
  pure Connection
    { connPeerId = PeerId "remote"
    , connDirection = Outbound
    , connLocalAddr = Multiaddr [IP4 0x7f000001, TCP 0]
    , connRemoteAddr = Multiaddr [IP4 0x7f000001, TCP 1]
    , connSecurity = "/noise"
    , connMuxer = "/yamux/1.0.0"
    , connSession = mux opened
    , connState = stateVar
    , connResourceScope = owned
    , connRelayLimit = budget
    }

mux :: IORef Bool -> MuxerSession
mux opened = MuxerSession
  { muxOpenStream = \_ -> writeIORef opened True >> pure idleStream
  , muxAcceptStream = fail "no inbound"
  , muxClose = pure ()
  }

idleStream :: StreamIO
idleStream = StreamIO
  { streamWrite = \_ -> pure ()
  , streamReadByte = fail "unused"
  , streamReadChunk = \_ -> fail "unused"
  , streamClose = pure ()
  }
