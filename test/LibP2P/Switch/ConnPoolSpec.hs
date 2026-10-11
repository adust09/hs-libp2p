module LibP2P.Switch.ConnPoolSpec (spec) where

import Control.Concurrent.STM (atomically, newTVarIO, readTVar, writeTVar)
import Control.Exception (finally)
import LibP2P.Crypto.PeerId (PeerId (..))
import LibP2P.Multiaddr (Multiaddr (..))
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.MultistreamSelect.Negotiation (StreamIO (..), mkByteStreamIO)
import LibP2P.Switch.ConnPool
import LibP2P.Switch.ResourceManager
  ( DefaultLimits (..)
  , MemoryAccount (..)
  , newResourceManager
  , noLimits
  , reserveConnection
  )
import LibP2P.Switch.Types
import Test.Hspec

-- | Create a mock MuxerSession for testing (all operations are no-ops).
mockMuxerSession :: MuxerSession
mockMuxerSession = MuxerSession
  { muxOpenStream = \account -> pure mockStreamIO
      { streamClose = streamClose mockStreamIO
          `finally` atomically (maClose account)
      }
  , muxAcceptStream = pure mockStreamIO
  , muxClose        = pure ()
  }

-- | Create a mock StreamIO for testing.
mockStreamIO :: StreamIO
mockStreamIO = mkByteStreamIO (\_ -> pure ()) (pure 0) (pure ())

-- | Create a mock connection with the given PeerId and direction.
mkMockConn :: PeerId -> Direction -> Multiaddr -> IO Connection
mkMockConn pid dir remoteAddr = do
  st <- newTVarIO ConnOpen
  rm <- newResourceManager (DefaultLimits noLimits noLimits noLimits noLimits)
  connScope <- atomically (reserveConnection rm pid dir)
    >>= either (fail . show) pure
  pure Connection
    { connPeerId     = pid
    , connDirection  = dir
    , connLocalAddr  = Multiaddr [IP4 0x7f000001, TCP 12345]
    , connRemoteAddr = remoteAddr
    , connSecurity   = "/noise"
    , connMuxer      = "/yamux/1.0.0"
    , connSession    = mockMuxerSession
    , connState      = st
    , connResourceScope = connScope
    }

-- | Two distinct PeerIds for testing.
peerA :: PeerId
peerA = PeerId "peer-a-id"

peerB :: PeerId
peerB = PeerId "peer-b-id"

addrA :: Multiaddr
addrA = Multiaddr [IP4 0x0a000001, TCP 4001]

addrB :: Multiaddr
addrB = Multiaddr [IP4 0x0a000002, TCP 4002]

spec :: Spec
spec = do
  describe "ConnPool" $ do
    it "empty pool lookup returns Nothing" $ do
      pool <- newConnPool
      result <- atomically $ lookupConn pool peerA
      case result of
        Nothing -> pure ()
        Just _  -> expectationFailure "Expected Nothing for empty pool"

    it "addConn + lookupConn returns the connection" $ do
      pool <- newConnPool
      conn <- mkMockConn peerA Outbound addrA
      atomically $ addConn pool conn
      result <- atomically $ lookupConn pool peerA
      case result of
        Nothing -> expectationFailure "Expected to find connection"
        Just c  -> connPeerId c `shouldBe` peerA

    it "addConn multiple connections for same peer" $ do
      pool <- newConnPool
      conn1 <- mkMockConn peerA Outbound addrA
      conn2 <- mkMockConn peerA Inbound addrA
      atomically $ addConn pool conn1
      atomically $ addConn pool conn2
      conns <- atomically $ lookupAllConns pool peerA
      length conns `shouldBe` 2

    it "removeConn removes specific connection" $ do
      pool <- newConnPool
      conn1 <- mkMockConn peerA Outbound addrA
      conn2 <- mkMockConn peerA Inbound addrA
      atomically $ addConn pool conn1
      atomically $ addConn pool conn2
      atomically $ removeConn pool conn1
      conns <- atomically $ lookupAllConns pool peerA
      length conns `shouldBe` 1
      case conns of
        [c] -> connDirection c `shouldBe` Inbound
        _   -> expectationFailure "Expected exactly one connection"

    it "lookupConn returns only Open connections" $ do
      pool <- newConnPool
      conn <- mkMockConn peerA Outbound addrA
      -- Set to Closing state
      atomically $ writeTVar (connState conn) Closing
      atomically $ addConn pool conn
      result <- atomically $ lookupConn pool peerA
      case result of
        Nothing -> pure ()
        Just _  -> expectationFailure "Expected Nothing for non-Open connection"

    it "allConns returns connections across all peers" $ do
      pool <- newConnPool
      connA <- mkMockConn peerA Outbound addrA
      connB <- mkMockConn peerB Outbound addrB
      atomically $ addConn pool connA
      atomically $ addConn pool connB
      conns <- atomically $ allConns pool
      length conns `shouldBe` 2

    it "removeConn for non-existent peer is no-op" $ do
      pool <- newConnPool
      conn <- mkMockConn peerA Outbound addrA
      -- Remove without adding — should not crash
      atomically $ removeConn pool conn
      conns <- atomically $ allConns pool
      length conns `shouldBe` 0

    it "lookupConn prefers Open over other states" $ do
      pool <- newConnPool
      conn1 <- mkMockConn peerA Outbound addrA
      conn2 <- mkMockConn peerA Inbound addrA
      -- conn1 is Closing, conn2 is Open
      atomically $ writeTVar (connState conn1) Closing
      atomically $ addConn pool conn1
      atomically $ addConn pool conn2
      result <- atomically $ lookupConn pool peerA
      case result of
        Nothing -> expectationFailure "Expected to find Open connection"
        Just c  -> connDirection c `shouldBe` Inbound
