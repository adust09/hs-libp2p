module LibP2P.Switch.ListenSpec (spec) where

import Control.Concurrent.Async (async, concurrently)
import Control.Concurrent.MVar (newEmptyMVar, putMVar, takeMVar)
import Control.Concurrent.STM (atomically, retry)
import Data.IORef (newIORef, readIORef, writeIORef)
import LibP2P.Crypto.Ed25519 (generateKeyPair)
import LibP2P.Crypto.Key (KeyPair, publicKey)
import LibP2P.Crypto.PeerId (PeerId, fromPublicKey)
import LibP2P.Multiaddr (Multiaddr (..))
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.MultistreamSelect.Negotiation
  ( NegotiationResult (..)
  , StreamIO (..)
  , mkMemoryStreamPair
  , negotiateInitiator
  )
import LibP2P.Switch.ConnPool (lookupConn)
import LibP2P.Switch.Listen
  ( ConnectionGater (..)
  , dispatchStream
  , handleInbound
  , streamAcceptLoop
  )
import LibP2P.Switch (newSwitch, setConnectionGater, setStreamHandler)
import LibP2P.Switch.Types
  ( Connection (..)
  , MuxerSession (..)
  , Switch (..)
  )
import LibP2P.Switch.Upgrade (upgradeInbound, upgradeOutbound)
import LibP2P.Transport (ConnectionEndpoint (..), RawConnection (..))
import System.Timeout (timeout)
import Test.Hspec

-- | Generate a test identity (PeerId, KeyPair).
mkTestIdentity :: IO (PeerId, KeyPair)
mkTestIdentity = do
  Right kp <- generateKeyPair
  let pid = fromPublicKey (publicKey kp)
  pure (pid, kp)

localAddr :: Multiaddr
localAddr = Multiaddr [IP4 0x7f000001, TCP 12345]

remoteAddr :: Multiaddr
remoteAddr = Multiaddr [IP4 0x7f000001, TCP 54321]

-- | Create a mock RawConnection from a StreamIO.
mkMockRawConn :: StreamIO -> Multiaddr -> Multiaddr -> RawConnection
mkMockRawConn sio local remote = RawConnection
  { rcEndpoint   = ByteStreamEndpoint sio
  , rcLocalAddr  = local
  , rcRemoteAddr = remote
  , rcClose      = pure ()
  }

spec :: Spec
spec = do
  describe "handleInbound" $ do
    it "upgrades connection and adds to pool" $ do
      (pidA, kpA) <- mkTestIdentity
      (pidB, kpB) <- mkTestIdentity
      sw <- newSwitch pidB kpB
      (streamA, streamB) <- mkMemoryStreamPair
      let rawConnA = mkMockRawConn streamA localAddr remoteAddr
          rawConnB = mkMockRawConn streamB remoteAddr localAddr
      -- handleInbound blocks on streamAcceptLoop, so spawn async
      _listenerThread <- async $ handleInbound sw rawConnB
      -- Dialer upgrades synchronously; both sides must handshake concurrently
      upgradeResult <- timeout 3000000 $ upgradeOutbound kpA rawConnA
      case upgradeResult of
        Nothing -> expectationFailure "upgradeOutbound timed out (handleInbound stub may not handshake)"
        Just connA -> do
          -- Wait for connection to appear in pool
          poolResult <- timeout 2000000 $ atomically $ do
            mc <- lookupConn (swConnPool sw) pidA
            case mc of
              Nothing -> retry
              Just c  -> pure c
          case poolResult of
            Nothing -> expectationFailure "timeout: connection not added to pool"
            Just c  -> connPeerId c `shouldBe` pidA
          muxClose (connSession connA)

    it "rejects connection when gateAccept returns False" $ do
      (pidB, kpB) <- mkTestIdentity
      sw <- newSwitch pidB kpB
      closeRef <- newIORef False
      (_streamA, streamB) <- mkMemoryStreamPair
      let rawConnB = RawConnection
            { rcEndpoint   = ByteStreamEndpoint streamB
            , rcLocalAddr  = remoteAddr
            , rcRemoteAddr = localAddr
            , rcClose      = writeIORef closeRef True
            }
          denyGater = ConnectionGater
            { gateAccept = \_ -> pure False
            , gateDialAddr = \_ -> pure True
            , gateSecured = \_ -> pure True
            }
      -- handleInbound should deny at gate and close raw connection
      setConnectionGater sw denyGater
      handleInbound sw rawConnB
      -- Verify rcClose was called
      closed <- readIORef closeRef
      closed `shouldBe` True

    it "rejects connection when gateSecured returns False" $ do
      (pidA, kpA) <- mkTestIdentity
      (pidB, kpB) <- mkTestIdentity
      sw <- newSwitch pidB kpB
      (streamA, streamB) <- mkMemoryStreamPair
      let rawConnA = mkMockRawConn streamA localAddr remoteAddr
          rawConnB = mkMockRawConn streamB remoteAddr localAddr
          denyAfterSecure = ConnectionGater
            { gateAccept = \_ -> pure True
            , gateDialAddr = \_ -> pure True
            , gateSecured = \_ -> pure False
            }
      -- Handshake completes but gateSecured denies.
      -- Both sides must run concurrently for the handshake to work.
      setConnectionGater sw denyAfterSecure
      result <- timeout 3000000 $ concurrently
        (upgradeOutbound kpA rawConnA)
        (handleInbound sw rawConnB)
      case result of
        Nothing -> expectationFailure "timeout during handshake"
        Just _ -> pure ()
      -- Pool should be empty (connection denied after handshake)
      poolConn <- atomically $ lookupConn (swConnPool sw) pidA
      case poolConn of
        Nothing -> pure ()
        Just _  -> expectationFailure "connection should not be in pool"

  describe "streamAcceptLoop" $ do
    it "dispatches stream to registered handler" $ do
      (pidA, kpA) <- mkTestIdentity
      (pidB, kpB) <- mkTestIdentity
      sw <- newSwitch pidB kpB
      -- Register a handler that signals when called via MVar
      handlerDone <- newEmptyMVar
      setStreamHandler sw "/test/1.0.0" $ \conn _stream ->
        putMVar handlerDone (connPeerId conn)
      -- Set up upgraded connections (dialer=outbound, listener=inbound)
      (streamA, streamB) <- mkMemoryStreamPair
      let rawConnA = mkMockRawConn streamA localAddr remoteAddr
          rawConnB = mkMockRawConn streamB remoteAddr localAddr
      (connDialer, connListener) <- concurrently
        (upgradeOutbound kpA rawConnA)
        (upgradeInbound kpB rawConnB)
      -- Start stream accept loop on listener's connection
      _loopThread <- async $ streamAcceptLoop sw connListener
      -- From dialer, open a mux stream, negotiate protocol, wait for handler
      result <- timeout 5000000 $ do
        dialerStream <- muxOpenStream (connSession connDialer)
        negResult <- negotiateInitiator dialerStream ["/test/1.0.0"]
        case negResult of
          Accepted _ -> takeMVar handlerDone
          _          -> fail "protocol negotiation failed"
      case result of
        Nothing -> expectationFailure "timeout: stream not dispatched to handler"
        Just receivedPeerId -> receivedPeerId `shouldBe` pidA
      muxClose (connSession connDialer)
      muxClose (connSession connListener)

    it "passes the Connection so the handler can see the remote address" $ do
      (_pidA, kpA) <- mkTestIdentity
      (pidB, kpB) <- mkTestIdentity
      sw <- newSwitch pidB kpB
      -- Register a handler that reports the connection's remote multiaddr
      handlerDone <- newEmptyMVar
      setStreamHandler sw "/test/1.0.0" $ \conn _stream ->
        putMVar handlerDone (connRemoteAddr conn)
      -- Set up upgraded connections (dialer=outbound, listener=inbound)
      (streamA, streamB) <- mkMemoryStreamPair
      let rawConnA = mkMockRawConn streamA localAddr remoteAddr
          rawConnB = mkMockRawConn streamB remoteAddr localAddr
      (connDialer, connListener) <- concurrently
        (upgradeOutbound kpA rawConnA)
        (upgradeInbound kpB rawConnB)
      _loopThread <- async $ streamAcceptLoop sw connListener
      result <- timeout 5000000 $ do
        dialerStream <- muxOpenStream (connSession connDialer)
        negResult <- negotiateInitiator dialerStream ["/test/1.0.0"]
        case negResult of
          Accepted _ -> takeMVar handlerDone
          _          -> fail "protocol negotiation failed"
      case result of
        Nothing -> expectationFailure "timeout: stream not dispatched to handler"
        Just seenAddr -> seenAddr `shouldBe` connRemoteAddr connListener
      muxClose (connSession connDialer)
      muxClose (connSession connListener)

  describe "dispatchStream" $ do
    it "handles unknown protocol gracefully" $ do
      (_pidA, kpA) <- mkTestIdentity
      (_pidB, kpB) <- mkTestIdentity
      sw <- newSwitch _pidB kpB
      -- No handlers registered
      (streamA, streamB) <- mkMemoryStreamPair
      let rawConnA = mkMockRawConn streamA localAddr remoteAddr
          rawConnB = mkMockRawConn streamB remoteAddr localAddr
      (connDialer, connListener) <- concurrently
        (upgradeOutbound kpA rawConnA)
        (upgradeInbound kpB rawConnB)
      -- Open mux stream from dialer, accept on listener
      (dialerStream, listenerStream) <- concurrently
        (muxOpenStream (connSession connDialer))
        (muxAcceptStream (connSession connListener))
      -- Dispatch on listener side with no handlers
      _dispatchThread <- async $ dispatchStream sw connListener listenerStream
      -- Dialer proposes unknown protocol; expect NoProtocol or timeout
      result <- timeout 2000000 $ negotiateInitiator dialerStream ["/unknown/1.0.0"]
      case result of
        Just NoProtocol -> pure ()
        Just (Accepted _) -> expectationFailure "expected NoProtocol"
        Nothing -> expectationFailure "timeout during negotiation"
      muxClose (connSession connDialer)
      muxClose (connSession connListener)
