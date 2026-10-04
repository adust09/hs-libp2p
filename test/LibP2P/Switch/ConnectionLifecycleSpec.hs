-- | Connection lifecycle tests (issue #179).
--
-- Verifies that connections are actually torn down: pool removal on
-- remote disconnect, explicit closeConnection, switchClose teardown,
-- resource release, stream slot accounting, and dial dedup cleanup.
module LibP2P.Switch.ConnectionLifecycleSpec (spec) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.Async (async)
import Control.Concurrent.MVar (newEmptyMVar, putMVar, takeMVar)
import Control.Concurrent.STM (TChan, TVar, atomically, newTVarIO, readTChan, readTVar, readTVarIO, retry, tryReadTChan, writeTVar)
import Control.Exception (SomeException, bracket, finally, try)
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import Data.Maybe (isJust, isNothing)
import qualified Data.Map.Strict as Map
import qualified LibP2P as Public
import LibP2P.Crypto.Ed25519 (generateKeyPair)
import LibP2P.Crypto.Key (KeyPair, publicKey)
import LibP2P.Crypto.PeerId (PeerId, fromPublicKey)
import LibP2P.Multiaddr (Multiaddr (..))
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.MultistreamSelect.Negotiation
  ( StreamIO (..)
  , mkByteStreamIO
  , mkMemoryStreamPair
  , negotiateInitiator
  )
import LibP2P.Switch (addTransport, newSwitch, setStreamHandler, switchClose)
import LibP2P.Switch.ConnPool (addConn, lookupConn)
import LibP2P.Switch.Connection (closeConnection, newStream)
import LibP2P.Switch.Dial (dial)
import LibP2P.Switch.Listen (defaultConnectionGater, dispatchStream, switchListen)
import LibP2P.Switch.ResourceManager
  ( ResourceManager (..)
  , ResourceScope (..)
  , ResourceUsage (..)
  )
import LibP2P.Switch.Types
  ( ConnState (..)
  , Connection (..)
  , DialError (..)
  , Direction (..)
  , MuxerSession (..)
  , Switch (..)
  )
import LibP2P.Switch.Upgrade (upgradeInbound)
import LibP2P.Transport (ConnectionEndpoint (..), RawConnection (..), Transport (..))
import LibP2P.Transport.TCP (newTCPTransport)
import System.Timeout (timeout)
import Test.Hspec

-- | Generate a test identity (PeerId, KeyPair).
mkTestIdentity :: IO (PeerId, KeyPair)
mkTestIdentity = do
  Right kp <- generateKeyPair
  let pid = fromPublicKey (publicKey kp)
  pure (pid, kp)

-- | A test multiaddr: /ip4/127.0.0.1/tcp/4001
testAddr :: Multiaddr
testAddr = Multiaddr [IP4 0x7f000001, TCP 4001]

-- | Loopback address with port 0 (OS assigns ephemeral port).
loopbackAddr :: Multiaddr
loopbackAddr = Multiaddr [IP4 0x7f000001, TCP 0]

-- | Poll a condition every 100ms, up to n attempts.
waitUntil :: Int -> IO Bool -> IO Bool
waitUntil 0 _ = pure False
waitUntil n check = do
  ok <- check
  if ok
    then pure True
    else threadDelay 100000 >> waitUntil (n - 1) check

-- | Read the peer scope usage for a peer, if the scope exists.
peerUsage :: Switch -> PeerId -> IO (Maybe ResourceUsage)
peerUsage sw pid = atomically $ do
  peers <- readTVar (rmPeerScopes (swResourceMgr sw))
  case Map.lookup pid peers of
    Nothing -> pure Nothing
    Just scope -> Just <$> readTVar (rsUsage scope)

-- | A dummy connection whose muxer serves in-memory streams.
mkDummyConnection :: PeerId -> IO StreamIO -> IO Connection
mkDummyConnection pid openAction = do
  stateVar <- newTVarIO ConnOpen
  pure Connection
    { connPeerId     = pid
    , connDirection  = Outbound
    , connLocalAddr  = Multiaddr [IP4 0x7f000001, TCP 0]
    , connRemoteAddr = testAddr
    , connSecurity   = "/noise"
    , connMuxer      = "/yamux/1.0.0"
    , connSession    = MuxerSession
        { muxOpenStream   = openAction
        , muxAcceptStream = fail "dummy: no inbound streams"
        , muxClose        = pure ()
        }
    , connState      = stateVar
    }

-- | Mock transport whose dialed connection records rcClose calls in an IORef.
mkClosableMockTransport :: KeyPair -> IORef Bool -> IO Transport
mkClosableMockTransport responderKP closedRef = pure Transport
  { transportDial = dialFn
  , transportDialFrom = \_ -> dialFn
  , transportListen = \_ -> error "mock: listen not supported"
  , transportCanDial = \(Multiaddr ps) -> case ps of
      (IP4 _ : TCP _ : _) -> True
      _ -> False
  }
  where
    dialFn addr = do
      (streamA, streamB) <- mkMemoryStreamPair
      let rawConnB = RawConnection
            { rcEndpoint   = ByteStreamEndpoint streamB
            , rcLocalAddr  = addr
            , rcRemoteAddr = Multiaddr [IP4 0x7f000001, TCP 0]
            , rcClose      = pure ()
            }
      _ <- async $ do
        _ <- upgradeInbound responderKP rawConnB
        pure ()
      pure RawConnection
        { rcEndpoint   = ByteStreamEndpoint streamA
        , rcLocalAddr  = Multiaddr [IP4 0x7f000001, TCP 0]
        , rcRemoteAddr = addr
        , rcClose      = writeIORef closedRef True
        }

-- | Build a TCP node with Switch.
mkTCPNode :: IO (Switch, PeerId)
mkTCPNode = do
  (pid, kp) <- mkTestIdentity
  sw <- newSwitch pid kp
  tcp <- newTCPTransport
  addTransport sw tcp
  pure (sw, pid)

-- | Fail with a label if an event test operation times out.
withinEventTest :: String -> IO a -> IO a
withinEventTest label action = do
  result <- timeout 5000000 action
  maybe (fail $ label ++ " timed out") pure result

-- | Run with two TCP nodes and guaranteed cleanup.
withEventPeers :: (Switch -> PeerId -> Multiaddr -> IO ()) -> IO ()
withEventPeers action =
  bracket mkTCPNode closeNode $ \(swA, _) ->
    bracket mkTCPNode closeNode $ \(swB, pidB) -> do
      addrs <- withinEventTest "listen" $
        Public.switchListen swB Public.defaultConnectionGater [loopbackAddr]
      case addrs of
        addr : _ -> action swA pidB addr
        [] -> expectationFailure "listen returned no addresses"
  where
    closeNode (sw, _) = withinEventTest "cleanup" $ Public.switchClose sw

dialEventConnection :: Switch -> PeerId -> Multiaddr -> IO Connection
dialEventConnection sw pid addr = do
  result <- withinEventTest "dial" $ Public.dial sw pid [addr]
  either (fail . ("dial failed: " ++) . show) pure result

readSwitchEvent :: TChan Public.SwitchEvent -> IO Public.SwitchEvent
readSwitchEvent events = withinEventTest "read event" $ atomically $ readTChan events

-- | Wrap a transport so its dialed connections can be silently frozen:
-- while the flag is set, writes are swallowed and reads never return,
-- but nothing is closed. This models a peer that vanished without a
-- FIN (cable pulled, process stopped with SIGSTOP).
mkFreezableTransport :: TVar Bool -> Transport -> Transport
mkFreezableTransport frozen inner = inner
  { transportDial = fmap freeze . transportDial inner
  , transportDialFrom = \from addr -> freeze <$> transportDialFrom inner from addr
  }
  where
    freeze raw = case rcEndpoint raw of
      ByteStreamEndpoint io -> raw { rcEndpoint = ByteStreamEndpoint (gate io) }
      NativeMuxerEndpoint _ -> raw
    gate io = io
      { streamWrite = \bs -> do
          isFrozen <- readTVarIO frozen
          if isFrozen then pure () else streamWrite io bs
      , streamReadByte = streamReadByte io >>= held
      , streamReadChunk = \n -> streamReadChunk io n >>= held
      }
    held x = atomically $ do
      isFrozen <- readTVar frozen
      if isFrozen then retry else pure x

-- | Keepalive short enough for a silent peer to be detected well inside
-- the test's deadline (the 30s default would outlast it).
fastKeepAliveConfig :: Public.SwitchConfig
fastKeepAliveConfig = Public.defaultSwitchConfig
  { Public.scYamuxConfig = Public.defaultYamuxConfig
      { Public.ycKeepAliveIntervalMicros = 100000
      , Public.ycPingTimeoutMicros = 350000
      }
  }

-- | Run with a dialer A whose TCP connections can be frozen and a plain
-- TCP listener B. The flag is cleared before teardown so cleanup never
-- waits on a frozen read.
withFreezablePeers
  :: (TVar Bool -> Switch -> Switch -> PeerId -> PeerId -> Multiaddr -> IO ())
  -> IO ()
withFreezablePeers action = do
  frozen <- newTVarIO False
  bracket (mkFreezableNode frozen) closeNode $ \(swA, pidA) ->
    bracket mkTCPNode closeNode $ \(swB, pidB) -> do
      addrs <- withinEventTest "listen" $
        Public.switchListen swB Public.defaultConnectionGater [loopbackAddr]
      case addrs of
        addr : _ ->
          action frozen swA swB pidA pidB addr
            `finally` atomically (writeTVar frozen False)
        [] -> expectationFailure "listen returned no addresses"
  where
    mkFreezableNode frozen = do
      (pid, kp) <- mkTestIdentity
      sw <- Public.newSwitchWith fastKeepAliveConfig pid kp
      tcp <- newTCPTransport
      addTransport sw (mkFreezableTransport frozen tcp)
      pure (sw, pid)
    closeNode (sw, _) = withinEventTest "cleanup" $ Public.switchClose sw

spec :: Spec
spec = do
  describe "Switch event subscriptions" $ do
    it "delivers the same Connected event to two independent subscribers" $
      withEventPeers $ \sw pid addr -> do
        first <- Public.subscribeSwitchEvents sw
        second <- Public.subscribeSwitchEvents sw
        conn <- dialEventConnection sw pid addr
        let expected = Public.Connected pid Public.Outbound (connRemoteAddr conn)
        readSwitchEvent first `shouldReturn` expected
        readSwitchEvent second `shouldReturn` expected

    it "delivers Disconnected to both subscribers when a connection closes" $
      withEventPeers $ \sw pid addr -> do
        first <- Public.subscribeSwitchEvents sw
        second <- Public.subscribeSwitchEvents sw
        conn <- dialEventConnection sw pid addr
        let connected = Public.Connected pid Public.Outbound (connRemoteAddr conn)
        readSwitchEvent first `shouldReturn` connected
        readSwitchEvent second `shouldReturn` connected
        withinEventTest "close connection" $ Public.closeConnection sw conn
        let disconnected = Public.Disconnected pid Public.Outbound (connRemoteAddr conn)
        readSwitchEvent first `shouldReturn` disconnected
        readSwitchEvent second `shouldReturn` disconnected

    it "starts later subscribers at future events without draining earlier subscribers" $
      withEventPeers $ \sw pid addr -> do
        first <- Public.subscribeSwitchEvents sw
        conn <- dialEventConnection sw pid addr
        later <- Public.subscribeSwitchEvents sw
        atomically (tryReadTChan later) `shouldReturn` Nothing
        readSwitchEvent first `shouldReturn`
          Public.Connected pid Public.Outbound (connRemoteAddr conn)
        withinEventTest "close connection" $ Public.closeConnection sw conn
        let disconnected = Public.Disconnected pid Public.Outbound (connRemoteAddr conn)
        readSwitchEvent first `shouldReturn` disconnected
        readSwitchEvent later `shouldReturn` disconnected

    it "shuts down with an unread subscriber and leaves its events readable" $
      withEventPeers $ \sw pid addr -> do
        events <- Public.subscribeSwitchEvents sw
        conn <- dialEventConnection sw pid addr
        withinEventTest "shutdown" $ Public.switchClose sw
        readSwitchEvent events `shouldReturn`
          Public.Connected pid Public.Outbound (connRemoteAddr conn)
        readSwitchEvent events `shouldReturn`
          Public.Disconnected pid Public.Outbound (connRemoteAddr conn)

  describe "closeConnection" $ do
    it "removes the connection from the pool, closes the transport, and releases the reservation" $ do
      (localPid, localKP) <- mkTestIdentity
      (_remotePid, remoteKP) <- mkTestIdentity
      sw <- newSwitch localPid localKP
      closedRef <- newIORef False
      transport <- mkClosableMockTransport remoteKP closedRef
      addTransport sw transport
      result <- dial sw _remotePid [testAddr]
      case result of
        Left err -> expectationFailure $ "dial failed: " <> show err
        Right conn -> do
          -- Reservation is held while the connection lives
          usageBefore <- peerUsage sw (connPeerId conn)
          fmap ruConnsOutbound usageBefore `shouldBe` Just 1
          closeConnection sw conn
          -- Pool no longer contains the connection
          poolConn <- atomically $ lookupConn (swConnPool sw) (connPeerId conn)
          isNothing poolConn `shouldBe` True
          -- Connection state is ConnClosed
          st <- atomically $ readTVar (connState conn)
          st `shouldBe` ConnClosed
          -- Underlying transport was closed
          closedOk <- waitUntil 20 (readIORef closedRef)
          closedOk `shouldBe` True
          -- Connection reservation was released
          usageAfter <- peerUsage sw (connPeerId conn)
          fmap ruConnsOutbound usageAfter `shouldBe` Just 0

    it "is idempotent (double close does not underflow the reservation)" $ do
      (localPid, localKP) <- mkTestIdentity
      (_remotePid, remoteKP) <- mkTestIdentity
      sw <- newSwitch localPid localKP
      closedRef <- newIORef False
      transport <- mkClosableMockTransport remoteKP closedRef
      addTransport sw transport
      Right conn <- dial sw _remotePid [testAddr]
      closeConnection sw conn
      closeConnection sw conn
      usage <- peerUsage sw (connPeerId conn)
      fmap ruConnsOutbound usage `shouldBe` Just 0

  describe "remote disconnect" $ do
    it "removes the connection from the pool when the remote closes; a fresh dial succeeds" $ do
      (swB, pidB) <- mkTCPNode
      addrs <- switchListen swB defaultConnectionGater [loopbackAddr]
      let listenAddr = head addrs
      (swA, pidA) <- mkTCPNode
      Right conn <- dial swA pidB [listenAddr]
      -- Wait for B to pool the inbound connection
      pooledOk <- waitUntil 30 $ do
        c <- atomically $ lookupConn (swConnPool swB) pidA
        pure (isJust c)
      pooledOk `shouldBe` True
      -- B closes its side of the connection
      Just connB <- atomically $ lookupConn (swConnPool swB) pidA
      closeConnection swB connB
      -- A must notice the dead session and drop the connection from its pool
      droppedOk <- waitUntil 50 $ do
        c <- atomically $ lookupConn (swConnPool swA) pidB
        pure (isNothing c)
      droppedOk `shouldBe` True
      -- A's connection reservation must be released
      usageA <- peerUsage swA pidB
      fmap ruConnsOutbound usageA `shouldBe` Just 0
      -- A subsequent dial creates a fresh connection
      redialResult <- timeout 5000000 $ dial swA pidB [listenAddr]
      case redialResult of
        Nothing -> expectationFailure "redial timed out"
        Just (Left err) -> expectationFailure $ "redial failed: " <> show err
        Just (Right conn2) ->
          -- Fresh connection: distinct state TVar
          (connState conn2 == connState conn) `shouldBe` False
      switchClose swA
      switchClose swB

  describe "silent peer" $ do
    -- Control: proves the freezable harness itself delivers Disconnected
    -- when the remote closes properly, so a failure below is about
    -- silence, not about the wrapper.
    it "publishes Disconnected when the remote closes (harness control)" $
      withFreezablePeers $ \_frozen swA swB pidA pidB addr -> do
        events <- Public.subscribeSwitchEvents swA
        conn <- dialEventConnection swA pidB addr
        readSwitchEvent events `shouldReturn`
          Public.Connected pidB Public.Outbound (connRemoteAddr conn)
        pooledOk <- waitUntil 30 $
          isJust <$> atomically (lookupConn (swConnPool swB) pidA)
        pooledOk `shouldBe` True
        Just connB <- atomically $ lookupConn (swConnPool swB) pidA
        closeConnection swB connB
        readSwitchEvent events `shouldReturn`
          Public.Disconnected pidB Public.Outbound (connRemoteAddr conn)

    it "publishes Disconnected when the remote goes silent without closing" $
      withFreezablePeers $ \frozen swA _swB _pidA pidB addr -> do
        events <- Public.subscribeSwitchEvents swA
        conn <- dialEventConnection swA pidB addr
        readSwitchEvent events `shouldReturn`
          Public.Connected pidB Public.Outbound (connRemoteAddr conn)
        atomically $ writeTVar frozen True
        -- Nothing else is done: the stack itself must notice the dead peer.
        result <- timeout 3000000 $ atomically $ readTChan events
        result `shouldBe`
          Just (Public.Disconnected pidB Public.Outbound (connRemoteAddr conn))

  describe "switchClose" $ do
    it "closes pooled connections on both sides" $ do
      (swB, pidB) <- mkTCPNode
      addrs <- switchListen swB defaultConnectionGater [loopbackAddr]
      let listenAddr = head addrs
      (swA, pidA) <- mkTCPNode
      Right conn <- dial swA pidB [listenAddr]
      pooledOk <- waitUntil 30 $ do
        c <- atomically $ lookupConn (swConnPool swB) pidA
        pure (isJust c)
      pooledOk `shouldBe` True
      switchClose swA
      -- A's pool is emptied and the connection is closed
      poolA <- atomically $ lookupConn (swConnPool swA) pidB
      isNothing poolA `shouldBe` True
      st <- atomically $ readTVar (connState conn)
      st `shouldBe` ConnClosed
      -- B notices the remote disconnect and drops A from its pool
      droppedOk <- waitUntil 50 $ do
        c <- atomically $ lookupConn (swConnPool swB) pidA
        pure (isNothing c)
      droppedOk `shouldBe` True
      switchClose swB

  describe "stream resource accounting" $ do
    it "newStream reserves an outbound stream slot and releases it on close" $ do
      (localPid, localKP) <- mkTestIdentity
      (remotePid, _remoteKP) <- mkTestIdentity
      sw <- newSwitch localPid localKP
      (sIO, _peerIO) <- mkMemoryStreamPair
      conn <- mkDummyConnection remotePid (pure sIO)
      atomically $ addConn (swConnPool sw) conn
      result <- newStream sw conn
      case result of
        Left err -> expectationFailure $ "newStream failed: " <> show err
        Right stream -> do
          usageOpen <- peerUsage sw remotePid
          fmap ruStreamsOutbound usageOpen `shouldBe` Just 1
          streamClose stream
          usageClosed <- peerUsage sw remotePid
          fmap ruStreamsOutbound usageClosed `shouldBe` Just 0
          -- Double close releases only once
          streamClose stream
          usageDouble <- peerUsage sw remotePid
          fmap ruStreamsOutbound usageDouble `shouldBe` Just 0

    it "dispatchStream counts an inbound stream against the peer limit and releases it" $ do
      (localPid, localKP) <- mkTestIdentity
      (remotePid, _remoteKP) <- mkTestIdentity
      sw <- newSwitch localPid localKP
      usageMVar <- newEmptyMVar
      setStreamHandler sw "/test/1.0.0" $ \_conn _stream -> do
        usage <- peerUsage sw remotePid
        putMVar usageMVar (fmap ruStreamsInbound usage)
      conn <- mkDummyConnection remotePid (fail "no outbound")
      (clientIO, serverIO) <- mkMemoryStreamPair
      _ <- async $ negotiateInitiator clientIO ["/test/1.0.0"]
      dispatchResult <- timeout 5000000 $ dispatchStream sw conn serverIO
      dispatchResult `shouldBe` Just ()
      -- During the handler, the inbound stream slot was held
      heldUsage <- takeMVar usageMVar
      heldUsage `shouldBe` Just 1
      -- After dispatch completes, the slot is released
      usageAfter <- peerUsage sw remotePid
      fmap ruStreamsInbound usageAfter `shouldBe` Just 0

    it "closes the stream when negotiation finds no common protocol" $ do
      (localPid, localKP) <- mkTestIdentity
      (remotePid, _remoteKP) <- mkTestIdentity
      sw <- newSwitch localPid localKP
      setStreamHandler sw "/test/1.0.0" $ \_conn _stream -> pure ()
      closed <- newIORef False
      conn <- mkDummyConnection remotePid (fail "no outbound")
      -- Immediate EOF: negotiateResponder returns NoProtocol without a
      -- handler, so dispatch is the only thing that can close.
      let tracked = mkByteStreamIO (\_ -> pure ()) (fail "EOF") (writeIORef closed True)
      dispatchResult <- timeout 5000000 $ dispatchStream sw conn tracked
      dispatchResult `shouldBe` Just ()
      readIORef closed `shouldReturn` True

    it "does not close a stream the handler returned without closing" $ do
      -- Circuit Relay STOP hands the stream off as a connection and
      -- returns; dispatch must not close-on-return (go-libp2p model).
      (localPid, localKP) <- mkTestIdentity
      (remotePid, _remoteKP) <- mkTestIdentity
      sw <- newSwitch localPid localKP
      setStreamHandler sw "/test/1.0.0" $ \_conn _stream -> pure ()
      closed <- newIORef False
      conn <- mkDummyConnection remotePid (fail "no outbound")
      (clientIO, serverIO) <- mkMemoryStreamPair
      let tracked = serverIO { streamClose = writeIORef closed True >> streamClose serverIO }
      _ <- async $ negotiateInitiator clientIO ["/test/1.0.0"]
      dispatchResult <- timeout 5000000 $ dispatchStream sw conn tracked
      dispatchResult `shouldBe` Just ()
      readIORef closed `shouldReturn` False

  describe "dial dedup" $ do
    it "removes the pending entry when the dial throws" $ do
      (localPid, localKP) <- mkTestIdentity
      (remotePid, _remoteKP) <- mkTestIdentity
      sw <- newSwitch localPid localKP
      -- A transport whose canDial check blows up mid-dial
      addTransport sw Transport
        { transportDial = \_ -> fail "unreachable"
        , transportDialFrom = \_ _ -> fail "unreachable"
        , transportListen = \_ -> error "mock: listen not supported"
        , transportCanDial = \_ -> error "boom: canDial exploded"
        }
      firstResult <- try (dial sw remotePid [testAddr]) :: IO (Either SomeException (Either DialError Connection))
      case firstResult of
        Left _ -> pure ()  -- Expected: the dial threw
        Right _ -> expectationFailure "expected the dial to throw"
      -- The pending dial entry must have been cleaned up
      pendingMap <- atomically $ readTVar (swPendingDials sw)
      Map.member remotePid pendingMap `shouldBe` False
      -- A subsequent dial must not wedge on the stale entry
      secondResult <- timeout 2000000 (try (dial sw remotePid [testAddr]) :: IO (Either SomeException (Either DialError Connection)))
      case secondResult of
        Nothing -> expectationFailure "second dial wedged on a stale pending entry"
        Just _ -> pure ()
