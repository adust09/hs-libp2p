module LibP2P.Switch.DialSpec (spec) where

import Control.Concurrent.Async (async, concurrently)
import Control.Concurrent.STM (atomically, newTVarIO, readTVar, writeTVar)
import qualified Data.ByteString as BS
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef)
import qualified Data.Map.Strict as Map
import Data.Time.Clock (NominalDiffTime, UTCTime, addUTCTime, diffUTCTime, getCurrentTime)
import Data.Word (Word16)
import LibP2P.Crypto.Ed25519 (generateKeyPair)
import LibP2P.Crypto.Key (KeyPair, publicKey)
import LibP2P.Crypto.PeerId (PeerId, fromPublicKey, peerIdBytes)
import LibP2P.Multiaddr (Multiaddr (..), toBytes)
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.MultistreamSelect.Negotiation (StreamIO (..), mkMemoryStreamPair)
import LibP2P.Protocol.Identify.Message (IdentifyInfo (..))
import LibP2P.Switch.CertifiedRecords (CertifiedRecord (..))
import LibP2P.Switch.ConnPool (addConn, lookupConn)
import LibP2P.Switch.Dial
  ( DialOpts (..)
  , checkBackoff
  , clearBackoff
  , defaultDialOpts
  , dial
  , dialWith
  , initialBackoffSeconds
  , maxBackoffSeconds
  , recordBackoff
  )
import LibP2P.Switch (addTransport, newSwitch, setConnectionGater, switchClose)
import LibP2P.Switch.Listen (defaultConnectionGater, gateDialAddr, gateSecured)
import LibP2P.Switch.ResourceManager
  ( DefaultLimits (..)
  , ResourceManager (..)
  , ResourceScope (..)
  , emptyUsage
  , newResourceManager
  , noLimits
  , reserveConnection
  )
import LibP2P.Switch.Types
  ( ActiveListener (..)
  , BackoffEntry (..)
  , ConnState (..)
  , Connection (..)
  , DialError (..)
  , Direction (..)
  , MuxerSession (..)
  , Switch (..)
  )
import LibP2P.Switch.Upgrade (upgradeInbound)
import LibP2P.Transport (ConnectionEndpoint (..), Listener (..), RawConnection (..), Transport (..))
import Test.Hspec

-- | Generate a test identity (PeerId, KeyPair).
mkTestIdentity :: IO (PeerId, KeyPair)
mkTestIdentity = do
  Right kp <- generateKeyPair
  let pid = fromPublicKey (publicKey kp)
  pure (pid, kp)

-- | A test multiaddr: /ip4/127.0.0.1/tcp/4001
testAddr :: Multiaddr
testAddr = addrAt 4001

addrAt :: Word16 -> Multiaddr
addrAt port = Multiaddr [IP4 0x7f000001, TCP port]

relayAddr :: PeerId -> PeerId -> Multiaddr
relayAddr relayPeer remotePeer = Multiaddr
  [ IP4 0x7f000001
  , TCP 4003
  , P2P (peerIdBytes relayPeer)
  , P2PCircuit
  , P2P (peerIdBytes remotePeer)
  ]

storeIdentifyAddrs :: Switch -> PeerId -> [Multiaddr] -> IO ()
storeIdentifyAddrs sw peer addrs = atomically $ do
  store <- readTVar (swPeerStore sw)
  let info = IdentifyInfo Nothing Nothing Nothing (map toBytes addrs) Nothing [] Nothing
  writeTVar (swPeerStore sw) (Map.insert peer info store)

storeCertifiedAddrs :: Switch -> PeerId -> [Multiaddr] -> IO ()
storeCertifiedAddrs sw peer addrs = atomically $ do
  records <- readTVar (swCertifiedRecords sw)
  let record = CertifiedRecord 1 BS.empty (map toBytes addrs)
  writeTVar (swCertifiedRecords sw) (Map.insert peer record records)

installTestListener :: Switch -> Multiaddr -> IO ()
installTestListener sw addr = do
  worker <- async (pure ())
  let listener = Listener
        { listenerAccept = fail "test listener does not accept"
        , listenerClose = pure ()
        , listenerAddr = addr
        }
  atomically $ writeTVar (swListeners sw) [ActiveListener listener worker addr]

-- | A dummy connection for pool tests.
mkDummyConnection :: Switch -> PeerId -> IO Connection
mkDummyConnection sw pid = do
  stateVar <- newTVarIO ConnOpen
  connScope <- atomically (reserveConnection (swResourceMgr sw) pid Outbound)
    >>= either (fail . show) pure
  pure Connection
    { connPeerId     = pid
    , connDirection  = Outbound
    , connLocalAddr  = Multiaddr [IP4 0x7f000001, TCP 0]
    , connRemoteAddr = testAddr
    , connSecurity   = "/noise"
    , connMuxer      = "/yamux/1.0.0"
    , connSession    = MuxerSession
        { muxOpenStream   = \_ -> fail "dummy: not connected"
        , muxAcceptStream = fail "dummy: not connected"
        , muxClose        = pure ()
        }
    , connState      = stateVar
    , connResourceScope = connScope
    , connRelayLimit = Nothing
    }

newTestResourceManager :: IO ResourceManager
newTestResourceManager =
  newResourceManager (DefaultLimits noLimits noLimits noLimits noLimits)

-- | Create a mock transport where dial connects to a concurrent responder.
-- The responder runs upgradeInbound concurrently on the other end of
-- the in-memory stream pair.
mkMockDialTransport :: KeyPair -> IO Transport
mkMockDialTransport responderKP = pure Transport
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
            , rcRelayLimit = Nothing
            }
      _ <- async $ do
        rm <- newTestResourceManager
        _ <- upgradeInbound rm responderKP rawConnB
        pure ()
      pure RawConnection
        { rcEndpoint   = ByteStreamEndpoint streamA
        , rcLocalAddr  = Multiaddr [IP4 0x7f000001, TCP 0]
        , rcRemoteAddr = addr
        , rcClose      = pure ()
        , rcRelayLimit = Nothing
        }

-- | Create a counting mock transport to verify dial deduplication.
-- Records the number of transportDial calls in the IORef.
mkCountingMockTransport :: KeyPair -> IORef Int -> IO Transport
mkCountingMockTransport responderKP counterRef = pure Transport
  { transportDial = dialFn
  , transportDialFrom = \_ -> dialFn
  , transportListen = \_ -> error "mock: listen not supported"
  , transportCanDial = \(Multiaddr ps) -> case ps of
      (IP4 _ : TCP _ : _) -> True
      _ -> False
  }
  where
    dialFn addr = do
      atomicModifyIORef' counterRef (\n -> (n + 1, ()))
      (streamA, streamB) <- mkMemoryStreamPair
      let rawConnB = RawConnection
            { rcEndpoint   = ByteStreamEndpoint streamB
            , rcLocalAddr  = addr
            , rcRemoteAddr = Multiaddr [IP4 0x7f000001, TCP 0]
            , rcClose      = pure ()
            , rcRelayLimit = Nothing
            }
      _ <- async $ do
        rm <- newTestResourceManager
        _ <- upgradeInbound rm responderKP rawConnB
        pure ()
      pure RawConnection
        { rcEndpoint   = ByteStreamEndpoint streamA
        , rcLocalAddr  = Multiaddr [IP4 0x7f000001, TCP 0]
        , rcRemoteAddr = addr
        , rcClose      = pure ()
        , rcRelayLimit = Nothing
        }

-- | Create a mock transport that records when the upgraded connection closes.
mkClosingMockTransport :: KeyPair -> IORef Int -> IO Transport
mkClosingMockTransport responderKP closeCount = pure Transport
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
            { rcEndpoint = ByteStreamEndpoint streamB
            , rcLocalAddr = addr
            , rcRemoteAddr = Multiaddr [IP4 0x7f000001, TCP 0]
            , rcClose = pure ()
            , rcRelayLimit = Nothing
            }
      _ <- async $ do
        rm <- newTestResourceManager
        _ <- upgradeInbound rm responderKP rawConnB
        pure ()
      pure RawConnection
        { rcEndpoint = ByteStreamEndpoint streamA
        , rcLocalAddr = Multiaddr [IP4 0x7f000001, TCP 0]
        , rcRemoteAddr = addr
        , rcClose = atomicModifyIORef' closeCount (\n -> (n + 1, ()))
        , rcRelayLimit = Nothing
        }

-- | Create a mock transport that always fails to dial.
mkFailingTransport :: IO Transport
mkFailingTransport = pure Transport
  { transportDial = \_ -> fail "connection refused"
  , transportDialFrom = \_ _ -> fail "connection refused"
  , transportListen = \_ -> error "mock: listen not supported"
  , transportCanDial = \_ -> True
  }

-- | Create a raw connection whose upgrade fails, recording transport cleanup.
mkUnupgradableTransport :: IORef Int -> IO Transport
mkUnupgradableTransport closeCount = pure Transport
  { transportDial = dialFn
  , transportDialFrom = \_ -> dialFn
  , transportListen = \_ -> error "mock: listen not supported"
  , transportCanDial = \_ -> True
  }
  where
    close = atomicModifyIORef' closeCount (\n -> (n + 1, ()))
    dialFn addr = pure RawConnection
      { rcEndpoint = ByteStreamEndpoint StreamIO
          { streamWrite = const (pure ())
          , streamReadByte = fail "upgrade failed"
          , streamReadChunk = const (fail "upgrade failed")
          , streamClose = close
          }
      , rcLocalAddr = Multiaddr [IP4 0x7f000001, TCP 0]
      , rcRemoteAddr = addr
      , rcClose = close
      , rcRelayLimit = Nothing
      }

spec :: Spec
spec = do
  describe "Backoff" $ do
    it "checkBackoff returns Right () when no backoff exists" $ do
      backoffs <- newTVarIO Map.empty
      (pid, _kp) <- mkTestIdentity
      result <- checkBackoff backoffs pid
      result `shouldBe` Right ()

    it "checkBackoff returns Left DialBackoff during active backoff" $ do
      backoffs <- newTVarIO Map.empty
      (pid, _kp) <- mkTestIdentity
      recordBackoff backoffs pid
      result <- checkBackoff backoffs pid
      result `shouldBe` Left DialBackoff

    it "checkBackoff returns Right () after backoff expires" $ do
      backoffs <- newTVarIO Map.empty
      (pid, _kp) <- mkTestIdentity
      -- Manually insert an already-expired backoff entry
      now <- getCurrentTime
      let expired = BackoffEntry
            { beExpiry   = addUTCTime (-1) now  -- 1 second in the past
            , beAttempts = 1
            }
      atomically $ do
        boffs <- readTVar backoffs
        writeTVar backoffs (Map.insert pid expired boffs)
        pure ()
      result <- checkBackoff backoffs pid
      result `shouldBe` Right ()

    it "recordBackoff creates initial ~5s backoff" $ do
      backoffs <- newTVarIO Map.empty
      (pid, _kp) <- mkTestIdentity
      beforeRecord <- getCurrentTime
      recordBackoff backoffs pid
      entry <- atomically $ do
        boffs <- readTVar backoffs
        pure $ Map.lookup pid boffs
      case entry of
        Nothing -> expectationFailure "expected backoff entry"
        Just be -> do
          beAttempts be `shouldBe` 1
          -- Expiry should be approximately now + 5s (within 1s tolerance)
          let diff = diffUTCTime (beExpiry be) beforeRecord
          diff `shouldSatisfy` (\d -> d >= 4 && d <= initialBackoffSeconds + 1)

    it "recordBackoff doubles duration on repeated failures" $ do
      backoffs <- newTVarIO Map.empty
      (pid, _kp) <- mkTestIdentity
      recordBackoff backoffs pid  -- 5s
      recordBackoff backoffs pid  -- 10s
      entry <- atomically $ do
        boffs <- readTVar backoffs
        pure $ Map.lookup pid boffs
      case entry of
        Nothing -> expectationFailure "expected backoff entry"
        Just be -> beAttempts be `shouldBe` 2

    it "recordBackoff caps at maxBackoff (300s)" $ do
      backoffs <- newTVarIO Map.empty
      (pid, _kp) <- mkTestIdentity
      -- Record many times to exceed max
      mapM_ (\_ -> recordBackoff backoffs pid) [1 :: Int .. 20]
      now <- getCurrentTime
      entry <- atomically $ do
        boffs <- readTVar backoffs
        pure $ Map.lookup pid boffs
      case entry of
        Nothing -> expectationFailure "expected backoff entry"
        Just be -> do
          beAttempts be `shouldBe` 20
          let diff = diffUTCTime (beExpiry be) now
          -- Should be capped at 300s (with some tolerance for test execution time)
          diff `shouldSatisfy` (\d -> d <= maxBackoffSeconds + 2)

    it "clearBackoff removes the backoff entry" $ do
      backoffs <- newTVarIO Map.empty
      (pid, _kp) <- mkTestIdentity
      recordBackoff backoffs pid
      clearBackoff backoffs pid
      result <- checkBackoff backoffs pid
      result `shouldBe` Right ()

  describe "Dial" $ do
    it "reuses existing Open connection from pool" $ do
      (localPid, localKP) <- mkTestIdentity
      (remotePid, _remoteKP) <- mkTestIdentity
      sw <- newSwitch localPid localKP
      -- Pre-populate pool with an Open connection
      conn <- mkDummyConnection sw remotePid
      atomically $ addConn (swConnPool sw) conn
      -- Dial should return the existing connection
      result <- dial sw remotePid [testAddr]
      case result of
        Left err -> expectationFailure $ "expected Right, got: " <> show err
        Right c  -> connPeerId c `shouldBe` remotePid

    it "returns DialSwitchClosed when switch is closed" $ do
      (localPid, localKP) <- mkTestIdentity
      (remotePid, _remoteKP) <- mkTestIdentity
      sw <- newSwitch localPid localKP
      switchClose sw
      result <- dial sw remotePid [testAddr]
      case result of
        Left DialSwitchClosed -> pure ()
        Left err -> expectationFailure $ "expected DialSwitchClosed, got: " <> show err
        Right _ -> expectationFailure "expected DialSwitchClosed, got Right"

    it "returns DialNoAddresses when no addresses provided" $ do
      (localPid, localKP) <- mkTestIdentity
      (remotePid, _remoteKP) <- mkTestIdentity
      sw <- newSwitch localPid localKP
      result <- dial sw remotePid []
      case result of
        Left DialNoAddresses -> pure ()
        Left err -> expectationFailure $ "expected DialNoAddresses, got: " <> show err
        Right _ -> expectationFailure "expected DialNoAddresses, got Right"

    it "should dial Identify addresses from peerstore when explicit addresses are empty" $ do
      (localPid, localKP) <- mkTestIdentity
      (remotePid, remoteKP) <- mkTestIdentity
      sw <- newSwitch localPid localKP
      let storedAddr = addrAt 4002
      storeIdentifyAddrs sw remotePid [storedAddr]
      transport <- mkMockDialTransport remoteKP
      addTransport sw transport

      result <- dial sw remotePid []

      case result of
        Left err -> expectationFailure $ "expected peerstore dial to succeed, got: " <> show err
        Right conn -> connRemoteAddr conn `shouldBe` storedAddr

    it "should prefer explicit addresses over peerstore addresses" $ do
      (localPid, localKP) <- mkTestIdentity
      (remotePid, remoteKP) <- mkTestIdentity
      sw <- newSwitch localPid localKP
      storeIdentifyAddrs sw remotePid [addrAt 4002]
      transport <- mkMockDialTransport remoteKP
      addTransport sw transport

      result <- dial sw remotePid [testAddr]

      case result of
        Left err -> expectationFailure $ "expected explicit dial to succeed, got: " <> show err
        Right conn -> connRemoteAddr conn `shouldBe` testAddr

    it "should prefer certified addresses over Identify addresses" $ do
      (localPid, localKP) <- mkTestIdentity
      (remotePid, remoteKP) <- mkTestIdentity
      sw <- newSwitch localPid localKP
      let certifiedAddr = addrAt 4003
      storeIdentifyAddrs sw remotePid [addrAt 4002]
      storeCertifiedAddrs sw remotePid [certifiedAddr]
      transport <- mkMockDialTransport remoteKP
      addTransport sw transport

      result <- dial sw remotePid []

      case result of
        Left err -> expectationFailure $ "expected certified-address dial to succeed, got: " <> show err
        Right conn -> connRemoteAddr conn `shouldBe` certifiedAddr

    it "should return DialNoAddresses when stored addresses are malformed" $ do
      (localPid, localKP) <- mkTestIdentity
      (remotePid, _remoteKP) <- mkTestIdentity
      sw <- newSwitch localPid localKP
      let malformed = IdentifyInfo Nothing Nothing Nothing [BS.pack [0xff]] Nothing [] Nothing
      atomically $ writeTVar (swPeerStore sw) (Map.singleton remotePid malformed)

      result <- dial sw remotePid []

      case result of
        Left DialNoAddresses -> pure ()
        Left err -> expectationFailure $ "expected DialNoAddresses, got: " <> show err
        Right _ -> expectationFailure "expected DialNoAddresses, got Right"

    it "should deduplicate stored addresses before dialing" $ do
      (localPid, localKP) <- mkTestIdentity
      (remotePid, remoteKP) <- mkTestIdentity
      sw <- newSwitch localPid localKP
      storeIdentifyAddrs sw remotePid [testAddr, testAddr]
      counter <- newIORef (0 :: Int)
      transport <- mkCountingMockTransport remoteKP counter
      addTransport sw transport

      result <- dial sw remotePid []

      case result of
        Left err -> expectationFailure $ "expected deduplicated dial to succeed, got: " <> show err
        Right _ -> readIORef counter `shouldReturn` 1

    it "should skip stored addresses matching a local listener" $ do
      (localPid, localKP) <- mkTestIdentity
      (remotePid, remoteKP) <- mkTestIdentity
      sw <- newSwitch localPid localKP
      let remoteAddr = addrAt 4002
      installTestListener sw testAddr
      storeIdentifyAddrs sw remotePid [testAddr, remoteAddr]
      transport <- mkMockDialTransport remoteKP
      addTransport sw transport

      result <- dial sw remotePid []

      case result of
        Left err -> expectationFailure $ "expected non-self dial to succeed, got: " <> show err
        Right conn -> connRemoteAddr conn `shouldBe` remoteAddr
      switchClose sw

    it "should prefer direct stored addresses over relay addresses" $ do
      (localPid, localKP) <- mkTestIdentity
      (remotePid, remoteKP) <- mkTestIdentity
      (relayPid, _relayKP) <- mkTestIdentity
      sw <- newSwitch localPid localKP
      let directAddr = addrAt 4002
      storeIdentifyAddrs sw remotePid [relayAddr relayPid remotePid, directAddr]
      transport <- mkMockDialTransport remoteKP
      addTransport sw transport

      result <- dial sw remotePid []

      case result of
        Left err -> expectationFailure $ "expected direct dial to succeed, got: " <> show err
        Right conn -> connRemoteAddr conn `shouldBe` directAddr

    it "should use relay stored addresses when no direct address exists" $ do
      (localPid, localKP) <- mkTestIdentity
      (remotePid, remoteKP) <- mkTestIdentity
      (relayPid, _relayKP) <- mkTestIdentity
      sw <- newSwitch localPid localKP
      let onlyRelayAddr = relayAddr relayPid remotePid
      storeIdentifyAddrs sw remotePid [onlyRelayAddr]
      transport <- mkMockDialTransport remoteKP
      addTransport sw transport

      result <- dial sw remotePid []

      case result of
        Left err -> expectationFailure $ "expected relay dial to succeed, got: " <> show err
        Right conn -> connRemoteAddr conn `shouldBe` onlyRelayAddr

    it "returns DialNoTransport when no transport matches any address" $ do
      (localPid, localKP) <- mkTestIdentity
      (remotePid, _remoteKP) <- mkTestIdentity
      sw <- newSwitch localPid localKP
      -- No transports registered
      result <- dial sw remotePid [testAddr]
      case result of
        Left (DialNoTransport _) -> pure ()
        Left err -> expectationFailure $ "expected DialNoTransport, got: " <> show err
        Right _ -> expectationFailure "expected DialNoTransport, got Right"

    it "successful dial adds connection to pool" $ do
      (localPid, localKP) <- mkTestIdentity
      (_remotePid, remoteKP) <- mkTestIdentity
      sw <- newSwitch localPid localKP
      transport <- mkMockDialTransport remoteKP
      addTransport sw transport
      result <- dial sw _remotePid [testAddr]
      case result of
        Left err -> expectationFailure $ "expected Right, got: " <> show err
        Right conn -> do
          -- Verify connection is in pool
          poolConn <- atomically $ lookupConn (swConnPool sw) (connPeerId conn)
          case poolConn of
            Nothing -> expectationFailure "connection not found in pool"
            Just _  -> pure ()

    it "should not call transportDial when the outbound address is gated" $ do
      (localPid, localKP) <- mkTestIdentity
      (remotePid, remoteKP) <- mkTestIdentity
      sw <- newSwitch localPid localKP
      counter <- newIORef (0 :: Int)
      addTransport sw =<< mkCountingMockTransport remoteKP counter
      setConnectionGater sw defaultConnectionGater
        { gateDialAddr = \_ -> pure False }

      result <- dial sw remotePid [testAddr]

      result `shouldBeLeft` DialGatedAddress testAddr
      readIORef counter `shouldReturn` 0
      checkBackoff (swDialBackoffs sw) remotePid `shouldReturn` Right ()

    it "should skip a gated address and dial an allowed address" $ do
      (localPid, localKP) <- mkTestIdentity
      (remotePid, remoteKP) <- mkTestIdentity
      sw <- newSwitch localPid localKP
      counter <- newIORef (0 :: Int)
      addTransport sw =<< mkCountingMockTransport remoteKP counter
      let allowedAddr = Multiaddr [IP4 0x7f000001, TCP 4002]
      setConnectionGater sw defaultConnectionGater
        { gateDialAddr = \addr -> pure (addr /= testAddr) }

      result <- dial sw remotePid [testAddr, allowedAddr]

      case result of
        Left err -> expectationFailure $ "expected allowed address to connect: " <> show err
        Right conn -> connRemoteAddr conn `shouldBe` allowedAddr
      readIORef counter `shouldReturn` 1

    it "should close an upgraded connection when the authenticated peer is gated" $ do
      (localPid, localKP) <- mkTestIdentity
      (remotePid, remoteKP) <- mkTestIdentity
      sw <- newSwitch localPid localKP
      closeCount <- newIORef (0 :: Int)
      addTransport sw =<< mkClosingMockTransport remoteKP closeCount
      setConnectionGater sw defaultConnectionGater
        { gateSecured = \_ -> pure False }

      result <- dial sw remotePid [testAddr]

      result `shouldBeLeft` DialGatedPeer remotePid
      readIORef closeCount `shouldReturn` 1
      poolConn <- atomically $ lookupConn (swConnPool sw) remotePid
      case poolConn of
        Nothing -> pure ()
        Just _ -> expectationFailure "gated connection should not enter the pool"
      checkBackoff (swDialBackoffs sw) remotePid `shouldReturn` Right ()

    it "should apply address gating to force-direct DCUtR dials" $ do
      (localPid, localKP) <- mkTestIdentity
      (remotePid, remoteKP) <- mkTestIdentity
      sw <- newSwitch localPid localKP
      counter <- newIORef (0 :: Int)
      addTransport sw =<< mkCountingMockTransport remoteKP counter
      setConnectionGater sw defaultConnectionGater
        { gateDialAddr = \_ -> pure False }
      let opts = defaultDialOpts { doForceDirect = True }

      result <- dialWith sw opts remotePid [testAddr]

      result `shouldBeLeft` DialGatedAddress testAddr
      readIORef counter `shouldReturn` 0

    it "failed dial records backoff" $ do
      (localPid, localKP) <- mkTestIdentity
      (remotePid, _remoteKP) <- mkTestIdentity
      sw <- newSwitch localPid localKP
      transport <- mkFailingTransport
      addTransport sw transport
      result <- dial sw remotePid [testAddr]
      -- Should fail
      case result of
        Right _ -> expectationFailure "expected failure"
        Left _  -> pure ()
      -- Backoff should now be active
      backoffResult <- checkBackoff (swDialBackoffs sw) remotePid
      backoffResult `shouldBe` Left DialBackoff

    it "should close the raw connection and release resources when upgrade fails" $ do
      (localPid, localKP) <- mkTestIdentity
      (remotePid, _remoteKP) <- mkTestIdentity
      sw <- newSwitch localPid localKP
      closeCount <- newIORef (0 :: Int)
      transport <- mkUnupgradableTransport closeCount
      addTransport sw transport

      result <- dial sw remotePid [testAddr]

      case result of
        Left _ -> pure ()
        Right _ -> expectationFailure "expected upgrade to fail"
      readIORef closeCount `shouldReturn` 1
      usage <- atomically $ readTVar (rsUsage (rmSystemScope (swResourceMgr sw)))
      usage `shouldBe` emptyUsage

    it "returns DialPeerIdMismatch when remote identity differs from target" $ do
      (localPid, localKP) <- mkTestIdentity
      (remotePid, _remoteKP) <- mkTestIdentity
      -- Eve's key: the actual responder identity (different from remotePid)
      (_evePid, eveKP) <- mkTestIdentity
      sw <- newSwitch localPid localKP
      -- Transport uses Eve's key, but we dial expecting remotePid
      transport <- mkMockDialTransport eveKP
      addTransport sw transport
      result <- dial sw remotePid [testAddr]
      case result of
        Left (DialPeerIdMismatch expected actual) -> do
          expected `shouldBe` remotePid
          actual `shouldNotBe` remotePid
        Left err -> expectationFailure $ "expected DialPeerIdMismatch, got: " <> show err
        Right _ -> expectationFailure "expected DialPeerIdMismatch, got Right"

    it "concurrent dials to same peer share a single dial operation" $ do
      (localPid, localKP) <- mkTestIdentity
      (_remotePid, remoteKP) <- mkTestIdentity
      sw <- newSwitch localPid localKP
      counter <- newIORef (0 :: Int)
      transport <- mkCountingMockTransport remoteKP counter
      addTransport sw transport
      -- Two concurrent dials to same peer
      (result1, result2) <- concurrently
        (dial sw _remotePid [testAddr])
        (dial sw _remotePid [testAddr])
      -- Both should succeed
      case result1 of
        Left err -> expectationFailure $ "dial 1 failed: " <> show err
        Right _  -> pure ()
      case result2 of
        Left err -> expectationFailure $ "dial 2 failed: " <> show err
        Right _  -> pure ()
      -- Only one actual transport dial should have occurred
      count <- readIORef counter
      count `shouldBe` 1

shouldBeLeft :: (Eq a, Show a) => Either a b -> a -> Expectation
shouldBeLeft result expected = case result of
  Left actual -> actual `shouldBe` expected
  Right _ -> expectationFailure "expected Left, got Right"
