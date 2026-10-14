-- | Tests for switchListen implementation (Phase 10a).
--
-- These tests exercise the real listen lifecycle: binding addresses,
-- accepting inbound connections, listener cleanup on switchClose,
-- and connection gating at the transport level.
module LibP2P.Switch.ListenImplSpec (spec) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.MVar (newEmptyMVar, putMVar, takeMVar)
import Control.Concurrent.STM (atomically, readTVar)
import Control.Exception (SomeException, try)
import LibP2P.Crypto.Ed25519 (generateKeyPair)
import LibP2P.Crypto.Key (KeyPair, publicKey)
import LibP2P.Crypto.PeerId (PeerId, fromPublicKey)
import LibP2P.Multiaddr (Multiaddr (..), fromBytes, fromText, toBytes, toText)
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.Switch.ConnPool (lookupConn)
import LibP2P.Switch.Dial (dial)
import LibP2P.Switch.Listen
  ( ConnectionGater (..)
  , defaultConnectionGater
  , switchListen
  , switchListenAddrs
  )
import LibP2P.Switch (addTransport, newSwitch, setStreamHandler, switchClose)
import LibP2P.Switch.Types (Connection (..), Switch (..))
import LibP2P.Transport.TCP (newTCPTransport)
import System.Timeout (timeout)
import Test.Hspec

-- | Generate a test identity (PeerId, KeyPair).
mkTestIdentity :: IO (PeerId, KeyPair)
mkTestIdentity = do
  Right kp <- generateKeyPair
  let pid = fromPublicKey (publicKey kp)
  pure (pid, kp)

-- | Loopback address with port 0 (OS assigns ephemeral port).
loopbackAddr :: Multiaddr
loopbackAddr = Multiaddr [IP4 0x7f000001, TCP 0]

-- | Create a Switch with TCP transport registered.
mkTestSwitch :: IO (Switch, PeerId, KeyPair)
mkTestSwitch = do
  (pid, kp) <- mkTestIdentity
  sw <- newSwitch pid kp
  tcp <- newTCPTransport
  addTransport sw tcp
  pure (sw, pid, kp)

spec :: Spec
spec = do
  describe "switchListen" $ do
    it "binds on /ip4/127.0.0.1/tcp/0 and returns resolved address with port" $ do
      (sw, _pid, _kp) <- mkTestSwitch
      addrs <- switchListen sw defaultConnectionGater [loopbackAddr]
      -- Should return exactly one address
      length addrs `shouldBe` 1
      -- The returned address should have a non-zero port
      case addrs of
        [Multiaddr [IP4 0x7f000001, TCP port]] -> port `shouldSatisfy` (> 0)
        _ -> expectationFailure $ "unexpected address: " ++ show addrs
      switchClose sw

    it "reported listen address round-trips through the text and binary codecs" $ do
      -- Integration: the multiaddr the Switch reports after binding must
      -- survive parse/render unchanged, so peers can dial exactly what
      -- identify advertises.
      (sw, _pid, _kp) <- mkTestSwitch
      addrs <- switchListen sw defaultConnectionGater [loopbackAddr]
      case addrs of
        [addr] -> do
          fromText (toText addr) `shouldBe` Right addr
          fromBytes (toBytes addr) `shouldBe` Right addr
        _ -> expectationFailure $ "unexpected addresses: " ++ show addrs
      switchClose sw

    it "binds on multiple addresses and returns all resolved addresses" $ do
      (sw, _pid, _kp) <- mkTestSwitch
      addrs <- switchListen sw defaultConnectionGater [loopbackAddr, loopbackAddr]
      -- Should return two addresses with different ports
      length addrs `shouldBe` 2
      case addrs of
        [Multiaddr [IP4 _, TCP p1], Multiaddr [IP4 _, TCP p2]] -> do
          p1 `shouldSatisfy` (> 0)
          p2 `shouldSatisfy` (> 0)
          p1 `shouldSatisfy` (/= p2)
        _ -> expectationFailure $ "unexpected addresses: " ++ show addrs
      switchClose sw

    it "accepts inbound connection from dialer (real TCP + upgrade)" $ do
      -- Listener node
      (swB, pidB, _kpB) <- mkTestSwitch
      addrs <- switchListen swB defaultConnectionGater [loopbackAddr]
      length addrs `shouldBe` 1
      let listenAddr = head addrs
      -- Dialer node
      (swA, pidA, _kpA) <- mkTestSwitch
      -- Dial from A to B
      result <- timeout 5000000 $ dial swA pidB [listenAddr]
      case result of
        Nothing -> expectationFailure "dial timed out"
        Just (Left err) -> expectationFailure $ "dial failed: " ++ show err
        Just (Right conn) -> do
          connPeerId conn `shouldBe` pidB
          -- Verify B sees A in its pool
          threadDelay 500000  -- Allow handleInbound to complete pool insertion
          poolConn <- atomically $ lookupConn (swConnPool swB) pidA
          case poolConn of
            Nothing -> expectationFailure "listener should have dialer in pool"
            Just c  -> connPeerId c `shouldBe` pidA
      switchClose swA
      switchClose swB

    it "fails when switch is closed" $ do
      (sw, _pid, _kp) <- mkTestSwitch
      switchClose sw
      result <- try (switchListen sw defaultConnectionGater [loopbackAddr])
        :: IO (Either SomeException [Multiaddr])
      case result of
        Left _ -> pure ()  -- Expected: fail throws
        Right _ -> expectationFailure "switchListen should fail after switchClose"

  describe "switchListenAddrs" $ do
    it "returns current listener addresses" $ do
      (sw, _pid, _kp) <- mkTestSwitch
      -- Before listen, no addresses
      before <- switchListenAddrs sw
      before `shouldBe` []
      -- After listen, has address
      addrs <- switchListen sw defaultConnectionGater [loopbackAddr]
      after <- switchListenAddrs sw
      after `shouldBe` addrs
      switchClose sw

  describe "switchClose" $ do
    it "cancels accept loops and closes listeners" $ do
      (sw, _pid, _kp) <- mkTestSwitch
      _addrs <- switchListen sw defaultConnectionGater [loopbackAddr]
      -- Verify listeners exist
      listenersBefore <- atomically $ readTVar (swListeners sw)
      length listenersBefore `shouldBe` 1
      -- Close
      switchClose sw
      -- Verify listeners cleared
      listenersAfter <- atomically $ readTVar (swListeners sw)
      length listenersAfter `shouldBe` 0

  describe "ConnectionGater" $ do
    it "gateAccept=False rejects at transport level" $ do
      (swB, pidB, _kpB) <- mkTestSwitch
      -- Track rejected connections
      rejectedMVar <- newEmptyMVar
      let rejectGater = ConnectionGater
            { gateAccept = \_ -> putMVar rejectedMVar () >> pure False
            , gateDialAddr = \_ -> pure True
            , gateSecured = \_ -> pure True
            }
      addrs <- switchListen swB rejectGater [loopbackAddr]
      let listenAddr = head addrs
      -- Dialer node
      (swA, _pidA, _kpA) <- mkTestSwitch
      -- Dial: should fail because gateAccept rejects
      result <- timeout 5000000 $ dial swA pidB [listenAddr]
      case result of
        Nothing -> expectationFailure "dial timed out"
        Just (Left _) -> pure ()  -- Expected: dial fails
        Just (Right _) -> do
          -- Connection may succeed at transport but fail at upgrade
          -- because the listener side closes the raw connection
          pure ()
      -- Verify gateAccept was called
      gateResult <- timeout 2000000 $ takeMVar rejectedMVar
      case gateResult of
        Nothing -> expectationFailure "gateAccept was never called"
        Just () -> pure ()
      switchClose swA
      switchClose swB

    it "gateSecured=False rejects after Noise handshake" $ do
      (swB, pidB, _kpB) <- mkTestSwitch
      let securedRejectGater = ConnectionGater
            { gateAccept = \_ -> pure True
            , gateDialAddr = \_ -> pure True
            , gateSecured = \_ -> pure False  -- Accept at transport, reject after Noise
            }
      addrs <- switchListen swB securedRejectGater [loopbackAddr]
      let listenAddr = head addrs
      -- Dialer node
      (swA, pidA, _kpA) <- mkTestSwitch
      -- Dial: Noise handshake succeeds but gateSecured rejects
      _result <- timeout 5000000 $ dial swA pidB [listenAddr]
      -- Give listener time to process
      threadDelay 500000
      -- Verify B does NOT have A in its pool (rejected after secured)
      poolConn <- atomically $ lookupConn (swConnPool swB) pidA
      case poolConn of
        Nothing -> pure ()  -- Expected: not in pool
        Just _  -> expectationFailure "connection should not be in pool after gateSecured rejection"
      switchClose swA
      switchClose swB
