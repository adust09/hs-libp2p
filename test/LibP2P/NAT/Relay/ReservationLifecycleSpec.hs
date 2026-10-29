-- | Tests for relay reservation invalidation on disconnect (issue #255).
--
-- specs/relay/circuit-v2: "the reservation remains valid until its
-- expiration, as long as there is an active connection from the peer to
-- the relay. If the peer disconnects, the reservation is no longer
-- valid."
--
-- The reservation is bound to the peer, not to the connection the
-- RESERVE arrived on, so these tests pin down both halves: a surviving
-- connection keeps the reservation alive, and losing the last one drops
-- it. Teardown is driven by calling 'closeConnection' on the relay's own
-- side of the connection, which runs the disconnect notifiers
-- synchronously and keeps the assertions deterministic.
module LibP2P.NAT.Relay.ReservationLifecycleSpec (spec) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.STM (atomically, modifyTVar', readTVarIO)
import qualified Data.Map.Strict as Map
import LibP2P.Crypto.Ed25519 (generateKeyPair)
import LibP2P.Crypto.Key (KeyPair, publicKey)
import LibP2P.Crypto.PeerId (PeerId, fromPublicKey)
import LibP2P.Multiaddr (Multiaddr (..))
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.MultistreamSelect.Negotiation
  ( NegotiationResult (..)
  , negotiateInitiator
  )
import LibP2P.NAT
  ( NATConfig (..)
  , defaultDCUtRUpgradeConfig
  , defaultNATConfig
  , defaultReservationRefreshConfig
  , registerNATHandlers
  )
import LibP2P.NAT.Relay
  ( ActiveReservation (..)
  , RelayConfig (..)
  , RelayState (..)
  , defaultRelayConfig
  )
import LibP2P.NAT.Relay.Client (makeReservation)
import LibP2P.NAT.Relay.Message (HopMessage (..), RelayStatus (..), hopProtocolId)
import LibP2P.Switch (addTransport, newSwitch, switchClose)
import LibP2P.Switch.ConnPool (lookupAllConns)
import LibP2P.Switch.Connection (closeConnection, newStream)
import LibP2P.Switch.Dial (dial)
import LibP2P.Switch.Listen (defaultConnectionGater, switchListen)
import LibP2P.Switch.Types (Connection (..), Switch (..))
import LibP2P.Switch.Upgrade (upgradeOutbound)
import LibP2P.Transport (Transport (..))
import LibP2P.Transport.TCP (newTCPTransport)
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

-- | A switch with TCP and a listener, used for the relay and its clients.
newListeningSwitch :: IO (Switch, PeerId, [Multiaddr])
newListeningSwitch = do
  (pid, kp) <- mkTestIdentity
  sw <- newSwitch pid kp
  addTransport sw =<< newTCPTransport
  addrs <- switchListen sw defaultConnectionGater [loopbackAddr]
  pure (sw, pid, addrs)

-- | A relay switch with the NAT handlers registered.
newRelaySwitch :: NATConfig -> IO (Switch, PeerId, Multiaddr, RelayState)
newRelaySwitch config = do
  (pid, kp) <- mkTestIdentity
  sw <- newSwitch pid kp
  addTransport sw =<< newTCPTransport
  (relayState, _circuitState, _autoNATService) <- registerNATHandlers sw config
  addrs <- switchListen sw defaultConnectionGater [loopbackAddr]
  case addrs of
    (a : _) -> pure (sw, pid, a, relayState)
    []      -> fail "relay did not bind a listen address"

-- | Send RESERVE to the relay over an existing connection and return the
-- status the relay replied with.
reserveOn :: Switch -> Connection -> IO (Maybe RelayStatus)
reserveOn sw conn = do
  stream <- newStream sw conn >>= either (fail . show) pure
  negotiated <- negotiateInitiator stream [hopProtocolId]
  case negotiated of
    NoProtocol -> fail "relay does not support the hop protocol"
    Accepted _ -> hopStatus <$> (makeReservation stream >>= either fail pure)

-- | Poll the relay's pool until it holds at least @n@ connections for the
-- peer. Inbound connections are admitted on the accept-loop thread, so a
-- dial returning does not yet mean the relay has pooled its side.
waitForConns :: Switch -> PeerId -> Int -> IO [Connection]
waitForConns sw pid n = go (200 :: Int)
  where
    go 0 = fail $ "relay never pooled " ++ show n ++ " connection(s) for the peer"
    go k = do
      conns <- atomically $ lookupAllConns (swConnPool sw) pid
      if length conns >= n
        then pure conns
        else threadDelay 10000 >> go (k - 1)

-- | Open a second connection to the relay, bypassing the pool.
-- 'LibP2P.Switch.Dial.dial' would return the existing pooled connection,
-- so the raw transport dial and the outbound upgrade are driven directly.
-- Only the relay's view matters here, and the relay pools its own side
-- through the normal accept path.
openSecondConnection :: Switch -> Multiaddr -> IO ()
openSecondConnection sw addr = do
  transport <- newTCPTransport
  rawConn <- transportDial transport addr
  _conn <- upgradeOutbound (swResourceMgr sw) (swIdentityKey sw) rawConn
  pure ()

reservedPeers :: RelayState -> IO [PeerId]
reservedPeers relayState = Map.keys <$> readTVarIO (rsReservations relayState)

spec :: Spec
spec = describe "relay reservation lifecycle" $ do
  it "drops the reservation when the reserving peer's last connection closes" $ do
    (swR, pidR, addrR, relayState) <- newRelaySwitch defaultNATConfig
    (swC, pidC, _) <- newListeningSwitch
    connCR <- dial swC pidR [addrR] >>= either (fail . show) pure
    status <- reserveOn swC connCR
    status `shouldBe` Just RelayOK
    reservedPeers relayState `shouldReturn` [pidC]
    -- Tear down the relay's own side of the connection: the notifier runs
    -- synchronously, so no polling is needed for the assertion.
    relayConns <- waitForConns swR pidC 1
    mapM_ (closeConnection swR) relayConns
    reservedPeers relayState `shouldReturn` []
    switchClose swC
    switchClose swR

  it "frees the reservation slot for another peer without waiting for expiry" $ do
    let config = defaultNATConfig
          { ncRelayConfig = defaultRelayConfig { rcMaxReservations = 1 }
          , ncReservationRefresh = defaultReservationRefreshConfig
          , ncDCUtRUpgrade = defaultDCUtRUpgradeConfig
          }
    (swR, pidR, addrR, relayState) <- newRelaySwitch config
    (swC1, pidC1, _) <- newListeningSwitch
    (swC2, _pidC2, _) <- newListeningSwitch
    conn1 <- dial swC1 pidR [addrR] >>= either (fail . show) pure
    reserveOn swC1 conn1 `shouldReturn` Just RelayOK
    -- The relay is now at capacity
    conn2 <- dial swC2 pidR [addrR] >>= either (fail . show) pure
    reserveOn swC2 conn2 `shouldReturn` Just ReservationRefused
    -- Disconnecting the holder must free the slot immediately
    relayConns <- waitForConns swR pidC1 1
    mapM_ (closeConnection swR) relayConns
    reservedPeers relayState `shouldReturn` []
    reserveOn swC2 conn2 `shouldReturn` Just RelayOK
    switchClose swC1
    switchClose swC2
    switchClose swR

  it "keeps the reservation while another connection to the same peer remains" $ do
    (swR, pidR, addrR, relayState) <- newRelaySwitch defaultNATConfig
    (swC, pidC, _) <- newListeningSwitch
    connCR <- dial swC pidR [addrR] >>= either (fail . show) pure
    reserveOn swC connCR `shouldReturn` Just RelayOK
    -- A second, independent connection from the same peer. Switch.dial
    -- would hand back the pooled one, so this goes straight through the
    -- transport and the upgrade pipeline; the relay accepts it as a
    -- second inbound connection for pidC.
    openSecondConnection swC addrR
    relayConns <- waitForConns swR pidC 2
    case relayConns of
      (first' : rest@(_ : _)) -> do
        -- Losing one connection must not invalidate the reservation
        closeConnection swR first'
        reservedPeers relayState `shouldReturn` [pidC]
        -- Losing the last one must
        mapM_ (closeConnection swR) rest
        reservedPeers relayState `shouldReturn` []
      _ -> expectationFailure "expected two pooled connections for the peer"
    switchClose swC
    switchClose swR

  it "is a no-op when the disconnecting peer holds no reservation" $ do
    (swR, pidR, addrR, relayState) <- newRelaySwitch defaultNATConfig
    (swHolder, pidHolder, _) <- newListeningSwitch
    (swPlain, pidPlain, _) <- newListeningSwitch
    connHolder <- dial swHolder pidR [addrR] >>= either (fail . show) pure
    reserveOn swHolder connHolder `shouldReturn` Just RelayOK
    _ <- dial swPlain pidR [addrR] >>= either (fail . show) pure
    plainConns <- waitForConns swR pidPlain 1
    mapM_ (closeConnection swR) plainConns
    -- The unrelated holder's reservation is untouched
    reservedPeers relayState `shouldReturn` [pidHolder]
    switchClose swHolder
    switchClose swPlain
    switchClose swR

  it "does not run the cleanup twice for the same connection" $ do
    (swR, pidR, addrR, relayState) <- newRelaySwitch defaultNATConfig
    (swC, pidC, _) <- newListeningSwitch
    connCR <- dial swC pidR [addrR] >>= either (fail . show) pure
    reserveOn swC connCR `shouldReturn` Just RelayOK
    relayConns <- waitForConns swR pidC 1
    mapM_ (closeConnection swR) relayConns
    reservedPeers relayState `shouldReturn` []
    -- Re-arm a reservation, then tear the same connections down again.
    -- closeConnection is idempotent, so the notifier must not fire a
    -- second time and must not remove the new reservation.
    let rearmed = ActiveReservation { arPeerId = pidC, arExpiration = maxBound }
    atomically $ modifyTVar' (rsReservations relayState) (Map.insert pidC rearmed)
    mapM_ (closeConnection swR) relayConns
    reservedPeers relayState `shouldReturn` [pidC]
    switchClose swC
    switchClose swR
