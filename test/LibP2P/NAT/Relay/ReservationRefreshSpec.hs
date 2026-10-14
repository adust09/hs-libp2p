-- | Tests for client-side reservation refresh (issue #268).
--
-- specs/relay/circuit-v2: "the `expire` field contains the expiration
-- time as a UTC UNIX time in seconds. The reservation becomes invalid
-- after this time and it's the responsibility of the client to
-- refresh." and: "the reservation remains valid until its expiration,
-- as long as there is an active connection from the peer to the relay
-- ... if the peer disconnects, the reservation is no longer valid."
--
-- Three behaviours are pinned down: a reservation nearing expiry is
-- refreshed in the background and the relay keeps routing to the
-- client; losing the connection to the relay withdraws the circuit
-- listen address immediately (driven deterministically via
-- 'closeConnection', following 'ReservationLifecycleSpec'); and a relay
-- that refuses a refresh also withdraws the listen address, without
-- affecting anything else.
module LibP2P.NAT.Relay.ReservationRefreshSpec (spec) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.STM (atomically)
import Data.IORef (IORef, atomicModifyIORef', newIORef)
import Data.Time.Clock.POSIX (getPOSIXTime)
import LibP2P.Crypto.Ed25519 (generateKeyPair)
import LibP2P.Crypto.Key (KeyPair, publicKey)
import LibP2P.Crypto.PeerId (PeerId, fromPublicKey, peerIdBytes)
import LibP2P.Multiaddr (Multiaddr (..))
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.MultistreamSelect.Negotiation (StreamIO (..))
import LibP2P.NAT
  ( NATConfig (..)
  , defaultDCUtRUpgradeConfig
  , ReservationRefreshConfig (..)
  , defaultNATConfig
  , registerNATHandlers
  )
import LibP2P.NAT.Relay (RelayConfig (..), defaultRelayConfig)
import LibP2P.NAT.Relay.Message
  ( HopMessage (..)
  , HopMessageType (..)
  , RelayStatus (..)
  , Reservation (..)
  , hopProtocolId
  , maxRelayMessageSize
  , readHopMessage
  , writeHopMessage
  )
import LibP2P.NAT.Relay.Transport
  ( circuitTransport
  , newCircuitState
  )
import LibP2P.Protocol.Ping (openPingSession, ping, registerPingHandler)
import LibP2P.Switch (addTransport, newSwitch, setStreamHandler, switchClose)
import LibP2P.Switch.ConnPool (lookupAllConns)
import LibP2P.Switch.Connection (closeConnection)
import LibP2P.Switch.Dial (dial)
import LibP2P.Switch.Listen (defaultConnectionGater, switchListen, switchListenAddrs)
import LibP2P.Switch.Types (Connection (..), Switch (..))
import LibP2P.Switch.Upgrade (upgradeOutbound)
import LibP2P.Transport (Transport (..))
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

-- | Append @\/p2p\/\<relay\>\/p2p-circuit@ (and optionally the target) to
-- a transport address.
withCircuit :: Multiaddr -> PeerId -> Maybe PeerId -> Multiaddr
withCircuit (Multiaddr comps) relayId mTarget =
  Multiaddr (comps ++ [P2P (peerIdBytes relayId), P2PCircuit] ++ target)
  where
    target = maybe [] (\t -> [P2P (peerIdBytes t)]) mTarget

-- | Poll a condition every 50ms until it holds or a bounded number of
-- attempts is exhausted. Used instead of a single fixed sleep so tests
-- run as fast as the background refresh loop allows.
waitUntil :: String -> IO Bool -> IO ()
waitUntil label check = go (100 :: Int)
  where
    go 0 = expectationFailure ("timed out waiting for: " ++ label)
    go n = do
      ok <- check
      if ok then pure () else threadDelay 50000 >> go (n - 1)

-- | Aggressive refresh tuning so tests exercise real background refresh
-- behaviour without waiting anywhere near go-libp2p's real-world
-- defaults (a 2 minute margin polled every minute).
fastRefreshConfig :: ReservationRefreshConfig
fastRefreshConfig = ReservationRefreshConfig
  { rrcMargin       = 1        -- refresh once within 1 second of expiry
  , rrcPollInterval = 100000   -- check every 100ms
  }

-- | Poll the pool until it holds at least @n@ connections for the peer.
waitForConns :: Switch -> PeerId -> Int -> IO [Connection]
waitForConns sw pid n = go (200 :: Int)
  where
    go 0 = fail $ "never pooled " ++ show n ++ " connection(s) for the peer"
    go k = do
      conns <- atomically $ lookupAllConns (swConnPool sw) pid
      if length conns >= n
        then pure conns
        else threadDelay 10000 >> go (k - 1)

spec :: Spec
spec = describe "circuit relay reservation refresh" $ do
  it "refreshes a reservation nearing expiry and keeps the relay routing to the client" $ do
    -- Relay grants a short-lived reservation so the test doesn't have to
    -- wait anywhere near a real-world expiry to see a refresh happen.
    let relayConfig = defaultRelayConfig { rcReservationDuration = 2 }
        natConfig = NATConfig
          { ncRelayConfig        = relayConfig
          , ncReservationRefresh = fastRefreshConfig
              , ncDCUtRUpgrade = defaultDCUtRUpgradeConfig
          }
    -- Relay R
    (pidR, kpR) <- mkTestIdentity
    swR <- newSwitch pidR kpR
    addTransport swR =<< newTCPTransport
    _ <- registerNATHandlers swR natConfig
    addrsR <- switchListen swR defaultConnectionGater [loopbackAddr]
    relayAddr <- case addrsR of
      (a : _) -> pure a
      []      -> fail "relay did not bind a listen address"
    -- Target B: reserves on R with the short-lived config and answers pings
    (pidB, kpB) <- mkTestIdentity
    swB <- newSwitch pidB kpB
    addTransport swB =<< newTCPTransport
    _ <- registerNATHandlers swB natConfig
    registerPingHandler swB
    _ <- switchListen swB defaultConnectionGater [withCircuit relayAddr pidR Nothing]
    -- Dialer A
    (pidA, kpA) <- mkTestIdentity
    swA <- newSwitch pidA kpA
    addTransport swA =<< newTCPTransport
    _ <- registerNATHandlers swA natConfig
    threadDelay 300000

    -- Wait well past the original 2 second expiry. Without a refresh the
    -- relay would have dropped B's reservation and CONNECT would fail.
    threadDelay 3500000
    let dialAddr = withCircuit relayAddr pidR (Just pidB)
    result <- timeout 20000000 $ do
      conn <- dial swA pidB [dialAddr] >>= either (fail . show) pure
      session <- openPingSession swA conn >>= either (fail . show) pure
      ping session
    case result of
      Nothing -> expectationFailure "ping through the relay timed out after the original expiry"
      Just (Left err) -> expectationFailure $ "ping through the relay failed: " ++ show err
      Just (Right _) -> pure ()

    switchClose swA
    switchClose swB
    switchClose swR

  it "withdraws the circuit listen address when the connection to the relay is lost" $ do
    let natConfig = defaultNATConfig { ncReservationRefresh = fastRefreshConfig
              , ncDCUtRUpgrade = defaultDCUtRUpgradeConfig }
    -- Relay R
    (pidR, kpR) <- mkTestIdentity
    swR <- newSwitch pidR kpR
    addTransport swR =<< newTCPTransport
    _ <- registerNATHandlers swR natConfig
    addrsR <- switchListen swR defaultConnectionGater [loopbackAddr]
    relayAddr <- case addrsR of
      (a : _) -> pure a
      []      -> fail "relay did not bind a listen address"
    -- Target B
    (pidB, kpB) <- mkTestIdentity
    swB <- newSwitch pidB kpB
    addTransport swB =<< newTCPTransport
    _ <- registerNATHandlers swB natConfig
    addrsB <- switchListen swB defaultConnectionGater [withCircuit relayAddr pidR Nothing]
    addrsB `shouldSatisfy` (not . null)
    switchListenAddrs swB `shouldReturn` addrsB

    -- Tear down B's own side of its connection to the relay: the
    -- disconnect notifier runs synchronously inside 'closeConnection',
    -- so the withdrawal is deterministic and needs no polling.
    bConns <- atomically $ lookupAllConns (swConnPool swB) pidR
    null bConns `shouldBe` False
    mapM_ (closeConnection swB) bConns

    remaining <- switchListenAddrs swB
    remaining `shouldBe` []

    switchClose swB
    switchClose swR

  it "keeps the circuit listen address while another connection to the relay remains" $ do
    -- The reservation is bound to the relay peer, not to the connection
    -- the RESERVE went out on, matching go-libp2p's relay_finder, which
    -- drops a reservation only once Connectedness reaches NotConnected.
    let natConfig = defaultNATConfig { ncReservationRefresh = fastRefreshConfig
              , ncDCUtRUpgrade = defaultDCUtRUpgradeConfig }
    (pidR, kpR) <- mkTestIdentity
    swR <- newSwitch pidR kpR
    addTransport swR =<< newTCPTransport
    _ <- registerNATHandlers swR natConfig
    addrsR <- switchListen swR defaultConnectionGater [loopbackAddr]
    relayAddr <- case addrsR of
      (a : _) -> pure a
      []      -> fail "relay did not bind a listen address"
    -- B listens on TCP as well, so the relay can dial it back and give B
    -- a second, independent connection to the same peer.
    (pidB, kpB) <- mkTestIdentity
    swB <- newSwitch pidB kpB
    addTransport swB =<< newTCPTransport
    _ <- registerNATHandlers swB natConfig
    tcpAddrsB <- switchListen swB defaultConnectionGater [loopbackAddr]
    addrB <- case tcpAddrsB of
      (a : _) -> pure a
      []      -> fail "client did not bind a listen address"
    circuitAddrsB <- switchListen swB defaultConnectionGater
                       [withCircuit relayAddr pidR Nothing]
    circuitAddrsB `shouldSatisfy` (not . null)
    -- Switch.dial on the relay would hand back the connection B already
    -- made, so drive the transport and the upgrade directly with the
    -- relay's identity. B's accept path pools it as a second inbound
    -- connection whose peer is the relay.
    transport <- newTCPTransport
    rawConn <- transportDial transport addrB
    _second <- upgradeOutbound (swResourceMgr swR) (swIdentityKey swR) rawConn
    bConns <- waitForConns swB pidR 2
    case bConns of
      (first' : rest@(_ : _)) -> do
        -- Losing one connection must not withdraw the circuit address
        closeConnection swB first'
        switchListenAddrs swB `shouldReturn` (tcpAddrsB ++ circuitAddrsB)
        -- Losing the last one must, and must leave the TCP listener alone
        mapM_ (closeConnection swB) rest
        switchListenAddrs swB `shouldReturn` tcpAddrsB
      _ -> expectationFailure "expected two pooled connections to the relay"
    switchClose swB
    switchClose swR

  it "withdraws the circuit listen address when the relay refuses a refresh, without affecting other connections" $ do
    -- A fake relay that grants the first RESERVE (with a short expiry so
    -- the refresh loop acts quickly) and refuses every subsequent one,
    -- simulating a relay that can no longer honour the reservation.
    (pidR, kpR) <- mkTestIdentity
    swR <- newSwitch pidR kpR
    addTransport swR =<< newTCPTransport
    reserveCount <- newIORef (0 :: Int)
    setStreamHandler swR hopProtocolId (fakeHopHandler reserveCount)
    addrsR <- switchListen swR defaultConnectionGater [loopbackAddr]
    relayAddr <- case addrsR of
      (a : _) -> pure a
      []      -> fail "fake relay did not bind a listen address"

    -- Target B: the circuit client transport pointed at the fake relay,
    -- plus a plain TCP listener and ping so an unrelated connection into
    -- B can be checked before and after the withdrawal.
    (pidB, kpB) <- mkTestIdentity
    (pidC, kpC) <- mkTestIdentity
    swB <- newSwitch pidB kpB
    addTransport swB =<< newTCPTransport
    circuitState <- newCircuitState
    addTransport swB (circuitTransport swB circuitState fastRefreshConfig)
    registerPingHandler swB
    addrsBPlain <- switchListen swB defaultConnectionGater [loopbackAddr]
    plainAddr <- case addrsBPlain of
      (a : _) -> pure a
      []      -> fail "target did not bind its plain listen address"
    addrsBCircuit <- switchListen swB defaultConnectionGater [withCircuit relayAddr pidR Nothing]
    circuitAddr <- case addrsBCircuit of
      (a : _) -> pure a
      []      -> fail "target did not bind its circuit listen address"

    -- An unrelated connection into B over the plain address.
    swC <- newSwitch pidC kpC
    addTransport swC =<< newTCPTransport
    connCB <- dial swC pidB [plainAddr] >>= either (fail . show) pure
    sessionBefore <- openPingSession swC connCB >>= either (fail . show) pure
    _ <- ping sessionBefore >>= either (fail . show) pure

    waitUntil "circuit listen address withdrawn after refused refresh" $ do
      remaining <- switchListenAddrs swB
      pure (circuitAddr `notElem` remaining)

    -- The plain listener and the unrelated connection are untouched.
    remainingAfter <- switchListenAddrs swB
    remainingAfter `shouldBe` [plainAddr]
    sessionAfter <- openPingSession swC connCB >>= either (fail . show) pure
    _ <- ping sessionAfter >>= either (fail . show) pure

    switchClose swB
    switchClose swC
    switchClose swR

-- | Hop protocol handler for a relay double that grants exactly one
-- RESERVE (with a 2 second expiry, so the refresh loop's poll interval
-- observes it well within the test's patience) and refuses every
-- subsequent RESERVE, simulating a relay refusing a refresh.
fakeHopHandler :: IORef Int -> Connection -> StreamIO -> IO ()
fakeHopHandler counterRef _conn stream = do
  result <- readHopMessage stream maxRelayMessageSize
  case result of
    Left _ -> pure ()
    Right msg -> case hopType msg of
      Just HopReserve -> do
        n <- atomicModifyIORef' counterRef (\k -> (k + 1, k))
        if n == 0
          then do
            now <- getPOSIXTime
            writeHopMessage stream HopMessage
              { hopType = Just HopStatus
              , hopPeer = Nothing
              , hopReservation = Just Reservation
                  { rsvExpire = Just (floor now + 2)
                  , rsvAddrs = []
                  , rsvVoucher = Nothing
                  }
              , hopLimit = Nothing
              , hopStatus = Just RelayOK
              }
          else writeHopMessage stream HopMessage
              { hopType = Just HopStatus
              , hopPeer = Nothing
              , hopReservation = Nothing
              , hopLimit = Nothing
              , hopStatus = Just ReservationRefused
              }
      _ -> pure ()
