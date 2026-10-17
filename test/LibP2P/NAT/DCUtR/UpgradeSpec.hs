-- | Tests for the DCUtR production integration (issue #258).
--
-- Real switches over loopback TCP. A genuine NAT hole punch is out of
-- reach in-process, so these pin down the parts that were wrong or
-- missing: that the dial no longer hands back the pooled relay
-- connection, that the resulting direct connection takes the roles the
-- spec assigns, that connection selection migrates to it, and that the
-- relay is released only once the direct connection has proved itself.
-- End-to-end hole punching against a real NAT is issue #131.
module LibP2P.NAT.DCUtR.UpgradeSpec (spec) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.Async (concurrently)
import Control.Concurrent.STM (atomically, modifyTVar', readTVarIO)
import Data.Maybe (isNothing)
import qualified Data.Map.Strict as Map
import LibP2P.Crypto.Ed25519 (generateKeyPair)
import LibP2P.Crypto.Key (KeyPair, publicKey)
import LibP2P.Crypto.PeerId (PeerId, fromPublicKey, peerIdBytes)
import LibP2P.Multiaddr (Multiaddr (..), isRelayedAddr, toBytes)
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.MultistreamSelect.Negotiation (StreamIO (..), mkMemoryStreamPair)
import LibP2P.NAT
  ( DCUtRUpgradeConfig (..)
  , NATConfig (..)
  , defaultDCUtRUpgradeConfig
  , defaultNATConfig
  , dcutrOwnAddrs
  , holePunchTargets
  , registerNATHandlers
  , upgradeRelayedConnection
  )
import LibP2P.Protocol.Identify.Message (IdentifyInfo (..))
import LibP2P.NAT.DCUtR (DCUtRResult (..))
import LibP2P.Protocol.Identify (registerIdentifyHandlers)
import LibP2P.Protocol.Ping (registerPingHandler)
import LibP2P.Switch (addTransport, newSwitch, switchClose)
import LibP2P.Switch.ConnPool (lookupAllConns, lookupConn)
import LibP2P.Switch.Dial (DialOpts (..), defaultDialOpts, dialWith)
import LibP2P.Switch.Listen (defaultConnectionGater, switchListen, switchListenAddrs)
import LibP2P.Switch.Types
  ( ConnState (..)
  , Connection (..)
  , Direction (..)
  , MuxerSession (..)
  , Switch (..)
  )
import LibP2P.Switch.ResourceManager
  ( DefaultLimits (..)
  , newResourceManager
  , noLimits
  , unlimitedMemoryAccount
  )
import LibP2P.Switch.Upgrade (readExact)
import qualified LibP2P.Switch.Upgrade as Upgrade
import LibP2P.Transport (ConnectionEndpoint (..), RawConnection (..))
import LibP2P.Transport.TCP (newTCPTransport)
import System.Timeout (timeout)
import Test.Hspec

mkTestIdentity :: IO (PeerId, KeyPair)
mkTestIdentity = do
  Right kp <- generateKeyPair
  let pid = fromPublicKey (publicKey kp)
  pure (pid, kp)

loopbackAddr :: Multiaddr
loopbackAddr = Multiaddr [IP4 0x7f000001, TCP 0]

withCircuit :: Multiaddr -> PeerId -> Maybe PeerId -> Multiaddr
withCircuit (Multiaddr comps) relayId mTarget =
  Multiaddr (comps ++ [P2P (peerIdBytes relayId), P2PCircuit] ++ target)
  where
    target = maybe [] (\t -> [P2P (peerIdBytes t)]) mTarget

firstAddr :: [Multiaddr] -> IO Multiaddr
firstAddr (a : _) = pure a
firstAddr []      = fail "switch did not bind a listen address"

-- | A fully wired node: TCP, NAT handlers, identify and ping.
newNode :: NATConfig -> IO (Switch, PeerId)
newNode config = do
  (pid, kp) <- mkTestIdentity
  sw <- newSwitch pid kp
  addTransport sw =<< newTCPTransport
  _ <- registerNATHandlers sw config
  registerIdentifyHandlers sw
  registerPingHandler sw
  pure (sw, pid)

-- | Relay R, target B reserving on R, and dialer A, all on loopback.
-- Returns the relay address and each node, with A already connected to B
-- through the circuit.
data Circuit = Circuit
  { cRelaySw   :: !Switch
  , cRelayId   :: !PeerId
  , cRelayAddr :: !Multiaddr
  , cTargetSw  :: !Switch
  , cTargetId  :: !PeerId
  , cDialerSw  :: !Switch
  , cDialerId  :: !PeerId
  , cRelayed   :: !Connection   -- ^ A's relayed connection to B
  }

withCircuitTrio :: NATConfig -> (Circuit -> IO a) -> IO a
withCircuitTrio config action = do
  (swR, pidR) <- newNode config
  addrsR <- switchListen swR defaultConnectionGater [loopbackAddr]
  relayAddr <- firstAddr addrsR
  (swB, pidB) <- newNode config
  _ <- switchListen swB defaultConnectionGater [loopbackAddr]
  _ <- switchListen swB defaultConnectionGater [withCircuit relayAddr pidR Nothing]
  (swA, pidA) <- newNode config
  _ <- switchListen swA defaultConnectionGater [loopbackAddr]
  relayed <- timeout 20000000 (dialWith swA defaultDialOpts pidB
               [withCircuit relayAddr pidR (Just pidB)])
  conn <- case relayed of
    Nothing -> fail "circuit dial timed out"
    Just (Left err) -> fail ("circuit dial failed: " ++ show err)
    Just (Right c) -> pure c
  threadDelay 500000
  result <- action Circuit
    { cRelaySw = swR, cRelayId = pidR, cRelayAddr = relayAddr
    , cTargetSw = swB, cTargetId = pidB
    , cDialerSw = swA, cDialerId = pidA
    , cRelayed = conn
    }
  switchClose swA
  switchClose swB
  switchClose swR
  pure result

-- | All Open connections a switch holds for a peer, split by transport.
connsFor :: Switch -> PeerId -> IO ([Connection], [Connection])
connsFor sw pid = do
  conns <- atomically $ lookupAllConns (swConnPool sw) pid
  open <- mapM (\c -> (,) c <$> readTVarIO (connState c)) conns
  let live = [c | (c, st) <- open, st == ConnOpen]
  pure ( filter (not . isRelayedAddr . connRemoteAddr) live
       , filter (isRelayedAddr . connRemoteAddr) live )

spec :: Spec
spec = do
  describe "force-direct dial" $ do
    it "establishes a new connection instead of returning the pooled relay one" $
      withCircuitTrio noPunchConfig $ \c -> do
        let swA = cDialerSw c
            pidB = cTargetId c
        -- Before: only the relayed connection is pooled
        (direct0, relayed0) <- connsFor swA pidB
        length relayed0 `shouldBe` 1
        length direct0 `shouldBe` 0
        -- A plain dial hands back the pooled relay connection
        addrB <- firstAddr =<< switchListenAddrsOf (cTargetSw c)
        reused <- dialWith swA defaultDialOpts pidB [addrB] >>= either (fail . show) pure
        isRelayedAddr (connRemoteAddr reused) `shouldBe` True
        -- A force-direct dial does not
        let opts = defaultDialOpts { doForceDirect = True }
        fresh <- dialWith swA opts pidB [addrB] >>= either (fail . show) pure
        isRelayedAddr (connRemoteAddr fresh) `shouldBe` False
        (direct1, relayed1) <- connsFor swA pidB
        length direct1 `shouldBe` 1
        length relayed1 `shouldBe` 1

  describe "connection selection" $
    it "prefers the direct connection once one exists, and falls back to the relay" $
      withCircuitTrio noPunchConfig $ \c -> do
        let swA = cDialerSw c
            pidB = cTargetId c
        -- Only the relay exists: it is what lookupConn returns
        beforePunch <- atomically $ lookupConn (swConnPool swA) pidB
        fmap (isRelayedAddr . connRemoteAddr) beforePunch `shouldBe` Just True
        addrB <- firstAddr =<< switchListenAddrsOf (cTargetSw c)
        let opts = defaultDialOpts { doForceDirect = True }
        _ <- dialWith swA opts pidB [addrB] >>= either (fail . show) pure
        after' <- atomically $ lookupConn (swConnPool swA) pidB
        fmap (isRelayedAddr . connRemoteAddr) after' `shouldBe` Just False

  describe "DCUtR CONNECT addresses" $ do
    it "should include the relevant relay's Identify observed address" $
      withCircuitTrio fastConfig $ \c -> do
        (unrelatedId, _unrelatedKey) <- mkTestIdentity
        let observed = Multiaddr [IP4 0xCB007101, TCP 4001]
            stale = Multiaddr [IP4 0xCB007102, TCP 4002]
        seedObservedAddr (cTargetSw c) (cRelayId c) observed
        seedObservedAddr (cTargetSw c) unrelatedId stale
        addrs <- dcutrOwnAddrs (cTargetSw c) (Just (cRelayId c))
        addrs `shouldContain` [observed]
        addrs `shouldNotContain` [stale]

    it "should retain private listen addresses alongside an observation" $
      withCircuitTrio fastConfig $ \c -> do
        let observed = Multiaddr [IP4 0xCB007101, TCP 4001]
        seedObservedAddr (cTargetSw c) (cRelayId c) observed
        listen <- switchListenAddrsOf (cTargetSw c)
        addrs <- dcutrOwnAddrs (cTargetSw c) (Just (cRelayId c))
        addrs `shouldContain` listen

    it "should fall back to listen addresses when no observed address is known" $ do
      (sw, _pid) <- newNode fastConfig
      bound <- switchListen sw defaultConnectionGater [loopbackAddr]
      addrs <- dcutrOwnAddrs sw Nothing
      addrs `shouldBe` bound
      switchClose sw

  describe "hole punch target selection" $ do
    it "keeps only public, non-relayed advertised addresses" $
      withCircuitTrio fastConfig $ \c -> do
        let swB = cTargetSw c
            pidA = cDialerId c
            publicAddr = Multiaddr [IP4 0x08080808, TCP 4001]
            privateAddr = Multiaddr [IP4 0xC0A80005, TCP 4001]
            loopback = Multiaddr [IP4 0x7f000001, TCP 4001]
            circuitAddr = withCircuit (cRelayAddr c) (cRelayId c) (Just pidA)
        seedListenAddrs swB pidA [publicAddr, privateAddr, loopback, circuitAddr]
        targets <- holePunchTargets swB pidA
        targets `shouldBe` [publicAddr]

    it "yields nothing when the peer advertises only unroutable addresses" $
      withCircuitTrio fastConfig $ \c -> do
        let swB = cTargetSw c
            pidA = cDialerId c
        seedListenAddrs swB pidA
          [ Multiaddr [IP4 0x7f000001, TCP 4001]
          , Multiaddr [IP4 0x0A000001, TCP 4001]
          , withCircuit (cRelayAddr c) (cRelayId c) (Just pidA)
          ]
        holePunchTargets swB pidA `shouldReturn` []

  describe "upgradeRelayedConnection" $ do
    it "reports failure and leaves the relay connection alone when the punch fails" $
      -- On loopback no address is public, so the unilateral path is
      -- skipped and the DCUtR exchange runs; B's role-reversed dial
      -- lands on A's ordinary listener and cannot complete. What must
      -- hold is that this is reported as a failure and the relay
      -- survives -- specs/relay/DCUtR: "If the hole punching attempt
      -- fails, they can keep using the relay connection as they were."
      withCircuitTrio fastConfig $ \c -> do
        relayConn <- targetRelayConn c
        result <- timeout 30000000 $
          upgradeRelayedConnection (cTargetSw c) (ncDCUtRUpgrade fastConfig) relayConn
        case result of
          Nothing -> expectationFailure "upgrade attempt never settled"
          Just DCUtRSuccess -> expectationFailure "upgrade unexpectedly reported success"
          Just (DCUtRFailed _) -> pure ()
        threadDelay 500000
        (_, relayedAfter) <- connsFor (cTargetSw c) (cDialerId c)
        length relayedAfter `shouldBe` 1

    it "does not throw when the relay connection is already dead" $
      withCircuitTrio fastConfig $ \c -> do
        relayConn <- targetRelayConn c
        switchClose (cRelaySw c)
        threadDelay 300000
        result <- timeout 30000000 $
          upgradeRelayedConnection (cTargetSw c) (ncDCUtRUpgrade fastConfig) relayConn
        case result of
          Nothing -> expectationFailure "upgrade attempt never settled"
          Just DCUtRSuccess -> expectationFailure "upgrade unexpectedly reported success"
          Just (DCUtRFailed _) -> pure ()

  describe "simultaneous-connect roles" $ do
    it "pairs a role-reversed dialler with an ordinary dialler" $ do
      -- specs/relay/DCUtR: "For the purpose of all protocols run on top
      -- of this TCP connection, A is assumed to be the client and B the
      -- server." Both peers call connect(); the roles come from
      -- doUpgradeAsClient, which upgradeAs turns into the security and
      -- muxer sides. Driven over a memory pair because a real
      -- simultaneous open cannot be produced in-process.
      (_pidA, kpA) <- mkTestIdentity
      (_pidB, kpB) <- mkTestIdentity
      (rawA, rawB) <- mkMemoryStreamPair
      rawConnA <- mkMockRawConn rawA localAddr remoteAddr
      rawConnB <- mkMockRawConn rawB remoteAddr localAddr
      (connA, connB) <-
        concurrently
          (upgradeAs Outbound kpA rawConnA)   -- peer A: the client
          (upgradeAs Inbound kpB rawConnB)    -- peer B: the server
      connDirection connA `shouldBe` Outbound
      connDirection connB `shouldBe` Inbound
      -- The muxer took opposite roles, so stream ids do not collide
      (streamA, streamB) <-
        concurrently
          (muxOpenStream (connSession connA) unlimitedMemoryAccount)
          (muxAcceptStream (connSession connB))
      streamWrite streamA "punch"
      readExact streamB 5 `shouldReturn` "punch"
      muxClose (connSession connA)
      muxClose (connSession connB)

    it "deadlocks when both ends take the server role, which is why the dial is bounded" $ do
      -- A simultaneous connect that fails to collide lands on the peer's
      -- ordinary listener, leaving both ends running the responder side.
      -- Nothing completes, which is what ducDirectDialTimeoutMicros
      -- exists to bound (go-libp2p: defaultDirectDialTimeout).
      (_pidA, kpA) <- mkTestIdentity
      (_pidB, kpB) <- mkTestIdentity
      (rawA, rawB) <- mkMemoryStreamPair
      rawConnA <- mkMockRawConn rawA localAddr remoteAddr
      rawConnB <- mkMockRawConn rawB remoteAddr localAddr
      settled <- timeout 500000 $
        concurrently (upgradeAs Inbound kpA rawConnA) (upgradeAs Inbound kpB rawConnB)
      -- Connection has no Show instance, so assert on the shape
      isNothing settled `shouldBe` True

-- | Automatic DCUtR upgrade disabled: 'System.Timeout.timeout' with a
-- zero-length window returns immediately without running the action, so
-- neither the initiator's exchange nor the handler's dial ever runs. On
-- loopback the handler-side dial is an ordinary client dial that lands
-- on a real listener and succeeds, so with chunked stream reads (#276)
-- the automatic upgrade can pool a direct connection within the settle
-- delay — these tests assert on pool preconditions and must not race it.
noPunchConfig :: NATConfig
noPunchConfig = defaultNATConfig
  { ncDCUtRUpgrade = defaultDCUtRUpgradeConfig
      { ducMaxAttempts             = 1
      , ducDirectDialTimeoutMicros = 0
      , ducStreamTimeoutMicros     = 0
      , ducRelayCloseGraceMicros   = 200000
      }
  }

-- | Short timeouts so a punch that cannot succeed in-process settles
-- quickly instead of burning the default 10s per dial.
fastConfig :: NATConfig
fastConfig = defaultNATConfig
  { ncDCUtRUpgrade = defaultDCUtRUpgradeConfig
      { ducMaxAttempts             = 1
      , ducDirectDialTimeoutMicros = 1000000
      , ducStreamTimeoutMicros     = 5000000
      , ducRelayCloseGraceMicros   = 200000
      }
  }

-- | Overwrite the listen addresses recorded for a peer.
seedListenAddrs :: Switch -> PeerId -> [Multiaddr] -> IO ()
seedListenAddrs sw pid addrs = atomically $
  modifyTVar' (swPeerStore sw) (Map.insert pid info)
  where
    info = IdentifyInfo
      { idProtocolVersion  = Nothing
      , idAgentVersion     = Nothing
      , idPublicKey        = Nothing
      , idListenAddrs      = map toBytes addrs
      , idObservedAddr     = Nothing
      , idProtocols        = []
      , idSignedPeerRecord = Nothing
      }

-- | Record how a peer has observed us (Identify observedAddr).
seedObservedAddr :: Switch -> PeerId -> Multiaddr -> IO ()
seedObservedAddr sw pid addr = atomically $
  modifyTVar' (swPeerStore sw) (Map.insert pid info)
  where
    info = IdentifyInfo
      { idProtocolVersion  = Nothing
      , idAgentVersion     = Nothing
      , idPublicKey        = Nothing
      , idListenAddrs      = []
      , idObservedAddr     = Just (toBytes addr)
      , idProtocols        = []
      , idSignedPeerRecord = Nothing
      }

-- | The target's relayed connection back to the dialer.
targetRelayConn :: Circuit -> IO Connection
targetRelayConn c = do
  (_, relayed) <- connsFor (cTargetSw c) (cDialerId c)
  case relayed of
    (x : _) -> pure x
    []      -> fail "target has no relayed connection to the dialer"

-- | The listen addresses of a switch, excluding relayed ones: only a
-- direct address is a hole punch target.
switchListenAddrsOf :: Switch -> IO [Multiaddr]
switchListenAddrsOf sw = filter (not . isRelayedAddr) <$> switchListenAddrs sw

-- | Addresses for the in-memory upgrade pairs.
localAddr :: Multiaddr
localAddr = Multiaddr [IP4 0x7f000001, TCP 1111]

remoteAddr :: Multiaddr
remoteAddr = Multiaddr [IP4 0x7f000001, TCP 2222]

upgradeAs :: Direction -> KeyPair -> RawConnection -> IO Connection
upgradeAs direction kp raw = do
  rm <- newResourceManager (DefaultLimits noLimits noLimits noLimits noLimits)
  Upgrade.upgradeAs rm direction kp raw

-- | A mock RawConnection over a memory stream.
mkMockRawConn :: StreamIO -> Multiaddr -> Multiaddr -> IO RawConnection
mkMockRawConn sio local remote = pure RawConnection
  { rcEndpoint   = ByteStreamEndpoint sio
  , rcLocalAddr  = local
  , rcRemoteAddr = remote
  , rcClose      = pure ()
  }
