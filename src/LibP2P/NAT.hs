-- | NAT traversal handler registration (specs/autonat, specs/relay, specs/relay/DCUtR).
--
-- Wires the AutoNAT, Circuit Relay v2, and DCUtR module implementations
-- into the Switch protocol registry, in the style of
-- 'LibP2P.Protocol.Identify.registerIdentifyHandlers':
--
--   /libp2p/autonat/1.0.0            — AutoNAT dial-back server
--   /libp2p/circuit/relay/0.2.0/hop  — Circuit Relay v2 relay server
--   /libp2p/circuit/relay/0.2.0/stop — Circuit Relay v2 target (inbound relayed streams)
--   /libp2p/dcutr                    — DCUtR hole-punch coordination (handler side)
module LibP2P.NAT
  ( -- * Configuration
    NATConfig (..)
  , defaultNATConfig
    -- * Registration
  , registerNATHandlers
  , registerAutoNATHandler
  , registerRelayHopHandler
  , registerRelayStopHandler
  , registerDCUtRHandler
  , registerReservationCleanup
    -- * DCUtR production integration
  , registerDCUtRUpgrade
  , upgradeRelayedConnection
  , holePunchTargets
  , dcutrOwnAddrs
  , DCUtRUpgradeConfig (..)
  , defaultDCUtRUpgradeConfig
    -- * Circuit client
  , CircuitState
  , ReservationRefreshConfig (..)
  , defaultReservationRefreshConfig
  ) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.Async (async)
import Control.Concurrent.STM (atomically, modifyTVar', readTVar)
import Control.Monad (filterM, unless, void)
import Data.List (nub)
import Data.Maybe (fromMaybe)
import System.Timeout (timeout)
import qualified Data.Map.Strict as Map
import Control.Exception (SomeException, catch, try)
import LibP2P.Crypto.PeerId (PeerId, peerIdBytes)
import LibP2P.Multiaddr (Multiaddr (..), encapsulate, fromBytes, isPublicAddr, isRelayedAddr)
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.MultistreamSelect.Negotiation
  ( NegotiationResult (..)
  , StreamIO (..)
  , negotiateInitiator
  )
import LibP2P.NAT.AutoNAT (AutoNATConfig (..), handleAutoNAT)
import LibP2P.NAT.AutoNAT.Message (autoNATProtocolId)
import LibP2P.NAT.DCUtR (DCUtRConfig (..), DCUtRResult (..), handleDCUtR, initiateDCUtR)
import LibP2P.NAT.DCUtR.Message (dcutrProtocolId)
import LibP2P.NAT.Relay
  ( HopContext (..)
  , RelayConfig
  , RelayState
  , defaultRelayConfig
  , handleConnect
  , handleReserve
  , newRelayState
  , rsReservations
  )
import LibP2P.NAT.Relay.Client (handleStop)
import LibP2P.NAT.Relay.Message
  ( HopMessage (..)
  , HopMessageType (..)
  , RelayStatus (..)
  , hopProtocolId
  , maxRelayMessageSize
  , readHopMessage
  , stopProtocolId
  , writeHopMessage
  )
import LibP2P.NAT.Relay.Transport
  ( CircuitAddr (..)
  , CircuitState
  , ReservationRefreshConfig (..)
  , acceptStopStream
  , circuitTransport
  , defaultReservationRefreshConfig
  , newCircuitState
  , parseCircuitAddr
  )
import LibP2P.Switch (addTransport, selectTransport, setStreamHandler)
import LibP2P.Switch.ConnPool (lookupAllConns, lookupConn)
import LibP2P.Switch.Connection (closeConnection, newStream)
import LibP2P.Switch.Dial (DialOpts (..), dialWith)
import LibP2P.Switch.Listen (switchListenAddrs)
import LibP2P.Protocol.Identify (identifyPeer)
import LibP2P.Protocol.Identify.Message (IdentifyInfo (..))
import LibP2P.Switch.Types
  ( ConnState (..)
  , Connection (..)
  , Direction (..)
  , MuxerSession (..)
  , Switch (..)
  , SwitchConfig (..)
  )
import LibP2P.Switch.Upgrade (upgradeAsWithConfig)
import LibP2P.Transport (Transport (..))

-- | Configuration for the NAT traversal handlers.
data NATConfig = NATConfig
  { ncRelayConfig       :: RelayConfig
    -- ^ Resource limits for the Circuit Relay v2 server side
  , ncReservationRefresh :: ReservationRefreshConfig
    -- ^ Tuning for the circuit client's reservation refresh loop
  , ncDCUtRUpgrade      :: DCUtRUpgradeConfig
    -- ^ Tuning for the DCUtR direct-connection upgrade
  }

-- | Tuning for the DCUtR upgrade that runs on an inbound relayed
-- connection.
data DCUtRUpgradeConfig = DCUtRUpgradeConfig
  { ducMaxAttempts :: !Int
    -- ^ Hole punch attempts, each re-running the CONNECT/SYNC exchange
    -- so RTT is re-measured. specs/relay/DCUtR: inbound peers "SHOULD
    -- retry twice (thus a total of 3 attempts)".
  , ducDirectDialTimeoutMicros :: !Int
    -- ^ Bound on one hole punch dial. Without it a dial whose peer never
    -- answers the handshake pins a socket and a thread forever: a
    -- simultaneous connect that fails to collide lands on the peer's
    -- ordinary listener, leaving both ends running the responder side.
    -- go-libp2p bounds the same dial with @defaultDirectDialTimeout@.
  , ducStreamTimeoutMicros :: !Int
    -- ^ Bound on the whole @\/libp2p\/dcutr@ coordination exchange. The
    -- relay carrying it can vanish mid-exchange. go-libp2p sets the same
    -- bound as a stream deadline (@StreamTimeout@).
  , ducRelayCloseGraceMicros :: !Int
    -- ^ How long the relay connection is kept after a successful
    -- upgrade. specs/relay/DCUtR: "the relay connection should be closed
    -- after a grace period". go-libp2p's holepunch package leaves this
    -- to its connection manager, which this implementation does not
    -- have, so the delay is applied here.
  }

-- | Three hole punch attempts and a 15s grace period before the relay
-- connection is dropped.
defaultDCUtRUpgradeConfig :: DCUtRUpgradeConfig
defaultDCUtRUpgradeConfig = DCUtRUpgradeConfig
  { ducMaxAttempts             = 3
  , ducDirectDialTimeoutMicros = 10000000  -- go-libp2p: defaultDirectDialTimeout
  , ducStreamTimeoutMicros     = 60000000  -- go-libp2p: StreamTimeout
  , ducRelayCloseGraceMicros   = 15000000
  }

-- | Default NAT configuration: default relay limits and refresh tuning.
defaultNATConfig :: NATConfig
defaultNATConfig = NATConfig
  { ncRelayConfig        = defaultRelayConfig
  , ncReservationRefresh = defaultReservationRefreshConfig
  , ncDCUtRUpgrade       = defaultDCUtRUpgradeConfig
  }

-- | Register the NAT protocol handlers and the circuit client transport
-- on the Switch.
--
-- Returns the relay server state (so callers can inspect
-- reservations/circuits) and the circuit client state, which ties
-- 'transportListen' on a @p2p-circuit@ address to the inbound @stop@
-- streams that arrive over the connection to that relay.
registerNATHandlers :: Switch -> NATConfig -> IO (RelayState, CircuitState)
registerNATHandlers sw config = do
  relayState <- newRelayState (ncRelayConfig config)
  circuitState <- newCircuitState
  addTransport sw (circuitTransport sw circuitState (ncReservationRefresh config))
  registerAutoNATHandler sw
  registerRelayHopHandler sw relayState
  registerRelayStopHandler sw circuitState
  registerDCUtRHandler sw (ncDCUtRUpgrade config)
  registerDCUtRUpgrade sw (ncDCUtRUpgrade config)
  registerReservationCleanup sw relayState
  pure (relayState, circuitState)

-- | Drop a peer's relay reservation once its last connection to us goes
-- away (specs/relay/circuit-v2): "the reservation remains valid until
-- its expiration, as long as there is an active connection from the peer
-- to the relay. If the peer disconnects, the reservation is no longer
-- valid."
--
-- The reservation is bound to the peer, not to the connection the
-- RESERVE arrived on, so a peer holding a second connection keeps it.
-- This matches go-libp2p, whose relay returns early from its disconnect
-- notifiee while @Connectedness(p) == Connected@.
--
-- 'closeConnection' removes the connection from the pool in the same STM
-- transaction that marks it closed, and only then runs the notifiers, so
-- the lookup below never observes the connection being torn down.
registerReservationCleanup :: Switch -> RelayState -> IO ()
registerReservationCleanup sw relayState =
  atomically $ modifyTVar' (swDisconnectNotifiers sw) (dropReservation :)
  where
    dropReservation conn = atomically $ do
      let peerId = connPeerId conn
      remaining <- lookupConn (swConnPool sw) peerId
      case remaining of
        Just _  -> pure ()
        Nothing -> modifyTVar' (rsReservations relayState) (Map.delete peerId)

-- | Subscribe the DCUtR direct-connection upgrade to new connections.
--
-- specs/relay/DCUtR: "The protocol starts with the completion of a relay
-- connection from @A@ to @B@. Upon observing the new connection, the
-- inbound peer (here @B@) checks the addresses advertised by @A@ via
-- identify." The trigger is therefore an *inbound* connection over a
-- circuit, the same condition go-libp2p's hole punch notifiee applies
-- (@Direction == DirInbound && isRelayAddress(RemoteMultiaddr())@).
registerDCUtRUpgrade :: Switch -> DCUtRUpgradeConfig -> IO ()
registerDCUtRUpgrade sw config =
  atomically $ modifyTVar' (swNotifiers sw) (notifier :)
  where
    notifier conn
      | connDirection conn == Inbound && isRelayedAddr (connRemoteAddr conn) =
          void (upgradeRelayedConnection sw config conn)
      | otherwise = pure ()

-- | Upgrade a relayed connection to a direct one (specs/relay/DCUtR).
--
-- Tries the unilateral upgrade first, falling back to the @\/libp2p\/dcutr@
-- exchange, and on success schedules the relay connection to close after
-- the grace period. Exposed so it can be driven directly instead of
-- through the notifier.
upgradeRelayedConnection
  :: Switch -> DCUtRUpgradeConfig -> Connection -> IO DCUtRResult
upgradeRelayedConnection sw config relayConn = do
  outcome <- try (upgradeRelayedConnection' sw config relayConn)
  pure $ case outcome of
    Left (e :: SomeException) -> DCUtRFailed (show e)
    Right r -> r

-- | The upgrade proper. Total only through 'upgradeRelayedConnection':
-- the relay connection can die at any point, and 'newStream' surfaces a
-- dead muxer as an exception rather than a 'Left'.
upgradeRelayedConnection'
  :: Switch -> DCUtRUpgradeConfig -> Connection -> IO DCUtRResult
upgradeRelayedConnection' sw config relayConn = do
  -- Learn the remote's advertised addresses. Identify also runs from its
  -- own on-connect notifier, but the two are unordered, so this waits on
  -- its own exchange rather than racing the peer store. storeIdentify
  -- merges, so the duplicate is harmless.
  _ <- identifyPeer sw relayConn
  publicAddrs <- holePunchTargets sw (connPeerId relayConn)
  outcome <-
    if null publicAddrs
      then pure (DCUtRFailed "no public address advertised")
      else unilateralUpgrade sw config relayConn publicAddrs
  result <- case outcome of
    DCUtRSuccess -> pure DCUtRSuccess
    DCUtRFailed _ -> initiateOverRelay sw config relayConn
  case result of
    DCUtRSuccess -> scheduleRelayClose sw config relayConn
    DCUtRFailed _ -> pure ()
  pure result

-- | The peer's advertised addresses that are worth a unilateral direct
-- dial: decodable, not relayed, and publicly routable.
--
-- specs/relay/DCUtR: "@B@ checks the addresses advertised by @A@ via
-- identify. If that set includes public addresses, then @A@ may be
-- reachable by a direct connection". go-libp2p applies the same pair of
-- filters (@!isRelayAddress(a) && manet.IsPublicAddr(a)@).
--
-- A circuit address is never a target: dialling it would go back through
-- the relay we are trying to get off.
holePunchTargets :: Switch -> PeerId -> IO [Multiaddr]
holePunchTargets sw peerId = do
  store <- atomically $ readTVar (swPeerStore sw)
  let raw = maybe [] idListenAddrs (Map.lookup peerId store)
  pure [ addr
       | Right addr <- map fromBytes raw
       , not (isRelayedAddr addr)
       , isPublicAddr addr
       ]

-- | Attempt a direct connection without any signalling.
--
-- specs/relay/DCUtR: "If that set includes public addresses, then @A@
-- may be reachable by a direct connection, in which case @B@ attempts a
-- unilateral connection upgrade by initiating a direct connection to
-- @A@." go-libp2p guards this the same way
-- (@!isRelayAddress(a) && manet.IsPublicAddr(a)@).
unilateralUpgrade
  :: Switch -> DCUtRUpgradeConfig -> Connection -> [Multiaddr] -> IO DCUtRResult
unilateralUpgrade sw config relayConn addrs = do
  dialed <- holePunchDial sw config True (connPeerId relayConn) addrs
  pure $ either DCUtRFailed (const DCUtRSuccess) dialed

-- | Run the CONNECT/CONNECT/SYNC exchange over the relayed connection.
--
-- We are peer @B@: the initiator of the exchange, and the server of the
-- resulting TCP simultaneous connect.
initiateOverRelay :: Switch -> DCUtRUpgradeConfig -> Connection -> IO DCUtRResult
initiateOverRelay sw config relayConn = do
  streamOrErr <- try (newStream sw relayConn)
  case streamOrErr of
    Left (e :: SomeException) ->
      pure (DCUtRFailed ("dcutr: cannot open stream: " ++ show e))
    Right (Left err) -> pure (DCUtRFailed ("dcutr: cannot open stream: " ++ show err))
    Right (Right stream) -> do
      negotiated <- negotiateInitiator stream [dcutrProtocolId]
      case negotiated of
        NoProtocol -> do
          closeQuietly stream
          pure (DCUtRFailed "remote does not support /libp2p/dcutr")
        Accepted _ -> do
          ownAddrs <- dcutrOwnAddrs sw (relayObserver relayConn)
          let dcConfig = DCUtRConfig
                { dcMaxAttempts = ducMaxAttempts config
                , dcDialer = \addr ->
                    holePunchDial sw config False (connPeerId relayConn) [addr]
                }
          result <- handleOrFail
            (bounded (ducStreamTimeoutMicros config) (initiateDCUtR dcConfig stream ownAddrs))
          closeQuietly stream
          pure result
  where
    handleOrFail action = do
      outcome <- try action
      pure $ case outcome of
        Left (e :: SomeException) -> DCUtRFailed (show e)
        Right r -> r
    bounded limit action = do
      r <- timeout limit action
      pure (fromMaybe (DCUtRFailed "dcutr exchange timed out") r)

-- | Dial for a hole punch: never reuse the pooled relay connection, and
-- take the security and muxer roles the spec assigns.
--
-- specs/relay/DCUtR: "For the purpose of all protocols run on top of
-- this TCP connection, @A@ is assumed to be the client and @B@ the
-- server." We are @B@, so we upgrade as the responder even though we
-- called connect(). The unilateral attempt has no counterpart dialling
-- back, so it stays the client.
holePunchDial
  :: Switch -> DCUtRUpgradeConfig -> Bool -> PeerId -> [Multiaddr]
  -> IO (Either String ())
holePunchDial sw config asClient peerId addrs = do
  let opts = DialOpts { doForceDirect = True, doUpgradeAsClient = asClient }
  dialed <- try (timeout (ducDirectDialTimeoutMicros config) (dialWith sw opts peerId addrs))
  pure $ case dialed of
    Left (e :: SomeException) -> Left (show e)
    Right Nothing -> Left "hole punch dial timed out"
    Right (Just (Left err)) -> Left (show err)
    Right (Just (Right _conn)) -> Right ()

-- | Addresses we put in DCUtR CONNECT: the address reported by the relay
-- that carries this connection, followed by every non-relayed listen
-- address. Scoping the observation to that relay avoids advertising stale
-- mappings learned from unrelated peers. Private listen addresses remain
-- useful to peers on the same LAN and as deterministic test fallbacks.
dcutrOwnAddrs :: Switch -> Maybe PeerId -> IO [Multiaddr]
dcutrOwnAddrs sw observer = do
  observed <- observedAddrs sw observer
  listen <- filter (not . isRelayedAddr) <$> switchListenAddrs sw
  pure (nub (observed ++ listen))

-- | How the relevant relay observed us during Identify.
observedAddrs :: Switch -> Maybe PeerId -> IO [Multiaddr]
observedAddrs sw observer = do
  store <- atomically $ readTVar (swPeerStore sw)
  let infos = case observer of
        Just peerId -> maybe [] pure (Map.lookup peerId store)
        Nothing -> []
  pure
    [ addr
    | info <- infos
    , Just raw <- [idObservedAddr info]
    , Right addr <- [fromBytes raw]
    , not (isRelayedAddr addr)
    ]

-- | The relay encoded in a relayed connection's remote multiaddr.
relayObserver :: Connection -> Maybe PeerId
relayObserver conn =
  either (const Nothing) (Just . caRelayId) (parseCircuitAddr (connRemoteAddr conn))

-- | Close the relay connection after the grace period, provided a direct
-- connection to the peer is still up.
--
-- specs/relay/DCUtR: "All new streams should be opened in the direct
-- connection, while the relay connection should be closed after a grace
-- period." The re-check matters because the direct connection can die
-- inside the grace window; dropping the relay as well would leave the
-- peer unreachable, and the spec keeps the relay as the fallback.
scheduleRelayClose :: Switch -> DCUtRUpgradeConfig -> Connection -> IO ()
scheduleRelayClose sw config relayConn = void . async $ do
  threadDelay (ducRelayCloseGraceMicros config)
  conns <- atomically $ lookupAllConns (swConnPool sw) (connPeerId relayConn)
  direct <- atomically $ filterM openAndDirect conns
  unless (null direct) $ closeConnection sw relayConn
  where
    openAndDirect c = do
      st <- readTVar (connState c)
      pure (st == ConnOpen && not (isRelayedAddr (connRemoteAddr c)))

-- | Close a stream, ignoring failures from an already-dead session.
closeQuietly :: StreamIO -> IO ()
closeQuietly stream = streamClose stream `catch` \(_ :: SomeException) -> pure ()

-- | Register the AutoNAT server handler (/libp2p/autonat/1.0.0).
--
-- The dial-back deliberately bypasses the connection pool: reusing the
-- requester's existing connection would always report success. Instead a
-- fresh transport dial + upgrade verifies both reachability and identity,
-- and the probe connection is closed immediately (go-libp2p uses a
-- separate dialer host for the same reason).
registerAutoNATHandler :: Switch -> IO ()
registerAutoNATHandler sw =
  setStreamHandler sw autoNATProtocolId $ \conn stream ->
    let config = AutoNATConfig
          { natThreshold = 3
          , natDialBack  = freshDialBack sw
          }
    in handleAutoNAT config stream (connPeerId conn) (connRemoteAddr conn)

-- | Dial back a peer on a fresh connection, verify its identity, and close.
-- Returns the address that actually succeeded, not the first candidate.
freshDialBack :: Switch -> PeerId -> [Multiaddr] -> IO (Either String Multiaddr)
freshDialBack _ _ [] = pure (Left "dial-back: no addresses")
freshDialBack sw pid (addr : rest) = do
  result <- try (probeAddr sw pid addr)
  case result of
    Right (Right ()) -> pure (Right addr)
    Right (Left err)
      | null rest -> pure (Left err)
      | otherwise -> freshDialBack sw pid rest
    Left (e :: SomeException)
      | null rest -> pure (Left (show e))
      | otherwise -> freshDialBack sw pid rest

-- | Probe a single address: transport dial, upgrade, check peer identity.
probeAddr :: Switch -> PeerId -> Multiaddr -> IO (Either String ())
probeAddr sw pid addr = do
  mTransport <- selectTransport sw addr
  case mTransport of
    Nothing -> pure (Left ("dial-back: no transport for " ++ show addr))
    Just transport -> do
      rawConn <- transportDial transport addr
      conn <- upgradeAsWithConfig (scYamuxConfig (swConfig sw)) Outbound (swIdentityKey sw) rawConn
      let matches = connPeerId conn == pid
      muxClose (connSession conn) `catch` \(_ :: SomeException) -> pure ()
      pure $ if matches
        then Right ()
        else Left "dial-back: peer identity mismatch"

-- | Register the Circuit Relay v2 hop handler
-- (/libp2p/circuit/relay/0.2.0/hop): serve RESERVE and CONNECT requests.
registerRelayHopHandler :: Switch -> RelayState -> IO ()
registerRelayHopHandler sw relayState =
  setStreamHandler sw hopProtocolId $ \conn stream -> do
    result <- readHopMessage stream maxRelayMessageSize
    case result of
      Left _ -> pure ()
      Right msg -> case hopType msg of
        Just HopReserve -> do
          ctx <- switchHopContext sw conn
          handleReserve relayState ctx stream (connPeerId conn)
        Just HopConnect -> do
          ctx <- switchHopContext sw conn
          handleConnect relayState ctx stream (connPeerId conn) msg (openStopStream sw)
        _ -> writeHopMessage stream HopMessage
          { hopType = Just HopStatus
          , hopPeer = Nothing
          , hopReservation = Nothing
          , hopLimit = Nothing
          , hopStatus = Just UnexpectedMessage
          }

-- | Build the per-request hop context from the Switch: the relay's own
-- identity (signs reservation vouchers), its listen addresses with the
-- @/p2p/\<relay\>@ suffix the circuit-v2 spec requires for reservation
-- addrs, and the address the requesting connection arrived over.
switchHopContext :: Switch -> Connection -> IO HopContext
switchHopContext sw conn = do
  addrs <- switchListenAddrs sw
  let relayP2P = Multiaddr [P2P (peerIdBytes (swLocalPeerId sw))]
  pure HopContext
    { hcRelayId    = swLocalPeerId sw
    , hcRelayKey   = swIdentityKey sw
    , hcRelayAddrs = map (`encapsulate` relayP2P) addrs
    , hcRemoteAddr = connRemoteAddr conn
    }

-- | Open a stop-protocol stream to the circuit target over an existing
-- connection. Returns Nothing when the target is not connected or the
-- stop protocol cannot be negotiated.
openStopStream :: Switch -> PeerId -> IO (Maybe StreamIO)
openStopStream sw targetId = do
  result <- try $ do
    mConn <- atomically $ lookupConn (swConnPool sw) targetId
    case mConn of
      Nothing -> pure Nothing
      Just conn -> do
        streamOrErr <- newStream sw conn
        case streamOrErr of
          Left _ -> pure Nothing
          Right stream -> do
            negotiated <- negotiateInitiator stream [stopProtocolId]
            case negotiated of
              Accepted _ -> pure (Just stream)
              NoProtocol -> do
                streamClose stream `catch` \(_ :: SomeException) -> pure ()
                pure Nothing
  case result of
    Left (_ :: SomeException) -> pure Nothing
    Right mStream -> pure mStream

-- | Register the Circuit Relay v2 stop handler
-- (/libp2p/circuit/relay/0.2.0/stop).
--
-- After the CONNECT/OK exchange the stop stream *is* the relayed
-- connection (specs/relay/circuit-v2), so it is handed to the circuit
-- transport's listener for the relay it arrived over. The Switch then
-- upgrades it like any other inbound raw connection.
--
-- The relay's advertised limit is not yet enforced (issue #269).
registerRelayStopHandler :: Switch -> CircuitState -> IO ()
registerRelayStopHandler sw circuitState =
  setStreamHandler sw stopProtocolId $ \conn stream -> do
    result <- handleStop stream
    case result of
      Left _ -> pure ()
      Right (sourcePeer, _mLimit) ->
        acceptStopStream circuitState conn sourcePeer stream

-- | Register the DCUtR handler (/libp2p/dcutr).
--
-- Answers the CONNECT/SYNC exchange with our listen addresses and dials
-- the initiator's addresses through the Switch for the hole punch.
registerDCUtRHandler :: Switch -> DCUtRUpgradeConfig -> IO ()
registerDCUtRHandler sw upgradeConfig =
  setStreamHandler sw dcutrProtocolId $ \conn stream -> do
    addrs <- dcutrOwnAddrs sw (relayObserver conn)
    let config = DCUtRConfig
          { dcMaxAttempts = ducMaxAttempts upgradeConfig
            -- We are peer A: the spec makes us the client of the
            -- simultaneous connect, and the dial must not be satisfied by
            -- the relay connection we are running this exchange over.
          , dcDialer = \addr ->
              holePunchDial sw upgradeConfig True (connPeerId conn) [addr]
          }
    _ <- timeout (ducStreamTimeoutMicros upgradeConfig) (handleDCUtR config stream addrs)
    pure ()
