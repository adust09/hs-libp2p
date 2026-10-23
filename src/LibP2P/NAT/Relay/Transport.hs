-- | Circuit Relay v2 client transport (specs/relay/circuit-v2).
--
-- Turns a @p2p-circuit@ multiaddr into a first-class 'Transport' so that
-- relayed peers become ordinary 'Connection's in the Switch's pool.
--
-- The spec states that once the @hop@ CONNECT (dialer side) or @stop@
-- CONNECT (target side) exchange succeeds, "the original stream becomes
-- the relayed connection", which clients then upgrade "with a security
-- protocol and a multiplexer, just like they would e.g. upgrade a TCP
-- connection". This module produces the 'RawConnection' for that stream;
-- the existing upgrade pipeline in "LibP2P.Switch.Upgrade" does the rest.
--
-- Outbound: dial the relay, negotiate @hop@, send CONNECT, hand the
-- stream to the Switch as a raw connection.
--
-- Inbound: 'transportListen' reserves on a relay and registers a queue
-- keyed by that relay's peer id. The @stop@ protocol handler calls
-- 'acceptStopStream', which enqueues the relayed stream; the Switch's
-- accept loop then drives it through the normal inbound path (gating,
-- upgrade, resource limits, pool, notifiers, teardown).
module LibP2P.NAT.Relay.Transport
  ( -- * Shared state
    CircuitState
  , newCircuitState
    -- * Reservation refresh
  , ReservationRefreshConfig (..)
  , defaultReservationRefreshConfig
    -- * Transport
  , circuitTransport
    -- * Inbound relayed streams
  , acceptStopStream
    -- * Address handling (exported for testing)
  , CircuitAddr (..)
  , parseCircuitAddr
  , circuitAddrOf
  ) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.Async (async)
import Control.Concurrent.STM
  ( TQueue
  , TVar
  , atomically
  , modifyTVar'
  , newTQueue
  , newTVar
  , newTVarIO
  , readTQueue
  , readTVar
  , readTVarIO
  , writeTQueue
  , writeTVar
  )
import Control.Exception (SomeException, catch, throwIO, try)
import Control.Monad (unless)
import qualified Data.Map.Strict as Map
import Data.Time.Clock.POSIX (POSIXTime, getPOSIXTime)
import Data.Word (Word64)
import LibP2P.Crypto.PeerId (PeerId (..), peerIdBytes)
import LibP2P.Multiaddr (Multiaddr (..), fromBytes)
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.MultistreamSelect.Negotiation
  ( NegotiationResult (..)
  , StreamIO (..)
  , negotiateInitiator
  )
import LibP2P.NAT.Relay.Client (connectViaRelay, makeReservation)
import LibP2P.NAT.Relay.Limit (enforceRelayCircuitLimit, toRelayCircuitLimit)
import LibP2P.NAT.Relay.Message
  ( HopMessage (..)
  , RelayLimit
  , RelayStatus (..)
  , Reservation (..)
  , hopProtocolId
  )
import LibP2P.Switch.ConnPool (lookupConn)
import LibP2P.Switch.Connection (newStream)
import LibP2P.Switch.Dial (dial)
import LibP2P.Switch.Listen (switchWithdrawListener)
import LibP2P.Switch.Types (Connection (..), Switch (..))
import LibP2P.Transport
  ( ConnectionEndpoint (..)
  , Listener (..)
  , RawConnection (..)
  , Transport (..)
  )

-- | A parsed circuit multiaddr.
--
-- Wire form: @\<relayTransportAddr\>\/p2p\/\<relay\>\/p2p-circuit[\/p2p\/\<target\>]@.
-- The target component is present when dialling and absent when listening.
data CircuitAddr = CircuitAddr
  { caRelayAddr :: !Multiaddr      -- ^ Relay's transport address, without the @\/p2p@ suffix
  , caRelayId   :: !PeerId         -- ^ Relay's peer id
  , caTarget    :: !(Maybe PeerId) -- ^ Destination peer id, when dialling
  } deriving (Show, Eq)

-- | Per-Switch state shared between the circuit transport and the @stop@
-- protocol handler: one inbound queue per relay we hold a reservation on.
newtype CircuitState = CircuitState (TVar (Map.Map PeerId InboundQueue))

-- | An inbound queue for relayed connections arriving via one relay.
-- The closed flag lets 'listenerClose' unblock a waiting 'listenerAccept'
-- so the Switch's accept loop terminates.
data InboundQueue = InboundQueue
  { iqQueue  :: !(TQueue RawConnection)
  , iqClosed :: !(TVar Bool)
  }

-- | Create empty circuit state.
newCircuitState :: IO CircuitState
newCircuitState = CircuitState <$> newTVarIO Map.empty

-- | Tuning for client-side reservation refresh (specs/relay/circuit-v2:
-- "the reservation becomes invalid after this time and it's the
-- responsibility of the client to refresh").
--
-- Values follow go-libp2p's @autorelay@ relay finder
-- (@rsvpExpirationSlack@ / @rsvpRefreshInterval@): refresh once the
-- reservation is within 'rrcMargin' of its expiry, checked every
-- 'rrcPollInterval'.
data ReservationRefreshConfig = ReservationRefreshConfig
  { rrcMargin       :: !POSIXTime  -- ^ Refresh once expiry is within this margin
  , rrcPollInterval :: !Int        -- ^ Microseconds between expiry checks
  } deriving (Show, Eq)

-- | Default refresh tuning: a 2 minute margin, checked every minute.
defaultReservationRefreshConfig :: ReservationRefreshConfig
defaultReservationRefreshConfig = ReservationRefreshConfig
  { rrcMargin       = 120
  , rrcPollInterval = 60 * 1000000
  }

-- | The Circuit Relay v2 client transport.
--
-- Captures the Switch so it can dial the relay; register it after
-- 'LibP2P.Switch.newSwitch' with 'LibP2P.Switch.addTransport'.
circuitTransport :: Switch -> CircuitState -> ReservationRefreshConfig -> Transport
circuitTransport sw st refreshCfg = Transport
  { transportDial     = dialCircuit sw
  , transportDialFrom = \_ -> dialCircuit sw
  , transportListen   = listenCircuit sw st refreshCfg
  , transportCanDial  = either (const False) (const True) . parseCircuitAddr
  }

-- Address handling

-- | Parse a circuit multiaddr into its relay and target parts.
parseCircuitAddr :: Multiaddr -> Either String CircuitAddr
parseCircuitAddr (Multiaddr ps) = case break (== P2PCircuit) ps of
  (_, []) -> Left "circuit address: no /p2p-circuit component"
  (before, _ : after) -> do
    (relayAddr, relayId) <- splitRelay before
    target <- parseTarget after
    pure CircuitAddr
      { caRelayAddr = relayAddr
      , caRelayId   = relayId
      , caTarget    = target
      }
  where
    splitRelay comps = case reverse comps of
      (P2P pid : rest)
        | not (null rest) -> Right (Multiaddr (reverse rest), PeerId pid)
        | otherwise -> Left "circuit address: relay has no transport address"
      _ -> Left "circuit address: relay component must end with /p2p/<relay>"
    parseTarget [] = Right Nothing
    parseTarget [P2P pid] = Right (Just (PeerId pid))
    parseTarget _ =
      Left "circuit address: expected at most /p2p/<target> after /p2p-circuit"

-- | Build the circuit multiaddr describing a relayed connection.
circuitAddrOf :: Multiaddr -> PeerId -> Maybe PeerId -> Multiaddr
circuitAddrOf relayAddr relayId mTarget =
  Multiaddr (stripP2P relayAddr ++ [P2P (peerIdBytes relayId), P2PCircuit] ++ targetPart)
  where
    targetPart = maybe [] (\t -> [P2P (peerIdBytes t)]) mTarget
    stripP2P (Multiaddr comps) = case reverse comps of
      (P2P _ : rest) -> reverse rest
      _              -> comps

-- Outbound

-- | Dial a peer through a relay.
--
-- Connects to the relay, negotiates @hop@, sends CONNECT for the target,
-- and on @STATUS OK@ returns the hop stream as the raw relayed connection.
dialCircuit :: Switch -> Multiaddr -> IO RawConnection
dialCircuit sw addr = do
  circuit <- either fail pure (parseCircuitAddr addr)
  target <- maybe (fail "circuit dial: address has no /p2p/<target>") pure
              (caTarget circuit)
  relayConn <- dialRelay sw circuit
  stream <- openHopStream sw relayConn
  resp <- connectViaRelay stream target >>= either (failClosing stream) pure
  unless (hopStatus resp == Just RelayOK) $
    failClosing stream ("relay refused CONNECT: " ++ show (hopStatus resp))
  limited <- limitedStream (hopLimit resp) stream
  pure RawConnection
    { rcEndpoint   = ByteStreamEndpoint limited
    , rcLocalAddr  = connLocalAddr relayConn
    , rcRemoteAddr = circuitAddrOf (caRelayAddr circuit) (caRelayId circuit) (Just target)
    , rcClose      = closeQuietly limited
    , rcRelayLimit = fmap toRelayCircuitLimit (hopLimit resp)
    }

-- Inbound

-- | Reserve a slot on a relay and listen for relayed connections through it.
--
-- The @hop@ stream used for RESERVE is closed once the reservation is
-- granted: per the spec the reservation lives as long as the connection
-- to the relay, and inbound circuits arrive as fresh @stop@ streams on
-- that connection. A background loop re-issues RESERVE on fresh @hop@
-- streams ahead of the granted expiry to keep the reservation alive; see
-- 'refreshLoop'.
listenCircuit :: Switch -> CircuitState -> ReservationRefreshConfig -> Multiaddr -> IO Listener
listenCircuit sw st refreshCfg addr = do
  circuit <- either fail pure (parseCircuitAddr addr)
  relayConn <- dialRelay sw circuit
  stream <- openHopStream sw relayConn
  resp <- makeReservation stream >>= either (failClosing stream) pure
  unless (hopStatus resp == Just RelayOK) $
    failClosing stream ("relay refused RESERVE: " ++ show (hopStatus resp))
  expiry <- either (failClosing stream) pure (reservationExpiry resp)
  closeQuietly stream
  queue <- registerQueue st (caRelayId circuit)
  let listenAddr = reservationAddr circuit resp
  registerRelayLossNotifier sw relayConn listenAddr
  _ <- async (refreshLoop refreshCfg sw relayConn queue listenAddr expiry)
  pure Listener
    { listenerAccept = acceptFrom queue
    , listenerClose  = unregisterQueue st (caRelayId circuit)
    , listenerAddr   = listenAddr
    }

-- | Extract the expiration time the relay granted, per circuit-v2's
-- Reservation.expire: "a UTC UNIX time in seconds". Refresh cannot be
-- scheduled without it, so a missing value is treated as a failure
-- rather than defaulted.
reservationExpiry :: HopMessage -> Either String Word64
reservationExpiry resp = case hopReservation resp >>= rsvExpire of
  Just expiry -> Right expiry
  Nothing     -> Left "relay RESERVE response is missing the reservation expiry"

-- | Periodically re-issue RESERVE on the existing connection to the
-- relay, ahead of the current reservation's expiry (specs/relay/circuit-v2:
-- "it's the responsibility of the client to refresh").
--
-- Stops once the listener's queue is closed -- by 'listenerClose'
-- (explicit close or 'LibP2P.Switch.switchClose'), by the relay-loss
-- notifier registered in 'listenCircuit', or by this loop itself
-- withdrawing the listener after a failed refresh.
refreshLoop
  :: ReservationRefreshConfig -> Switch -> Connection -> InboundQueue
  -> Multiaddr -> Word64 -> IO ()
refreshLoop cfg sw relayConn queue listenAddr = go
  where
    go expiry = do
      threadDelay (rrcPollInterval cfg)
      closed <- readTVarIO (iqClosed queue)
      unless closed $ do
        now <- getPOSIXTime
        if now + rrcMargin cfg >= fromIntegral expiry
          then do
            result <- refreshReservation sw relayConn
            case result of
              Left _err       -> switchWithdrawListener sw listenAddr
              Right newExpiry -> go newExpiry
          else go expiry

-- | Re-issue RESERVE on a fresh @hop@ stream over an existing connection
-- to the relay, returning the new expiry or a description of why the
-- refresh failed (transport error or a non-OK STATUS).
refreshReservation :: Switch -> Connection -> IO (Either String Word64)
refreshReservation sw relayConn = do
  result <- try attempt
  pure $ case result of
    Left (e :: SomeException) -> Left (show e)
    Right expiry               -> expiry
  where
    attempt = do
      stream <- openHopStream sw relayConn
      resp <- makeReservation stream >>= either (failClosing stream) pure
      unless (hopStatus resp == Just RelayOK) $
        failClosing stream ("relay refused RESERVE refresh: " ++ show (hopStatus resp))
      closeQuietly stream
      pure (reservationExpiry resp)

-- | Withdraw the circuit listen address once the last connection to the
-- relay is gone (specs/relay/circuit-v2: "the reservation remains valid
-- until its expiration, as long as there is an active connection from
-- the peer to the relay. If the peer disconnects, the reservation is no
-- longer valid").
--
-- The reservation is bound to the relay peer, not to the connection the
-- RESERVE went out on, so a second connection to the same relay keeps
-- the listen address alive. This is the same predicate the relay server
-- side applies in 'LibP2P.NAT.registerReservationCleanup', and it has to
-- match: against a go-libp2p relay, which keeps a reservation while any
-- connection from us remains, per-connection matching would withdraw a
-- listen address the relay still honours.
--
-- 'closeConnection' removes the connection from the pool in the same STM
-- transaction that marks it closed and only then runs the notifiers, so
-- the lookup below never observes the connection being torn down.
registerRelayLossNotifier :: Switch -> Connection -> Multiaddr -> IO ()
registerRelayLossNotifier sw relayConn listenAddr =
  atomically $ modifyTVar' (swDisconnectNotifiers sw) (notifier :)
  where
    relayId = connPeerId relayConn
    notifier conn
      | connPeerId conn /= relayId = pure ()
      | otherwise = do
          remaining <- atomically $ lookupConn (swConnPool sw) relayId
          case remaining of
            Just _  -> pure ()
            Nothing -> switchWithdrawListener sw listenAddr

-- | Hand a relayed stream that arrived via the @stop@ protocol to the
-- listener for the relay it came over.
--
-- The stream is closed when no listener is registered for that relay:
-- without a reservation we have nothing to accept the circuit into.
acceptStopStream
  :: CircuitState -> Connection -> PeerId -> Maybe RelayLimit -> StreamIO -> IO ()
acceptStopStream (CircuitState var) relayConn source mLimit stream = do
  limited <- limitedStream mLimit stream
  let rawConn = RawConnection
        { rcEndpoint   = ByteStreamEndpoint limited
        , rcLocalAddr  = connLocalAddr relayConn
        , rcRemoteAddr =
            circuitAddrOf (connRemoteAddr relayConn) (connPeerId relayConn) (Just source)
        , rcClose      = closeQuietly limited
        , rcRelayLimit = fmap toRelayCircuitLimit mLimit
        }
  enqueued <- atomically $ do
    queues <- readTVar var
    case Map.lookup (connPeerId relayConn) queues of
      Nothing -> pure False
      Just q -> do
        closed <- readTVar (iqClosed q)
        if closed
          then pure False
          else do
            writeTQueue (iqQueue q) rawConn
            pure True
  unless enqueued (closeQuietly limited)

-- Helpers

-- | Dial the relay named by a circuit address, reusing a pooled
-- connection to it when one exists.
dialRelay :: Switch -> CircuitAddr -> IO Connection
dialRelay sw circuit =
  dial sw (caRelayId circuit) [caRelayAddr circuit]
    >>= either (\err -> fail ("circuit: cannot reach relay: " ++ show err)) pure

-- | Open a stream to the relay and negotiate the @hop@ protocol.
openHopStream :: Switch -> Connection -> IO StreamIO
openHopStream sw relayConn = do
  stream <- newStream sw relayConn
    >>= either (\err -> fail ("circuit: cannot open hop stream: " ++ show err)) pure
  negotiated <- negotiateInitiator stream [hopProtocolId]
  case negotiated of
    Accepted _ -> pure stream
    NoProtocol -> failClosing stream "relay does not support /libp2p/circuit/relay/0.2.0/hop"

-- | The address this listener is reachable on: the relay's advertised
-- reservation address with @\/p2p-circuit@ appended. Falls back to the
-- dialled relay address when the relay advertises none.
reservationAddr :: CircuitAddr -> HopMessage -> Multiaddr
reservationAddr circuit resp =
  case hopReservation resp >>= firstDecodable . rsvAddrs of
    Just relayAddr -> circuitAddrOf relayAddr (caRelayId circuit) Nothing
    Nothing -> circuitAddrOf (caRelayAddr circuit) (caRelayId circuit) Nothing
  where
    firstDecodable [] = Nothing
    firstDecodable (bs : rest) = either (const (firstDecodable rest)) Just (fromBytes bs)

-- | Register an inbound queue for a relay, replacing any previous one.
registerQueue :: CircuitState -> PeerId -> IO InboundQueue
registerQueue (CircuitState var) relayId = atomically $ do
  queue <- InboundQueue <$> newTQueue <*> newTVar False
  queues <- readTVar var
  writeTVar var (Map.insert relayId queue queues)
  pure queue

-- | Mark a relay's inbound queue closed and drop it, releasing any
-- 'listenerAccept' blocked on it.
unregisterQueue :: CircuitState -> PeerId -> IO ()
unregisterQueue (CircuitState var) relayId = atomically $ do
  queues <- readTVar var
  case Map.lookup relayId queues of
    Nothing -> pure ()
    Just q -> do
      writeTVar (iqClosed q) True
      writeTVar var (Map.delete relayId queues)

-- | Block for the next relayed connection, or throw once the listener is
-- closed so the Switch's accept loop stops.
acceptFrom :: InboundQueue -> IO RawConnection
acceptFrom q = do
  result <- atomically $ do
    closed <- readTVar (iqClosed q)
    if closed
      then pure Nothing
      else Just <$> readTQueue (iqQueue q)
  maybe (fail "circuit listener closed") pure result

-- | Charge a relayed stream against the advertised budget. An inactive
-- budget is returned unchanged; the clock starts here, once hop or stop
-- has completed and the stream is the circuit.
limitedStream :: Maybe RelayLimit -> StreamIO -> IO StreamIO
limitedStream mLimit =
  enforceRelayCircuitLimit (fmap toRelayCircuitLimit mLimit)

-- | Close a stream, ignoring failures from an already-dead session.
closeQuietly :: StreamIO -> IO ()
closeQuietly stream = streamClose stream `catch` \(_ :: SomeException) -> pure ()

-- | Abort with an error, closing the stream we were using first.
failClosing :: StreamIO -> String -> IO a
failClosing stream msg = do
  closeQuietly stream
  throwIO (userError msg)
