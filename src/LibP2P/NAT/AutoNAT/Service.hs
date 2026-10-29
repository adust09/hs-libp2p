{- | Background AutoNAT v1 reachability probing.

The client only probes peers that already have a direct connection. It never
dials a peer merely to ask for a dial-back, bounds each request with a
timeout, probes one peer at a time, and throttles repeated requests to the
same peer.
-}
module LibP2P.NAT.AutoNAT.Service (
  AutoNATClientConfig (..),
  defaultAutoNATClientConfig,
  AutoNATClientService,
  startAutoNATClient,
  autoNATClientStatus,
  stopAutoNATClient,
) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.Async (Async, async, cancel)
import Control.Concurrent.STM (
  TVar,
  atomically,
  newTVarIO,
  readTVar,
  writeTVar,
 )
import Control.Exception (
  SomeAsyncException,
  SomeException,
  fromException,
  tryJust,
 )
import Control.Monad (filterM, forever)
import Data.Map.Strict qualified as Map
import Data.Time.Clock (UTCTime, diffUTCTime, getCurrentTime)
import LibP2P.Crypto.PeerId (PeerId)
import LibP2P.Multiaddr (Multiaddr, isRelayedAddr)
import LibP2P.MultistreamSelect.Negotiation (
  NegotiationResult (..),
  closeQuietly,
  negotiateInitiator,
 )
import LibP2P.NAT.AutoNAT (
  NATStatus (..),
  probeNATStatusPure,
  requestAutoNAT,
 )
import LibP2P.NAT.AutoNAT.Message (
  AutoNATDialResponse,
  autoNATProtocolId,
 )
import LibP2P.Switch (registerSwitchShutdownAction)
import LibP2P.Switch.ConnPool (allConns)
import LibP2P.Switch.Connection (newStream)
import LibP2P.Switch.Listen (switchListenAddrs)
import LibP2P.Switch.Types (
  ConnState (..),
  Connection (..),
  Switch (..),
 )
import System.Timeout (timeout)

-- | AutoNAT client scheduling and resource bounds.
data AutoNATClientConfig = AutoNATClientConfig
  { ancThreshold :: !Int
  -- ^ A status requires strictly more agreeing reports than this value.
  , ancBootDelayMicros :: !Int
  -- ^ Delay before the first probe cycle.
  , ancRetryIntervalMicros :: !Int
  -- ^ Delay while reachability is unknown.
  , ancRefreshIntervalMicros :: !Int
  -- ^ Delay after reaching a public or private decision.
  , ancRequestTimeoutMicros :: !Int
  -- ^ Timeout for one peer's complete stream negotiation and request.
  , ancPeerThrottleMicros :: !Int
  -- ^ Minimum interval before probing the same peer again.
  , ancMaxPeers :: !Int
  {- ^ Maximum peers queried in one cycle. Requests are sequential, so the
  number of outstanding requests is always at most one.
  -}
  }
  deriving (Show, Eq)

{- | go-libp2p scheduling defaults, with four peers per cycle to satisfy the
AutoNAT v1 requirement for more than three agreeing dial reports.
-}
defaultAutoNATClientConfig :: AutoNATClientConfig
defaultAutoNATClientConfig =
  AutoNATClientConfig
    { ancThreshold = 3
    , ancBootDelayMicros = 15 * second
    , ancRetryIntervalMicros = 90 * second
    , ancRefreshIntervalMicros = 15 * minute
    , ancRequestTimeoutMicros = 30 * second
    , ancPeerThrottleMicros = 90 * second
    , ancMaxPeers = 4
    }
 where
  second = 1000000
  minute = 60 * second

-- | Handle for observing and stopping the background client.
data AutoNATClientService = AutoNATClientService
  { acsStatus :: !(TVar NATStatus)
  , acsWorker :: !(Async ())
  }

-- | Start periodic reachability probing and attach its lifetime to the Switch.
startAutoNATClient :: Switch -> AutoNATClientConfig -> IO AutoNATClientService
startAutoNATClient sw config = do
  validateConfig config
  status <- newTVarIO NATUnknown
  recent <- newTVarIO Map.empty
  worker <- async (clientLoop sw config status recent)
  let service = AutoNATClientService status worker
  registerSwitchShutdownAction sw (stopAutoNATClient service)
  pure service

-- | Read the most recently aggregated reachability status.
autoNATClientStatus :: AutoNATClientService -> IO NATStatus
autoNATClientStatus service = atomically $ readTVar (acsStatus service)

-- | Stop the client and cancel any in-flight request.
stopAutoNATClient :: AutoNATClientService -> IO ()
stopAutoNATClient = cancel . acsWorker

validateConfig :: AutoNATClientConfig -> IO ()
validateConfig config
  | ancThreshold config < 0 = invalid "threshold must be non-negative"
  | ancBootDelayMicros config < 0 = invalid "boot delay must be non-negative"
  | ancRetryIntervalMicros config < 0 = invalid "retry interval must be non-negative"
  | ancRefreshIntervalMicros config < 0 = invalid "refresh interval must be non-negative"
  | ancRequestTimeoutMicros config <= 0 = invalid "request timeout must be positive"
  | ancPeerThrottleMicros config < 0 = invalid "peer throttle must be non-negative"
  | ancMaxPeers config <= ancThreshold config =
      invalid "max peers must be greater than the decision threshold"
  | otherwise = pure ()
 where
  invalid = ioError . userError . ("invalid AutoNAT client configuration: " ++)

clientLoop ::
  Switch ->
  AutoNATClientConfig ->
  TVar NATStatus ->
  TVar (Map.Map PeerId UTCTime) ->
  IO ()
clientLoop sw config status recent = do
  threadDelay (ancBootDelayMicros config)
  forever $ do
    result <- runProbeCycle sw config recent
    atomically $ writeTVar status result
    threadDelay $ case result of
      NATUnknown -> ancRetryIntervalMicros config
      _ -> ancRefreshIntervalMicros config

runProbeCycle ::
  Switch ->
  AutoNATClientConfig ->
  TVar (Map.Map PeerId UTCTime) ->
  IO NATStatus
runProbeCycle sw config recentVar = do
  now <- getCurrentTime
  connections <- connectedProbeCandidates sw
  recent <- atomically $ readTVar recentVar
  let eligible =
        take
          (ancMaxPeers config)
          (filter (not . throttled config now recent . connPeerId) connections)
      updated = foldr (\conn -> Map.insert (connPeerId conn) now) recent eligible
  atomically $ writeTVar recentVar (pruneRecent config now updated)
  addrs <- switchListenAddrs sw
  results <- mapM (probePeer sw config addrs) eligible
  pure (probeNATStatusPure (ancThreshold config) results)

connectedProbeCandidates :: Switch -> IO [Connection]
connectedProbeCandidates sw = atomically $ do
  connections <- allConns (swConnPool sw)
  openDirect <- filterM isOpenDirect connections
  pure (Map.elems (Map.fromList [(connPeerId conn, conn) | conn <- openDirect]))
 where
  isOpenDirect conn = do
    state <- readTVar (connState conn)
    pure (state == ConnOpen && not (isRelayedAddr (connRemoteAddr conn)))

probePeer ::
  Switch ->
  AutoNATClientConfig ->
  [Multiaddr] ->
  Connection ->
  IO (Either String AutoNATDialResponse)
probePeer sw config addrs conn = do
  outcome <- tryJust synchronousException $ timeout (ancRequestTimeoutMicros config) $ do
    opened <- newStream sw conn
    case opened of
      Left err -> pure (Left (show err))
      Right stream -> do
        negotiated <- negotiateInitiator stream [autoNATProtocolId]
        case negotiated of
          NoProtocol -> closeQuietly stream >> pure (Left "peer does not support AutoNAT v1")
          Accepted _ -> requestAutoNAT stream (swLocalPeerId sw) addrs
  pure $ case outcome of
    Left (err :: SomeException) -> Left (show err)
    Right Nothing -> Left "AutoNAT request timed out"
    Right (Just result) -> result

throttled ::
  AutoNATClientConfig ->
  UTCTime ->
  Map.Map PeerId UTCTime ->
  PeerId ->
  Bool
throttled config now recent peerId =
  case Map.lookup peerId recent of
    Nothing -> False
    Just probedAt -> elapsedMicros now probedAt < ancPeerThrottleMicros config

pruneRecent ::
  AutoNATClientConfig ->
  UTCTime ->
  Map.Map PeerId UTCTime ->
  Map.Map PeerId UTCTime
pruneRecent config now = Map.filter $ \probedAt ->
  elapsedMicros now probedAt < ancPeerThrottleMicros config

synchronousException :: SomeException -> Maybe SomeException
synchronousException err = case fromException err :: Maybe SomeAsyncException of
  Just _ -> Nothing
  Nothing -> Just err

elapsedMicros :: UTCTime -> UTCTime -> Int
elapsedMicros later earlier = floor (realToFrac (diffUTCTime later earlier) * (1000000 :: Double))
