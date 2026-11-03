-- | Generic application-defined GossipSub partial-message runtime.
module LibP2P.Protocol.GossipSub.PartialMessages
  ( PartialMessagesExtension
  , PartialMessagesConfig (..)
  , PartialCallbackResult (..)
  , PartialPublishAction (..)
  , PartialPublishPlan
  , PartialMessagesError (..)
  , defaultPartialMessagesConfig
  , newPartialMessagesExtension
  , installPartialMessages
  , partialMeshPeers
  , partialPeerRequests
  , publishPartial
  ) where

import Control.Concurrent.MVar
import Control.Concurrent.STM
import Control.Exception (Exception)
import Control.Monad (foldM, forM, forM_, unless)
import Data.ByteString (ByteString)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (fromMaybe, isJust, isNothing)
import qualified Data.Set as Set
import LibP2P.Crypto.PeerId (PeerId)
import LibP2P.Protocol.GossipSub.Extensions
  ( localPartialMode
  , peerRequestsPartial
  , peerSupportsPartialExtension
  , peerSupportsSendingPartial
  )
import LibP2P.Protocol.GossipSub.Types

-- | Application callbacks and bounded-state limits.
--
-- Callbacks are serialized with partial-message state updates. They should
-- return sends through 'partialPublishActions' rather than recursively calling
-- 'publishPartial'.
data PartialMessagesConfig state = PartialMessagesConfig
  { partialInitialPeerState :: !state
  , partialOnIncoming ::
      !(PeerId -> Map PeerId state -> PartialMessage -> IO (PartialCallbackResult state))
    -- ^ Handle an inbound group update, regardless of mesh membership.
  , partialOnEmitGossip ::
      !(Topic -> ByteString -> [PeerId] -> Map PeerId state -> IO (PartialCallbackResult state))
    -- ^ Initialize newly selected gossip peers for a locally initiated group.
  , partialGroupTTLHeartbeats :: !Int
  , partialPeerGroupLimitPerTopic :: !Int
  , partialPeerGroupLimitPerTopicPerPeer :: !Int
  }

-- | Updated application state plus per-peer messages to send.
data PartialCallbackResult state = PartialCallbackResult
  { partialUpdatedPeerStates :: !(Map PeerId state)
  , partialPublishActions :: ![PartialPublishAction]
  }

-- | One application-defined partial-message send.
data PartialPublishAction = PartialPublishAction
  { partialActionPeer :: !PeerId
  , partialActionMessage :: !(Maybe ByteString)
  , partialActionMetadata :: !(Maybe ByteString)
  }
  deriving (Show, Eq)

-- | Plan sends for a locally published or updated group. The predicate reports
-- whether a peer requested partial data; metadata-only peers return False.
type PartialPublishPlan state =
  Map PeerId state ->
  (PeerId -> Bool) ->
  IO (PartialCallbackResult state)

-- | Configuration and lifecycle errors exposed to callers.
data PartialMessagesError
  = PartialMessagesAlreadyInstalled
  | PartialMessagesNodeStarted
  | PartialMessagesNotInstalled
  | PartialMessagesNotEnabledForTopic
  deriving (Show, Eq)

instance Exception PartialMessagesError

data PartialMessagesExtension state = PartialMessagesExtension
  { pmeConfig :: !(PartialMessagesConfig state)
  , pmeState :: !(MVar (PartialRuntimeState state))
  , pmeRouter :: !(MVar (Maybe GossipSubRouter))
  }

data PartialRuntimeState state = PartialRuntimeState
  { prsGroups :: !(Map Topic (Map ByteString (PartialGroupState state)))
  , prsCounters :: !(Map Topic PeerGroupCounter)
  }

data PartialGroupState state = PartialGroupState
  { pgsPeerStates :: !(Map PeerId state)
  , pgsTTL :: !Int
  , pgsInitiatedBy :: !(Maybe PeerId)
  }

data PeerGroupCounter = PeerGroupCounter
  { pgcTotal :: !Int
  , pgcPerPeer :: !(Map PeerId Int)
  }

-- | Go-compatible defaults for group state limits and lifetime.
defaultPartialMessagesConfig ::
  state ->
  (PeerId -> Map PeerId state -> PartialMessage -> IO (PartialCallbackResult state)) ->
  (Topic -> ByteString -> [PeerId] -> Map PeerId state -> IO (PartialCallbackResult state)) ->
  PartialMessagesConfig state
defaultPartialMessagesConfig initial onIncoming onGossip =
  PartialMessagesConfig
    { partialInitialPeerState = initial
    , partialOnIncoming = onIncoming
    , partialOnEmitGossip = onGossip
    , partialGroupTTLHeartbeats = 3
    , partialPeerGroupLimitPerTopic = 255
    , partialPeerGroupLimitPerTopicPerPeer = 8
    }

newPartialMessagesExtension ::
  PartialMessagesConfig state -> IO (PartialMessagesExtension state)
newPartialMessagesExtension config =
  PartialMessagesExtension config
    <$> newMVar (PartialRuntimeState Map.empty Map.empty)
    <*> newMVar Nothing

-- | Attach one partial-message runtime to a router.
installPartialMessages ::
  GossipSubRouter ->
  PartialMessagesExtension state ->
  IO (Either PartialMessagesError ())
installPartialMessages router extension = modifyMVar (pmeRouter extension) $ \installed ->
  case installed of
    Just _ -> pure (installed, Left PartialMessagesAlreadyInstalled)
    Nothing -> do
      claimed <- atomically $ claimHooks router hooks
      if claimed
        then pure (Just router, Right ())
        else pure (Nothing, Left PartialMessagesAlreadyInstalled)
 where
  hooks =
    PartialMessagesHooks
      { pmhHandleRPC = handleIncoming extension router
      , pmhHeartbeat = heartbeat extension
      , pmhEmitGossip = emitGossip extension router
      , pmhPeerDisconnected = peerDisconnected extension
      }

claimHooks :: GossipSubRouter -> PartialMessagesHooks -> STM Bool
claimHooks router hooks = do
  current <- readTVar (gsPartialMessagesHooks router)
  if isJust current
    then pure False
    else writeTVar (gsPartialMessagesHooks router) (Just hooks) >> pure True

-- | Compatible mesh/fanout peers for an enabled topic.
partialMeshPeers ::
  PartialMessagesExtension state ->
  Topic ->
  IO (Either PartialMessagesError [PeerId])
partialMeshPeers extension topic = do
  installed <- readMVar (pmeRouter extension)
  case installed of
    Nothing -> pure (Left PartialMessagesNotInstalled)
    Just router -> Right <$> eligiblePeers router topic

-- | Whether a peer requested partial data for a topic.
partialPeerRequests ::
  PartialMessagesExtension state -> PeerId -> Topic -> IO Bool
partialPeerRequests extension pid topic = do
  installed <- readMVar (pmeRouter extension)
  maybe (pure False) (\router -> peerRequestsPartial router pid topic) installed

-- | Publish or update one application-defined partial-message group. The
-- application owns the encoding of data and metadata; this runtime only routes
-- the opaque bytes and bounds group state.
publishPartial ::
  PartialMessagesExtension state ->
  Topic ->
  ByteString ->
  PartialPublishPlan state ->
  IO (Either PartialMessagesError ())
publishPartial extension topic groupId plan = do
  installed <- readMVar (pmeRouter extension)
  case installed of
    Nothing -> pure (Left PartialMessagesNotInstalled)
    Just router -> do
      mode <- localPartialMode router topic
      case mode of
        Nothing -> pure (Left PartialMessagesNotEnabledForTopic)
        Just _ -> do
          eligible <- eligiblePeers router topic
          requesting <- filterMFor eligible $ \pid ->
            peerRequestsPartial router pid topic
          actions <- modifyMVar (pmeState extension) $ \runtime ->
            publishGroup extension runtime topic groupId eligible requesting plan
          sendActions router topic groupId actions
          pure (Right ())

publishGroup ::
  PartialMessagesExtension state ->
  PartialRuntimeState state ->
  Topic ->
  ByteString ->
  [PeerId] ->
  [PeerId] ->
  PartialPublishPlan state ->
  IO (PartialRuntimeState state, [PartialPublishAction])
publishGroup extension runtime topic groupId eligible requesting plan = do
  let config = pmeConfig extension
      (runtime', group) = localGroup config runtime topic groupId
      peers = initializePeers config eligible (pgsPeerStates group)
      requested pid = pid `elem` requesting
  result <- plan peers requested
  let updated =
        group
          { pgsPeerStates = partialUpdatedPeerStates result
          , pgsTTL = groupTTL config
          , pgsInitiatedBy = Nothing
          }
      finalState = putGroup topic groupId updated runtime'
  pure (finalState, partialPublishActions result)

handleIncoming ::
  PartialMessagesExtension state ->
  GossipSubRouter ->
  PeerId ->
  PartialMessage ->
  IO Bool
handleIncoming extension router sender partial = do
  violation <- invalidIncoming router partial
  if violation
    then pure True
    else do
      eligible <- eligiblePeers router (partialTopicId partial)
      outcome <- modifyMVar (pmeState extension) $ \runtime ->
        receiveGroup extension runtime sender eligible partial
      case outcome of
        Left () -> pure True
        Right actions -> do
          sendActions router (partialTopicId partial) (partialGroupId partial) actions
          pure False

invalidIncoming :: GossipSubRouter -> PartialMessage -> IO Bool
invalidIncoming router partial = do
  mode <- localPartialMode router (partialTopicId partial)
  pure $ case mode of
    Nothing -> True
    Just RequestsPartialMessages -> False
    Just SupportsPartialMessages -> isJust (partialMessageData partial)

receiveGroup ::
  PartialMessagesExtension state ->
  PartialRuntimeState state ->
  PeerId ->
  [PeerId] ->
  PartialMessage ->
  IO (PartialRuntimeState state, Either () [PartialPublishAction])
receiveGroup extension runtime sender eligible partial =
  case remoteGroup config runtime topic groupId sender of
    Left () -> pure (runtime, Left ())
    Right (runtime', group) -> do
      let peers =
            Map.insertWith
              (\_ old -> old)
              sender
              (partialInitialPeerState config)
              (initializePeers config eligible (pgsPeerStates group))
      result <- partialOnIncoming config sender peers partial
      let updated = group{pgsPeerStates = partialUpdatedPeerStates result}
      pure (putGroup topic groupId updated runtime', Right (partialPublishActions result))
 where
  config = pmeConfig extension
  topic = partialTopicId partial
  groupId = partialGroupId partial

emitGossip ::
  PartialMessagesExtension state ->
  GossipSubRouter ->
  Topic ->
  [PeerId] ->
  IO ()
emitGossip extension router topic candidates = do
  eligible <- filterEligible router topic candidates
  actions <- modifyMVar (pmeState extension) $ \runtime ->
    gossipGroups extension runtime topic eligible
  forM_ actions (uncurry (sendActions router topic))

gossipGroups ::
  PartialMessagesExtension state ->
  PartialRuntimeState state ->
  Topic ->
  [PeerId] ->
  IO (PartialRuntimeState state, [(ByteString, [PartialPublishAction])])
gossipGroups extension runtime topic eligible = do
  let groups = Map.findWithDefault Map.empty topic (prsGroups runtime)
  (updated, sends) <-
    foldM
      (gossipGroup extension topic eligible)
      (groups, [])
      (Map.toList groups)
  pure (runtime{prsGroups = Map.insert topic updated (prsGroups runtime)}, reverse sends)

gossipGroup ::
  PartialMessagesExtension state ->
  Topic ->
  [PeerId] ->
  (Map ByteString (PartialGroupState state), [(ByteString, [PartialPublishAction])]) ->
  (ByteString, PartialGroupState state) ->
  IO (Map ByteString (PartialGroupState state), [(ByteString, [PartialPublishAction])])
gossipGroup extension topic eligible (groups, sends) (groupId, group)
  | isJust (pgsInitiatedBy group) = pure (groups, sends)
  | null newPeers = pure (groups, sends)
  | otherwise = do
      let config = pmeConfig extension
          peers = initializePeers config newPeers (pgsPeerStates group)
      result <- partialOnEmitGossip config topic groupId newPeers peers
      let updated = group{pgsPeerStates = partialUpdatedPeerStates result}
      pure
        ( Map.insert groupId updated groups
        , (groupId, partialPublishActions result) : sends
        )
 where
  newPeers = filter (`Map.notMember` pgsPeerStates group) eligible

heartbeat :: PartialMessagesExtension state -> IO ()
heartbeat extension = modifyMVar_ (pmeState extension) $ \runtime ->
  pure (ageRuntime runtime)

peerDisconnected :: PartialMessagesExtension state -> PeerId -> IO ()
peerDisconnected extension pid = modifyMVar_ (pmeState extension) $ \runtime ->
  pure (dropDisconnectedPeer pid runtime)

dropDisconnectedPeer ::
  PeerId -> PartialRuntimeState state -> PartialRuntimeState state
dropDisconnectedPeer pid runtime =
  foldr cleanTopic withoutPeer (Map.toList (prsGroups withoutPeer))
 where
  withoutPeer =
    runtime
      { prsGroups = Map.map (Map.map dropPeer) (prsGroups runtime)
      , prsCounters = Map.map (removePeerCount pid) (prsCounters runtime)
      }
  dropPeer group = group{pgsPeerStates = Map.delete pid (pgsPeerStates group)}

cleanTopic ::
  (Topic, Map ByteString (PartialGroupState state)) ->
  PartialRuntimeState state ->
  PartialRuntimeState state
cleanTopic (topic, groups) runtime =
  let (runtime', live) =
        Map.foldrWithKey
          (keepNonEmpty topic)
          (runtime, Map.empty)
          groups
   in if Map.null live
        then
          runtime'
            { prsGroups = Map.delete topic (prsGroups runtime')
            , prsCounters = Map.delete topic (prsCounters runtime')
            }
        else runtime'{prsGroups = Map.insert topic live (prsGroups runtime')}

keepNonEmpty ::
  Topic ->
  ByteString ->
  PartialGroupState state ->
  (PartialRuntimeState state, Map ByteString (PartialGroupState state)) ->
  (PartialRuntimeState state, Map ByteString (PartialGroupState state))
keepNonEmpty topic groupId group (runtime, live)
  | Map.null (pgsPeerStates group) =
      (maybe runtime (\pid -> decrementCounter topic pid runtime) (pgsInitiatedBy group), live)
  | otherwise = (runtime, Map.insert groupId group live)

eligiblePeers :: GossipSubRouter -> Topic -> IO [PeerId]
eligiblePeers router topic = do
  mesh <- readTVarIO (gsMesh router)
  fanout <- readTVarIO (gsFanout router)
  let meshPeers = Map.findWithDefault Set.empty topic mesh
      candidates =
        if Set.null meshPeers
          then Map.findWithDefault Set.empty topic fanout
          else meshPeers
  filterEligible router topic (Set.toList candidates)

filterEligible :: GossipSubRouter -> Topic -> [PeerId] -> IO [PeerId]
filterEligible router topic peers = do
  mode <- localPartialMode router topic
  filterMFor peers $ \pid -> do
    extension <- peerSupportsPartialExtension router pid
    relation <- case mode of
      Just RequestsPartialMessages -> peerSupportsSendingPartial router pid topic
      Just SupportsPartialMessages -> peerRequestsPartial router pid topic
      Nothing -> pure False
    pure (extension && relation)

filterMFor :: [a] -> (a -> IO Bool) -> IO [a]
filterMFor values predicate = do
  pairs <- forM values $ \value -> do
    keep <- predicate value
    pure (value, keep)
  pure [value | (value, keep) <- pairs, keep]

sendActions ::
  GossipSubRouter -> Topic -> ByteString -> [PartialPublishAction] -> IO ()
sendActions router topic groupId actions =
  forM_ actions $ \action -> do
    extension <- peerSupportsPartialExtension router (partialActionPeer action)
    requests <- peerRequestsPartial router (partialActionPeer action) topic
    supports <- peerSupportsSendingPartial router (partialActionPeer action) topic
    let message = if extension && requests then partialActionMessage action else Nothing
        metadata = if extension && supports then partialActionMetadata action else Nothing
    unless (isNothing message && isNothing metadata) $
      gsSendRPC
        router
        (partialActionPeer action)
        emptyRPC
          { rpcPartial =
              Just
                PartialMessage
                  { partialTopicId = topic
                  , partialGroupId = groupId
                  , partialMessageData = message
                  , partialPartsMetadata = metadata
                  }
          }

localGroup ::
  PartialMessagesConfig state ->
  PartialRuntimeState state ->
  Topic ->
  ByteString ->
  (PartialRuntimeState state, PartialGroupState state)
localGroup config runtime topic groupId =
  case lookupGroup runtime topic groupId of
    Just group
      | Just initiator <- pgsInitiatedBy group ->
          (decrementCounter topic initiator runtime, group)
    Just group -> (runtime, group)
    Nothing -> (runtime, emptyGroup config Nothing)

remoteGroup ::
  PartialMessagesConfig state ->
  PartialRuntimeState state ->
  Topic ->
  ByteString ->
  PeerId ->
  Either () (PartialRuntimeState state, PartialGroupState state)
remoteGroup config runtime topic groupId sender =
  case lookupGroup runtime topic groupId of
    Just group -> Right (runtime, group)
    Nothing -> do
      counter <-
        incrementCounter
          config
          sender
          (Map.findWithDefault emptyCounter topic (prsCounters runtime))
      let updated =
            runtime
              { prsCounters = Map.insert topic counter (prsCounters runtime)
              }
      Right (updated, emptyGroup config (Just sender))

lookupGroup ::
  PartialRuntimeState state -> Topic -> ByteString -> Maybe (PartialGroupState state)
lookupGroup runtime topic groupId =
  Map.lookup topic (prsGroups runtime) >>= Map.lookup groupId

putGroup ::
  Topic ->
  ByteString ->
  PartialGroupState state ->
  PartialRuntimeState state ->
  PartialRuntimeState state
putGroup topic groupId group runtime =
  runtime
    { prsGroups = Map.alter insertTopic topic (prsGroups runtime)
    }
 where
  insertTopic = Just . Map.insert groupId group . fromMaybe Map.empty

emptyGroup ::
  PartialMessagesConfig state -> Maybe PeerId -> PartialGroupState state
emptyGroup config = PartialGroupState Map.empty (groupTTL config)

groupTTL :: PartialMessagesConfig state -> Int
groupTTL = max 3 . partialGroupTTLHeartbeats

initializePeers ::
  PartialMessagesConfig state -> [PeerId] -> Map PeerId state -> Map PeerId state
initializePeers config peers states = foldr insertInitial states peers
 where
  insertInitial pid = Map.insertWith (\_ old -> old) pid (partialInitialPeerState config)

incrementCounter ::
  PartialMessagesConfig state -> PeerId -> PeerGroupCounter -> Either () PeerGroupCounter
incrementCounter config pid counter
  | pgcTotal counter >= max 0 (partialPeerGroupLimitPerTopic config) = Left ()
  | peerCount >= max 0 (partialPeerGroupLimitPerTopicPerPeer config) = Left ()
  | otherwise =
      Right
        counter
          { pgcTotal = pgcTotal counter + 1
          , pgcPerPeer = Map.insert pid (peerCount + 1) (pgcPerPeer counter)
          }
 where
  peerCount = Map.findWithDefault 0 pid (pgcPerPeer counter)

decrementCounter ::
  Topic -> PeerId -> PartialRuntimeState state -> PartialRuntimeState state
decrementCounter topic pid runtime =
  runtime
    { prsCounters = Map.adjust (removeOne pid) topic (prsCounters runtime)
    }

removeOne :: PeerId -> PeerGroupCounter -> PeerGroupCounter
removeOne pid counter =
  case Map.lookup pid (pgcPerPeer counter) of
    Nothing -> counter
    Just count ->
      counter
        { pgcTotal = max 0 (pgcTotal counter - 1)
        , pgcPerPeer =
            if count <= 1
              then Map.delete pid (pgcPerPeer counter)
              else Map.insert pid (count - 1) (pgcPerPeer counter)
        }

removePeerCount :: PeerId -> PeerGroupCounter -> PeerGroupCounter
removePeerCount pid counter =
  counter
    { pgcTotal = max 0 (pgcTotal counter - count)
    , pgcPerPeer = Map.delete pid (pgcPerPeer counter)
    }
 where
  count = Map.findWithDefault 0 pid (pgcPerPeer counter)

ageRuntime :: PartialRuntimeState state -> PartialRuntimeState state
ageRuntime runtime = foldr ageTopic runtime (Map.toList (prsGroups runtime))

ageTopic ::
  (Topic, Map ByteString (PartialGroupState state)) ->
  PartialRuntimeState state ->
  PartialRuntimeState state
ageTopic (topic, groups) runtime =
  let (runtime', live) = Map.foldrWithKey (ageGroup topic) (runtime, Map.empty) groups
      groupMap =
        if Map.null live
          then Map.delete topic (prsGroups runtime')
          else Map.insert topic live (prsGroups runtime')
      counters =
        if Map.null live
          then Map.delete topic (prsCounters runtime')
          else prsCounters runtime'
   in runtime'{prsGroups = groupMap, prsCounters = counters}

ageGroup ::
  Topic ->
  ByteString ->
  PartialGroupState state ->
  (PartialRuntimeState state, Map ByteString (PartialGroupState state)) ->
  (PartialRuntimeState state, Map ByteString (PartialGroupState state))
ageGroup topic groupId group (runtime, live)
  | pgsTTL group <= 0 || Map.null (pgsPeerStates group) =
      (maybe runtime (\pid -> decrementCounter topic pid runtime) (pgsInitiatedBy group), live)
  | otherwise =
      (runtime, Map.insert groupId group{pgsTTL = pgsTTL group - 1} live)

emptyCounter :: PeerGroupCounter
emptyCounter = PeerGroupCounter 0 Map.empty
