-- | GossipSub heartbeat procedure (specs/pubsub/gossipsub).
--
-- The heartbeat runs periodically and performs:
-- 1. Mesh maintenance: prune negative-score, fill undersubscribed, trim oversubscribed
-- 2. Fanout maintenance: expire old, fill undersubscribed
-- 3. Gossip emission: send IHAVE to non-mesh peers, rotate cache
-- 4. Score decay: decay all counters for all peers
-- 5. Seen cache cleanup: remove expired entries
-- 6. Opportunistic grafting, then heartbeat counter increment
module LibP2P.Protocol.GossipSub.Heartbeat
  ( heartbeatOnce
  , runHeartbeat
  ) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.Async (Async, async)
import Control.Concurrent.STM
import Control.Monad (forM_, unless, when)
import Data.ByteString (ByteString)
import Data.List (sort, sortOn)
import Data.Maybe (listToMaybe)
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import Data.Ord (Down (..))
import Data.Time (UTCTime, addUTCTime, diffUTCTime)
import Data.Word (Word64)
import List.Shuffle (sampleIO)
import LibP2P.Crypto.PeerId (PeerId)
import LibP2P.Protocol.GossipSub.Types
import LibP2P.Protocol.GossipSub.IDontWant (expireIDontWantState)
import LibP2P.Protocol.GossipSub.MessageCache (cacheGetGossipIds, cacheShift)
import LibP2P.Protocol.GossipSub.Router (buildPrune)
import LibP2P.Protocol.GossipSub.Score
  ( computeScore
  , decayPeerCounters
  , addP7Penalty
  , refreshMeshTime
  , markPeerInMesh
  , unmarkPeerInMesh
  , captureP3b
  )

-- | Run a single heartbeat cycle. Exported for testing.
heartbeatOnce :: GossipSubRouter -> IO ()
heartbeatOnce router = do
  meshMaintenance router
  opportunisticGraft router
  fanoutMaintenance router
  emitGossip router
  expireIWantPromises router
  decayAllScores router
  expireRetainedScores router
  expireBackoff router
  cleanSeenCache router
  resetGossipBudgets router
  expireIDontWantState router
  -- Increment heartbeat counter
  atomically $ modifyTVar' (gsHeartbeatCount router) (+ 1)

-- | Start the heartbeat background thread.
runHeartbeat :: GossipSubRouter -> IO (Async ())
runHeartbeat router = async $ heartbeatLoop router

heartbeatLoop :: GossipSubRouter -> IO ()
heartbeatLoop router = do
  let intervalUs = round (paramHeartbeatInterval (gsParams router) * 1000000) :: Int
  threadDelay intervalUs
  heartbeatOnce router
  heartbeatLoop router

-- Mesh maintenance

meshMaintenance :: GossipSubRouter -> IO ()
meshMaintenance router = do
  now <- gsGetTime router
  meshMap <- readTVarIO (gsMesh router)
  subs <- readTVarIO (gsSubscriptions router)
  -- Maintain every subscribed topic, not just topics with a mesh entry:
  -- a topic joined with no peers must be filled once peers appear (#155).
  let topics = Set.union subs (Map.keysSet meshMap)
  forM_ (Set.toList topics) $ \topic -> do
    let meshPeers = Map.findWithDefault Set.empty topic meshMap
    -- Step 1: Remove negative-score peers
    remaining <- pruneNegativeScore router topic meshPeers now
    -- Step 2: Fill if undersubscribed (< D_lo)
    filled <- fillUndersubscribed router topic remaining now
    -- Step 3: Trim if oversubscribed (> D_hi)
    trimOversubscribed router topic filled

-- | Remove peers with negative score from mesh, send PRUNE. Direct
-- peers are exempt: explicit peering agreements are never scored out
-- (gossipsub-v1.1.md; they should never be mesh members to begin with).
pruneNegativeScore :: GossipSubRouter -> Topic -> Set.Set PeerId -> UTCTime -> IO (Set.Set PeerId)
pruneNegativeScore router topic meshPeers now = do
  let scoreParams = gsScoreParams router
      direct = paramDirectPeers (gsParams router)
  ipMap <- readTVarIO (gsIPPeerCount router)
  peers <- readTVarIO (gsPeers router)
  let negatives = Set.filter (\pid ->
        not (Set.member pid direct) &&
        case Map.lookup pid peers of
          Nothing -> False
          Just ps -> computeScore scoreParams pid ps ipMap now < 0
        ) meshPeers
  -- Send PRUNE to negative-score peers (no PX for negative-score peers)
  forM_ (Set.toList negatives) $ \pid -> do
    let backoffSecs = round (paramPruneBackoff (gsParams router)) :: Word64
    prn <- buildPrune router pid topic False backoffSecs
    gsSendRPC router pid emptyRPC
      { rpcControl = Just emptyControlMessage { ctrlPrune = [prn] } }
    -- Capture P3b before clearing mesh state, then backoff.
    captureLocalP3b router pid topic now
    atomically $ do
      modifyTVar' (gsBackoff router) $
        Map.insert (pid, topic) (addUTCTime (paramPruneBackoff (gsParams router)) now)
      modifyTVar' (gsPeers router) $
        Map.adjust (unmarkPeerInMesh topic) pid
  -- Update mesh
  let remaining = Set.difference meshPeers negatives
  atomically $ modifyTVar' (gsMesh router) $
    Map.insert topic remaining
  pure remaining

-- | Fill mesh if below D_lo with eligible peers (non-negative score, no backoff).
fillUndersubscribed :: GossipSubRouter -> Topic -> Set.Set PeerId -> UTCTime -> IO (Set.Set PeerId)
fillUndersubscribed router topic meshPeers now = do
  let params = gsParams router
      dlo = paramDlo params
      d   = paramD params
  if Set.size meshPeers >= dlo
    then pure meshPeers
    else do
      -- Find eligible peers: subscribed to topic, not in mesh, not in backoff, score >= 0
      peersMap <- readTVarIO (gsPeers router)
      backoffMap <- readTVarIO (gsBackoff router)
      ipMap <- readTVarIO (gsIPPeerCount router)
      let direct = paramDirectPeers params
          eligible = [ pid | (pid, ps) <- Map.toList peersMap
                           , Set.member topic (psTopics ps)
                           , not (Set.member pid meshPeers)
                           , not (Set.member pid direct)  -- never graft direct peers
                           , psProtocol ps /= FloodSubPeer  -- floodsub peers have no mesh (#157)
                           , not (isInBackoff backoffMap pid topic now)
                           , computeScore (gsScoreParams router) pid ps ipMap now >= 0
                           ]
      let needed = d - Set.size meshPeers
      selected <- sampleIO (min needed (length eligible)) eligible
      -- Send GRAFT and add to mesh
      forM_ selected $ \pid ->
        gsSendRPC router pid emptyRPC
          { rpcControl = Just emptyControlMessage { ctrlGraft = [Graft topic] } }
      let newMesh = Set.union meshPeers (Set.fromList selected)
      atomically $ do
        modifyTVar' (gsMesh router) $ Map.insert topic newMesh
        -- Start the P1 mesh clock for the newly grafted peers
        modifyTVar' (gsPeers router) $ \pm ->
          foldl' (\m pid -> Map.adjust (markPeerInMesh topic now) pid m)
            pm selected
      pure newMesh

-- | Trim mesh if above D_hi down to D peers, send PRUNE with PX.
--
-- Per gossipsub-v1.1.md mesh maintenance: keep the best D_score peers by
-- score, select the rest at random, under the constraint that at least
-- D_out of the kept peers are outbound connections.
trimOversubscribed :: GossipSubRouter -> Topic -> Set.Set PeerId -> IO ()
trimOversubscribed router topic meshPeers = do
  let params = gsParams router
      dhi    = paramDhi params
      d      = paramD params
      dscore = paramDscore params
      dout   = paramDout params
  when (Set.size meshPeers > dhi) $ do
    now <- gsGetTime router
    peersMap <- readTVarIO (gsPeers router)
    ipMap <- readTVarIO (gsIPPeerCount router)
    let scoreOf pid = case Map.lookup pid peersMap of
          Nothing -> 0
          Just ps -> computeScore (gsScoreParams router) pid ps ipMap now
        isOutbound pid = maybe False psIsOutbound (Map.lookup pid peersMap)
        ranked = sortOn (Down . scoreOf) (Set.toList meshPeers)
        (best, rest) = splitAt (min dscore d) ranked
    restKept <- sampleIO (max 0 (d - length best)) rest
    -- keptList is ordered best-first: the score-retained peers, then the
    -- random selection. D_out swaps drop from the tail first.
    let keptList = best ++ restKept
        kept0 = Set.fromList keptList
        outDeficit = max 0 (dout - length (filter isOutbound keptList))
        swapIn = take outDeficit
          (filter (\p -> isOutbound p && not (Set.member p kept0)) ranked)
        swapOut = take (length swapIn)
          (filter (not . isOutbound) (reverse keptList))
        keptSet = Set.union
          (Set.difference kept0 (Set.fromList swapOut))
          (Set.fromList swapIn)
        toRemove = Set.difference meshPeers keptSet
    -- Send PRUNE with peer exchange to removed peers
    forM_ (Set.toList toRemove) $ \pid -> do
      let backoffSecs = round (paramPruneBackoff params) :: Word64
      prn <- buildPrune router pid topic True backoffSecs
      gsSendRPC router pid emptyRPC
        { rpcControl = Just emptyControlMessage { ctrlPrune = [prn] } }
      captureLocalP3b router pid topic now
      atomically $ do
        modifyTVar' (gsBackoff router) $
          Map.insert (pid, topic) (addUTCTime (paramPruneBackoff params) now)
        modifyTVar' (gsPeers router) $
          Map.adjust (unmarkPeerInMesh topic) pid
    -- Update mesh
    atomically $ modifyTVar' (gsMesh router) $
      Map.insert topic keptSet

-- Opportunistic grafting (gossipsub-v1.1.md).
--
-- Every 'paramOpportunisticGraftTicks' heartbeats, for each subscribed
-- topic whose mesh median is below 'stOpportunisticGraftThreshold',
-- GRAFT up to 'paramOpportunisticGraftPeers' peers chosen at random from
-- those with a score strictly above that median. Runs after D_lo fill
-- and D_hi trim so the extras survive this heartbeat and the every-
-- heartbeat fill is unchanged. The counter is still incremented at the
-- end of 'heartbeatOnce': the Nth call (count going from N-1 to N)
-- grafts, matching go-libp2p's pre-increment tick. A mesh of 0 or 1 has
-- no median and is skipped. The median is the upper one (sort ascending,
-- index len/2), not the mean of the two middle scores.

opportunisticGraft :: GossipSubRouter -> IO ()
opportunisticGraft router = do
  let ticks = paramOpportunisticGraftTicks (gsParams router)
  count <- readTVarIO (gsHeartbeatCount router)
  when (ticks > 0 && (count + 1) `mod` ticks == 0) $ do
    subs <- readTVarIO (gsSubscriptions router)
    forM_ (Set.toList subs) $ opportunisticGraftTopic router

opportunisticGraftTopic :: GossipSubRouter -> Topic -> IO ()
opportunisticGraftTopic router topic = do
  now <- gsGetTime router
  meshMap <- readTVarIO (gsMesh router)
  peersMap <- readTVarIO (gsPeers router)
  ipMap <- readTVarIO (gsIPPeerCount router)
  let meshPeers = Map.findWithDefault Set.empty topic meshMap
      scores = map (peerScoreAt router peersMap ipMap now) (Set.toList meshPeers)
  case upperMedian scores of
    Nothing -> pure ()
    Just median ->
      when (median < stOpportunisticGraftThreshold (gsThresholds router)) $
        graftAboveMedian router topic meshPeers median now

-- | Upper median. Nothing for meshes too small to compare against.
upperMedian :: [Double] -> Maybe Double
upperMedian scores
  | n <= 1 = Nothing
  | otherwise = listToMaybe (drop (n `div` 2) (sort scores))
  where
    n = length scores

peerScoreAt
  :: GossipSubRouter
  -> Map.Map PeerId PeerState
  -> Map.Map ByteString (Set.Set PeerId)
  -> UTCTime
  -> PeerId
  -> Double
peerScoreAt router peersMap ipMap now pid =
  case Map.lookup pid peersMap of
    Nothing -> 0
    Just ps -> computeScore (gsScoreParams router) pid ps ipMap now

graftAboveMedian
  :: GossipSubRouter -> Topic -> Set.Set PeerId -> Double -> UTCTime -> IO ()
graftAboveMedian router topic meshPeers median now = do
  let wanted = paramOpportunisticGraftPeers (gsParams router)
  selected <- selectOpportunistic router topic meshPeers median now wanted
  unless (null selected) $ do
    forM_ selected $ \pid ->
      gsSendRPC router pid emptyRPC
        { rpcControl = Just emptyControlMessage { ctrlGraft = [Graft topic] } }
    let newMesh = Set.union meshPeers (Set.fromList selected)
    atomically $ do
      modifyTVar' (gsMesh router) $ Map.insert topic newMesh
      modifyTVar' (gsPeers router) $ \pm ->
        foldl' (\m pid -> Map.adjust (markPeerInMesh topic now) pid m)
          pm selected

selectOpportunistic
  :: GossipSubRouter
  -> Topic
  -> Set.Set PeerId
  -> Double
  -> UTCTime
  -> Int
  -> IO [PeerId]
selectOpportunistic router topic meshPeers median now wanted
  | wanted <= 0 = pure []
  | otherwise = do
      peersMap <- readTVarIO (gsPeers router)
      backoffMap <- readTVarIO (gsBackoff router)
      ipMap <- readTVarIO (gsIPPeerCount router)
      let direct = paramDirectPeers (gsParams router)
          eligible =
            [ pid
            | (pid, ps) <- Map.toList peersMap
            , Set.member topic (psTopics ps)
            , not (Set.member pid meshPeers)
            , not (Set.member pid direct)
            , psProtocol ps /= FloodSubPeer
            , not (isInBackoff backoffMap pid topic now)
            , let score = computeScore (gsScoreParams router) pid ps ipMap now
            , score >= 0
            , score > median
            ]
      if null eligible
        then pure []
        else sampleIO (min wanted (length eligible)) eligible

-- Fanout maintenance

fanoutMaintenance :: GossipSubRouter -> IO ()
fanoutMaintenance router = do
  now <- gsGetTime router
  let ttl = paramFanoutTTL (gsParams router)
  fanoutMap <- readTVarIO (gsFanout router)
  fanoutPubMap <- readTVarIO (gsFanoutPub router)
  forM_ (Map.toList fanoutMap) $ \(topic, fanoutPeers) -> do
    let lastPub = Map.findWithDefault now topic fanoutPubMap
    if diffUTCTime now lastPub > ttl
      then -- Expire fanout entry
        atomically $ do
          modifyTVar' (gsFanout router) (Map.delete topic)
          modifyTVar' (gsFanoutPub router) (Map.delete topic)
      else do
        -- Fill if below D
        let d = paramD (gsParams router)
        when (Set.size fanoutPeers < d) $ do
          peersMap <- readTVarIO (gsPeers router)
          let direct = paramDirectPeers (gsParams router)
              eligible = [ pid | (pid, ps) <- Map.toList peersMap
                               , Set.member topic (psTopics ps)
                               , not (Set.member pid fanoutPeers)
                               , not (Set.member pid direct)
                               , psProtocol ps /= FloodSubPeer  -- flooded, never fanout members (#157)
                               ]
          let needed = d - Set.size fanoutPeers
          selected <- sampleIO (min needed (length eligible)) eligible
          let newFanout = Set.union fanoutPeers (Set.fromList selected)
          atomically $ modifyTVar' (gsFanout router) $
            Map.insert topic newFanout

-- Gossip emission

emitGossip :: GossipSubRouter -> IO ()
emitGossip router = do
  now <- gsGetTime router
  meshMap <- readTVarIO (gsMesh router)
  fanoutMap <- readTVarIO (gsFanout router)
  subs <- readTVarIO (gsSubscriptions router)
  cache <- readTVarIO (gsMessageCache router)
  peersMap <- readTVarIO (gsPeers router)
  ipMap <- readTVarIO (gsIPPeerCount router)
  let params = gsParams router
      -- gossipsub-v1.0.md heartbeat: gossip covers "each topic in
      -- mesh+fanout", so topics we publish to without subscribing
      -- also emit IHAVE (#155).
      topics = Set.unions
        [ subs, Map.keysSet meshMap, Map.keysSet fanoutMap ]

  -- For each topic in mesh+fanout, send IHAVE to non-mesh peers.
  -- The advertised id list is capped at paramMaxIHaveLength (#157).
  forM_ (Set.toList topics) $ \topic -> do
    let gossipIds = take (paramMaxIHaveLength params) (cacheGetGossipIds topic cache)
    unless (null gossipIds) $ do
      let meshPeers = Map.findWithDefault Set.empty topic meshMap
          -- Eligible: subscribed to topic, not in mesh, and scoring at or
          -- above the gossip threshold — no gossip is emitted towards
          -- peers below it (gossipsub-v1.1.md gossip threshold). Floodsub
          -- peers never receive control messages, IHAVE included (#157).
          gossipThreshold = stGossipThreshold (gsThresholds router)
          nonMeshPeers = [ pid | (pid, ps) <- Map.toList peersMap
                               , Set.member topic (psTopics ps)
                               , not (Set.member pid meshPeers)
                               , psProtocol ps /= FloodSubPeer
                               , computeScore (gsScoreParams router) pid ps ipMap now
                                   >= gossipThreshold
                               ]
          -- Select max(D_lazy, |eligible| * gossipFactor) targets
          dlazy = paramDlazy params
          factor = paramGossipFactor params
          targetCount = max dlazy (ceiling (factor * fromIntegral (length nonMeshPeers)))
      targets <- sampleIO (min targetCount (length nonMeshPeers)) nonMeshPeers
      forM_ targets $ \pid ->
        gsSendRPC router pid emptyRPC
          { rpcControl = Just emptyControlMessage
              { ctrlIHave = [IHave topic gossipIds] }
          }

  -- Rotate cache
  atomically $ modifyTVar' (gsMessageCache router) cacheShift

-- IWANT promise expiry (P7)

-- | Penalise peers whose IWANT promises expired without delivery
-- (gossipsub-v1.1.md: a peer that advertises via IHAVE but never sends
-- the requested message commits a behavioural violation).
expireIWantPromises :: GossipSubRouter -> IO ()
expireIWantPromises router = do
  now <- gsGetTime router
  broken <- atomically $ do
    promises <- readTVar (gsIWantPromises router)
    let (expired, live) = Map.partition (<= now) promises
    writeTVar (gsIWantPromises router) live
    pure (map fst (Map.keys expired))
  atomically $ modifyTVar' (gsPeers router) $ \pm ->
    foldl' (\m pid -> Map.adjust addP7Penalty pid m) pm broken

-- IHAVE/IWANT budget reset

-- | Reset the per-peer IHAVE/IWANT flood-protection budgets; the caps in
-- Router.handleIHave / Router.handleIWant apply per heartbeat (#157).
resetGossipBudgets :: GossipSubRouter -> IO ()
resetGossipBudgets router = atomically $ do
  writeTVar (gsIHaveCounts router) Map.empty
  writeTVar (gsIAskedCounts router) Map.empty
  writeTVar (gsIWantServed router) Map.empty

-- Score decay

-- | Refresh accrued mesh time (P1 input) and decay all scoring counters.
decayAllScores :: GossipSubRouter -> IO ()
decayAllScores router = do
  now <- gsGetTime router
  let params = gsScoreParams router
      interval = pspDecayInterval params
  steps <- atomically $ do
    lastTick <- readTVar (gsLastDecay router)
    let elapsed = diffUTCTime now lastTick
        n = if interval <= 0 then 0 else floor (elapsed / interval) :: Int
    when (n > 0) $
      writeTVar (gsLastDecay router) (addUTCTime (fromIntegral n * interval) lastTick)
    pure (max 0 n)
  let decayN 0 ps = ps
      decayN k ps = decayN (k - 1) (decayPeerCounters params ps)
  atomically $ do
    modifyTVar' (gsPeers router) $
      Map.map (decayN steps . refreshMeshTime now)
    -- Counters keep decaying while the score is retained (gossipsub-v1.1.md).
    modifyTVar' (gsRetainedScores router) $
      Map.map (\(ps, expiry) -> (decayN steps ps, expiry))

-- | Capture P3b on a local prune/removal path.
captureLocalP3b :: GossipSubRouter -> PeerId -> Topic -> UTCTime -> IO ()
captureLocalP3b router pid topic now =
  case Map.lookup topic (pspTopicParams (gsScoreParams router)) of
    Nothing -> pure ()
    Just tsp -> atomically $ modifyTVar' (gsPeers router) $
      Map.adjust (\ps ->
        let tps = Map.findWithDefault defaultTopicPeerState topic (psTopicState ps)
            tps' = captureP3b tsp now tps
        in ps { psTopicState = Map.insert topic tps' (psTopicState ps) }
      ) pid

-- | Drop retained scores whose RetainScore window has elapsed.
expireRetainedScores :: GossipSubRouter -> IO ()
expireRetainedScores router = do
  now <- gsGetTime router
  atomically $ modifyTVar' (gsRetainedScores router) $
    Map.filter (\(_, expiry) -> now < expiry)

-- | Physically remove expired (peer, topic) backoff entries.
expireBackoff :: GossipSubRouter -> IO ()
expireBackoff router = do
  now <- gsGetTime router
  atomically $ modifyTVar' (gsBackoff router) $
    Map.filter (\expiry -> now < expiry)

-- Seen cache cleanup

cleanSeenCache :: GossipSubRouter -> IO ()
cleanSeenCache router = do
  now <- gsGetTime router
  let ttl = paramSeenTTL (gsParams router)
  atomically $ modifyTVar' (gsSeen router) $
    Map.filter (\ts -> diffUTCTime now ts <= ttl)

-- Helpers

isInBackoff :: Map.Map (PeerId, Topic) UTCTime -> PeerId -> Topic -> UTCTime -> Bool
isInBackoff backoffMap pid topic now =
  case Map.lookup (pid, topic) backoffMap of
    Nothing -> False
    Just expires -> now < expires
