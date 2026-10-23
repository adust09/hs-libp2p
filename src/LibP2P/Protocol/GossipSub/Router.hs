-- | GossipSub mesh management: JOIN, LEAVE, GRAFT/PRUNE, message forwarding.
--
-- The router manages the mesh overlay and handles inbound/outbound
-- RPC messages. For testability, peer communication is injectable
-- via gsSendRPC on GossipSubRouter.
module LibP2P.Protocol.GossipSub.Router
  ( -- * Construction
    newRouter
    -- * Peer management
  , addPeer
  , removePeer
  , setPeerIP
  , setSignedPeerRecord
    -- * Topic subscription
  , join
  , leave
    -- * Publishing
  , publish
    -- * Topic validation
  , registerValidator
  , unregisterValidator
    -- * Inbound RPC handling
  , handleRPC
    -- * Control message handlers
  , handleGraft
  , handlePrune
  , handleIHave
  , handleIWant
  , handleSubscriptions
    -- * Message forwarding
  , forwardMessage
    -- * Scoring
  , peerScore
    -- * Peer exchange
  , selectPXPeers
    -- * Version-gated PRUNE construction
  , buildPrune
  ) where

import Prelude
import Control.Exception (throwIO)
import Control.Monad (unless, when)
import Control.Concurrent.STM
import Data.ByteString (ByteString)
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import Data.Time (UTCTime, addUTCTime, diffUTCTime)
import Data.Word (Word64)
import Crypto.Random (getRandomBytes)
import List.Shuffle (sampleIO)
import LibP2P.Crypto.PeerId (PeerId, peerIdBytes)
import LibP2P.Crypto.PeerRecord (PeerRecord (..), openPeerRecordEnvelope)
import LibP2P.Crypto.Key (KeyPair (..), sign)
import LibP2P.Crypto.Protobuf (encodePublicKey)
import LibP2P.Protocol.GossipSub.Types
import LibP2P.Protocol.GossipSub.IDontWant
  ( announceIDontWant
  , filterAllowedPeers
  , handleIDontWant
  , peerRejectsMessage
  )
import LibP2P.Protocol.GossipSub.MessageCache (newMessageCache, cachePut, cacheGet)
import LibP2P.Protocol.GossipSub.Score
  ( computeScore
  , addP7Penalty
  , captureP3b
  , recordInvalidMessage
  , recordFirstDelivery
  , recordMeshDelivery
  , markPeerInMesh
  , unmarkPeerInMesh
  )
import LibP2P.Protocol.GossipSub.Validation (validateMessage, signingBytes)

-- | Create a new GossipSub router with empty state.
newRouter :: GossipSubParams
          -> PeerId
          -> (PeerId -> RPC -> IO ())   -- ^ RPC sender
          -> IO UTCTime                 -- ^ Time source
          -> IO GossipSubRouter
newRouter params localPid sendRPC getTime = do
  subs     <- newTVarIO Set.empty
  mesh     <- newTVarIO Map.empty
  fanout   <- newTVarIO Map.empty
  fanoutPub <- newTVarIO Map.empty
  peers    <- newTVarIO Map.empty
  seen     <- newTVarIO Map.empty
  backoff  <- newTVarIO Map.empty
  retained <- newTVarIO Map.empty
  now0     <- getTime
  lastDecay <- newTVarIO now0
  ipCount  <- newTVarIO Map.empty
  mcache   <- newTVarIO (newMessageCache (paramMcacheLen params) (paramMcacheGossip params))
  hbCount  <- newTVarIO 0
  onMsg    <- newTVarIO (\_ _ -> pure ())
  validators <- newTVarIO Map.empty
  promises <- newTVarIO Map.empty
  ihaveCounts <- newTVarIO Map.empty
  iaskedCounts <- newTVarIO Map.empty
  iwantServed <- newTVarIO Map.empty
  idontwantCounts <- newTVarIO Map.empty
  dontSendMessageIds <- newTVarIO Map.empty
  onPX     <- newTVarIO (\_ _ -> pure ())
  signedRecords <- newTVarIO Map.empty
  pure GossipSubRouter
    { gsParams         = params
    , gsLocalPeerId    = localPid
    , gsSubscriptions  = subs
    , gsMesh           = mesh
    , gsFanout         = fanout
    , gsFanoutPub      = fanoutPub
    , gsPeers          = peers
    , gsSeen           = seen
    , gsBackoff        = backoff
    , gsRetainedScores = retained
    , gsLastDecay      = lastDecay
    , gsScoreParams    = defaultPeerScoreParams
    , gsThresholds     = defaultScoreThresholds
    , gsIPPeerCount    = ipCount
    , gsIWantPromises  = promises
    , gsIHaveCounts    = ihaveCounts
    , gsIAskedCounts   = iaskedCounts
    , gsIWantServed    = iwantServed
    , gsIDontWantCounts = idontwantCounts
    , gsDontSendMessageIds = dontSendMessageIds
    , gsMessageCache   = mcache
    , gsHeartbeatCount = hbCount
    , gsSendRPC        = sendRPC
    , gsGetTime        = getTime
    , gsOnMessage      = onMsg
    , gsValidators     = validators
    , gsOnPeerExchange = onPX
    , gsSignedPeerRecords = signedRecords
    }

-- Topic validation

-- | Attach an application validator to a topic. Messages the validator
-- rejects are dropped without propagation and count against the sender's
-- P4 score; ignored messages are dropped without any penalty
-- (gossipsub-v1.1.md extended validators).
registerValidator :: GossipSubRouter -> Topic -> TopicValidator -> IO ()
registerValidator router topic v = atomically $
  modifyTVar' (gsValidators router) (Map.insert topic v)

-- | Remove a topic's validator.
unregisterValidator :: GossipSubRouter -> Topic -> IO ()
unregisterValidator router topic = atomically $
  modifyTVar' (gsValidators router) (Map.delete topic)

-- Peer management

-- | Register a connected peer. If the peer already exists, preserves
-- accumulated state (topics, scores) to avoid overwriting subscriptions.
addPeer :: GossipSubRouter -> PeerId -> PeerProtocol -> Bool -> UTCTime -> IO ()
addPeer router pid proto isOutbound now = atomically $ do
  retained <- readTVar (gsRetainedScores router)
  writeTVar (gsRetainedScores router) (Map.delete pid retained)
  modifyTVar' (gsPeers router) $ \m ->
    case Map.lookup pid m of
      Just _existing -> m  -- Peer already registered, keep existing state
      Nothing -> Map.insert pid (restoredOrFresh retained) m
  where
    restoredOrFresh retained =
      case Map.lookup pid retained of
        Just (saved, expiry) | now < expiry ->
          saved
            { psProtocol        = proto
            , psTopics          = Set.empty
            , psIsOutbound      = isOutbound
            , psConnectedAt     = now
            , psIPAddress       = Nothing
            }
        _ -> PeerState
          { psProtocol        = proto
          , psTopics          = Set.empty
          , psIsOutbound      = isOutbound
          , psConnectedAt     = now
          , psTopicState      = Map.empty
          , psBehaviorPenalty = 0
          , psIPAddress       = Nothing
          , psCachedScore     = 0
          }

-- | Remove a disconnected peer and clean up mesh/fanout membership,
-- IP colocation tracking (P6) and outstanding IWANT promises.
-- Scoring counters are retained for 'pspRetainScore' so a reconnecting
-- peer cannot reset a negative score (gossipsub-v1.1.md).
removePeer :: GossipSubRouter -> PeerId -> IO ()
removePeer router pid = do
  now <- gsGetTime router
  atomically $ do
    peers <- readTVar (gsPeers router)
    case Map.lookup pid peers of
      Nothing -> pure ()
      Just ps -> do
        let expiry = addUTCTime (pspRetainScore (gsScoreParams router)) now
            snapshot = ps
              { psTopics = Set.empty
              , psIPAddress = Nothing
              , psTopicState = Map.map clearMeshClock (psTopicState ps)
              }
        modifyTVar' (gsRetainedScores router) (Map.insert pid (snapshot, expiry))
        case psIPAddress ps of
          Just ip -> modifyTVar' (gsIPPeerCount router) (removeIPMember ip pid)
          Nothing -> pure ()
    modifyTVar' (gsPeers router) (Map.delete pid)
    modifyTVar' (gsMesh router) (Map.map (Set.delete pid))
    modifyTVar' (gsSignedPeerRecords router) (Map.delete pid)
    modifyTVar' (gsFanout router) (Map.map (Set.delete pid))
    modifyTVar' (gsIWantPromises router) $
      Map.filterWithKey (\(p, _) _ -> p /= pid)
    modifyTVar' (gsIDontWantCounts router) (Map.delete pid)
    modifyTVar' (gsDontSendMessageIds router) (Map.delete pid)

clearMeshClock :: TopicPeerState -> TopicPeerState
clearMeshClock tps = tps { tpsInMesh = False, tpsGraftTime = Nothing, tpsMeshTime = 0 }

-- | Record a peer's IP address for P6 (IP colocation) scoring.
-- No-op for unknown peers; replaces any previously recorded address.
setPeerIP :: GossipSubRouter -> PeerId -> ByteString -> IO ()
setPeerIP router pid ip = atomically $ do
  peers <- readTVar (gsPeers router)
  case Map.lookup pid peers of
    Nothing -> pure ()
    Just ps -> do
      case psIPAddress ps of
        Just oldIp | oldIp /= ip ->
          modifyTVar' (gsIPPeerCount router) (removeIPMember oldIp pid)
        _ -> pure ()
      modifyTVar' (gsPeers router) $
        Map.insert pid ps { psIPAddress = Just ip }
      modifyTVar' (gsIPPeerCount router) $
        Map.insertWith Set.union ip (Set.singleton pid)

-- | Drop a peer from an IP's membership set, deleting empty sets.
removeIPMember :: ByteString -> PeerId
               -> Map.Map ByteString (Set.Set PeerId)
               -> Map.Map ByteString (Set.Set PeerId)
removeIPMember ip pid = Map.update
  (\s -> let s' = Set.delete pid s
         in if Set.null s' then Nothing else Just s') ip

-- Direct peers (gossipsub-v1.1.md explicit peering agreements)

-- | True when the peer is a configured direct peer.
isDirectPeer :: GossipSubRouter -> PeerId -> Bool
isDirectPeer router pid = Set.member pid (paramDirectPeers (gsParams router))

-- | Known direct peers subscribed to the topic. They always receive
-- published and forwarded messages although they are never in the mesh.
directTopicPeers :: GossipSubRouter -> Map.Map PeerId PeerState -> Topic
                 -> Set.Set PeerId
directTopicPeers router peers topic =
  Set.filter (\pid -> case Map.lookup pid peers of
    Just ps -> Set.member topic (psTopics ps)
    Nothing -> False) (paramDirectPeers (gsParams router))

-- FloodSub peers (gossipsub-v1.0.md "Compatibility with FloodSub")

-- | True when the peer negotiated /floodsub/1.0.0. Floodsub peers have
-- no mesh and understand no gossipsub control messages: they are flooded
-- every message for topics they subscribe to and must never be grafted,
-- pruned or gossiped to.
isFloodSubPeer :: Map.Map PeerId PeerState -> PeerId -> Bool
isFloodSubPeer peers pid = case Map.lookup pid peers of
  Just ps -> psProtocol ps == FloodSubPeer
  Nothing -> False

-- | Known floodsub peers subscribed to the topic. They receive every
-- published and forwarded message for it (flooding).
floodSubTopicPeers :: Map.Map PeerId PeerState -> Topic -> Set.Set PeerId
floodSubTopicPeers peers topic =
  Map.foldlWithKey' (\acc pid ps ->
    if psProtocol ps == FloodSubPeer && Set.member topic (psTopics ps)
    then Set.insert pid acc
    else acc) Set.empty peers

-- Protocol version gating

-- | True when the peer negotiated a version supporting v1.1 extensions.
-- Unknown peers retain the historical permissive behavior.
peerSupportsV11 :: Map.Map PeerId PeerState -> PeerId -> Bool
peerSupportsV11 peers pid = case Map.lookup pid peers of
  Just ps -> psProtocol ps `elem` [GossipSubV12Peer, GossipSubPeer]
  Nothing -> True

-- | Build a PRUNE for a peer, gated on its negotiated protocol version:
-- /meshsub/1.0.0 peers receive a bare PRUNE — PX records and the backoff
-- field are v1.1 control extensions (#157).
buildPrune :: GossipSubRouter -> PeerId -> Topic
           -> Bool     -- ^ Include PX records (only for v1.1 peers in good standing)
           -> Word64   -- ^ Backoff seconds (only encoded for v1.1 peers)
           -> IO Prune
buildPrune router pid topic withPX backoffSecs = do
  peers <- readTVarIO (gsPeers router)
  if peerSupportsV11 peers pid
    then do
      px <- if withPX then selectPXPeers router topic pid else pure []
      pure (Prune topic px (Just backoffSecs))
    else pure (Prune topic [] Nothing)

-- Topic subscription

-- | Subscribe to a topic (JOIN): announce, fanout→mesh transition, fill to D, GRAFT.
join :: GossipSubRouter -> Topic -> IO ()
join router topic = do
  -- 1. Record the subscription. This must happen regardless of how many
  -- peers currently know the topic: the subscription set (not mesh key
  -- presence) is what GRAFT acceptance and hello-packet announcements
  -- consult (gossipsub-v1.0.md JOIN/GRAFT; issue #155).
  atomically $ modifyTVar' (gsSubscriptions router) (Set.insert topic)

  -- 2. Announce subscription to all known peers
  peers <- readTVarIO (gsPeers router)
  let allPeerIds = Map.keys peers
      subRPC = emptyRPC { rpcSubscriptions = [SubOpts True topic] }
  mapM_ (\pid -> gsSendRPC router pid subRPC) allPeerIds

  -- 3. Check fanout and transition to mesh
  (fanoutPeers, topicPeers) <- atomically $ do
    fo <- readTVar (gsFanout router)
    let foPeers = Map.findWithDefault Set.empty topic fo
    -- Move fanout peers to mesh
    unless (Set.null foPeers) $ do
      modifyTVar' (gsMesh router) (Map.insert topic foPeers)
      modifyTVar' (gsFanout router) (Map.delete topic)
      modifyTVar' (gsFanoutPub router) (Map.delete topic)
    -- Get current mesh and all eligible peers
    meshNow <- readTVar (gsMesh router)
    let currentMesh = Map.findWithDefault Set.empty topic meshNow
    peerMap <- readTVar (gsPeers router)
    -- Direct peers are never mesh candidates (gossipsub-v1.1.md
    -- explicit peering agreements); neither are floodsub peers, which
    -- have no mesh and would not understand the GRAFT (#157)
    let eligible = Map.foldlWithKey' (\acc pid ps ->
          if Set.member topic (psTopics ps)
             && not (Set.member pid currentMesh)
             && pid /= gsLocalPeerId router
             && not (isDirectPeer router pid)
             && psProtocol ps /= FloodSubPeer
          then Set.insert pid acc
          else acc) Set.empty peerMap
    pure (foPeers, eligible)

  -- 4. Fill mesh to D if needed
  currentMesh <- atomically $ do
    m <- readTVar (gsMesh router)
    pure (Map.findWithDefault Set.empty topic m)
  let needed = paramD (gsParams router) - Set.size currentMesh
  newPeers <- if needed > 0 && not (Set.null topicPeers)
    then do
      selected <- sampleIO (min needed (Set.size topicPeers)) (Set.toList topicPeers)
      let newSet = Set.fromList selected
      atomically $ modifyTVar' (gsMesh router) $
        Map.insertWith Set.union topic newSet
      pure newSet
    else pure Set.empty

  -- 5. Send GRAFT to all new mesh peers, including former fanout peers.
  -- fanoutPeers was captured before the mesh insert; currentMesh already
  -- contains the promoted peers, so it must not be subtracted here (#155).
  let allNewMeshPeers = Set.union fanoutPeers newPeers
  -- Start the P1 mesh clock for every peer entering the mesh (#156)
  now <- gsGetTime router
  atomically $ modifyTVar' (gsPeers router) $ \pm ->
    Set.foldl' (\m pid -> Map.adjust (markPeerInMesh topic now) pid m)
      pm allNewMeshPeers
  mapM_ (\pid -> gsSendRPC router pid (graftRPC topic)) (Set.toList allNewMeshPeers)

-- | Unsubscribe from a topic (LEAVE): announce, PRUNE with backoff, delete mesh.
leave :: GossipSubRouter -> Topic -> IO ()
leave router topic = do
  -- 1. Drop the subscription
  atomically $ modifyTVar' (gsSubscriptions router) (Set.delete topic)

  -- 2. Announce unsubscription to all known peers
  peers <- readTVarIO (gsPeers router)
  let allPeerIds = Map.keys peers
      unsubRPC = emptyRPC { rpcSubscriptions = [SubOpts False topic] }
  mapM_ (\pid -> gsSendRPC router pid unsubRPC) allPeerIds

  -- 3. Send PRUNE with unsubscribe backoff and peer exchange to mesh
  -- peers, then delete (gossipsub-v1.1.md PRUNE peer exchange: help the
  -- pruned peer re-form its mesh without a discovery service)
  meshPeers <- atomically $ do
    m <- readTVar (gsMesh router)
    let mp = Map.findWithDefault Set.empty topic m
    modifyTVar' (gsMesh router) (Map.delete topic)
    pure mp
  let backoffSecs = round (paramUnsubBackoff (gsParams router)) :: Word64
  now <- gsGetTime router
  mapM_ (\pid -> do
          applyP3b router pid topic now
          atomically $ modifyTVar' (gsPeers router) $
            Map.adjust (unmarkPeerInMesh topic) pid
          prn <- buildPrune router pid topic True backoffSecs
          gsSendRPC router pid (pruneRPC prn))
    (Set.toList meshPeers)

-- Publishing

-- | Publish a message to a topic.
-- In StrictSign mode, signs the message and populates from/seqno/signature/key.
-- With FloodPublish=True (default), sends to ALL topic peers above PublishThreshold.
-- Otherwise, sends via mesh (or fanout if not subscribed).
publish :: GossipSubRouter -> Topic -> ByteString -> Maybe KeyPair -> IO ()
publish router topic payload mKeyPair = do
  now <- gsGetTime router

  -- Build message (with signing if StrictSign)
  msg <- case paramSignaturePolicy (gsParams router) of
    StrictSign -> case mKeyPair of
      Nothing -> throwIO (SigningFailed "StrictSign publish requires a key pair")
      Just kp -> mkSignedMessage router topic payload kp
    StrictNoSign -> pure $ mkUnsignedMessage topic payload

  let msgId = paramMessageIdFn (gsParams router) msg

  -- Mark as seen and cache for IWANT/IHAVE: gossipsub-v1.0.md answers
  -- IWANT from the mcache, so our own messages must be cached too (#155).
  atomically $ do
    modifyTVar' (gsSeen router) (Map.insert msgId now)
    modifyTVar' (gsMessageCache router) (cachePut msgId msg)

  -- Build RPC with published message and apply any live IDONTWANTs.
  let pubRPC = emptyRPC { rpcPublish = [msg] }
  unwanted <- readTVarIO (gsDontSendMessageIds router)

  if paramFloodPublish (gsParams router)
    then do
      -- Flood publish: send to all topic peers scoring at or above the
      -- publish threshold (gossipsub-v1.1.md flood publishing). Direct
      -- peers always receive our messages regardless of score.
      peers <- readTVarIO (gsPeers router)
      ipMap <- readTVarIO (gsIPPeerCount router)
      let threshold = stPublishThreshold (gsThresholds router)
          targets = Map.foldlWithKey' (\acc pid ps ->
            if Set.member topic (psTopics ps)
               && pid /= gsLocalPeerId router
               && not (peerRejectsMessage unwanted pid msgId)
               && (isDirectPeer router pid
                   || computeScore (gsScoreParams router) pid ps ipMap now >= threshold)
            then pid : acc
            else acc) [] peers
      mapM_ (\pid -> gsSendRPC router pid pubRPC) targets
    else do
      -- Mesh-based publish; subscribed direct and floodsub peers are
      -- always included although they are never mesh or fanout members
      -- (floodsub peers are flooded every message for their topics, #157)
      peers <- readTVarIO (gsPeers router)
      let direct = directTopicPeers router peers topic
          flood  = floodSubTopicPeers peers topic
      meshPeers <- atomically $ do
        m <- readTVar (gsMesh router)
        pure (Map.findWithDefault Set.empty topic m)
      if not (Set.null meshPeers)
        then mapM_ (\pid -> gsSendRPC router pid pubRPC)
               (Set.toList (filterAllowedPeers unwanted msgId
                 (Set.unions [meshPeers, direct, flood])))
        else do
          -- Fanout: use existing or create new (direct and floodsub
          -- peers excluded from selection but always sent to)
          foPeers <- atomically $ do
            fo <- readTVar (gsFanout router)
            pure (Map.findWithDefault Set.empty topic fo)
          targets <- if Set.null foPeers
            then do
              let eligible = Map.foldlWithKey' (\acc pid ps ->
                    if Set.member topic (psTopics ps)
                       && pid /= gsLocalPeerId router
                       && not (isDirectPeer router pid)
                       && psProtocol ps /= FloodSubPeer
                    then pid : acc
                    else acc) [] peers
              selected <- sampleIO (min (paramD (gsParams router)) (length eligible)) eligible
              let selectedSet = Set.fromList selected
              atomically $ do
                modifyTVar' (gsFanout router) (Map.insert topic selectedSet)
                modifyTVar' (gsFanoutPub router) (Map.insert topic now)
              pure selectedSet
            else do
              atomically $ modifyTVar' (gsFanoutPub router) (Map.insert topic now)
              pure foPeers
          mapM_ (\pid -> gsSendRPC router pid pubRPC)
            (Set.toList (filterAllowedPeers unwanted msgId
              (Set.unions [targets, direct, flood])))

  -- Deliver to local application
  onMsg <- readTVarIO (gsOnMessage router)
  onMsg topic msg

-- Inbound RPC handling

-- | Handle an inbound RPC from a peer.
--
-- Graylisted peers (score below 'stGraylistThreshold') have their RPCs
-- ignored entirely (gossipsub-v1.1.md graylist). Direct peers are exempt:
-- explicit peering agreements exchange messages unconditionally.
handleRPC :: GossipSubRouter -> PeerId -> RPC -> IO ()
handleRPC router sender rpc = do
  score <- peerScore router sender
  if score < stGraylistThreshold (gsThresholds router)
       && not (isDirectPeer router sender)
    then pure ()
    else handleRPC' router sender rpc

handleRPC' :: GossipSubRouter -> PeerId -> RPC -> IO ()
handleRPC' router sender rpc = do
  -- Process subscriptions
  handleSubscriptions router sender (rpcSubscriptions rpc)

  -- IDONTWANT is emitted immediately before validation of each first-seen
  -- large message, then the normal validation/deduplication path runs.
  mapM_ (\msg -> announceIDontWant router sender msg
              >> handlePublishedMessage router sender msg) (rpcPublish rpc)

  -- Process control messages
  case rpcControl rpc of
    Nothing -> pure ()
    Just ctrl -> do
      handleIHave router sender (ctrlIHave ctrl)
      handleIWant router sender (ctrlIWant ctrl)
      handleGraft router sender (ctrlGraft ctrl)
      handlePrune router sender (ctrlPrune ctrl)
      handleIDontWant router sender (ctrlIDontWant ctrl)

-- | Process a published message: verify, deduplicate, validate, forward, deliver.
--
-- Signature verification runs before deduplication so that an invalid message
-- is never cached, forwarded or delivered, and never poisons the seen cache for
-- the genuine message with the same ID.
handlePublishedMessage :: GossipSubRouter -> PeerId -> PubSubMessage -> IO ()
handlePublishedMessage router sender msg =
  case validateMessage (paramSignaturePolicy (gsParams router)) msg of
    Left _err -> rejectMessage router sender msg
    Right ()  -> do
      let msgId = paramMessageIdFn (gsParams router) msg
          topic = msgTopic msg
      now <- gsGetTime router

      -- Deduplicate, keeping the first-seen time for the P3 near-first window
      mFirstSeen <- atomically $ do
        s <- readTVar (gsSeen router)
        case Map.lookup msgId s of
          Just firstSeen -> pure (Just firstSeen)
          Nothing -> do
            writeTVar (gsSeen router) (Map.insert msgId now s)
            pure Nothing

      -- A signature-valid delivery fulfils any outstanding IWANT promise
      -- for this message ID (P7 promise tracking, gossipsub-v1.1.md)
      atomically $ modifyTVar' (gsIWantPromises router) $
        Map.filterWithKey (\(_, mid) _ -> mid /= msgId)

      case mFirstSeen of
        Just firstSeen ->
          -- Duplicate: count as a mesh delivery (P3) when the sender is
          -- in our mesh and delivered within the near-first window
          creditMeshDelivery router sender topic (Just (firstSeen, now))
        Nothing -> do
          outcome <- runTopicValidator router sender msg
          case outcome of
            -- Provably invalid: drop and penalise the source (P4)
            ValidationReject -> rejectMessage router sender msg
            -- Undecidable: drop without penalty (extended validators,
            -- gossipsub-v1.1.md — Ignore must not affect the score)
            ValidationIgnore -> pure ()
            ValidationAccept -> do
              -- First valid delivery: P2, plus P3 for mesh senders (#156)
              creditFirstDelivery router sender topic
              creditMeshDelivery router sender topic Nothing

              -- Cache the message for IWANT responses
              atomically $ modifyTVar' (gsMessageCache router) $
                cachePut msgId msg

              -- Forward to mesh peers (excluding sender)
              forwardMessage router sender msg

              -- Deliver to application
              onMsg <- readTVarIO (gsOnMessage router)
              onMsg (msgTopic msg) msg

-- | Record a P2 first-message delivery for the sender.
creditFirstDelivery :: GossipSubRouter -> PeerId -> Topic -> IO ()
creditFirstDelivery router sender topic = atomically $
  modifyTVar' (gsPeers router) $ Map.adjust bump sender
  where
    tsp = Map.findWithDefault defaultTopicScoreParams topic
      (pspTopicParams (gsScoreParams router))
    bump ps =
      let tps = Map.findWithDefault defaultTopicPeerState topic (psTopicState ps)
      in ps { psTopicState =
                Map.insert topic (recordFirstDelivery tsp tps) (psTopicState ps) }

-- | Record a P3 mesh delivery for a sender in our mesh. For duplicates,
-- the delivery only counts inside the near-first window after the first
-- sighting (gossipsub-v1.1.md mesh message delivery rate).
creditMeshDelivery :: GossipSubRouter -> PeerId -> Topic
                   -> Maybe (UTCTime, UTCTime) -> IO ()
creditMeshDelivery router sender topic mWindow = do
  meshMap <- readTVarIO (gsMesh router)
  let inMesh = Set.member sender (Map.findWithDefault Set.empty topic meshMap)
      tsp = Map.findWithDefault defaultTopicScoreParams topic
        (pspTopicParams (gsScoreParams router))
      withinWindow = case mWindow of
        Nothing -> True
        Just (firstSeen, now) ->
          diffUTCTime now firstSeen <= tspMeshMessageDeliveryWindow tsp
  when (inMesh && withinWindow) $ atomically $
    modifyTVar' (gsPeers router) $ Map.adjust
      (\ps ->
        let tps = Map.findWithDefault defaultTopicPeerState topic (psTopicState ps)
        in ps { psTopicState =
                  Map.insert topic (recordMeshDelivery tsp tps) (psTopicState ps) })
      sender

-- | Run the topic validator, if one is registered. No validator means accept.
runTopicValidator :: GossipSubRouter -> PeerId -> PubSubMessage -> IO ValidationResult
runTopicValidator router sender msg = do
  validators <- readTVarIO (gsValidators router)
  case Map.lookup (msgTopic msg) validators of
    Nothing -> pure ValidationAccept
    Just v  -> v sender msg

-- | Drop a message and charge the propagation source a P4 invalid delivery.
rejectMessage :: GossipSubRouter -> PeerId -> PubSubMessage -> IO ()
rejectMessage router sender msg = atomically $
  modifyTVar' (gsPeers router) $ Map.adjust bumpInvalid sender
  where
    topic = msgTopic msg
    bumpInvalid ps =
      let tps = Map.findWithDefault defaultTopicPeerState topic (psTopicState ps)
      in ps { psTopicState = Map.insert topic (recordInvalidMessage tps) (psTopicState ps) }

-- Control message handlers

-- | Handle GRAFT: accept if subscribed, non-negative score, and no backoff.
handleGraft :: GossipSubRouter -> PeerId -> [Graft] -> IO ()
handleGraft router sender grafts = do
  now <- gsGetTime router
  pruneResponses <- mapM (handleOneGraft router sender now) grafts
  let prunes = concat pruneResponses
  unless (null prunes) $
    gsSendRPC router sender emptyRPC
      { rpcControl = Just emptyControlMessage { ctrlPrune = prunes } }

-- | Handle a single GRAFT request.
handleOneGraft :: GossipSubRouter -> PeerId -> UTCTime -> Graft -> IO [Prune]
handleOneGraft router sender now (Graft topic) = do
  -- Check the subscription set, not mesh key presence: a topic joined
  -- with no peers has no mesh entry but its GRAFTs must be accepted
  -- (gossipsub-v1.0.md GRAFT handling; issue #155).
  subs <- readTVarIO (gsSubscriptions router)
  peersMap <- readTVarIO (gsPeers router)
  let subscribed = Set.member topic subs

  if isFloodSubPeer peersMap sender
    then
      -- Floodsub peers have no mesh and understand no control messages:
      -- never graft them and never answer with PRUNE (#157)
      pure []
    else if not subscribed
    then
      -- gossipsub-v1.1.md GRAFT flood protection: GRAFTs for unknown
      -- topics are ignored — replying with PRUNE (the v1.0 behaviour)
      -- lets an attacker elicit traffic with spam GRAFTs (#157).
      pure []
    else if isDirectPeer router sender
      then do
        -- gossipsub-v1.1.md explicit peering: direct peers must never be
        -- mesh members — answer with PRUNE and do not graft
        prn <- buildPrune router sender topic False
          (round (paramPruneBackoff (gsParams router)))
        pure [prn]
    else do
      -- Check backoff
      backoffMap <- readTVarIO (gsBackoff router)
      let inBackoff = case Map.lookup (sender, topic) backoffMap of
            Nothing -> False
            Just expires -> now < expires

      score <- peerScore router sender

      -- Any rejection PRUNEs with a fresh backoff and never includes
      -- peer exchange (no PX for misbehaving or negative-score peers)
      let backoffSecs = round (paramPruneBackoff (gsParams router)) :: Word64
          rejectWithBackoff = do
            atomically $ modifyTVar' (gsBackoff router) $
              Map.insert (sender, topic)
                (addUTCTime (paramPruneBackoff (gsParams router)) now)
            prn <- buildPrune router sender topic False backoffSecs
            pure [prn]

      if inBackoff
        then do
          -- GRAFT flood protection: re-GRAFTing inside the backoff window
          -- is a protocol violation — penalise (P7) and prune with backoff
          atomically $ modifyTVar' (gsPeers router) $
            Map.adjust addP7Penalty sender
          rejectWithBackoff
        else if score < 0
          then rejectWithBackoff
          else do
            -- Accept: add sender to mesh and start its P1 mesh clock
            atomically $ do
              modifyTVar' (gsMesh router) $
                Map.insertWith Set.union topic (Set.singleton sender)
              modifyTVar' (gsPeers router) $
                Map.adjust (markPeerInMesh topic now) sender
            pure []

-- | Capture P3b for a mesh peer if the topic is scored and activation elapsed.
applyP3b :: GossipSubRouter -> PeerId -> Topic -> UTCTime -> IO ()
applyP3b router pid topic now =
  case Map.lookup topic (pspTopicParams (gsScoreParams router)) of
    Nothing -> pure ()
    Just tsp -> atomically $ modifyTVar' (gsPeers router) $
      Map.adjust (\ps ->
        let tps = Map.findWithDefault defaultTopicPeerState topic (psTopicState ps)
            tps' = captureP3b tsp now tps
        in ps { psTopicState = Map.insert topic tps' (psTopicState ps) }
      ) pid

-- | Handle PRUNE: remove from mesh and start backoff.
handlePrune :: GossipSubRouter -> PeerId -> [Prune] -> IO ()
handlePrune router sender prunes = do
  now <- gsGetTime router
  mapM_ (handleOnePrune router sender now) prunes

handleOnePrune :: GossipSubRouter -> PeerId -> UTCTime -> Prune -> IO ()
handleOnePrune router sender now prune = do
  let topic = pruneTopic prune
  inMesh <- atomically $ do
    mesh <- readTVar (gsMesh router)
    pure (Set.member sender (Map.findWithDefault Set.empty topic mesh))
  -- P3b only for a peer we currently have in this mesh, after activation.
  when inMesh $ applyP3b router sender topic now
  -- Remove sender from mesh and stop its P1 mesh clock
  atomically $ do
    modifyTVar' (gsMesh router) $
      Map.adjust (Set.delete sender) topic
    modifyTVar' (gsPeers router) $
      Map.adjust (unmarkPeerInMesh topic) sender
  -- Start backoff timer
  let backoffDuration = case pruneBackoff prune of
        Just secs -> fromIntegral secs
        Nothing   -> paramPruneBackoff (gsParams router)
      expires = addUTCTime backoffDuration now
  atomically $ modifyTVar' (gsBackoff router) $
    Map.insert (sender, topic) expires
  -- Honour peer exchange, but only from peers whose score clears the
  -- PX acceptance threshold (gossipsub-v1.1.md: PX from low-scoring
  -- peers is an eclipse-attack vector)
  -- Any attached signed peer record must verify (RFC 0003 envelope
  -- opens and names the advertised peer) — a record that fails drops
  -- its whole PX entry, matching go-libp2p's pxConnect. Entries without
  -- a record are passed through unchanged.
  unless (null (prunePeers prune)) $ do
    score <- peerScore router sender
    when (score >= stAcceptPXThreshold (gsThresholds router)) $ do
      let verified = filter validPXRecord (prunePeers prune)
      unless (null verified) $ do
        onPX <- readTVarIO (gsOnPeerExchange router)
        onPX topic verified

-- | A PX entry is acceptable if it carries no signed record, or a
-- record whose envelope verifies and whose subject is the advertised
-- peer id.
validPXRecord :: PeerExchangeInfo -> Bool
validPXRecord pxi = case pxSignedPeerRecord pxi of
  Nothing -> True
  Just envBytes -> case openPeerRecordEnvelope envBytes of
    Right (_, record) -> prPeerId record == pxPeerId pxi
    Left _ -> False

-- | Handle IHAVE: request unseen messages via IWANT.
--
-- Gossip from peers below the gossip threshold is ignored
-- (gossipsub-v1.1.md gossip threshold). One advertised-and-requested
-- message ID is tracked as an IWANT promise: if the peer never delivers
-- it before the follow-up deadline, it is a P7 behavioural violation.
--
-- IHAVE flood protection (#157): at most 'paramMaxIHaveMessages' IHAVE
-- batches are accepted per peer per heartbeat, and at most
-- 'paramMaxIHaveLength' message ids are requested from a peer per
-- heartbeat (go-libp2p defaults 10 and 5000).
handleIHave :: GossipSubRouter -> PeerId -> [IHave] -> IO ()
handleIHave router sender ihaves = do
  score <- peerScore router sender
  peersMap <- readTVarIO (gsPeers router)
  -- Floodsub peers never receive control messages, so an (unexpected)
  -- IHAVE from one must not be answered with IWANT (#157)
  unless (score < stGossipThreshold (gsThresholds router)
          || isFloodSubPeer peersMap sender
          || null ihaves) $ do
    let params = gsParams router
    withinBudget <- atomically $ do
      counts <- readTVar (gsIHaveCounts router)
      let n = Map.findWithDefault 0 sender counts + 1
      writeTVar (gsIHaveCounts router) (Map.insert sender n counts)
      pure (n <= paramMaxIHaveMessages params)
    when withinBudget $ do
      seenMap <- readTVarIO (gsSeen router)
      let unseen = concatMap (\(IHave _ mids) ->
            filter (\mid -> not (Map.member mid seenMap)) mids) ihaves
      toAsk <- atomically $ do
        asked <- readTVar (gsIAskedCounts router)
        let a = Map.findWithDefault 0 sender asked
            budget = max 0 (paramMaxIHaveLength params - a)
            capped = take budget unseen
        writeTVar (gsIAskedCounts router)
          (Map.insert sender (a + length capped) asked)
        pure capped
      unless (null toAsk) $ do
        now <- gsGetTime router
        promised <- sampleIO 1 toAsk
        let deadline = addUTCTime (paramIWantFollowupTime params) now
        atomically $ modifyTVar' (gsIWantPromises router) $ \m ->
          foldr (\mid -> Map.insert (sender, mid) deadline) m promised
        gsSendRPC router sender emptyRPC
          { rpcControl = Just emptyControlMessage { ctrlIWant = [IWant toAsk] } }

-- | Handle IWANT: respond with cached messages from the message cache.
-- Requests from peers below the gossip threshold are ignored, and at
-- most 'paramMaxIHaveLength' messages are served per peer per heartbeat
-- (IWANT flood protection, #157).
handleIWant :: GossipSubRouter -> PeerId -> [IWant] -> IO ()
handleIWant router sender iwants = do
  score <- peerScore router sender
  unless (score < stGossipThreshold (gsThresholds router)) $ do
    cache <- readTVarIO (gsMessageCache router)
    unwanted <- readTVarIO (gsDontSendMessageIds router)
    let requestedIds = concatMap iwantMessageIds iwants
        found = [ msg | mid <- requestedIds
                       , not (peerRejectsMessage unwanted sender mid)
                       , Just msg <- [cacheGet mid cache] ]
    toServe <- atomically $ do
      served <- readTVar (gsIWantServed router)
      let s = Map.findWithDefault 0 sender served
          budget = max 0 (paramMaxIHaveLength (gsParams router) - s)
          capped = take budget found
      writeTVar (gsIWantServed router)
        (Map.insert sender (s + length capped) served)
      pure capped
    unless (null toServe) $
      gsSendRPC router sender emptyRPC { rpcPublish = toServe }

-- | Handle subscription changes from a peer.
handleSubscriptions :: GossipSubRouter -> PeerId -> [SubOpts] -> IO ()
handleSubscriptions router sender subs = atomically $
  modifyTVar' (gsPeers router) $ \peerMap ->
    case Map.lookup sender peerMap of
      Nothing -> peerMap  -- Unknown peer, ignore
      Just ps ->
        let topics' = foldl (\ts sub ->
              if subSubscribe sub
                then Set.insert (subTopicId sub) ts
                else Set.delete (subTopicId sub) ts
              ) (psTopics ps) subs
        in Map.insert sender ps { psTopics = topics' } peerMap

-- Message forwarding

-- | Forward a message to mesh peers for its topic, excluding the sender.
-- Subscribed direct peers always receive the message even though they
-- are never mesh members (gossipsub-v1.1.md explicit peering), and so do
-- subscribed floodsub peers, which are flooded before the mesh
-- (gossipsub-v1.0.md: forward "to every peer in peers.floodsub[topic]").
forwardMessage :: GossipSubRouter -> PeerId -> PubSubMessage -> IO ()
forwardMessage router sender msg = do
  let topic = msgTopic msg
  meshPeers <- atomically $ do
    m <- readTVar (gsMesh router)
    pure (Map.findWithDefault Set.empty topic m)
  peers <- readTVarIO (gsPeers router)
  unwanted <- readTVarIO (gsDontSendMessageIds router)
  let direct = directTopicPeers router peers topic
      flood  = floodSubTopicPeers peers topic
      candidates = Set.delete sender (Set.unions [meshPeers, direct, flood])
      targets = filterAllowedPeers unwanted
        (paramMessageIdFn (gsParams router) msg) candidates
      fwdRPC = emptyRPC { rpcPublish = [msg] }
  mapM_ (\pid -> gsSendRPC router pid fwdRPC) (Set.toList targets)

-- Scoring

-- | Compute peer score using Score.computeScore (P1-P7).
peerScore :: GossipSubRouter -> PeerId -> IO Double
peerScore router pid = do
  peers <- readTVarIO (gsPeers router)
  now <- gsGetTime router
  ipMap <- readTVarIO (gsIPPeerCount router)
  case Map.lookup pid peers of
    Nothing -> pure 0
    Just ps -> pure $ computeScore (gsScoreParams router) pid ps ipMap now

-- Peer exchange

-- | Store the encoded signed peer record (RFC 0003 envelope bytes) for
-- a peer, typically obtained via identify. It is attached to PX entries
-- advertising that peer in outgoing PRUNEs (gossipsub-v1.1.md). Cleared
-- by 'removePeer'.
setSignedPeerRecord :: GossipSubRouter -> PeerId -> ByteString -> IO ()
setSignedPeerRecord router pid recBytes = atomically $
  modifyTVar' (gsSignedPeerRecords router) (Map.insert pid recBytes)

-- | Select peer-exchange records for a PRUNE: up to 'paramPrunePeers'
-- random peers subscribed to the topic with non-negative score,
-- excluding the pruned peer itself (gossipsub-v1.1.md peer exchange).
-- Peers whose signed peer record we hold get it attached.
selectPXPeers :: GossipSubRouter -> Topic -> PeerId -> IO [PeerExchangeInfo]
selectPXPeers router topic excluded = do
  now <- gsGetTime router
  peers <- readTVarIO (gsPeers router)
  ipMap <- readTVarIO (gsIPPeerCount router)
  signedRecords <- readTVarIO (gsSignedPeerRecords router)
  let candidates =
        [ pid | (pid, ps) <- Map.toList peers
              , pid /= excluded
              , pid /= gsLocalPeerId router
              , Set.member topic (psTopics ps)
              , computeScore (gsScoreParams router) pid ps ipMap now >= 0 ]
  chosen <- sampleIO
    (min (paramPrunePeers (gsParams router)) (length candidates)) candidates
  pure [ PeerExchangeInfo (peerIdBytes pid) (Map.lookup pid signedRecords)
       | pid <- chosen ]

-- Helper: construct a GRAFT RPC
graftRPC :: Topic -> RPC
graftRPC topic = emptyRPC
  { rpcControl = Just emptyControlMessage { ctrlGraft = [Graft topic] } }

-- Helper: wrap a PRUNE in an RPC
pruneRPC :: Prune -> RPC
pruneRPC prn = emptyRPC
  { rpcControl = Just emptyControlMessage { ctrlPrune = [prn] } }

-- Helpers: message construction

mkUnsignedMessage :: Topic -> ByteString -> PubSubMessage
mkUnsignedMessage topic payload = PubSubMessage
  { msgFrom      = Nothing
  , msgData      = payload
  , msgSeqNo     = Nothing
  , msgTopic     = topic
  , msgSignature = Nothing
  , msgKey       = Nothing
  }

mkSignedMessage :: GossipSubRouter -> Topic -> ByteString -> KeyPair -> IO PubSubMessage
mkSignedMessage router topic payload kp = do
  seqno <- getRandomBytes 8 :: IO ByteString
  let from = peerIdBytes (gsLocalPeerId router)
      pubKeyBytes = encodePublicKey (kpPublic kp)
      -- Build unsigned message for signing
      unsigned = PubSubMessage
        { msgFrom      = Just from
        , msgData      = payload
        , msgSeqNo     = Just seqno
        , msgTopic     = topic
        , msgSignature = Nothing
        , msgKey       = Just pubKeyBytes
        }
  case sign (kpPrivate kp) (signingBytes unsigned) of
    -- Publishing unsigned under StrictSign would emit a message every
    -- compliant receiver must drop, so fail loudly instead.
    Left err  -> throwIO (SigningFailed err)
    Right sig -> pure unsigned { msgSignature = Just sig }
