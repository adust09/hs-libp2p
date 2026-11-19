-- | Validation-aware deduplication and delivery scoring.
module LibP2P.Protocol.GossipSub.Delivery (handlePublishedMessage) where

import Control.Concurrent.STM
import Control.Exception (mask, onException)
import Control.Monad (forM_, unless, void, when)
import qualified Data.Map.Strict as Map
import Data.Maybe (isJust)
import qualified Data.Set as Set
import Data.Time (UTCTime, diffUTCTime)
import LibP2P.Crypto.PeerId (PeerId)
import LibP2P.Protocol.GossipSub.MessageCache (cachePut)
import LibP2P.Protocol.GossipSub.Score
  ( recordFirstDelivery, recordInvalidMessage, recordMeshDelivery )
import LibP2P.Protocol.GossipSub.Types
import LibP2P.Protocol.GossipSub.Validation (validateMessage)

-- Signature verification precedes deduplication to prevent seen-cache poisoning.
handlePublishedMessage
  :: GossipSubRouter -> (PeerId -> PubSubMessage -> IO ())
  -> PeerId -> PubSubMessage -> IO ()
handlePublishedMessage router forward sender msg =
  case validateMessage (paramSignaturePolicy (gsParams router)) msg of
    Left _ -> rejectMessage router sender (msgTopic msg)
    Right () -> mask $ \restore -> do
      let mid = paramMessageIdFn (gsParams router) msg
      now <- gsGetTime router
      previous <- atomically $ do
        seen <- trackDelivery router mid sender now
        modifyTVar' (gsIWantPromises router) $
          Map.filterWithKey (\(_, promised) _ -> promised /= mid)
        pure seen
      shouldDeliver <- case previous of
        Just (SeenMessage _ (AcceptedValidation validated sources)) ->
          False <$ unless (Set.member sender sources)
            (creditMeshDelivery router sender (msgTopic msg) (Just (validated, now)))
        Just (SeenMessage _ RejectedValidation) ->
          False <$ rejectMessage router sender (msgTopic msg)
        Just _ -> pure False
        Nothing -> do
          (outcome, validated) <- restore
            ((,) <$> runTopicValidator router sender msg <*> gsGetTime router)
            `onException` void (atomically $
              finishValidation router mid now (const IgnoredValidation))
          let completed = case outcome of
                ValidationAccept -> AcceptedValidation validated
                ValidationReject -> const RejectedValidation
                ValidationIgnore -> const IgnoredValidation
          pending <- atomically $ finishValidation router mid now completed
          forM_ pending (applyValidation router sender mid msg outcome)
          pure (outcome == ValidationAccept && isJust pending)
      when shouldDeliver $ restore $ do
        forward sender msg
        onMsg <- readTVarIO (gsOnMessage router)
        onMsg (msgTopic msg) msg

-- Reserve each source's delivery in STM so concurrent duplicates cannot both score.
trackDelivery
  :: GossipSubRouter -> MessageId -> PeerId -> UTCTime
  -> STM (Maybe SeenMessage)
trackDelivery router mid sender now = do
  seen <- readTVar (gsSeen router)
  let previous = Map.lookup mid seen
  case previous of
    Nothing -> writeTVar (gsSeen router) $
      Map.insert mid (SeenMessage now (PendingValidation (Set.singleton sender))) seen
    Just entry@(SeenMessage _ (PendingValidation sources))
      | Set.notMember sender sources -> writeTVar (gsSeen router) $ Map.insert mid
          (entry { seenValidation = PendingValidation (Set.insert sender sources) }) seen
    Just entry@(SeenMessage _ (AcceptedValidation validated sources))
      | Set.notMember sender sources -> writeTVar (gsSeen router) $ Map.insert mid
          (entry { seenValidation = AcceptedValidation validated (Set.insert sender sources) }) seen
    Just _ -> pure ()
  pure previous

-- A validator outliving its seen-cache entry cannot replace a newer outcome.
finishValidation
  :: GossipSubRouter -> MessageId -> UTCTime -> (Set.Set PeerId -> SeenValidation)
  -> STM (Maybe (Set.Set PeerId))
finishValidation router mid started completed = do
  seen <- readTVar (gsSeen router)
  case Map.lookup mid seen of
    Just entry@(SeenMessage firstSeen (PendingValidation sources))
      | firstSeen == started -> do
          writeTVar (gsSeen router) $
            Map.insert mid (entry { seenValidation = completed sources }) seen
          pure (Just sources)
    _ -> pure Nothing

applyValidation
  :: GossipSubRouter -> PeerId -> MessageId -> PubSubMessage
  -> ValidationResult -> Set.Set PeerId -> IO ()
applyValidation router sender mid msg outcome sources = case outcome of
  ValidationReject -> forM_ sources $ \source -> rejectMessage router source (msgTopic msg)
  ValidationIgnore -> pure ()
  ValidationAccept -> do
    acceptMessage router sender mid msg
    -- All deliveries during validation qualify, regardless of its duration.
    forM_ (Set.delete sender sources) $ \source ->
      creditMeshDelivery router source (msgTopic msg) Nothing

acceptMessage :: GossipSubRouter -> PeerId -> MessageId -> PubSubMessage -> IO ()
acceptMessage router sender mid msg = do
  let topic = msgTopic msg
      params = topicScoreParams router topic
  updateTopicState router sender topic (recordFirstDelivery params)
  creditMeshDelivery router sender topic Nothing
  atomically $ modifyTVar' (gsMessageCache router) (cachePut mid msg)

creditMeshDelivery
  :: GossipSubRouter -> PeerId -> Topic -> Maybe (UTCTime, UTCTime) -> IO ()
creditMeshDelivery router sender topic window = do
  mesh <- readTVarIO (gsMesh router)
  let params = topicScoreParams router topic
      inMesh = Set.member sender (Map.findWithDefault Set.empty topic mesh)
      withinWindow = case window of
        Nothing -> True
        Just (validated, arrived) ->
          diffUTCTime arrived validated <= tspMeshMessageDeliveryWindow params
  when (inMesh && withinWindow) $
    updateTopicState router sender topic (recordMeshDelivery params)

topicScoreParams :: GossipSubRouter -> Topic -> TopicScoreParams
topicScoreParams router topic = Map.findWithDefault defaultTopicScoreParams topic
  (pspTopicParams (gsScoreParams router))

updateTopicState
  :: GossipSubRouter -> PeerId -> Topic -> (TopicPeerState -> TopicPeerState) -> IO ()
updateTopicState router sender topic update = atomically $ do
  peers <- readTVar (gsPeers router)
  if Map.member sender peers
    then writeTVar (gsPeers router) (Map.adjust updatePeer sender peers)
    else modifyTVar' (gsRetainedScores router) $
      Map.adjust (\(peer, expiry) -> (updatePeer peer, expiry)) sender
  where
    updatePeer peer = peer
      { psTopicState = Map.alter
          (Just . update . maybe defaultTopicPeerState id) topic (psTopicState peer) }

runTopicValidator :: GossipSubRouter -> PeerId -> PubSubMessage -> IO ValidationResult
runTopicValidator router sender msg = do
  validators <- readTVarIO (gsValidators router)
  case Map.lookup (msgTopic msg) validators of
    Nothing -> pure ValidationAccept
    Just validate -> validate sender msg

rejectMessage :: GossipSubRouter -> PeerId -> Topic -> IO ()
rejectMessage router sender topic =
  updateTopicState router sender topic recordInvalidMessage
