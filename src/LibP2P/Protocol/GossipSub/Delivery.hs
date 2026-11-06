-- | Validation-aware deduplication and delivery scoring.
module LibP2P.Protocol.GossipSub.Delivery (handlePublishedMessage) where

import Control.Concurrent.STM
import Control.Exception (mask, onException)
import Control.Monad (forM_, void, when)
import qualified Data.Map.Strict as Map
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
      case previous of
        Just (SeenMessage firstSeen (ValidationComplete outcome)) ->
          scoreDuplicate router (msgTopic msg) firstSeen outcome (sender, now)
        Just (SeenMessage _ (PendingValidation _)) -> pure ()
        Nothing -> do
          outcome <- restore (runTopicValidator router sender msg)
            `onException` void (atomically $
              finishValidation router mid now ValidationIgnore)
          pending <- atomically $ finishValidation router mid now outcome
          forM_ pending $ \sources -> do
            mapM_ (scoreDuplicate router (msgTopic msg) now outcome)
              (Map.toList (Map.delete sender sources))
            case outcome of
              ValidationReject -> rejectMessage router sender (msgTopic msg)
              ValidationIgnore -> pure ()
              ValidationAccept -> do
                acceptMessage router sender mid msg
                restore $ do
                  forward sender msg
                  onMsg <- readTVarIO (gsOnMessage router)
                  onMsg (msgTopic msg) msg

-- Pending duplicates register once per source without waiting on application IO.
trackDelivery
  :: GossipSubRouter -> MessageId -> PeerId -> UTCTime
  -> STM (Maybe SeenMessage)
trackDelivery router mid sender now = do
  seen <- readTVar (gsSeen router)
  let previous = Map.lookup mid seen
  case previous of
    Nothing -> writeTVar (gsSeen router) $
      Map.insert mid (SeenMessage now (PendingValidation Map.empty)) seen
    Just entry@(SeenMessage _ (PendingValidation sources)) ->
      writeTVar (gsSeen router) $ Map.insert mid
        (entry { seenValidation = PendingValidation (Map.insertWith min sender now sources) }) seen
    Just _ -> pure ()
  pure previous

-- A validator outliving its seen-cache entry cannot replace a newer outcome.
finishValidation
  :: GossipSubRouter -> MessageId -> UTCTime -> ValidationResult
  -> STM (Maybe (Map.Map PeerId UTCTime))
finishValidation router mid started outcome = do
  seen <- readTVar (gsSeen router)
  case Map.lookup mid seen of
    Just entry@(SeenMessage firstSeen (PendingValidation sources))
      | firstSeen == started -> do
          writeTVar (gsSeen router) $
            Map.insert mid (entry { seenValidation = ValidationComplete outcome }) seen
          pure (Just sources)
    _ -> pure Nothing

scoreDuplicate
  :: GossipSubRouter -> Topic -> UTCTime -> ValidationResult
  -> (PeerId, UTCTime) -> IO ()
scoreDuplicate router topic firstSeen outcome (sender, arrived) = case outcome of
  ValidationReject -> rejectMessage router sender topic
  ValidationIgnore -> pure ()
  ValidationAccept -> creditMeshDelivery router sender topic (Just (firstSeen, arrived))

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
        Just (firstSeen, arrived) ->
          diffUTCTime arrived firstSeen <= tspMeshMessageDeliveryWindow params
  when (inMesh && withinWindow) $
    updateTopicState router sender topic (recordMeshDelivery params)

topicScoreParams :: GossipSubRouter -> Topic -> TopicScoreParams
topicScoreParams router topic = Map.findWithDefault defaultTopicScoreParams topic
  (pspTopicParams (gsScoreParams router))

updateTopicState
  :: GossipSubRouter -> PeerId -> Topic -> (TopicPeerState -> TopicPeerState) -> IO ()
updateTopicState router sender topic update = atomically $
  modifyTVar' (gsPeers router) $ Map.adjust (\peer -> peer
    { psTopicState = Map.alter
        (Just . update . maybe defaultTopicPeerState id) topic (psTopicState peer) }) sender

runTopicValidator :: GossipSubRouter -> PeerId -> PubSubMessage -> IO ValidationResult
runTopicValidator router sender msg = do
  validators <- readTVarIO (gsValidators router)
  case Map.lookup (msgTopic msg) validators of
    Nothing -> pure ValidationAccept
    Just validate -> validate sender msg

rejectMessage :: GossipSubRouter -> PeerId -> Topic -> IO ()
rejectMessage router sender topic =
  updateTopicState router sender topic recordInvalidMessage
