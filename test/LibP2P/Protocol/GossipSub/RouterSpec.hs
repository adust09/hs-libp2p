module LibP2P.Protocol.GossipSub.RouterSpec (spec) where

import Test.Hspec

import Control.Concurrent.STM
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import Data.IORef
import Data.Time (UTCTime, addUTCTime)
import Data.Time.Clock.POSIX (posixSecondsToUTCTime)
import Control.Exception (try)
import LibP2P.Crypto.Ed25519 (generateKeyPair)
import LibP2P.Crypto.Key (KeyPair (..), sign)
import LibP2P.Crypto.PeerId (PeerId (..), fromPublicKey, peerIdBytes)
import LibP2P.Crypto.PeerRecord (PeerRecord (..), sealPeerRecord)
import LibP2P.Crypto.SignedEnvelope (encodeSignedEnvelope)
import LibP2P.Crypto.Protobuf (encodePublicKey)
import LibP2P.Protocol.GossipSub.Types
import LibP2P.Protocol.GossipSub.Router
import LibP2P.Protocol.GossipSub.Heartbeat (heartbeatOnce)
import LibP2P.Protocol.GossipSub.MessageCache (cachePut)
import LibP2P.Protocol.GossipSub.Validation (signingBytes, validateMessage)

-- Test helpers

-- | Create a PeerId from a byte.
mkPeerId :: Int -> PeerId
mkPeerId n = PeerId (BS.pack [fromIntegral n])

-- | Fixed time for deterministic tests.
fixedTime :: UTCTime
fixedTime = posixSecondsToUTCTime 1000000

-- | A time source that always returns fixedTime.
fixedTimeSource :: IO UTCTime
fixedTimeSource = pure fixedTime

-- | Adjustable time source for backoff tests.
newTimeRef :: UTCTime -> IO (IORef UTCTime, IO UTCTime)
newTimeRef t = do
  ref <- newIORef t
  pure (ref, readIORef ref)

-- | Record all sent RPCs for verification.
newSendLog :: IO (IORef [(PeerId, RPC)], PeerId -> RPC -> IO ())
newSendLog = do
  ref <- newIORef []
  let sendFn pid rpc = modifyIORef' ref (++ [(pid, rpc)])
  pure (ref, sendFn)

-- | Create a test router with send logging.
mkTestRouter :: PeerId -> IO (GossipSubRouter, IORef [(PeerId, RPC)])
mkTestRouter localPid = do
  (logRef, sendFn) <- newSendLog
  router <- newRouter defaultGossipSubParams localPid sendFn fixedTimeSource
  pure (router, logRef)

-- | Create a test router with custom parameters and send logging.
mkTestRouterWithParams :: GossipSubParams -> PeerId -> IO (GossipSubRouter, IORef [(PeerId, RPC)])
mkTestRouterWithParams params pid = do
  (logRef, sendFn) <- newSendLog
  router <- newRouter params pid sendFn fixedTimeSource
  pure (router, logRef)

-- | All IWANT id lists sent, in order.
iwantsSent :: [(PeerId, RPC)] -> [[MessageId]]
iwantsSent sent =
  [ iwantMessageIds iw
  | (_, rpc) <- sent, Just ctrl <- [rpcControl rpc], iw <- ctrlIWant ctrl ]

-- | All PRUNEs sent to a given peer.
prunesTo :: PeerId -> [(PeerId, RPC)] -> [Prune]
prunesTo pid sent =
  [ p | (to, rpc) <- sent, to == pid
      , Just ctrl <- [rpcControl rpc], p <- ctrlPrune ctrl ]

-- | Create a test router with adjustable time.
mkTestRouterWithTime :: PeerId -> UTCTime -> IO (GossipSubRouter, IORef [(PeerId, RPC)], IORef UTCTime)
mkTestRouterWithTime localPid t = do
  (logRef, sendFn) <- newSendLog
  (timeRef, getTime) <- newTimeRef t
  router <- newRouter defaultGossipSubParams localPid sendFn getTime
  pure (router, logRef, timeRef)

localPid :: PeerId
localPid = mkPeerId 0

-- | A fresh Ed25519 identity for signing test messages.
newKeyPair :: IO KeyPair
newKeyPair = either (error . ("keygen failed: " <>)) id <$> generateKeyPair

-- | Build a correctly signed message, mirroring the publish path.
signedMessage :: KeyPair -> Topic -> ByteString -> PubSubMessage
signedMessage kp topic payload =
  let PeerId from = fromPublicKey (kpPublic kp)
      unsigned = PubSubMessage
        { msgFrom      = Just from
        , msgData      = payload
        , msgSeqNo     = Just (BS.pack [0, 0, 0, 0, 0, 0, 0, 1])
        , msgTopic     = topic
        , msgSignature = Nothing
        , msgKey       = Just (encodePublicKey (kpPublic kp))
        }
  in case sign (kpPrivate kp) (signingBytes unsigned) of
       Left err  -> error ("test fixture signing failed: " <> err)
       Right sig -> unsigned { msgSignature = Just sig }

-- | P4 invalid-message counter recorded for a peer on a topic.
invalidCount :: GossipSubRouter -> PeerId -> Topic -> IO Double
invalidCount router pid topic = do
  peers <- readTVarIO (gsPeers router)
  pure $ case Map.lookup pid peers of
    Nothing -> 0
    Just ps -> tpsInvalidMessages
      (Map.findWithDefault defaultTopicPeerState topic (psTopicState ps))

-- | Add a peer that is subscribed to a topic.
addSubscribedPeer :: GossipSubRouter -> PeerId -> Topic -> IO ()
addSubscribedPeer router pid topic = do
  addPeer router pid GossipSubPeer False fixedTime
  atomically $ modifyTVar' (gsPeers router) $
    Map.adjust (\ps -> ps { psTopics = Set.singleton topic }) pid

-- | Add a /floodsub/1.0.0 peer that is subscribed to a topic.
addFloodSubPeer :: GossipSubRouter -> PeerId -> Topic -> IO ()
addFloodSubPeer router pid topic = do
  addPeer router pid FloodSubPeer False fixedTime
  atomically $ modifyTVar' (gsPeers router) $
    Map.adjust (\ps -> ps { psTopics = Set.singleton topic }) pid

spec :: Spec
spec = do
  describe "GossipSub.Router" $ do
    describe "newRouter" $ do
      it "creates router with empty state" $ do
        (router, _) <- mkTestRouter localPid
        mesh <- readTVarIO (gsMesh router)
        fanout <- readTVarIO (gsFanout router)
        peers <- readTVarIO (gsPeers router)
        seen <- readTVarIO (gsSeen router)
        mesh `shouldBe` Map.empty
        fanout `shouldBe` Map.empty
        peers `shouldBe` Map.empty
        seen `shouldBe` Map.empty

    describe "addPeer / removePeer" $ do
      it "addPeer registers peer with empty topics" $ do
        (router, _) <- mkTestRouter localPid
        let pid = mkPeerId 1
        addPeer router pid GossipSubPeer True fixedTime
        peers <- readTVarIO (gsPeers router)
        Map.member pid peers `shouldBe` True
        case Map.lookup pid peers of
          Just ps -> do
            psProtocol ps `shouldBe` GossipSubPeer
            psIsOutbound ps `shouldBe` True
            psTopics ps `shouldBe` Set.empty
          Nothing -> expectationFailure "peer not found"

      it "removePeer cleans up mesh and fanout" $ do
        (router, _) <- mkTestRouter localPid
        let pid = mkPeerId 1
        addPeer router pid GossipSubPeer False fixedTime
        -- Manually add to mesh
        atomically $ modifyTVar' (gsMesh router) $
          Map.insert "topic1" (Set.singleton pid)
        removePeer router pid
        peers <- readTVarIO (gsPeers router)
        Map.member pid peers `shouldBe` False
        mesh <- readTVarIO (gsMesh router)
        let topicPeers = Map.findWithDefault Set.empty "topic1" mesh
        Set.member pid topicPeers `shouldBe` False

      it "retains a negative score across disconnect and reconnect" $ do
        (router, _) <- mkTestRouter localPid
        let pid = mkPeerId 1
        addPeer router pid GossipSubPeer False fixedTime
        atomically $ modifyTVar' (gsPeers router) $
          Map.adjust (\ps -> ps { psBehaviorPenalty = 5 }) pid
        removePeer router pid
        peersGone <- readTVarIO (gsPeers router)
        Map.member pid peersGone `shouldBe` False
        addPeer router pid GossipSubPeer False fixedTime
        peersBack <- readTVarIO (gsPeers router)
        fmap psBehaviorPenalty (Map.lookup pid peersBack) `shouldBe` Just 5

      it "decays retained counters while the peer is disconnected" $ do
        (router, _, timeRef) <- mkTestRouterWithTime localPid fixedTime
        let pid = mkPeerId 1
        addPeer router pid GossipSubPeer False fixedTime
        atomically $ modifyTVar' (gsPeers router) $
          Map.adjust (\ps -> ps { psBehaviorPenalty = 10 }) pid
        removePeer router pid
        writeIORef timeRef (addUTCTime 1 fixedTime)
        heartbeatOnce router
        addPeer router pid GossipSubPeer False (addUTCTime 1 fixedTime)
        peersBack <- readTVarIO (gsPeers router)
        -- default P7 decay is 0.99
        fmap psBehaviorPenalty (Map.lookup pid peersBack) `shouldBe` Just 9.9

      it "starts with fresh score state after RetainScore expires" $ do
        (router0, _, timeRef) <- mkTestRouterWithTime localPid fixedTime
        let router = router0 { gsScoreParams = (gsScoreParams router0) { pspRetainScore = 1 } }
            pid = mkPeerId 1
        addPeer router pid GossipSubPeer False fixedTime
        atomically $ modifyTVar' (gsPeers router) $
          Map.adjust (\ps -> ps { psBehaviorPenalty = 5 }) pid
        removePeer router pid
        writeIORef timeRef (addUTCTime 2 fixedTime)
        heartbeatOnce router
        addPeer router pid GossipSubPeer False (addUTCTime 2 fixedTime)
        peersBack <- readTVarIO (gsPeers router)
        fmap psBehaviorPenalty (Map.lookup pid peersBack) `shouldBe` Just 0

      it "physically removes expired backoff entries during heartbeat" $ do
        (router, _, timeRef) <- mkTestRouterWithTime localPid fixedTime
        let pid = mkPeerId 1
        atomically $ modifyTVar' (gsBackoff router) $
          Map.insert (pid, "topic1") (addUTCTime 1 fixedTime)
        writeIORef timeRef (addUTCTime 2 fixedTime)
        heartbeatOnce router
        backoff <- readTVarIO (gsBackoff router)
        Map.member (pid, "topic1") backoff `shouldBe` False

    describe "join" $ do
      it "announces subscription to all peers" $ do
        (router, logRef) <- mkTestRouter localPid
        let peerA = mkPeerId 1
            peerB = mkPeerId 2
        addPeer router peerA GossipSubPeer False fixedTime
        addPeer router peerB GossipSubPeer False fixedTime
        join router "blocks"
        sent <- readIORef logRef
        -- Should have sent subscription announcement to both peers
        let subMsgs = filter (\(_, rpc) ->
              any (\s -> subSubscribe s && subTopicId s == "blocks")
                  (rpcSubscriptions rpc)) sent
        length subMsgs `shouldSatisfy` (>= 2)

      it "creates mesh with up to D peers" $ do
        (router, _) <- mkTestRouter localPid
        -- Add 8 peers subscribed to "blocks"
        let peerIds = map mkPeerId [1..8]
        mapM_ (\pid -> addSubscribedPeer router pid "blocks") peerIds
        join router "blocks"
        mesh <- readTVarIO (gsMesh router)
        let meshPeers = Map.findWithDefault Set.empty "blocks" mesh
        -- Should have D=6 peers in mesh
        Set.size meshPeers `shouldBe` 6

      it "sends GRAFT to new mesh peers" $ do
        (router, logRef) <- mkTestRouter localPid
        let peerIds = map mkPeerId [1..8]
        mapM_ (\pid -> addSubscribedPeer router pid "blocks") peerIds
        join router "blocks"
        sent <- readIORef logRef
        -- Check that GRAFT messages were sent
        let graftMsgs = filter (\(_, rpc) ->
              case rpcControl rpc of
                Just ctrl -> any (\(Graft t) -> t == "blocks") (ctrlGraft ctrl)
                Nothing -> False) sent
        length graftMsgs `shouldBe` 6

      it "transitions fanout peers to mesh" $ do
        (router, _) <- mkTestRouter localPid
        let peerA = mkPeerId 1
            peerB = mkPeerId 2
        addSubscribedPeer router peerA "topic1"
        addSubscribedPeer router peerB "topic1"
        -- Pre-populate fanout
        atomically $ modifyTVar' (gsFanout router) $
          Map.insert "topic1" (Set.fromList [peerA, peerB])
        join router "topic1"
        -- Fanout should be cleared
        fanout <- readTVarIO (gsFanout router)
        Map.member "topic1" fanout `shouldBe` False
        -- Mesh should contain former fanout peers
        mesh <- readTVarIO (gsMesh router)
        let meshPeers = Map.findWithDefault Set.empty "topic1" mesh
        Set.member peerA meshPeers `shouldBe` True
        Set.member peerB meshPeers `shouldBe` True

      it "fills mesh when fanout has fewer than D peers" $ do
        (router, _) <- mkTestRouter localPid
        -- 2 fanout peers + 6 more eligible
        let fanoutPeers = map mkPeerId [1, 2]
            morePeers = map mkPeerId [3..8]
        mapM_ (\pid -> addSubscribedPeer router pid "topic1") (fanoutPeers ++ morePeers)
        atomically $ modifyTVar' (gsFanout router) $
          Map.insert "topic1" (Set.fromList fanoutPeers)
        join router "topic1"
        mesh <- readTVarIO (gsMesh router)
        let meshPeers = Map.findWithDefault Set.empty "topic1" mesh
        -- Should have D=6 peers total (2 from fanout + 4 new)
        Set.size meshPeers `shouldBe` 6

      -- gossipsub-v1.0.md JOIN: "notifies them with a GRAFT(topic) control
      -- message" — this includes fanout peers promoted into the mesh (#155).
      it "sends GRAFT to fanout peers promoted into the mesh" $ do
        (router, logRef) <- mkTestRouter localPid
        let peerA = mkPeerId 1
            peerB = mkPeerId 2
        addSubscribedPeer router peerA "topic1"
        addSubscribedPeer router peerB "topic1"
        atomically $ modifyTVar' (gsFanout router) $
          Map.insert "topic1" (Set.fromList [peerA, peerB])
        join router "topic1"
        sent <- readIORef logRef
        let graftTargets = [ pid | (pid, rpc) <- sent
                                 , Just ctrl <- [rpcControl rpc]
                                 , any (\(Graft t) -> t == "topic1") (ctrlGraft ctrl) ]
        Set.fromList graftTargets `shouldBe` Set.fromList [peerA, peerB]

      -- Issue #155: a node maintains its own subscription set independent of
      -- mesh state (gossipsub-v1.0.md "the router keeps track of the topics
      -- its directly connected peers are subscribed to" and announces its own
      -- subscriptions); joining with zero peers must still leave a trace.
      it "records the subscription when the topic has no known peers" $ do
        (router, _) <- mkTestRouter localPid
        join router "empty-topic"
        subs <- readTVarIO (gsSubscriptions router)
        Set.member "empty-topic" subs `shouldBe` True

      it "accepts a GRAFT for a topic joined with no peers at join time" $ do
        -- gossipsub-v1.0.md GRAFT: "On receiving a GRAFT(topic) message, the
        -- router will check to see if it is indeed subscribed to the topic
        -- identified in the message. If so, the router will add the peer to
        -- mesh[topic]." Mesh emptiness at join time is irrelevant (#155).
        (router, logRef) <- mkTestRouter localPid
        join router "empty-topic"
        let sender = mkPeerId 1
        addPeer router sender GossipSubPeer False fixedTime
        handleGraft router sender [Graft "empty-topic"]
        mesh <- readTVarIO (gsMesh router)
        Set.member sender (Map.findWithDefault Set.empty "empty-topic" mesh)
          `shouldBe` True
        sent <- readIORef logRef
        let pruneMsgs = filter (\(_, rpc) ->
              case rpcControl rpc of
                Just ctrl -> not (null (ctrlPrune ctrl))
                Nothing -> False) sent
        length pruneMsgs `shouldBe` 0

    describe "leave" $ do
      it "announces unsubscription to all peers" $ do
        (router, logRef) <- mkTestRouter localPid
        let peerA = mkPeerId 1
        addPeer router peerA GossipSubPeer False fixedTime
        -- Set up mesh
        atomically $ modifyTVar' (gsMesh router) $
          Map.insert "blocks" (Set.singleton peerA)
        leave router "blocks"
        sent <- readIORef logRef
        let unsubMsgs = filter (\(_, rpc) ->
              any (\s -> not (subSubscribe s) && subTopicId s == "blocks")
                  (rpcSubscriptions rpc)) sent
        length unsubMsgs `shouldSatisfy` (>= 1)

      it "sends PRUNE with unsubscribe backoff (10s) to mesh peers" $ do
        (router, logRef) <- mkTestRouter localPid
        let peerA = mkPeerId 1
        addPeer router peerA GossipSubPeer False fixedTime
        atomically $ modifyTVar' (gsMesh router) $
          Map.insert "blocks" (Set.singleton peerA)
        leave router "blocks"
        sent <- readIORef logRef
        let pruneMsgs = filter (\(pid, rpc) ->
              pid == peerA && case rpcControl rpc of
                Just ctrl -> any (\p -> pruneTopic p == "blocks"
                                     && pruneBackoff p == Just 10) (ctrlPrune ctrl)
                Nothing -> False) sent
        length pruneMsgs `shouldBe` 1

      it "deletes mesh entry for topic" $ do
        (router, _) <- mkTestRouter localPid
        atomically $ modifyTVar' (gsMesh router) $
          Map.insert "blocks" (Set.singleton (mkPeerId 1))
        leave router "blocks"
        mesh <- readTVarIO (gsMesh router)
        Map.member "blocks" mesh `shouldBe` False

      it "removes the topic from the subscription set" $ do
        (router, _) <- mkTestRouter localPid
        join router "blocks"
        leave router "blocks"
        subs <- readTVarIO (gsSubscriptions router)
        Set.member "blocks" subs `shouldBe` False

    describe "handleGraft" $ do
      it "accepts graft when subscribed and no backoff" $ do
        (router, logRef) <- mkTestRouter localPid
        let sender = mkPeerId 1
        addPeer router sender GossipSubPeer False fixedTime
        -- #155: subscription is tracked in gsSubscriptions, not inferred
        -- from mesh-map key presence (gossipsub-v1.0.md GRAFT handling)
        atomically $ modifyTVar' (gsSubscriptions router) (Set.insert "blocks")
        handleGraft router sender [Graft "blocks"]
        -- Sender should be in mesh
        mesh <- readTVarIO (gsMesh router)
        let meshPeers = Map.findWithDefault Set.empty "blocks" mesh
        Set.member sender meshPeers `shouldBe` True
        -- No PRUNE should be sent
        sent <- readIORef logRef
        let pruneMsgs = filter (\(_, rpc) ->
              case rpcControl rpc of
                Just ctrl -> not (null (ctrlPrune ctrl))
                Nothing -> False) sent
        length pruneMsgs `shouldBe` 0

      it "ignores a GRAFT for an unsubscribed topic entirely" $ do
        (router, logRef) <- mkTestRouter localPid
        let sender = mkPeerId 1
        addPeer router sender GossipSubPeer False fixedTime
        handleGraft router sender [Graft "unknown-topic"]
        -- The sender must never enter a mesh for a topic we are not
        -- subscribed to, and per gossipsub-v1.1.md the GRAFT is ignored
        -- entirely: replying with PRUNE (the v1.0 behaviour) is a spam
        -- amplification vector (#157).
        mesh <- readTVarIO (gsMesh router)
        Map.findWithDefault Set.empty "unknown-topic" mesh `shouldBe` Set.empty
        readIORef logRef `shouldReturn` []

      it "rejects graft during backoff (sends PRUNE with backoff)" $ do
        (router, logRef, timeRef) <- mkTestRouterWithTime localPid fixedTime
        let sender = mkPeerId 1
        addPeer router sender GossipSubPeer False fixedTime
        -- #155: mark ourselves subscribed via the subscription set
        atomically $ modifyTVar' (gsSubscriptions router) (Set.insert "blocks")
        -- Set backoff that expires in the future
        let backoffExpiry = addUTCTime 60 fixedTime
        atomically $ modifyTVar' (gsBackoff router) $
          Map.insert (sender, "blocks") backoffExpiry
        handleGraft router sender [Graft "blocks"]
        -- Should send PRUNE carrying a fresh backoff (GRAFT flood
        -- protection, gossipsub-v1.1.md; #157)
        sent <- readIORef logRef
        let pruneMsgs = filter (\(pid, rpc) ->
              pid == sender && case rpcControl rpc of
                Just ctrl -> any (\p -> pruneTopic p == "blocks"
                                     && pruneBackoff p == Just 60) (ctrlPrune ctrl)
                Nothing -> False) sent
        length pruneMsgs `shouldBe` 1
        -- Sender should NOT be in mesh
        mesh <- readTVarIO (gsMesh router)
        Set.member sender (Map.findWithDefault Set.empty "blocks" mesh) `shouldBe` False

      it "extends the backoff when a peer GRAFTs during the backoff window" $ do
        -- gossipsub-v1.1.md GRAFT flood protection: re-GRAFTing inside the
        -- backoff window restarts the full backoff, it does not merely
        -- keep the old (shorter) expiry (#157).
        (router, _, _) <- mkTestRouterWithTime localPid fixedTime
        let sender = mkPeerId 1
        addPeer router sender GossipSubPeer False fixedTime
        atomically $ modifyTVar' (gsSubscriptions router) (Set.insert "blocks")
        -- Backoff about to expire in 10s
        atomically $ modifyTVar' (gsBackoff router) $
          Map.insert (sender, "blocks") (addUTCTime 10 fixedTime)
        handleGraft router sender [Graft "blocks"]
        backoff <- readTVarIO (gsBackoff router)
        -- Restarted at the full paramPruneBackoff (60s) from now
        Map.lookup (sender, "blocks") backoff
          `shouldBe` Just (addUTCTime 60 fixedTime)

      it "rejects a negative-score peer's GRAFT with a fresh backoff penalty" $ do
        -- The rejection is not just a PRUNE reply: it starts a backoff so
        -- the peer cannot immediately re-GRAFT or be re-selected by the
        -- heartbeat fill (gossipsub-v1.1.md score-gated GRAFT).
        (router, logRef) <- mkTestRouter localPid
        let sender = mkPeerId 1
            routerNeg = router
              { gsScoreParams = defaultPeerScoreParams
                  { pspAppSpecificScore = const (-1) } }
        addPeer routerNeg sender GossipSubPeer False fixedTime
        atomically $ modifyTVar' (gsSubscriptions routerNeg) (Set.insert "blocks")
        handleGraft routerNeg sender [Graft "blocks"]
        mesh <- readTVarIO (gsMesh routerNeg)
        Set.member sender (Map.findWithDefault Set.empty "blocks" mesh) `shouldBe` False
        backoff <- readTVarIO (gsBackoff routerNeg)
        Map.lookup (sender, "blocks") backoff
          `shouldBe` Just (addUTCTime 60 fixedTime)
        -- The PRUNE reply carries no PX: peer exchange is withheld from
        -- peers below threshold (eclipse-attack hardening, #157/#156)
        sent <- readIORef logRef
        case prunesTo sender sent of
          [p] -> prunePeers p `shouldBe` []
          _   -> expectationFailure "expected exactly one PRUNE reply"

    describe "handlePrune" $ do
      it "removes peer from mesh" $ do
        (router, _) <- mkTestRouter localPid
        let sender = mkPeerId 1
        atomically $ modifyTVar' (gsMesh router) $
          Map.insert "blocks" (Set.singleton sender)
        handlePrune router sender [Prune "blocks" [] (Just 60)]
        mesh <- readTVarIO (gsMesh router)
        Set.member sender (Map.findWithDefault Set.empty "blocks" mesh) `shouldBe` False

      it "starts backoff timer" $ do
        (router, _, _) <- mkTestRouterWithTime localPid fixedTime
        let sender = mkPeerId 1
        atomically $ modifyTVar' (gsMesh router) $
          Map.insert "blocks" (Set.singleton sender)
        handlePrune router sender [Prune "blocks" [] (Just 60)]
        backoff <- readTVarIO (gsBackoff router)
        case Map.lookup (sender, "blocks") backoff of
          Just expires -> expires `shouldBe` addUTCTime 60 fixedTime
          Nothing -> expectationFailure "backoff timer not set"

      it "uses default backoff when not specified in PRUNE" $ do
        (router, _, _) <- mkTestRouterWithTime localPid fixedTime
        let sender = mkPeerId 1
        atomically $ modifyTVar' (gsMesh router) $
          Map.insert "blocks" (Set.singleton sender)
        handlePrune router sender [Prune "blocks" [] Nothing]
        backoff <- readTVarIO (gsBackoff router)
        case Map.lookup (sender, "blocks") backoff of
          Just expires -> expires `shouldBe` addUTCTime 60 fixedTime  -- default pruneBackoff=60
          Nothing -> expectationFailure "backoff timer not set"

    describe "handleSubscriptions" $ do
      it "updates peer topic set" $ do
        (router, _) <- mkTestRouter localPid
        let sender = mkPeerId 1
        addPeer router sender GossipSubPeer False fixedTime
        handleSubscriptions router sender
          [SubOpts True "blocks" False False, SubOpts True "tx" False False]
        peers <- readTVarIO (gsPeers router)
        case Map.lookup sender peers of
          Just ps -> psTopics ps `shouldBe` Set.fromList ["blocks", "tx"]
          Nothing -> expectationFailure "peer not found"

      it "removes topics on unsubscribe" $ do
        (router, _) <- mkTestRouter localPid
        let sender = mkPeerId 1
        addPeer router sender GossipSubPeer False fixedTime
        handleSubscriptions router sender
          [SubOpts True "blocks" False False, SubOpts True "tx" False False]
        handleSubscriptions router sender [SubOpts False "blocks" False False]
        peers <- readTVarIO (gsPeers router)
        case Map.lookup sender peers of
          Just ps -> psTopics ps `shouldBe` Set.singleton "tx"
          Nothing -> expectationFailure "peer not found"

      it "ignores subscriptions from unknown peers" $ do
        (router, _) <- mkTestRouter localPid
        let unknown = mkPeerId 99
        handleSubscriptions router unknown [SubOpts True "blocks" False False]
        peers <- readTVarIO (gsPeers router)
        Map.member unknown peers `shouldBe` False

    describe "handleIHave" $ do
      it "requests unseen message IDs via IWANT" $ do
        (router, logRef) <- mkTestRouter localPid
        let sender = mkPeerId 1
            mid1 = BS.pack [1, 2]
            mid2 = BS.pack [3, 4]
        addPeer router sender GossipSubPeer False fixedTime
        -- Mark mid1 as seen
        atomically $ modifyTVar' (gsSeen router) $
          Map.insert mid1 fixedTime
        handleIHave router sender [IHave "blocks" [mid1, mid2]]
        sent <- readIORef logRef
        -- Should send IWANT for mid2 only
        let iwantMsgs = concatMap (\(_, rpc) ->
              case rpcControl rpc of
                Just ctrl -> concatMap (\(IWant mids) -> mids) (ctrlIWant ctrl)
                Nothing -> []) sent
        iwantMsgs `shouldBe` [mid2]

      it "ignores IHAVE when all messages are seen" $ do
        (router, logRef) <- mkTestRouter localPid
        let sender = mkPeerId 1
            mid1 = BS.pack [1, 2]
        addPeer router sender GossipSubPeer False fixedTime
        atomically $ modifyTVar' (gsSeen router) $
          Map.insert mid1 fixedTime
        handleIHave router sender [IHave "blocks" [mid1]]
        sent <- readIORef logRef
        -- Should not send any IWANT
        sent `shouldBe` []

    describe "handleIWant" $ do
      -- gossipsub-v1.0.md: IWANT requests are answered from the mcache.
      -- These replace the retired "stub does nothing" test, which passed
      -- only because the cache happened to be empty (#175).
      it "answers IWANT for our own published message from the mcache" $ do
        (router, logRef) <- mkTestRouter localPid
        addSubscribedPeer router (mkPeerId 1) "blocks"
        kp <- newKeyPair
        publish router "blocks" (BS.pack [1, 2, 3]) (Just kp)
        published <- concatMap (rpcPublish . snd) <$> readIORef logRef
        case published of
          [msg] -> do
            writeIORef logRef []
            let requester = mkPeerId 2
            handleIWant router requester [IWant [defaultMessageId msg]]
            sent <- readIORef logRef
            map fst sent `shouldBe` [requester]
            concatMap (rpcPublish . snd) sent `shouldBe` [msg]
          _ -> expectationFailure "expected exactly one published message"

      it "answers IWANT for a message received from another peer" $ do
        (router, logRef) <- mkTestRouter localPid
        let sender = mkPeerId 1
            requester = mkPeerId 2
        addPeer router sender GossipSubPeer False fixedTime
        kp <- newKeyPair
        let msg = signedMessage kp "t" (BS.pack [5])
        handleRPC router sender emptyRPC { rpcPublish = [msg] }
        writeIORef logRef []
        handleIWant router requester [IWant [defaultMessageId msg]]
        sent <- readIORef logRef
        concatMap (rpcPublish . snd) sent `shouldBe` [msg]

      it "sends nothing for message ids not in the cache" $ do
        (router, logRef) <- mkTestRouter localPid
        handleIWant router (mkPeerId 1) [IWant [BS.pack [9, 9]]]
        readIORef logRef `shouldReturn` []

    describe "publish" $ do
      it "flood publishes to all topic peers" $ do
        (router, logRef) <- mkTestRouter localPid
        let peerA = mkPeerId 1
            peerB = mkPeerId 2
            peerC = mkPeerId 3  -- not subscribed
        addSubscribedPeer router peerA "blocks"
        addSubscribedPeer router peerB "blocks"
        addPeer router peerC GossipSubPeer False fixedTime
        kp <- newKeyPair
        publish router "blocks" (BS.pack [1, 2, 3]) (Just kp)
        sent <- readIORef logRef
        -- peerA and peerB should receive, but not peerC
        let publishedTo = map fst $ filter (\(_, rpc) -> not (null (rpcPublish rpc))) sent
        Set.fromList publishedTo `shouldBe` Set.fromList [peerA, peerB]

      -- gossipsub-v1.0.md: IWANT is answered from the mcache and IHAVE is
      -- built from it; our own published messages must be cached too (#155).
      it "caches own published message in the mcache" $ do
        (router, _) <- mkTestRouter localPid
        addSubscribedPeer router (mkPeerId 1) "blocks"
        kp <- newKeyPair
        publish router "blocks" (BS.pack [1, 2, 3]) (Just kp)
        cache <- readTVarIO (gsMessageCache router)
        Map.size (mcIndex cache) `shouldBe` 1

      it "marks published message as seen" $ do
        (router, _) <- mkTestRouter localPid
        let peerA = mkPeerId 1
        addSubscribedPeer router peerA "blocks"
        kp <- newKeyPair
        publish router "blocks" (BS.pack [1, 2, 3]) (Just kp)
        seen <- readTVarIO (gsSeen router)
        Map.size seen `shouldBe` 1

      -- #217: anonymous messages carry neither from nor seqno; if their ids
      -- collapsed to one value, the second publish would be deduplicated away
      -- and the mcache entry overwritten.
      it "keeps distinct anonymous publishes distinct under StrictNoSign" $ do
        let params = defaultGossipSubParams { paramSignaturePolicy = StrictNoSign }
        (router, _) <- mkTestRouterWithParams params localPid
        addSubscribedPeer router (mkPeerId 1) "blocks"
        publish router "blocks" (BS.pack [1]) Nothing
        publish router "blocks" (BS.pack [2]) Nothing
        seen <- readTVarIO (gsSeen router)
        Map.size seen `shouldBe` 2
        cache <- readTVarIO (gsMessageCache router)
        Map.size (mcIndex cache) `shouldBe` 2

      it "signs the message and the result verifies under StrictSign" $ do
        kp <- newKeyPair
        (router, logRef) <- mkTestRouter (fromPublicKey (kpPublic kp))
        let peerA = mkPeerId 1
        addSubscribedPeer router peerA "blocks"
        publish router "blocks" (BS.pack [1, 2, 3]) (Just kp)
        sent <- readIORef logRef
        case concatMap (rpcPublish . snd) sent of
          [msg] -> do
            msgSignature msg `shouldSatisfy` (/= Nothing)
            validateMessage StrictSign msg `shouldBe` Right ()
          other -> expectationFailure ("expected one published message, got " <> show (length other))

      it "fails loudly instead of publishing unsigned under StrictSign" $ do
        (router, logRef) <- mkTestRouter localPid
        addSubscribedPeer router (mkPeerId 1) "blocks"
        result <- try (publish router "blocks" (BS.pack [1]) Nothing)
        case result of
          Left (SigningFailed _) -> pure ()
          Right ()               -> expectationFailure "expected SigningFailed"
        sent <- readIORef logRef
        sent `shouldBe` []

      it "delivers message to local application callback" $ do
        (router, _) <- mkTestRouter localPid
        deliveredRef <- newIORef ([] :: [(Topic, ByteString)])
        atomically $ writeTVar (gsOnMessage router) $ \topic msg ->
          modifyIORef' deliveredRef (++ [(topic, msgData msg)])
        let peerA = mkPeerId 1
        addSubscribedPeer router peerA "blocks"
        kp <- newKeyPair
        publish router "blocks" (BS.pack [42]) (Just kp)
        delivered <- readIORef deliveredRef
        length delivered `shouldBe` 1
        snd (head delivered) `shouldBe` BS.pack [42]

    describe "forwardMessage" $ do
      it "forwards to mesh peers excluding sender" $ do
        (router, logRef) <- mkTestRouter localPid
        let sender = mkPeerId 1
            peerB = mkPeerId 2
            peerC = mkPeerId 3
        -- Set up mesh with sender, peerB, peerC
        atomically $ modifyTVar' (gsMesh router) $
          Map.insert "blocks" (Set.fromList [sender, peerB, peerC])
        let msg = PubSubMessage Nothing (BS.pack [1]) Nothing "blocks" Nothing Nothing
        forwardMessage router sender msg
        sent <- readIORef logRef
        let sentTo = map fst sent
        -- Should forward to B and C, not sender
        Set.fromList sentTo `shouldBe` Set.fromList [peerB, peerC]

      it "does nothing when no mesh peers" $ do
        (router, logRef) <- mkTestRouter localPid
        let msg = PubSubMessage Nothing (BS.pack [1]) Nothing "empty" Nothing Nothing
        forwardMessage router (mkPeerId 1) msg
        sent <- readIORef logRef
        sent `shouldBe` []

    describe "handleRPC" $ do
      it "dispatches subscriptions, publish, and control" $ do
        (router, logRef) <- mkTestRouter localPid
        let sender = mkPeerId 1
        addPeer router sender GossipSubPeer False fixedTime
        -- #155: subscribe so GRAFT can be accepted
        atomically $ modifyTVar' (gsSubscriptions router) (Set.insert "blocks")
        let rpc = RPC
              { rpcSubscriptions = [SubOpts True "blocks" False False]
              , rpcPublish = []
              , rpcControl = Just ControlMessage
                  { ctrlIHave = []
                  , ctrlIWant = []
                  , ctrlGraft = [Graft "blocks"]
                  , ctrlPrune = []
                  , ctrlIDontWant = []
                  , ctrlExtensions = Nothing
                  }
              , rpcPartial = Nothing
              }
        handleRPC router sender rpc
        -- Subscription should be recorded
        peers <- readTVarIO (gsPeers router)
        case Map.lookup sender peers of
          Just ps -> Set.member "blocks" (psTopics ps) `shouldBe` True
          Nothing -> expectationFailure "peer not found"
        -- GRAFT should be accepted
        mesh <- readTVarIO (gsMesh router)
        Set.member sender (Map.findWithDefault Set.empty "blocks" mesh) `shouldBe` True

      it "deduplicates published messages via seen cache" $ do
        (router, _) <- mkTestRouter localPid
        let sender = mkPeerId 1
        addPeer router sender GossipSubPeer False fixedTime
        deliveredRef <- newIORef (0 :: Int)
        atomically $ writeTVar (gsOnMessage router) $ \_ _ ->
          modifyIORef' deliveredRef (+ 1)
        kp <- newKeyPair
        let rpc = emptyRPC { rpcPublish = [signedMessage kp "t" (BS.pack [1])] }
        -- Send same message twice
        handleRPC router sender rpc
        handleRPC router sender rpc
        delivered <- readIORef deliveredRef
        -- Should only be delivered once
        delivered `shouldBe` 1

    describe "inbound message validation" $ do
      it "delivers and forwards a correctly signed message" $ do
        (router, logRef) <- mkTestRouter localPid
        let sender = mkPeerId 1
            meshPeer = mkPeerId 2
        addPeer router sender GossipSubPeer False fixedTime
        atomically $ modifyTVar' (gsMesh router) $
          Map.insert "t" (Set.fromList [sender, meshPeer])
        deliveredRef <- newIORef (0 :: Int)
        atomically $ writeTVar (gsOnMessage router) $ \_ _ ->
          modifyIORef' deliveredRef (+ 1)
        kp <- newKeyPair
        handleRPC router sender emptyRPC { rpcPublish = [signedMessage kp "t" (BS.pack [1])] }
        readIORef deliveredRef `shouldReturn` 1
        sent <- readIORef logRef
        map fst sent `shouldBe` [meshPeer]

      it "drops a message with a forged signature without forwarding or delivering" $ do
        (router, logRef) <- mkTestRouter localPid
        let sender = mkPeerId 1
            meshPeer = mkPeerId 2
        addPeer router sender GossipSubPeer False fixedTime
        atomically $ modifyTVar' (gsMesh router) $
          Map.insert "t" (Set.fromList [sender, meshPeer])
        deliveredRef <- newIORef (0 :: Int)
        atomically $ writeTVar (gsOnMessage router) $ \_ _ ->
          modifyIORef' deliveredRef (+ 1)
        kp <- newKeyPair
        let forged = (signedMessage kp "t" (BS.pack [1])) { msgData = BS.pack [99] }
        handleRPC router sender emptyRPC { rpcPublish = [forged] }
        readIORef deliveredRef `shouldReturn` 0
        readIORef logRef `shouldReturn` []
        -- Not cached for IWANT, and not marked seen
        cache <- readTVarIO (gsMessageCache router)
        Map.size (mcIndex cache) `shouldBe` 0
        seen <- readTVarIO (gsSeen router)
        Map.size seen `shouldBe` 0

      it "drops a message whose from does not match its key" $ do
        (router, _) <- mkTestRouter localPid
        let sender = mkPeerId 1
        addPeer router sender GossipSubPeer False fixedTime
        deliveredRef <- newIORef (0 :: Int)
        atomically $ writeTVar (gsOnMessage router) $ \_ _ ->
          modifyIORef' deliveredRef (+ 1)
        kp <- newKeyPair
        impostor <- newKeyPair
        let PeerId spoofed = fromPublicKey (kpPublic impostor)
            msg = (signedMessage kp "t" (BS.pack [1])) { msgFrom = Just spoofed }
        handleRPC router sender emptyRPC { rpcPublish = [msg] }
        readIORef deliveredRef `shouldReturn` 0

      it "rejects an unsigned message under StrictSign" $ do
        -- pubsub/README.md StrictSign: "Enforce the fields to be present,
        -- reject otherwise." The pre-#154 suite asserted the opposite:
        -- that an unsigned message is delivered (#175).
        (router, logRef) <- mkTestRouter localPid
        let sender = mkPeerId 1
            meshPeer = mkPeerId 2
        addPeer router sender GossipSubPeer False fixedTime
        atomically $ modifyTVar' (gsMesh router) $
          Map.insert "t" (Set.fromList [sender, meshPeer])
        deliveredRef <- newIORef (0 :: Int)
        atomically $ writeTVar (gsOnMessage router) $ \_ _ ->
          modifyIORef' deliveredRef (+ 1)
        let unsigned = PubSubMessage Nothing (BS.pack [1]) Nothing "t" Nothing Nothing
        handleRPC router sender emptyRPC { rpcPublish = [unsigned] }
        readIORef deliveredRef `shouldReturn` 0
        readIORef logRef `shouldReturn` []
        invalidCount router sender "t" `shouldReturn` 1

      it "still delivers the genuine message after rejecting a forgery with the same id" $ do
        -- pubsub/README.md:236-238 — a rejected message must not poison the
        -- seen cache: validation runs before dedup, so the genuine message
        -- (same from and seqno, hence the same message id) still goes through.
        (router, _) <- mkTestRouter localPid
        let sender = mkPeerId 1
        addPeer router sender GossipSubPeer False fixedTime
        deliveredRef <- newIORef (0 :: Int)
        atomically $ writeTVar (gsOnMessage router) $ \_ _ ->
          modifyIORef' deliveredRef (+ 1)
        kp <- newKeyPair
        let genuine = signedMessage kp "t" (BS.pack [1])
            forged  = genuine { msgData = BS.pack [99] }
        defaultMessageId forged `shouldBe` defaultMessageId genuine
        handleRPC router sender emptyRPC { rpcPublish = [forged] }
        readIORef deliveredRef `shouldReturn` 0
        handleRPC router sender emptyRPC { rpcPublish = [genuine] }
        readIORef deliveredRef `shouldReturn` 1

      it "charges the sender a P4 invalid delivery for a rejected message" $ do
        (router, _) <- mkTestRouter localPid
        let sender = mkPeerId 1
        addPeer router sender GossipSubPeer False fixedTime
        kp <- newKeyPair
        let forged = (signedMessage kp "t" (BS.pack [1])) { msgData = BS.pack [99] }
        handleRPC router sender emptyRPC { rpcPublish = [forged] }
        invalidCount router sender "t" `shouldReturn` 1

    -- gossipsub-v1.1.md "Extended Validators": Accept propagates, Reject
    -- drops with a P4 penalty, Ignore drops without penalising the source.
    describe "topic validators" $ do
      it "drops a message the topic validator rejects and charges P4" $ do
        (router, logRef) <- mkTestRouter localPid
        let sender = mkPeerId 1
            meshPeer = mkPeerId 2
        addPeer router sender GossipSubPeer False fixedTime
        atomically $ modifyTVar' (gsMesh router) $
          Map.insert "t" (Set.fromList [sender, meshPeer])
        deliveredRef <- newIORef (0 :: Int)
        atomically $ writeTVar (gsOnMessage router) $ \_ _ ->
          modifyIORef' deliveredRef (+ 1)
        registerValidator router "t" (\_ _ -> pure ValidationReject)
        kp <- newKeyPair
        handleRPC router sender emptyRPC { rpcPublish = [signedMessage kp "t" (BS.pack [1])] }
        readIORef deliveredRef `shouldReturn` 0
        readIORef logRef `shouldReturn` []
        invalidCount router sender "t" `shouldReturn` 1

      it "neither delivers nor forwards on Ignore, without a P4 penalty" $ do
        -- The Accept/Reject/Ignore distinction is the point of extended
        -- validators (gossipsub-v1.1.md): an application that cannot
        -- validate a message right now must be able to drop it without
        -- punishing the peer that relayed it.
        (router, logRef) <- mkTestRouter localPid
        let sender = mkPeerId 1
            meshPeer = mkPeerId 2
        addPeer router sender GossipSubPeer False fixedTime
        atomically $ modifyTVar' (gsMesh router) $
          Map.insert "t" (Set.fromList [sender, meshPeer])
        deliveredRef <- newIORef (0 :: Int)
        atomically $ writeTVar (gsOnMessage router) $ \_ _ ->
          modifyIORef' deliveredRef (+ 1)
        registerValidator router "t" (\_ _ -> pure ValidationIgnore)
        kp <- newKeyPair
        handleRPC router sender emptyRPC { rpcPublish = [signedMessage kp "t" (BS.pack [1])] }
        readIORef deliveredRef `shouldReturn` 0
        readIORef logRef `shouldReturn` []
        invalidCount router sender "t" `shouldReturn` 0

      it "propagates a message the topic validator accepts" $ do
        (router, _) <- mkTestRouter localPid
        let sender = mkPeerId 1
        addPeer router sender GossipSubPeer False fixedTime
        deliveredRef <- newIORef (0 :: Int)
        atomically $ writeTVar (gsOnMessage router) $ \_ _ ->
          modifyIORef' deliveredRef (+ 1)
        registerValidator router "t" (\_ _ -> pure ValidationAccept)
        kp <- newKeyPair
        handleRPC router sender emptyRPC { rpcPublish = [signedMessage kp "t" (BS.pack [1])] }
        readIORef deliveredRef `shouldReturn` 1

      it "applies validators per topic" $ do
        (router, _) <- mkTestRouter localPid
        let sender = mkPeerId 1
        addPeer router sender GossipSubPeer False fixedTime
        deliveredRef <- newIORef ([] :: [Topic])
        atomically $ writeTVar (gsOnMessage router) $ \topic _ ->
          modifyIORef' deliveredRef (++ [topic])
        registerValidator router "vetoed" (\_ _ -> pure ValidationReject)
        -- Distinct keys give distinct message ids (from <> seqno), so the
        -- second message is not swallowed by dedup
        kp1 <- newKeyPair
        kp2 <- newKeyPair
        handleRPC router sender emptyRPC
          { rpcPublish = [signedMessage kp1 "vetoed" (BS.pack [1])] }
        handleRPC router sender emptyRPC
          { rpcPublish = [signedMessage kp2 "open" (BS.pack [2])] }
        readIORef deliveredRef `shouldReturn` ["open"]

      it "receives the propagation source and the message" $ do
        (router, _) <- mkTestRouter localPid
        let sender = mkPeerId 1
        addPeer router sender GossipSubPeer False fixedTime
        seenRef <- newIORef ([] :: [(PeerId, ByteString)])
        registerValidator router "t" $ \src msg -> do
          modifyIORef' seenRef (++ [(src, msgData msg)])
          pure ValidationAccept
        kp <- newKeyPair
        handleRPC router sender emptyRPC { rpcPublish = [signedMessage kp "t" (BS.pack [7])] }
        readIORef seenRef `shouldReturn` [(sender, BS.pack [7])]

      it "unregisterValidator restores unvalidated propagation" $ do
        (router, _) <- mkTestRouter localPid
        let sender = mkPeerId 1
        addPeer router sender GossipSubPeer False fixedTime
        deliveredRef <- newIORef (0 :: Int)
        atomically $ writeTVar (gsOnMessage router) $ \_ _ ->
          modifyIORef' deliveredRef (+ 1)
        registerValidator router "t" (\_ _ -> pure ValidationReject)
        unregisterValidator router "t"
        kp <- newKeyPair
        handleRPC router sender emptyRPC { rpcPublish = [signedMessage kp "t" (BS.pack [1])] }
        readIORef deliveredRef `shouldReturn` 1

    describe "peerScore" $ do
      it "returns 0 for unknown peer" $ do
        (router, _) <- mkTestRouter localPid
        score <- peerScore router (mkPeerId 99)
        score `shouldBe` 0

      it "returns 0 for newly added peer with no counters" $ do
        (router, _) <- mkTestRouter localPid
        addPeer router (mkPeerId 1) GossipSubPeer True fixedTime
        score <- peerScore router (mkPeerId 1)
        score `shouldBe` 0

    describe "Scoring integration" $ do
      it "handleGraft rejects negative-score peer" $ do
        (router, logRef) <- mkTestRouter localPid
        let sender = mkPeerId 1
            -- Configure topic params so P4 penalty applies
            routerWithParams = router
              { gsScoreParams = defaultPeerScoreParams
                  { pspTopicParams = Map.singleton "blocks" defaultTopicScoreParams }
              }
        addPeer routerWithParams sender GossipSubPeer False fixedTime
        -- Manually set negative score via P4 (invalid messages)
        atomically $ modifyTVar' (gsPeers routerWithParams) $
          Map.adjust (\ps -> ps
            { psTopicState = Map.singleton "blocks"
                (defaultTopicPeerState { tpsInvalidMessages = 10 })
            }) sender
        -- #155: mark ourselves subscribed via the subscription set
        atomically $ modifyTVar' (gsSubscriptions routerWithParams) (Set.insert "blocks")
        handleGraft routerWithParams sender [Graft "blocks"]
        -- Sender should NOT be in mesh (rejected due to negative score)
        mesh <- readTVarIO (gsMesh routerWithParams)
        Set.member sender (Map.findWithDefault Set.empty "blocks" mesh) `shouldBe` False
        -- Should send PRUNE
        sent <- readIORef logRef
        let pruneMsgs = filter (\(pid, rpc) ->
              pid == sender && case rpcControl rpc of
                Just ctrl -> not (null (ctrlPrune ctrl))
                Nothing -> False) sent
        length pruneMsgs `shouldBe` 1

      it "P7 penalty applied for GRAFT during backoff" $ do
        (router, _) <- mkTestRouter localPid
        let sender = mkPeerId 1
        addPeer router sender GossipSubPeer False fixedTime
        -- #155: mark ourselves subscribed via the subscription set
        atomically $ modifyTVar' (gsSubscriptions router) (Set.insert "blocks")
        -- Set backoff
        let backoffExpiry = addUTCTime 60 fixedTime
        atomically $ modifyTVar' (gsBackoff router) $
          Map.insert (sender, "blocks") backoffExpiry
        -- Behavior penalty should be 0 before
        peers0 <- readTVarIO (gsPeers router)
        case Map.lookup sender peers0 of
          Just ps -> psBehaviorPenalty ps `shouldBe` 0
          Nothing -> expectationFailure "peer not found"
        -- GRAFT during backoff
        handleGraft router sender [Graft "blocks"]
        -- Behavior penalty should increment to 1
        peers1 <- readTVarIO (gsPeers router)
        case Map.lookup sender peers1 of
          Just ps -> psBehaviorPenalty ps `shouldBe` 1
          Nothing -> expectationFailure "peer not found"

      -- Issue #156: every counter feeding the score formula was write-free
      it "GRAFT acceptance starts the P1 mesh clock" $ do
        (router, _) <- mkTestRouter localPid
        let sender = mkPeerId 1
        addPeer router sender GossipSubPeer False fixedTime
        atomically $ modifyTVar' (gsSubscriptions router) (Set.insert "blocks")
        handleGraft router sender [Graft "blocks"]
        peers <- readTVarIO (gsPeers router)
        case Map.lookup sender peers >>= Map.lookup "blocks" . psTopicState of
          Just tps -> do
            tpsInMesh tps `shouldBe` True
            tpsGraftTime tps `shouldBe` Just fixedTime
          Nothing -> expectationFailure "topic state not created on GRAFT"

      it "first valid delivery increments P2 for the sender" $ do
        (router, _) <- mkTestRouter localPid
        let sender = mkPeerId 1
        addPeer router sender GossipSubPeer False fixedTime
        kp <- newKeyPair
        handleRPC router sender emptyRPC { rpcPublish = [signedMessage kp "t" (BS.pack [1])] }
        peers <- readTVarIO (gsPeers router)
        case Map.lookup sender peers >>= Map.lookup "t" . psTopicState of
          Just tps -> tpsFirstMessageDeliveries tps `shouldBe` 1
          Nothing -> expectationFailure "no topic state recorded"

      it "delivery from a mesh peer increments P3" $ do
        (router, _) <- mkTestRouter localPid
        let sender = mkPeerId 1
        addPeer router sender GossipSubPeer False fixedTime
        atomically $ modifyTVar' (gsMesh router) $
          Map.insert "t" (Set.singleton sender)
        kp <- newKeyPair
        handleRPC router sender emptyRPC { rpcPublish = [signedMessage kp "t" (BS.pack [1])] }
        peers <- readTVarIO (gsPeers router)
        case Map.lookup sender peers >>= Map.lookup "t" . psTopicState of
          Just tps -> tpsMeshMessageDeliveries tps `shouldBe` 1
          Nothing -> expectationFailure "no topic state recorded"

      it "duplicate delivery within the window counts P3 but not P2" $ do
        (router, _) <- mkTestRouter localPid
        let first  = mkPeerId 1
            second = mkPeerId 2
        addPeer router first GossipSubPeer False fixedTime
        addPeer router second GossipSubPeer False fixedTime
        atomically $ modifyTVar' (gsMesh router) $
          Map.insert "t" (Set.fromList [first, second])
        kp <- newKeyPair
        let msg = signedMessage kp "t" (BS.pack [1])
        handleRPC router first emptyRPC { rpcPublish = [msg] }
        handleRPC router second emptyRPC { rpcPublish = [msg] }
        peers <- readTVarIO (gsPeers router)
        case Map.lookup second peers >>= Map.lookup "t" . psTopicState of
          Just tps -> do
            tpsFirstMessageDeliveries tps `shouldBe` 0
            tpsMeshMessageDeliveries tps `shouldBe` 1
          Nothing -> expectationFailure "no topic state recorded"

      it "peerScore includes P5 (application-specific score)" $ do
        (router, _) <- mkTestRouter localPid
        let pid = mkPeerId 1
            routerP5 = router
              { gsScoreParams = defaultPeerScoreParams
                  { pspAppSpecificScore = const 42 }
              }
        addPeer routerP5 pid GossipSubPeer False fixedTime
        peerScore routerP5 pid `shouldReturn` 42

      it "setPeerIP feeds P6 IP colocation" $ do
        (router, _) <- mkTestRouter localPid
        let pids = map mkPeerId [1..4]
            ip = BS.pack [10, 0, 0, 1]
        mapM_ (\pid -> addPeer router pid GossipSubPeer False fixedTime) pids
        mapM_ (\pid -> setPeerIP router pid ip) pids
        -- Threshold is 3, so 4 peers on one IP give excess 1: P6 = 1,
        -- weight -10 => score -10
        mapM_ (\pid -> peerScore router pid `shouldReturn` (-10)) pids

      it "removePeer clears the P6 IP colocation entry" $ do
        (router, _) <- mkTestRouter localPid
        let pid = mkPeerId 1
            ip = BS.pack [10, 0, 0, 1]
        addPeer router pid GossipSubPeer False fixedTime
        setPeerIP router pid ip
        removePeer router pid
        ipMap <- readTVarIO (gsIPPeerCount router)
        Map.member ip ipMap `shouldBe` False

      it "graylisted peers have their RPCs ignored" $ do
        (router, _) <- mkTestRouter localPid
        let sender = mkPeerId 1
            routerGl = router
              { gsScoreParams = defaultPeerScoreParams
                  { pspAppSpecificScore = const (-20000) }
              }
        addPeer routerGl sender GossipSubPeer False fixedTime
        -- Below stGraylistThreshold (-10000): the subscription is dropped
        handleRPC routerGl sender emptyRPC { rpcSubscriptions = [SubOpts True "t" False False] }
        peers <- readTVarIO (gsPeers routerGl)
        case Map.lookup sender peers of
          Just ps -> psTopics ps `shouldBe` Set.empty
          Nothing -> expectationFailure "peer not found"

      it "ignores a graylisted peer's GRAFT and publishes entirely" $ do
        -- gossipsub-v1.1.md graylist: below stGraylistThreshold the whole
        -- RPC is ignored — control messages included, with no PRUNE reply
        -- and no message processing.
        (router, logRef) <- mkTestRouter localPid
        let sender = mkPeerId 1
            routerGl = router
              { gsScoreParams = defaultPeerScoreParams
                  { pspAppSpecificScore = const (-20000) } }
        addPeer routerGl sender GossipSubPeer False fixedTime
        atomically $ modifyTVar' (gsSubscriptions routerGl) (Set.insert "blocks")
        deliveredRef <- newIORef (0 :: Int)
        atomically $ writeTVar (gsOnMessage routerGl) $ \_ _ ->
          modifyIORef' deliveredRef (+ 1)
        kp <- newKeyPair
        handleRPC routerGl sender emptyRPC
          { rpcPublish = [signedMessage kp "blocks" (BS.pack [1])]
          , rpcControl = Just emptyControlMessage { ctrlGraft = [Graft "blocks"] }
          }
        mesh <- readTVarIO (gsMesh routerGl)
        Map.findWithDefault Set.empty "blocks" mesh `shouldBe` Set.empty
        readIORef deliveredRef `shouldReturn` 0
        readIORef logRef `shouldReturn` []
        seen <- readTVarIO (gsSeen routerGl)
        Map.size seen `shouldBe` 0

      it "flood publish skips peers below the publish threshold" $ do
        (router, logRef) <- mkTestRouter localPid
        let good = mkPeerId 1
            bad  = mkPeerId 2
            routerTh = router
              { gsScoreParams = defaultPeerScoreParams
                  { pspAppSpecificScore = \pid -> if pid == bad then -2000 else 0 }
              }
        addSubscribedPeer routerTh good "blocks"
        addSubscribedPeer routerTh bad "blocks"
        kp <- newKeyPair
        publish routerTh "blocks" (BS.pack [1]) (Just kp)
        sent <- readIORef logRef
        let publishedTo = map fst $ filter (\(_, rpc) -> not (null (rpcPublish rpc))) sent
        publishedTo `shouldBe` [good]

    describe "PRUNE peer exchange (#157)" $ do
      it "leave sends PRUNE with PX records for other topic peers" $ do
        (router, logRef) <- mkTestRouter localPid
        let meshPeer = mkPeerId 1
            otherA = mkPeerId 2
            otherB = mkPeerId 3
        mapM_ (\pid -> addSubscribedPeer router pid "blocks") [meshPeer, otherA, otherB]
        atomically $ modifyTVar' (gsMesh router) $
          Map.insert "blocks" (Set.singleton meshPeer)
        atomically $ modifyTVar' (gsSubscriptions router) (Set.insert "blocks")
        writeIORef logRef []
        leave router "blocks"
        sent <- readIORef logRef
        let pxSets = [ map pxPeerId (prunePeers p)
                     | (pid, rpc) <- sent
                     , pid == meshPeer
                     , Just ctrl <- [rpcControl rpc]
                     , p <- ctrlPrune ctrl
                     , pruneTopic p == "blocks" ]
        case pxSets of
          [pxIds] -> do
            let PeerId bytesA = otherA
                PeerId bytesB = otherB
            Set.fromList pxIds `shouldBe` Set.fromList [bytesA, bytesB]
          _ -> expectationFailure "expected exactly one PRUNE with PX to the mesh peer"

      it "honours PX from a sender above the acceptance threshold" $ do
        (router, _) <- mkTestRouter localPid
        let sender = mkPeerId 1
            routerPx = router
              { gsScoreParams = defaultPeerScoreParams
                  { pspAppSpecificScore = const 200 }  -- >= stAcceptPXThreshold (100)
              }
        addPeer routerPx sender GossipSubPeer False fixedTime
        receivedRef <- newIORef ([] :: [(Topic, [PeerExchangeInfo])])
        atomically $ writeTVar (gsOnPeerExchange routerPx) $ \t px ->
          modifyIORef' receivedRef (++ [(t, px)])
        let px = [PeerExchangeInfo (BS.pack [9]) Nothing]
        handlePrune routerPx sender [Prune "t" px (Just 60)]
        readIORef receivedRef `shouldReturn` [("t", px)]

      it "ignores PX from a sender below the acceptance threshold" $ do
        (router, _) <- mkTestRouter localPid
        let sender = mkPeerId 1
        addPeer router sender GossipSubPeer False fixedTime
        receivedRef <- newIORef ([] :: [(Topic, [PeerExchangeInfo])])
        atomically $ writeTVar (gsOnPeerExchange router) $ \t px ->
          modifyIORef' receivedRef (++ [(t, px)])
        -- Default score is 0, below stAcceptPXThreshold (100)
        handlePrune router sender [Prune "t" [PeerExchangeInfo (BS.pack [9]) Nothing] (Just 60)]
        readIORef receivedRef `shouldReturn` []

    describe "IWANT promise tracking (#157/#156 P7)" $ do
      it "records a promise when requesting from an IHAVE" $ do
        (router, _) <- mkTestRouter localPid
        let sender = mkPeerId 1
            mid = BS.pack [1, 2, 3]
        addPeer router sender GossipSubPeer False fixedTime
        handleIHave router sender [IHave "t" [mid]]
        promises <- readTVarIO (gsIWantPromises router)
        Map.member (sender, mid) promises `shouldBe` True

      it "clears the promise when the message is delivered" $ do
        (router, _) <- mkTestRouter localPid
        let sender = mkPeerId 1
        addPeer router sender GossipSubPeer False fixedTime
        kp <- newKeyPair
        let msg = signedMessage kp "t" (BS.pack [1])
            mid = defaultMessageId msg
        handleIHave router sender [IHave "t" [mid]]
        promises0 <- readTVarIO (gsIWantPromises router)
        Map.member (sender, mid) promises0 `shouldBe` True
        handleRPC router sender emptyRPC { rpcPublish = [msg] }
        promises1 <- readTVarIO (gsIWantPromises router)
        promises1 `shouldBe` Map.empty

      it "ignores IHAVE from peers below the gossip threshold" $ do
        (router, logRef) <- mkTestRouter localPid
        let sender = mkPeerId 1
            routerTh = router
              { gsScoreParams = defaultPeerScoreParams
                  { pspAppSpecificScore = const (-200) }  -- < stGossipThreshold (-100)
              }
        addPeer routerTh sender GossipSubPeer False fixedTime
        handleIHave routerTh sender [IHave "t" [BS.pack [1]]]
        readIORef logRef `shouldReturn` []

    describe "P3b mesh failure penalty" $ do
      it "handlePrune records P3b mesh failure" $ do
        (router, _) <- mkTestRouter localPid
        let sender = mkPeerId 1
        addPeer router sender GossipSubPeer False fixedTime
        -- Set topic params so P3b can be recorded
        -- The router uses gsScoreParams which defaults to empty topic params
        -- We need to configure topic params for "blocks"
        let tsp = defaultTopicScoreParams { tspMeshMessageDeliveriesThreshold = 5 }
            routerWithParams = router
              { gsScoreParams = defaultPeerScoreParams
                  { pspTopicParams = Map.singleton "blocks" tsp }
              }
        -- In-mesh past the 5s activation window, 0 deliveries.
        atomically $ do
          modifyTVar' (gsMesh routerWithParams) $
            Map.insert "blocks" (Set.singleton sender)
          modifyTVar' (gsPeers routerWithParams) $
            Map.adjust (\ps -> ps
              { psTopicState = Map.singleton "blocks"
                  defaultTopicPeerState
                    { tpsMeshMessageDeliveries = 0
                    , tpsInMesh = True
                    , tpsGraftTime = Just (addUTCTime (-10) fixedTime)
                    }
              }) sender
        handlePrune routerWithParams sender [Prune "blocks" [] (Just 60)]
        -- P3b should capture deficit^2 = (5-0)^2 = 25
        peers <- readTVarIO (gsPeers routerWithParams)
        case Map.lookup sender peers of
          Just ps -> case Map.lookup "blocks" (psTopicState ps) of
            Just tps -> tpsMeshFailurePenalty tps `shouldBe` 25
            Nothing -> expectationFailure "topic state not found"
          Nothing -> expectationFailure "peer not found"

      it "does not add P3b for a PRUNE before activation" $ do
        (router, _) <- mkTestRouter localPid
        let sender = mkPeerId 1
            tsp = defaultTopicScoreParams { tspMeshMessageDeliveriesThreshold = 5 }
            routerWithParams = router
              { gsScoreParams = defaultPeerScoreParams
                  { pspTopicParams = Map.singleton "blocks" tsp }
              }
        addPeer routerWithParams sender GossipSubPeer False fixedTime
        atomically $ do
          modifyTVar' (gsMesh routerWithParams) $
            Map.insert "blocks" (Set.singleton sender)
          modifyTVar' (gsPeers routerWithParams) $
            Map.adjust (\ps -> ps
              { psTopicState = Map.singleton "blocks"
                  defaultTopicPeerState
                    { tpsInMesh = True
                    , tpsGraftTime = Just fixedTime
                    }
              }) sender
        handlePrune routerWithParams sender [Prune "blocks" [] Nothing]
        peers <- readTVarIO (gsPeers routerWithParams)
        fmap (fmap tpsMeshFailurePenalty . Map.lookup "blocks" . psTopicState)
          (Map.lookup sender peers) `shouldBe` Just (Just 0)

      it "does not add P3b for a PRUNE from a non-mesh peer" $ do
        (router, _) <- mkTestRouter localPid
        let sender = mkPeerId 1
            tsp = defaultTopicScoreParams { tspMeshMessageDeliveriesThreshold = 5 }
            routerWithParams = router
              { gsScoreParams = defaultPeerScoreParams
                  { pspTopicParams = Map.singleton "blocks" tsp }
              }
        addPeer routerWithParams sender GossipSubPeer False fixedTime
        handlePrune routerWithParams sender [Prune "blocks" [] Nothing]
        peers <- readTVarIO (gsPeers routerWithParams)
        fmap (Map.lookup "blocks" . psTopicState) (Map.lookup sender peers)
          `shouldBe` Just Nothing

    -- Issue #157 remainder: peers that negotiated /meshsub/1.0.0 must not
    -- receive v1.1 control extensions (PX records, backoff field).
    describe "Protocol version gating (#157)" $ do
      it "leave sends a bare PRUNE (no PX, no backoff) to a /meshsub/1.0.0 peer" $ do
        (router, logRef) <- mkTestRouter localPid
        let v10Peer = mkPeerId 1
            other   = mkPeerId 2
        addPeer router v10Peer GossipSubV10Peer False fixedTime
        atomically $ modifyTVar' (gsPeers router) $
          Map.adjust (\ps -> ps { psTopics = Set.singleton "blocks" }) v10Peer
        addSubscribedPeer router other "blocks"
        atomically $ do
          modifyTVar' (gsMesh router) (Map.insert "blocks" (Set.singleton v10Peer))
          modifyTVar' (gsSubscriptions router) (Set.insert "blocks")
        writeIORef logRef []
        leave router "blocks"
        sent <- readIORef logRef
        case prunesTo v10Peer sent of
          [p] -> do
            prunePeers p `shouldBe` []
            pruneBackoff p `shouldBe` Nothing
          _ -> expectationFailure "expected exactly one PRUNE to the v1.0 peer"

      it "GRAFT rejection PRUNE to a /meshsub/1.0.0 peer omits backoff and PX" $ do
        (router, logRef) <- mkTestRouter localPid
        let sender = mkPeerId 1
            routerNeg = router
              { gsScoreParams = defaultPeerScoreParams
                  { pspAppSpecificScore = const (-1) } }
        addPeer routerNeg sender GossipSubV10Peer False fixedTime
        atomically $ modifyTVar' (gsSubscriptions routerNeg) (Set.insert "blocks")
        handleGraft routerNeg sender [Graft "blocks"]
        sent <- readIORef logRef
        case prunesTo sender sent of
          [p] -> do
            prunePeers p `shouldBe` []
            pruneBackoff p `shouldBe` Nothing
          _ -> expectationFailure "expected exactly one PRUNE reply"

      it "GRAFT rejection PRUNE to a /meshsub/1.1.0 peer carries the backoff field" $ do
        (router, logRef) <- mkTestRouter localPid
        let sender = mkPeerId 1
            routerNeg = router
              { gsScoreParams = defaultPeerScoreParams
                  { pspAppSpecificScore = const (-1) } }
        addPeer routerNeg sender GossipSubPeer False fixedTime
        atomically $ modifyTVar' (gsSubscriptions routerNeg) (Set.insert "blocks")
        handleGraft routerNeg sender [Graft "blocks"]
        sent <- readIORef logRef
        case prunesTo sender sent of
          [p] -> pruneBackoff p `shouldBe` Just 60
          _ -> expectationFailure "expected exactly one PRUNE reply"

    -- Issue #157 remainder: IHAVE/IWANT abuse limits (go-libp2p defaults:
    -- MaxIHaveLength 5000, MaxIHaveMessages 10, reset every heartbeat).
    describe "IHAVE/IWANT limits (#157)" $ do
      it "ignores IHAVE batches beyond paramMaxIHaveMessages per heartbeat" $ do
        (router, logRef) <- mkTestRouterWithParams
          defaultGossipSubParams { paramMaxIHaveMessages = 2 } localPid
        let sender = mkPeerId 1
        addPeer router sender GossipSubPeer False fixedTime
        handleIHave router sender [IHave "t" [BS.pack [1]]]
        handleIHave router sender [IHave "t" [BS.pack [2]]]
        handleIHave router sender [IHave "t" [BS.pack [3]]]
        sent <- readIORef logRef
        length (iwantsSent sent) `shouldBe` 2

      it "caps message ids requested per peer per heartbeat at paramMaxIHaveLength" $ do
        (router, logRef) <- mkTestRouterWithParams
          defaultGossipSubParams { paramMaxIHaveLength = 3 } localPid
        let sender = mkPeerId 1
        addPeer router sender GossipSubPeer False fixedTime
        handleIHave router sender [IHave "t" (map (BS.pack . pure) [1..5])]
        handleIHave router sender [IHave "t" (map (BS.pack . pure) [6..10])]
        sent <- readIORef logRef
        sum (map length (iwantsSent sent)) `shouldBe` 3

      it "heartbeat resets the IHAVE budget" $ do
        (router, logRef) <- mkTestRouterWithParams
          defaultGossipSubParams { paramMaxIHaveMessages = 1 } localPid
        let sender = mkPeerId 1
        addPeer router sender GossipSubPeer False fixedTime
        handleIHave router sender [IHave "t" [BS.pack [1]]]
        handleIHave router sender [IHave "t" [BS.pack [2]]]  -- over budget, ignored
        heartbeatOnce router
        handleIHave router sender [IHave "t" [BS.pack [3]]]
        sent <- readIORef logRef
        length (iwantsSent sent) `shouldBe` 2

      it "serves at most paramMaxIHaveLength messages per peer per heartbeat on IWANT" $ do
        (router, logRef) <- mkTestRouterWithParams
          defaultGossipSubParams
            { paramMaxIHaveLength = 2
            , paramMessageIdFn = msgData } localPid
        let sender = mkPeerId 1
            mkMsg n = PubSubMessage
              { msgFrom = Nothing, msgData = BS.pack [n], msgSeqNo = Nothing
              , msgTopic = "t", msgSignature = Nothing, msgKey = Nothing }
            msgs = map mkMsg [1, 2, 3]
        addPeer router sender GossipSubPeer False fixedTime
        atomically $ modifyTVar' (gsMessageCache router) $ \c ->
          foldl (\acc m -> cachePut (msgData m) m acc) c msgs
        handleIWant router sender [IWant (map msgData msgs)]
        sent <- readIORef logRef
        let served = concat [ rpcPublish rpc | (pid, rpc) <- sent, pid == sender ]
        length served `shouldBe` 2

      it "a hostile peer exhausting its IHAVE budget does not starve other peers" $ do
        -- The flood-protection budgets are per peer: an attacker spamming
        -- IHAVE batches must not consume the honest peers' allowance.
        (router, logRef) <- mkTestRouterWithParams
          defaultGossipSubParams { paramMaxIHaveMessages = 2 } localPid
        let hostile = mkPeerId 1
            honest  = mkPeerId 2
        addPeer router hostile GossipSubPeer False fixedTime
        addPeer router honest GossipSubPeer False fixedTime
        -- Hostile volume: 20 batches, 18 over budget
        mapM_ (\n -> handleIHave router hostile [IHave "t" [BS.pack [n]]]) [1..20]
        sent0 <- readIORef logRef
        length (iwantsSent sent0) `shouldBe` 2
        writeIORef logRef []
        -- The honest peer's advertisement is still answered
        handleIHave router honest [IHave "t" [BS.pack [99]]]
        sent1 <- readIORef logRef
        map fst sent1 `shouldBe` [honest]
        iwantsSent sent1 `shouldBe` [[BS.pack [99]]]

    -- Issue #157 remainder: direct (explicit) peering agreements,
    -- gossipsub-v1.1.md: direct peers always exchange messages and are
    -- never part of the mesh.
    describe "Direct peers (#157)" $ do
      it "forwardMessage always includes subscribed direct peers outside the mesh" $ do
        let dp = mkPeerId 9
        (router, logRef) <- mkTestRouterWithParams
          defaultGossipSubParams { paramDirectPeers = Set.singleton dp } localPid
        let meshPeer = mkPeerId 1
            sender   = mkPeerId 2
        mapM_ (\pid -> addSubscribedPeer router pid "t") [meshPeer, sender, dp]
        atomically $ modifyTVar' (gsMesh router) $
          Map.insert "t" (Set.fromList [meshPeer, sender])
        kp <- newKeyPair
        forwardMessage router sender (signedMessage kp "t" (BS.pack [1]))
        sent <- readIORef logRef
        let recipients = Set.fromList
              [ pid | (pid, rpc) <- sent, not (null (rpcPublish rpc)) ]
        recipients `shouldBe` Set.fromList [meshPeer, dp]

      it "join never adds a direct peer to the mesh" $ do
        let dp = mkPeerId 9
        (router, logRef) <- mkTestRouterWithParams
          defaultGossipSubParams { paramDirectPeers = Set.singleton dp } localPid
        addSubscribedPeer router dp "t"
        join router "t"
        mesh <- readTVarIO (gsMesh router)
        Set.member dp (Map.findWithDefault Set.empty "t" mesh) `shouldBe` False
        sent <- readIORef logRef
        let graftsTo = [ pid | (pid, rpc) <- sent
                             , Just ctrl <- [rpcControl rpc]
                             , not (null (ctrlGraft ctrl)) ]
        graftsTo `shouldBe` []

      it "rejects GRAFT from a direct peer without adding it to the mesh" $ do
        let dp = mkPeerId 9
        (router, logRef) <- mkTestRouterWithParams
          defaultGossipSubParams { paramDirectPeers = Set.singleton dp } localPid
        addSubscribedPeer router dp "t"
        atomically $ modifyTVar' (gsSubscriptions router) (Set.insert "t")
        handleGraft router dp [Graft "t"]
        mesh <- readTVarIO (gsMesh router)
        Set.member dp (Map.findWithDefault Set.empty "t" mesh) `shouldBe` False
        sent <- readIORef logRef
        length (prunesTo dp sent) `shouldBe` 1

      it "direct peers bypass the graylist" $ do
        let dp = mkPeerId 9
        (router, _) <- mkTestRouterWithParams
          defaultGossipSubParams { paramDirectPeers = Set.singleton dp } localPid
        let routerGl = router
              { gsScoreParams = defaultPeerScoreParams
                  { pspAppSpecificScore = const (-20000) } }
        addPeer routerGl dp GossipSubPeer False fixedTime
        handleRPC routerGl dp emptyRPC { rpcSubscriptions = [SubOpts True "t" False False] }
        peers <- readTVarIO (gsPeers routerGl)
        case Map.lookup dp peers of
          Just ps -> psTopics ps `shouldBe` Set.singleton "t"
          Nothing -> expectationFailure "peer not found"

      it "flood publish includes direct peers regardless of score" $ do
        let dp = mkPeerId 9
        (router, logRef) <- mkTestRouterWithParams
          defaultGossipSubParams { paramDirectPeers = Set.singleton dp } localPid
        let routerTh = router
              { gsScoreParams = defaultPeerScoreParams
                  { pspAppSpecificScore =
                      \pid -> if pid == dp then -2000 else 0 } }
        addSubscribedPeer routerTh dp "t"
        kp <- newKeyPair
        publish routerTh "t" (BS.pack [1]) (Just kp)
        sent <- readIORef logRef
        let publishedTo = [ pid | (pid, rpc) <- sent, not (null (rpcPublish rpc)) ]
        publishedTo `shouldBe` [dp]

    -- Issue #157 last item: floodsub compatibility (gossipsub-v1.0.md
    -- "Compatibility with FloodSub"). Floodsub peers receive every message
    -- for topics they subscribe to, are never mesh members, and are never
    -- sent gossipsub control messages.
    describe "FloodSub compatibility (#157)" $ do
      it "forwardMessage floods to a subscribed floodsub peer outside the mesh" $ do
        (router, logRef) <- mkTestRouter localPid
        let fsPeer   = mkPeerId 9
            meshPeer = mkPeerId 1
            sender   = mkPeerId 2
        addSubscribedPeer router meshPeer "t"
        addSubscribedPeer router sender "t"
        addFloodSubPeer router fsPeer "t"
        atomically $ modifyTVar' (gsMesh router) $
          Map.insert "t" (Set.fromList [meshPeer, sender])
        kp <- newKeyPair
        forwardMessage router sender (signedMessage kp "t" (BS.pack [1]))
        sent <- readIORef logRef
        let recipients = Set.fromList
              [ pid | (pid, rpc) <- sent, not (null (rpcPublish rpc)) ]
        recipients `shouldBe` Set.fromList [meshPeer, fsPeer]

      it "forwardMessage skips floodsub peers subscribed to other topics" $ do
        (router, logRef) <- mkTestRouter localPid
        let fsPeer = mkPeerId 9
            sender = mkPeerId 2
        addSubscribedPeer router sender "t"
        addFloodSubPeer router fsPeer "other"
        kp <- newKeyPair
        forwardMessage router sender (signedMessage kp "t" (BS.pack [1]))
        sent <- readIORef logRef
        let recipients = [ pid | (pid, rpc) <- sent, not (null (rpcPublish rpc)) ]
        recipients `shouldBe` []

      it "mesh publish always includes subscribed floodsub peers" $ do
        (router, logRef) <- mkTestRouterWithParams
          defaultGossipSubParams { paramFloodPublish = False } localPid
        let fsPeer   = mkPeerId 9
            meshPeer = mkPeerId 1
        addSubscribedPeer router meshPeer "t"
        addFloodSubPeer router fsPeer "t"
        atomically $ modifyTVar' (gsMesh router) $
          Map.insert "t" (Set.singleton meshPeer)
        kp <- newKeyPair
        publish router "t" (BS.pack [1]) (Just kp)
        sent <- readIORef logRef
        let publishedTo = Set.fromList
              [ pid | (pid, rpc) <- sent, not (null (rpcPublish rpc)) ]
        publishedTo `shouldBe` Set.fromList [meshPeer, fsPeer]

      it "fanout publish reaches floodsub peers without selecting them into fanout" $ do
        (router, logRef) <- mkTestRouterWithParams
          defaultGossipSubParams { paramFloodPublish = False } localPid
        let fsPeer = mkPeerId 9
            gsPeer = mkPeerId 1
        addSubscribedPeer router gsPeer "t"
        addFloodSubPeer router fsPeer "t"
        kp <- newKeyPair
        publish router "t" (BS.pack [1]) (Just kp)
        sent <- readIORef logRef
        let publishedTo = Set.fromList
              [ pid | (pid, rpc) <- sent, not (null (rpcPublish rpc)) ]
        publishedTo `shouldBe` Set.fromList [gsPeer, fsPeer]
        fanout <- readTVarIO (gsFanout router)
        Set.member fsPeer (Map.findWithDefault Set.empty "t" fanout)
          `shouldBe` False

      it "delivers and forwards an inbound message from a floodsub peer" $ do
        (router, logRef) <- mkTestRouter localPid
        let fsPeer   = mkPeerId 9
            meshPeer = mkPeerId 1
        addFloodSubPeer router fsPeer "t"
        addSubscribedPeer router meshPeer "t"
        atomically $ modifyTVar' (gsMesh router) $
          Map.insert "t" (Set.singleton meshPeer)
        deliveredRef <- newIORef []
        atomically $ writeTVar (gsOnMessage router) $
          \topic msg -> modifyIORef' deliveredRef (++ [(topic, msgData msg)])
        kp <- newKeyPair
        let msg = signedMessage kp "t" (BS.pack [42])
        handleRPC router fsPeer emptyRPC { rpcPublish = [msg] }
        readIORef deliveredRef `shouldReturn` [("t", BS.pack [42])]
        sent <- readIORef logRef
        let forwardedTo = [ pid | (pid, rpc) <- sent, not (null (rpcPublish rpc)) ]
        forwardedTo `shouldBe` [meshPeer]

      it "join never adds a floodsub peer to the mesh or sends it control" $ do
        (router, logRef) <- mkTestRouter localPid
        let fsPeer = mkPeerId 9
        addFloodSubPeer router fsPeer "t"
        join router "t"
        mesh <- readTVarIO (gsMesh router)
        Set.member fsPeer (Map.findWithDefault Set.empty "t" mesh) `shouldBe` False
        sent <- readIORef logRef
        let controlTo = [ pid | (pid, rpc) <- sent
                              , Just _ <- [rpcControl rpc] ]
        controlTo `shouldBe` []

      it "ignores GRAFT from a floodsub peer without grafting it" $ do
        (router, logRef) <- mkTestRouter localPid
        let fsPeer = mkPeerId 9
        addFloodSubPeer router fsPeer "t"
        atomically $ modifyTVar' (gsSubscriptions router) (Set.insert "t")
        handleGraft router fsPeer [Graft "t"]
        mesh <- readTVarIO (gsMesh router)
        Set.member fsPeer (Map.findWithDefault Set.empty "t" mesh) `shouldBe` False
        sent <- readIORef logRef
        prunesTo fsPeer sent `shouldBe` []

      it "never replies PRUNE to a rejected GRAFT from a floodsub peer" $ do
        (router, logRef) <- mkTestRouter localPid
        let fsPeer = mkPeerId 9
            routerNeg = router
              { gsScoreParams = defaultPeerScoreParams
                  { pspAppSpecificScore = const (-1) } }
        addFloodSubPeer routerNeg fsPeer "t"
        atomically $ modifyTVar' (gsSubscriptions routerNeg) (Set.insert "t")
        handleGraft routerNeg fsPeer [Graft "t"]
        sent <- readIORef logRef
        prunesTo fsPeer sent `shouldBe` []

      it "never replies IWANT to an IHAVE from a floodsub peer" $ do
        (router, logRef) <- mkTestRouter localPid
        let fsPeer = mkPeerId 9
        addFloodSubPeer router fsPeer "t"
        handleIHave router fsPeer [IHave "t" [BS.pack [1]]]
        sent <- readIORef logRef
        iwantsSent sent `shouldBe` []

    describe "PX signed peer records (#230)" $ do
      it "selectPXPeers attaches the stored signed peer record" $ do
        (router, _) <- mkTestRouter localPid
        kp <- newKeyPair
        let pxPeer = fromPublicKey (kpPublic kp)
        addSubscribedPeer router pxPeer "blocks"
        Right env <- pure (sealPeerRecord kp
          (PeerRecord (peerIdBytes pxPeer) 1
            [BS.pack [0x04, 0x7f, 0x00, 0x00, 0x01, 0x06, 0x0f, 0xa1]]))
        let envBytes = encodeSignedEnvelope env
        setSignedPeerRecord router pxPeer envBytes
        px <- selectPXPeers router "blocks" (mkPeerId 9)
        map pxPeerId px `shouldBe` [peerIdBytes pxPeer]
        map pxSignedPeerRecord px `shouldBe` [Just envBytes]

      it "selectPXPeers omits the record for peers without a stored one" $ do
        (router, _) <- mkTestRouter localPid
        let pxPeer = mkPeerId 1
        addSubscribedPeer router pxPeer "blocks"
        px <- selectPXPeers router "blocks" (mkPeerId 9)
        map pxSignedPeerRecord px `shouldBe` [Nothing]

      it "removePeer forgets the stored signed peer record" $ do
        (router, _) <- mkTestRouter localPid
        let pxPeer = mkPeerId 1
        addSubscribedPeer router pxPeer "blocks"
        setSignedPeerRecord router pxPeer (BS.pack [1, 2, 3])
        removePeer router pxPeer
        recs <- readTVarIO (gsSignedPeerRecords router)
        Map.member pxPeer recs `shouldBe` False

      it "handlePrune drops PX entries whose signed record fails verification" $ do
        (router, _) <- mkTestRouter localPid
        let sender = mkPeerId 1
            routerPx = router
              { gsScoreParams = defaultPeerScoreParams
                  { pspAppSpecificScore = const 200 }  -- >= stAcceptPXThreshold (100)
              }
        addPeer routerPx sender GossipSubPeer False fixedTime
        receivedRef <- newIORef ([] :: [(Topic, [PeerExchangeInfo])])
        atomically $ writeTVar (gsOnPeerExchange routerPx) $ \t px ->
          modifyIORef' receivedRef (++ [(t, px)])
        kpGood <- newKeyPair
        kpEvil <- newKeyPair
        let goodPid = fromPublicKey (kpPublic kpGood)
            evilPid = fromPublicKey (kpPublic kpEvil)
        Right goodEnv <- pure (sealPeerRecord kpGood
          (PeerRecord (peerIdBytes goodPid) 1 []))
        -- Forged: signed by kpEvil over a record claiming goodPid's identity
        Right forgedEnv <- pure (sealPeerRecord kpEvil
          (PeerRecord (peerIdBytes goodPid) 1 []))
        let validEntry    = PeerExchangeInfo (peerIdBytes goodPid)
                              (Just (encodeSignedEnvelope goodEnv))
            forgedEntry   = PeerExchangeInfo (peerIdBytes evilPid)
                              (Just (encodeSignedEnvelope forgedEnv))
            -- Valid envelope attached to an entry claiming a different peer
            mismatchEntry = PeerExchangeInfo (BS.pack [9])
                              (Just (encodeSignedEnvelope goodEnv))
            garbageEntry  = PeerExchangeInfo (BS.pack [8])
                              (Just (BS.pack [0x01, 0x02, 0x03]))
            unsignedEntry = PeerExchangeInfo (BS.pack [7]) Nothing
        handlePrune routerPx sender
          [Prune "t" [validEntry, forgedEntry, mismatchEntry, garbageEntry, unsignedEntry]
                 (Just 60)]
        readIORef receivedRef `shouldReturn` [("t", [validEntry, unsignedEntry])]

      it "handlePrune passes nothing to the PX callback when every record is forged" $ do
        (router, _) <- mkTestRouter localPid
        let sender = mkPeerId 1
            routerPx = router
              { gsScoreParams = defaultPeerScoreParams
                  { pspAppSpecificScore = const 200 }
              }
        addPeer routerPx sender GossipSubPeer False fixedTime
        receivedRef <- newIORef ([] :: [(Topic, [PeerExchangeInfo])])
        atomically $ writeTVar (gsOnPeerExchange routerPx) $ \t px ->
          modifyIORef' receivedRef (++ [(t, px)])
        handlePrune routerPx sender
          [Prune "t" [PeerExchangeInfo (BS.pack [9]) (Just (BS.pack [0xFF]))] (Just 60)]
        readIORef receivedRef `shouldReturn` []
