module LibP2P.Protocol.GossipSub.HeartbeatSpec (spec) where

import Test.Hspec

import Control.Concurrent.STM
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import Data.IORef
import Data.Time (UTCTime, addUTCTime)
import Data.Time.Clock.POSIX (posixSecondsToUTCTime)
import LibP2P.Crypto.PeerId (PeerId (..))
import LibP2P.Protocol.GossipSub.Types
import LibP2P.Protocol.GossipSub.Router (newRouter, addPeer, handleIHave, peerScore)
import LibP2P.Protocol.GossipSub.MessageCache (newMessageCache, cachePut, cacheGetGossipIds)
import LibP2P.Protocol.GossipSub.Score (markPeerInMesh)
import LibP2P.Protocol.GossipSub.Heartbeat

-- Test helpers

mkPeerId :: Int -> PeerId
mkPeerId n = PeerId (BS.pack [fromIntegral n])

fixedTime :: UTCTime
fixedTime = posixSecondsToUTCTime 1000000

newSendLog :: IO (IORef [(PeerId, RPC)], PeerId -> RPC -> IO ())
newSendLog = do
  ref <- newIORef []
  let sendFn pid rpc = modifyIORef' ref (++ [(pid, rpc)])
  pure (ref, sendFn)

-- | Create a test router with adjustable time and topic score params.
mkHeartbeatRouter :: PeerId -> UTCTime -> IO (GossipSubRouter, IORef [(PeerId, RPC)], IORef UTCTime)
mkHeartbeatRouter localPid t = do
  (logRef, sendFn) <- newSendLog
  timeRef <- newIORef t
  let getTime = readIORef timeRef
  router <- newRouter defaultGossipSubParams localPid sendFn getTime
  pure (router, logRef, timeRef)

-- | Add peer that's subscribed and in mesh for a topic.
addMeshPeer :: GossipSubRouter -> PeerId -> Topic -> UTCTime -> IO ()
addMeshPeer router pid topic now = do
  addPeer router pid GossipSubPeer False now
  atomically $ do
    modifyTVar' (gsPeers router) $
      Map.adjust (\ps -> ps { psTopics = Set.singleton topic }) pid
    modifyTVar' (gsMesh router) $
      Map.insertWith Set.union topic (Set.singleton pid)

-- | Add peer that's subscribed but NOT in mesh.
addSubscribedPeer :: GossipSubRouter -> PeerId -> Topic -> UTCTime -> IO ()
addSubscribedPeer router pid topic now = do
  addPeer router pid GossipSubPeer False now
  atomically $ modifyTVar' (gsPeers router) $
    Map.adjust (\ps -> ps { psTopics = Set.singleton topic }) pid

-- | Add a subscribed /floodsub/1.0.0 peer (never a mesh candidate).
addFloodSubPeer :: GossipSubRouter -> PeerId -> Topic -> UTCTime -> IO ()
addFloodSubPeer router pid topic now = do
  addPeer router pid FloodSubPeer False now
  atomically $ modifyTVar' (gsPeers router) $
    Map.adjust (\ps -> ps { psTopics = Set.singleton topic }) pid

localPid :: PeerId
localPid = mkPeerId 0

spec :: Spec
spec = do
  describe "GossipSub.Heartbeat" $ do

    describe "Mesh maintenance" $ do
      it "prunes negative-score peers from mesh" $ do
        (router, logRef, _) <- mkHeartbeatRouter localPid fixedTime
        let routerWithParams = router
              { gsScoreParams = defaultPeerScoreParams
                  { pspTopicParams = Map.singleton "t" defaultTopicScoreParams }
              }
        -- Add a peer with negative score (high invalid message count)
        let pid = mkPeerId 1
        addMeshPeer routerWithParams pid "t" fixedTime
        atomically $ modifyTVar' (gsPeers routerWithParams) $
          Map.adjust (\ps -> ps
            { psTopicState = Map.singleton "t"
                (defaultTopicPeerState { tpsInvalidMessages = 10 })
            }) pid
        -- Run heartbeat
        heartbeatOnce routerWithParams
        -- Peer should be removed from mesh
        mesh <- readTVarIO (gsMesh routerWithParams)
        Set.member pid (Map.findWithDefault Set.empty "t" mesh) `shouldBe` False
        -- Should have sent PRUNE
        sent <- readIORef logRef
        let pruneMsgs = filter (\(p, rpc) ->
              p == pid && case rpcControl rpc of
                Just ctrl -> not (null (ctrlPrune ctrl))
                Nothing -> False) sent
        length pruneMsgs `shouldSatisfy` (>= 1)

      it "withholds PX in the PRUNE to a negative-score peer" $ do
        -- gossipsub-v1.1.md peer exchange: PX is only supplied to peers in
        -- good standing — handing an attacker a list of topic peers on the
        -- way out would aid eclipse attacks.
        (router, logRef, _) <- mkHeartbeatRouter localPid fixedTime
        let bad = mkPeerId 1
            routerNeg = router
              { gsScoreParams = defaultPeerScoreParams
                  { pspAppSpecificScore = \pid ->
                      if pid == bad then -1 else 0 } }
        addMeshPeer routerNeg bad "t" fixedTime
        -- Other well-scoring topic peers exist, so PX would have content
        mapM_ (\n -> addSubscribedPeer routerNeg (mkPeerId n) "t" fixedTime)
          [2..5 :: Int]
        heartbeatOnce routerNeg
        sent <- readIORef logRef
        let prunes = [ p | (to, rpc) <- sent, to == bad
                         , Just ctrl <- [rpcControl rpc], p <- ctrlPrune ctrl ]
        case prunes of
          [p] -> prunePeers p `shouldBe` []
          _   -> expectationFailure "expected exactly one PRUNE to the bad peer"
        -- And the backoff penalty is recorded
        backoff <- readTVarIO (gsBackoff routerNeg)
        Map.member (bad, "t") backoff `shouldBe` True

      it "GRAFTs when mesh is undersubscribed (< D_lo)" $ do
        (router, logRef, _) <- mkHeartbeatRouter localPid fixedTime
        -- D=6, D_lo=4: add 2 mesh peers + 4 more subscribed but not in mesh
        let meshPeers = map mkPeerId [1, 2]
            otherPeers = map mkPeerId [3, 4, 5, 6]
        mapM_ (\pid -> addMeshPeer router pid "t" fixedTime) meshPeers
        mapM_ (\pid -> addSubscribedPeer router pid "t" fixedTime) otherPeers
        -- Make sure mesh entry exists
        atomically $ modifyTVar' (gsMesh router) $
          Map.insertWith Set.union "t" Set.empty
        heartbeatOnce router
        -- Mesh should have grown toward D=6
        mesh <- readTVarIO (gsMesh router)
        let meshSize = Set.size (Map.findWithDefault Set.empty "t" mesh)
        meshSize `shouldSatisfy` (>= 4)  -- at least D_lo
        -- Should have sent GRAFT messages
        sent <- readIORef logRef
        let graftMsgs = filter (\(_, rpc) ->
              case rpcControl rpc of
                Just ctrl -> not (null (ctrlGraft ctrl))
                Nothing -> False) sent
        length graftMsgs `shouldSatisfy` (>= 1)

      it "skips peers in backoff during undersubscribed fill" $ do
        (router, logRef, _) <- mkHeartbeatRouter localPid fixedTime
        let meshPeer = mkPeerId 1
            backoffPeer = mkPeerId 2
            availPeer = mkPeerId 3
        addMeshPeer router meshPeer "t" fixedTime
        addSubscribedPeer router backoffPeer "t" fixedTime
        addSubscribedPeer router availPeer "t" fixedTime
        -- Put backoffPeer in backoff
        atomically $ modifyTVar' (gsBackoff router) $
          Map.insert (backoffPeer, "t") (addUTCTime 60 fixedTime)
        heartbeatOnce router
        -- backoffPeer should NOT be in mesh
        mesh <- readTVarIO (gsMesh router)
        let meshPeers = Map.findWithDefault Set.empty "t" mesh
        Set.member backoffPeer meshPeers `shouldBe` False

      it "enforces the backoff across heartbeats and grafts after expiry" $ do
        -- gossipsub-v1.1.md backoff: the pruned peer stays out of the mesh
        -- for the whole backoff window, however many heartbeats that
        -- spans, and becomes an ordinary candidate again once it ends.
        (router, _, timeRef) <- mkHeartbeatRouter localPid fixedTime
        let pid = mkPeerId 1
        addSubscribedPeer router pid "t" fixedTime
        atomically $ do
          modifyTVar' (gsSubscriptions router) (Set.insert "t")
          modifyTVar' (gsBackoff router) $
            Map.insert (pid, "t") (addUTCTime 30 fixedTime)
        let inMesh = do
              mesh <- readTVarIO (gsMesh router)
              pure (Set.member pid (Map.findWithDefault Set.empty "t" mesh))
        -- Two heartbeats inside the window: still excluded
        heartbeatOnce router
        inMesh `shouldReturn` False
        writeIORef timeRef (addUTCTime 15 fixedTime)
        heartbeatOnce router
        inMesh `shouldReturn` False
        -- First heartbeat after expiry: grafted again
        writeIORef timeRef (addUTCTime 31 fixedTime)
        heartbeatOnce router
        inMesh `shouldReturn` True

      it "PRUNEs when mesh is oversubscribed (> D_hi)" $ do
        (router, logRef, _) <- mkHeartbeatRouter localPid fixedTime
        -- D_hi=12: add 15 mesh peers
        let pids = map mkPeerId [1..15]
        mapM_ (\pid -> addMeshPeer router pid "t" fixedTime) pids
        heartbeatOnce router
        -- Mesh should be trimmed to D=6
        mesh <- readTVarIO (gsMesh router)
        let meshSize = Set.size (Map.findWithDefault Set.empty "t" mesh)
        meshSize `shouldBe` 6  -- trimmed to D
        -- Should have sent PRUNE to excess peers
        sent <- readIORef logRef
        let pruneMsgs = filter (\(_, rpc) ->
              case rpcControl rpc of
                Just ctrl -> not (null (ctrlPrune ctrl))
                Nothing -> False) sent
        length pruneMsgs `shouldBe` 9  -- 15 - 6 = 9

      -- Issue #155: a topic joined with zero known peers must still be
      -- maintained; when peers appear later, the heartbeat fills its mesh.
      it "fills the mesh for a subscribed topic that had no peers at join time" $ do
        (router, logRef, _) <- mkHeartbeatRouter localPid fixedTime
        atomically $ modifyTVar' (gsSubscriptions router) (Set.insert "t")
        -- Peers discovered only after the join
        mapM_ (\pid -> addSubscribedPeer router pid "t" fixedTime) (map mkPeerId [1..4])
        heartbeatOnce router
        mesh <- readTVarIO (gsMesh router)
        Set.size (Map.findWithDefault Set.empty "t" mesh) `shouldSatisfy` (>= 1)
        sent <- readIORef logRef
        let graftMsgs = filter (\(_, rpc) ->
              case rpcControl rpc of
                Just ctrl -> not (null (ctrlGraft ctrl))
                Nothing -> False) sent
        length graftMsgs `shouldSatisfy` (>= 1)

    describe "Fanout maintenance" $ do
      it "expires old fanout entries" $ do
        (router, _, timeRef) <- mkHeartbeatRouter localPid fixedTime
        let pid = mkPeerId 1
        addSubscribedPeer router pid "t" fixedTime
        -- Add fanout entry with old timestamp
        atomically $ do
          modifyTVar' (gsFanout router) $
            Map.insert "t" (Set.singleton pid)
          modifyTVar' (gsFanoutPub router) $
            Map.insert "t" fixedTime
        -- Advance time past fanout_ttl (60s)
        writeIORef timeRef (addUTCTime 61 fixedTime)
        heartbeatOnce router
        -- Fanout should be expired
        fanout <- readTVarIO (gsFanout router)
        Map.member "t" fanout `shouldBe` False

      it "fills fanout when < D" $ do
        (router, _, _) <- mkHeartbeatRouter localPid fixedTime
        let pids = map mkPeerId [1..8]
        mapM_ (\pid -> addSubscribedPeer router pid "t" fixedTime) pids
        -- Add fanout entry with 1 peer (recent, so won't expire)
        atomically $ do
          modifyTVar' (gsFanout router) $
            Map.insert "t" (Set.singleton (mkPeerId 1))
          modifyTVar' (gsFanoutPub router) $
            Map.insert "t" fixedTime
        heartbeatOnce router
        -- Fanout should be filled toward D=6
        fanout <- readTVarIO (gsFanout router)
        let fanoutSize = Set.size (Map.findWithDefault Set.empty "t" fanout)
        fanoutSize `shouldSatisfy` (>= 2)  -- at least grew

    describe "Gossip emission" $ do
      it "sends IHAVE to non-mesh peers" $ do
        (router, logRef, _) <- mkHeartbeatRouter localPid fixedTime
        -- Need D=6 mesh peers so mesh maintenance doesn't steal our non-mesh peer
        let meshPeers = map mkPeerId [1..6]
            nonMeshPeer = mkPeerId 10
        mapM_ (\pid -> addMeshPeer router pid "t" fixedTime) meshPeers
        addSubscribedPeer router nonMeshPeer "t" fixedTime
        -- Put a message in the cache
        let mid = BS.pack [42]
            msg = PubSubMessage (Just (BS.pack [1])) (BS.pack [1]) (Just mid) "t" Nothing Nothing
        atomically $ modifyTVar' (gsMessageCache router) $
          cachePut mid msg
        heartbeatOnce router
        -- nonMeshPeer should receive IHAVE
        sent <- readIORef logRef
        let ihaveMsgs = filter (\(pid, rpc) ->
              pid == nonMeshPeer && case rpcControl rpc of
                Just ctrl -> not (null (ctrlIHave ctrl))
                Nothing -> False) sent
        length ihaveMsgs `shouldSatisfy` (>= 1)

      it "does not send IHAVE to mesh peers" $ do
        (router, logRef, _) <- mkHeartbeatRouter localPid fixedTime
        -- Need D=6 mesh peers so mesh maintenance doesn't modify mesh
        let meshPeers = map mkPeerId [1..6]
        mapM_ (\pid -> addMeshPeer router pid "t" fixedTime) meshPeers
        let mid = BS.pack [42]
            msg = PubSubMessage (Just (BS.pack [1])) (BS.pack [1]) (Just mid) "t" Nothing Nothing
        atomically $ modifyTVar' (gsMessageCache router) $
          cachePut mid msg
        heartbeatOnce router
        -- Mesh peers should NOT receive IHAVE (only GRAFTs from maintenance)
        sent <- readIORef logRef
        let ihaveMsgs = filter (\(pid, rpc) ->
              Set.member pid (Set.fromList meshPeers) &&
              case rpcControl rpc of
                Just ctrl -> not (null (ctrlIHave ctrl))
                Nothing -> False) sent
        length ihaveMsgs `shouldBe` 0

      -- gossipsub-v1.0.md heartbeat: gossip is emitted "for each topic in
      -- mesh+fanout"; fanout-only topics were previously skipped (#155).
      it "emits IHAVE for fanout topics" $ do
        (router, logRef, _) <- mkHeartbeatRouter localPid fixedTime
        let pids = map mkPeerId [1..3]
        mapM_ (\pid -> addSubscribedPeer router pid "ftopic" fixedTime) pids
        -- Fanout entry: we publish to "ftopic" without subscribing
        atomically $ do
          modifyTVar' (gsFanout router) $
            Map.insert "ftopic" (Set.singleton (mkPeerId 1))
          modifyTVar' (gsFanoutPub router) $
            Map.insert "ftopic" fixedTime
        let mid = BS.pack [7]
            msg = PubSubMessage (Just (BS.pack [1])) (BS.pack [1]) (Just mid) "ftopic" Nothing Nothing
        atomically $ modifyTVar' (gsMessageCache router) $
          cachePut mid msg
        heartbeatOnce router
        sent <- readIORef logRef
        let ihaveMsgs = filter (\(_, rpc) ->
              case rpcControl rpc of
                Just ctrl -> any (\(IHave t _) -> t == "ftopic") (ctrlIHave ctrl)
                Nothing -> False) sent
        length ihaveMsgs `shouldSatisfy` (>= 1)

      it "rotates message cache after gossip" $ do
        (router, _, _) <- mkHeartbeatRouter localPid fixedTime
        let mid = BS.pack [42]
            msg = PubSubMessage (Just (BS.pack [1])) (BS.pack [1]) (Just mid) "t" Nothing Nothing
        atomically $ modifyTVar' (gsMessageCache router) $
          cachePut mid msg
        -- After mcLen=5 heartbeats, message should be evicted
        mapM_ (\_ -> heartbeatOnce router) [1..5 :: Int]
        cache <- readTVarIO (gsMessageCache router)
        cacheGetGossipIds "t" cache `shouldBe` []

    describe "Score decay" $ do
      it "decays P2 counter" $ do
        (router, _, timeRef) <- mkHeartbeatRouter localPid fixedTime
        let routerWithParams = router
              { gsScoreParams = defaultPeerScoreParams
                  { pspTopicParams = Map.singleton "t"
                      (defaultTopicScoreParams { tspFirstMessageDeliveriesDecay = 0.5 })
                  }
              }
        let pid = mkPeerId 1
        addPeer routerWithParams pid GossipSubPeer False fixedTime
        atomically $ modifyTVar' (gsPeers routerWithParams) $
          Map.adjust (\ps -> ps
            { psTopicState = Map.singleton "t"
                (defaultTopicPeerState { tpsFirstMessageDeliveries = 10 })
            }) pid
        writeIORef timeRef (addUTCTime 1 fixedTime)
        heartbeatOnce routerWithParams
        peers <- readTVarIO (gsPeers routerWithParams)
        case Map.lookup pid peers of
          Just ps -> case Map.lookup "t" (psTopicState ps) of
            Just tps -> tpsFirstMessageDeliveries tps `shouldBe` 5
            Nothing -> expectationFailure "topic state not found"
          Nothing -> expectationFailure "peer not found"

      it "decays P7 counter" $ do
        (router, _, timeRef) <- mkHeartbeatRouter localPid fixedTime
        let routerWithParams = router
              { gsScoreParams = defaultPeerScoreParams
                  { pspBehaviorPenaltyDecay = 0.5 }
              }
        let pid = mkPeerId 1
        addPeer routerWithParams pid GossipSubPeer False fixedTime
        atomically $ modifyTVar' (gsPeers routerWithParams) $
          Map.adjust (\ps -> ps { psBehaviorPenalty = 10 }) pid
        writeIORef timeRef (addUTCTime 1 fixedTime)
        heartbeatOnce routerWithParams
        peers <- readTVarIO (gsPeers routerWithParams)
        case Map.lookup pid peers of
          Just ps -> psBehaviorPenalty ps `shouldBe` 5
          Nothing -> expectationFailure "peer not found"

      it "applies one decay factor per elapsed DecayInterval" $ do
        (router, _, timeRef) <- mkHeartbeatRouter localPid fixedTime
        let routerWithParams = router
              { gsScoreParams = defaultPeerScoreParams
                  { pspBehaviorPenaltyDecay = 0.5 }
              }
            pid = mkPeerId 1
        addPeer routerWithParams pid GossipSubPeer False fixedTime
        atomically $ modifyTVar' (gsPeers routerWithParams) $
          Map.adjust (\ps -> ps { psBehaviorPenalty = 8 }) pid
        writeIORef timeRef (addUTCTime 2 fixedTime)
        heartbeatOnce routerWithParams
        peers <- readTVarIO (gsPeers routerWithParams)
        fmap psBehaviorPenalty (Map.lookup pid peers) `shouldBe` Just 2

      it "does not decay twice at the same wall-clock instant" $ do
        (router, _, timeRef) <- mkHeartbeatRouter localPid fixedTime
        let routerWithParams = router
              { gsScoreParams = defaultPeerScoreParams
                  { pspBehaviorPenaltyDecay = 0.5 }
              }
            pid = mkPeerId 1
        addPeer routerWithParams pid GossipSubPeer False fixedTime
        atomically $ modifyTVar' (gsPeers routerWithParams) $
          Map.adjust (\ps -> ps { psBehaviorPenalty = 8 }) pid
        writeIORef timeRef (addUTCTime 1 fixedTime)
        heartbeatOnce routerWithParams
        heartbeatOnce routerWithParams
        peers <- readTVarIO (gsPeers routerWithParams)
        fmap psBehaviorPenalty (Map.lookup pid peers) `shouldBe` Just 4

    describe "Seen cache cleanup" $ do
      it "cleans expired entries from seen cache" $ do
        (router, _, timeRef) <- mkHeartbeatRouter localPid fixedTime
        -- Add seen entry at fixedTime
        atomically $ modifyTVar' (gsSeen router) $
          Map.insert (BS.pack [1]) (SeenMessage fixedTime (ValidationComplete ValidationAccept))
        -- Advance time past SeenTTL (120s)
        writeIORef timeRef (addUTCTime 121 fixedTime)
        heartbeatOnce router
        seen <- readTVarIO (gsSeen router)
        Map.member (BS.pack [1]) seen `shouldBe` False

      it "preserves unexpired entries" $ do
        (router, _, timeRef) <- mkHeartbeatRouter localPid fixedTime
        atomically $ modifyTVar' (gsSeen router) $
          Map.insert (BS.pack [1]) (SeenMessage fixedTime (ValidationComplete ValidationAccept))
        -- Only 10s later — still within TTL
        writeIORef timeRef (addUTCTime 10 fixedTime)
        heartbeatOnce router
        seen <- readTVarIO (gsSeen router)
        Map.member (BS.pack [1]) seen `shouldBe` True

    describe "Heartbeat counter" $ do
      it "increments on each heartbeat" $ do
        (router, _, _) <- mkHeartbeatRouter localPid fixedTime
        count0 <- readTVarIO (gsHeartbeatCount router)
        count0 `shouldBe` 0
        heartbeatOnce router
        count1 <- readTVarIO (gsHeartbeatCount router)
        count1 `shouldBe` 1
        heartbeatOnce router
        count2 <- readTVarIO (gsHeartbeatCount router)
        count2 `shouldBe` 2

    -- Issue #156: P1 mesh time was never accrued, so time-in-mesh never
    -- contributed to any score.
    describe "P1 mesh time accrual" $ do
      it "accrues mesh time on heartbeat and yields a positive score" $ do
        (router, _, timeRef) <- mkHeartbeatRouter localPid fixedTime
        let tsp = defaultTopicScoreParams { tspMeshMessageDeliveriesThreshold = 0 }
            routerP1 = router
              { gsScoreParams = defaultPeerScoreParams
                  { pspTopicParams = Map.singleton "t" tsp } }
            pid = mkPeerId 1
        addMeshPeer routerP1 pid "t" fixedTime
        atomically $ modifyTVar' (gsPeers routerP1) $
          Map.adjust (markPeerInMesh "t" fixedTime) pid
        writeIORef timeRef (addUTCTime 10 fixedTime)
        heartbeatOnce routerP1
        peers <- readTVarIO (gsPeers routerP1)
        case Map.lookup pid peers >>= Map.lookup "t" . psTopicState of
          Just tps -> tpsMeshTime tps `shouldBe` 10
          Nothing -> expectationFailure "topic state not found"
        score <- peerScore routerP1 pid
        score `shouldSatisfy` (> 0)

    -- Issue #156/#157: IWANT promises (P7) and gossip threshold.
    describe "IWANT promise expiry (P7)" $ do
      it "penalizes peers whose IWANT promise expired undelivered" $ do
        (router, _, timeRef) <- mkHeartbeatRouter localPid fixedTime
        let pid = mkPeerId 1
        addPeer router pid GossipSubPeer False fixedTime
        atomically $ modifyTVar' (gsIWantPromises router) $
          Map.insert (pid, BS.pack [1]) (addUTCTime 3 fixedTime)
        writeIORef timeRef (addUTCTime 4 fixedTime)
        heartbeatOnce router
        peers <- readTVarIO (gsPeers router)
        case Map.lookup pid peers of
          Just ps -> psBehaviorPenalty ps `shouldSatisfy` (> 0)
          Nothing -> expectationFailure "peer not found"
        promises <- readTVarIO (gsIWantPromises router)
        promises `shouldBe` Map.empty

      it "drives the peer's score negative after a broken IHAVE promise" $ do
        -- End-to-end P7: the promise is created by the router's own
        -- IHAVE handling (not injected), expires on heartbeat, and the
        -- resulting penalty is visible in peerScore — w7 is negative by
        -- default, so a broken promise alone must take the score below 0.
        (router, _, timeRef) <- mkHeartbeatRouter localPid fixedTime
        let pid = mkPeerId 1
        addPeer router pid GossipSubPeer False fixedTime
        peerScore router pid `shouldReturn` 0
        -- Peer advertises a message id we have not seen: router IWANTs it
        -- and records the promise with deadline paramIWantFollowupTime (3s)
        handleIHave router pid [IHave "t" [BS.pack [1]]]
        promises <- readTVarIO (gsIWantPromises router)
        Map.member (pid, BS.pack [1]) promises `shouldBe` True
        -- The peer never delivers; past the deadline the promise breaks
        writeIORef timeRef (addUTCTime 4 fixedTime)
        heartbeatOnce router
        score <- peerScore router pid
        score `shouldSatisfy` (< 0)

      it "does not penalize before the deadline" $ do
        (router, _, _) <- mkHeartbeatRouter localPid fixedTime
        let pid = mkPeerId 1
        addPeer router pid GossipSubPeer False fixedTime
        atomically $ modifyTVar' (gsIWantPromises router) $
          Map.insert (pid, BS.pack [1]) (addUTCTime 3 fixedTime)
        heartbeatOnce router
        peers <- readTVarIO (gsPeers router)
        case Map.lookup pid peers of
          Just ps -> psBehaviorPenalty ps `shouldBe` 0
          Nothing -> expectationFailure "peer not found"

    describe "Gossip threshold" $ do
      it "emits no IHAVE to peers below the gossip threshold" $ do
        (router, logRef, _) <- mkHeartbeatRouter localPid fixedTime
        let badPeer = mkPeerId 10
            routerTh = router
              { gsScoreParams = defaultPeerScoreParams
                  { pspAppSpecificScore = \pid ->
                      if pid == badPeer then -200 else 0 } }
        mapM_ (\pid -> addMeshPeer routerTh pid "t" fixedTime) (map mkPeerId [1..6])
        addSubscribedPeer routerTh badPeer "t" fixedTime
        let mid = BS.pack [42]
            msg = PubSubMessage (Just (BS.pack [1])) (BS.pack [1]) (Just mid) "t" Nothing Nothing
        atomically $ modifyTVar' (gsMessageCache routerTh) $ cachePut mid msg
        heartbeatOnce routerTh
        sent <- readIORef logRef
        let ihaveTo = [ pid | (pid, rpc) <- sent
                            , Just ctrl <- [rpcControl rpc]
                            , not (null (ctrlIHave ctrl)) ]
        badPeer `shouldSatisfy` (`notElem` ihaveTo)

    -- Issue #156 (score-aware trim) and #157 (PX on PRUNE).
    describe "Score-aware mesh trim" $ do
      it "keeps the best D_score peers and PRUNEs with peer exchange" $ do
        (router, logRef, _) <- mkHeartbeatRouter localPid fixedTime
        let appScore pid = let PeerId bs = pid in fromIntegral (BS.head bs)
            routerSc = router
              { gsScoreParams = defaultPeerScoreParams
                  { pspAppSpecificScore = appScore } }
        mapM_ (\pid -> addMeshPeer routerSc pid "t" fixedTime) (map mkPeerId [1..15])
        heartbeatOnce routerSc
        mesh <- readTVarIO (gsMesh routerSc)
        let kept = Map.findWithDefault Set.empty "t" mesh
        Set.size kept `shouldBe` 6
        -- D_score = 4: the four best-scoring peers survive the trim
        mapM_ (\n -> Set.member (mkPeerId n) kept `shouldBe` True) [12..15 :: Int]
        -- PRUNEs to removed peers carry PX records (#157)
        sent <- readIORef logRef
        let pxPrunes = [ p | (_, rpc) <- sent
                           , Just ctrl <- [rpcControl rpc]
                           , p <- ctrlPrune ctrl
                           , not (null (prunePeers p)) ]
        length pxPrunes `shouldSatisfy` (>= 1)

      it "keeps at least D_out outbound peers when trimming" $ do
        (router, _, _) <- mkHeartbeatRouter localPid fixedTime
        let appScore pid = let PeerId bs = pid in fromIntegral (BS.head bs)
            routerSc = router
              { gsScoreParams = defaultPeerScoreParams
                  { pspAppSpecificScore = appScore } }
        -- Peers 1-2 are outbound with the lowest scores; 3-15 inbound
        mapM_ (\n -> do
                let pid = mkPeerId n
                addPeer routerSc pid GossipSubPeer True fixedTime
                atomically $ do
                  modifyTVar' (gsPeers routerSc) $
                    Map.adjust (\ps -> ps { psTopics = Set.singleton "t" }) pid
                  modifyTVar' (gsMesh routerSc) $
                    Map.insertWith Set.union "t" (Set.singleton pid))
          [1, 2 :: Int]
        mapM_ (\n -> addMeshPeer routerSc (mkPeerId n) "t" fixedTime) [3..15 :: Int]
        heartbeatOnce routerSc
        mesh <- readTVarIO (gsMesh routerSc)
        let kept = Map.findWithDefault Set.empty "t" mesh
        Set.size kept `shouldBe` 6
        Set.member (mkPeerId 1) kept `shouldBe` True
        Set.member (mkPeerId 2) kept `shouldBe` True

    -- Issue #157 remainder: direct peering, version-gated PRUNE, IHAVE cap
    describe "Direct peers (#157)" $ do
      it "mesh fill never GRAFTs a direct peer" $ do
        let dp = mkPeerId 9
        (logRef, sendFn) <- newSendLog
        timeRef <- newIORef fixedTime
        router <- newRouter
          defaultGossipSubParams { paramDirectPeers = Set.singleton dp }
          localPid sendFn (readIORef timeRef)
        addSubscribedPeer router dp "t" fixedTime
        addSubscribedPeer router (mkPeerId 1) "t" fixedTime
        atomically $ modifyTVar' (gsSubscriptions router) (Set.insert "t")
        heartbeatOnce router
        mesh <- readTVarIO (gsMesh router)
        Set.member dp (Map.findWithDefault Set.empty "t" mesh) `shouldBe` False
        Set.member (mkPeerId 1) (Map.findWithDefault Set.empty "t" mesh) `shouldBe` True
        sent <- readIORef logRef
        let graftTo = [ pid | (pid, rpc) <- sent
                            , Just ctrl <- [rpcControl rpc]
                            , not (null (ctrlGraft ctrl)) ]
        graftTo `shouldBe` [mkPeerId 1]

    -- Issue #157 last item: floodsub peers are skipped by all mesh/fanout
    -- maintenance and never receive control messages, including heartbeat
    -- gossip (gossipsub-v1.0.md "Compatibility with FloodSub").
    describe "FloodSub compatibility (#157)" $ do
      it "mesh fill never GRAFTs a floodsub peer" $ do
        (router, logRef, _) <- mkHeartbeatRouter localPid fixedTime
        let fsPeer = mkPeerId 9
        addFloodSubPeer router fsPeer "t" fixedTime
        addSubscribedPeer router (mkPeerId 1) "t" fixedTime
        atomically $ modifyTVar' (gsSubscriptions router) (Set.insert "t")
        heartbeatOnce router
        mesh <- readTVarIO (gsMesh router)
        let meshPeers = Map.findWithDefault Set.empty "t" mesh
        Set.member fsPeer meshPeers `shouldBe` False
        Set.member (mkPeerId 1) meshPeers `shouldBe` True
        sent <- readIORef logRef
        let graftTo = [ pid | (pid, rpc) <- sent
                            , Just ctrl <- [rpcControl rpc]
                            , not (null (ctrlGraft ctrl)) ]
        graftTo `shouldBe` [mkPeerId 1]

      it "heartbeat gossip emits no control to a floodsub peer and never selects it into fanout" $ do
        (router, logRef, _) <- mkHeartbeatRouter localPid fixedTime
        let fsPeer = mkPeerId 9
        addFloodSubPeer router fsPeer "t" fixedTime
        let mkMsg n = PubSubMessage
              { msgFrom = Nothing, msgData = BS.pack [n], msgSeqNo = Nothing
              , msgTopic = "t", msgSignature = Nothing, msgKey = Nothing }
        atomically $ do
          modifyTVar' (gsFanout router) (Map.insert "t" Set.empty)
          modifyTVar' (gsMessageCache router) $ \c ->
            foldl (\acc n -> cachePut (BS.pack [n]) (mkMsg n) acc) c [1, 2, 3]
        heartbeatOnce router
        sent <- readIORef logRef
        let controlTo = [ pid | (pid, rpc) <- sent
                              , Just _ <- [rpcControl rpc] ]
        controlTo `shouldBe` []
        fanout <- readTVarIO (gsFanout router)
        Set.member fsPeer (Map.findWithDefault Set.empty "t" fanout)
          `shouldBe` False

    describe "Protocol version gating (#157)" $ do
      it "negative-score PRUNE to a /meshsub/1.0.0 peer omits the backoff field" $ do
        (router, logRef, _) <- mkHeartbeatRouter localPid fixedTime
        let pid = mkPeerId 1
            routerNeg = router
              { gsScoreParams = defaultPeerScoreParams
                  { pspAppSpecificScore = const (-1) } }
        addPeer routerNeg pid GossipSubV10Peer False fixedTime
        atomically $ do
          modifyTVar' (gsPeers routerNeg) $
            Map.adjust (\ps -> ps { psTopics = Set.singleton "t" }) pid
          modifyTVar' (gsMesh routerNeg) $ Map.insert "t" (Set.singleton pid)
        heartbeatOnce routerNeg
        sent <- readIORef logRef
        let prunes = [ p | (to, rpc) <- sent, to == pid
                         , Just ctrl <- [rpcControl rpc], p <- ctrlPrune ctrl ]
        case prunes of
          [p] -> do
            prunePeers p `shouldBe` []
            pruneBackoff p `shouldBe` Nothing
          _ -> expectationFailure "expected exactly one PRUNE"

    describe "IHAVE limits (#157)" $ do
      it "caps gossip IHAVE ids at paramMaxIHaveLength" $ do
        (logRef, sendFn) <- newSendLog
        timeRef <- newIORef fixedTime
        router <- newRouter
          defaultGossipSubParams { paramMaxIHaveLength = 2 }
          localPid sendFn (readIORef timeRef)
        -- Topic lives in fanout so mesh maintenance does not graft the
        -- gossip target into the mesh before gossip emission runs.
        addSubscribedPeer router (mkPeerId 1) "t" fixedTime
        let mkMsg n = PubSubMessage
              { msgFrom = Nothing, msgData = BS.pack [n], msgSeqNo = Nothing
              , msgTopic = "t", msgSignature = Nothing, msgKey = Nothing }
        atomically $ do
          modifyTVar' (gsFanout router) (Map.insert "t" Set.empty)
          modifyTVar' (gsMessageCache router) $ \c ->
            foldl (\acc n -> cachePut (BS.pack [n]) (mkMsg n) acc) c [1, 2, 3]
        heartbeatOnce router
        sent <- readIORef logRef
        let ihaveIds = concat [ ihaveMessageIds ih | (_, rpc) <- sent
                              , Just ctrl <- [rpcControl rpc]
                              , ih <- ctrlIHave ctrl ]
        length ihaveIds `shouldBe` 2
