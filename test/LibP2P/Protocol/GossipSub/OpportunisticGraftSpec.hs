module LibP2P.Protocol.GossipSub.OpportunisticGraftSpec (spec) where

import Test.Hspec

import Control.Concurrent.STM
import Data.ByteString qualified as BS
import Data.IORef
import Data.Map.Strict qualified as Map
import Data.Set qualified as Set
import Data.Time (UTCTime, addUTCTime)
import Data.Time.Clock.POSIX (posixSecondsToUTCTime)
import LibP2P.Crypto.PeerId (PeerId (..))
import LibP2P.Protocol.GossipSub.Heartbeat (heartbeatOnce)
import LibP2P.Protocol.GossipSub.Router (addPeer, newRouter)
import LibP2P.Protocol.GossipSub.Types

{- | Issue #291: opportunistic grafting never ran. These tests pin the
gossipsub-v1.1 cadence, the upper median, and the same ineligibility
rules as ordinary mesh fill.
-}
mkPeerId :: Int -> PeerId
mkPeerId n = PeerId (BS.pack [fromIntegral n])

fixedTime :: UTCTime
fixedTime = posixSecondsToUTCTime 1000000

localPid :: PeerId
localPid = mkPeerId 0

topic :: Topic
topic = "t"

-- Mesh already at D_lo, so the every-heartbeat fill does not add peers
-- and cannot hide an opportunistic graft.
isolatedParams :: Int -> Int -> GossipSubParams
isolatedParams ticks peers =
  defaultGossipSubParams
    { paramOpportunisticGraftTicks = ticks
    , paramOpportunisticGraftPeers = peers
    , paramDlo = 2
    , paramD = 2
    , paramDhi = 12
    }

mkRouter ::
  GossipSubParams ->
  (PeerId -> Double) ->
  IO (GossipSubRouter, IORef [(PeerId, RPC)])
mkRouter params scoreFn = do
  ref <- newIORef []
  let sendFn pid rpc = modifyIORef' ref (++ [(pid, rpc)])
  router0 <- newRouter params localPid sendFn (pure fixedTime)
  let router =
        router0
          { gsScoreParams =
              (gsScoreParams router0)
                { pspAppSpecificScore = scoreFn
                }
          }
  pure (router, ref)

subscribe :: GossipSubRouter -> IO ()
subscribe router =
  atomically $ modifyTVar' (gsSubscriptions router) (Set.insert topic)

addMeshPeer :: GossipSubRouter -> PeerId -> IO ()
addMeshPeer router pid = do
  addPeer router pid GossipSubPeer False fixedTime
  atomically $ do
    modifyTVar' (gsPeers router) $
      Map.adjust (\ps -> ps{psTopics = Set.singleton topic}) pid
    modifyTVar' (gsMesh router) $
      Map.insertWith Set.union topic (Set.singleton pid)

addOutside :: GossipSubRouter -> PeerId -> PeerProtocol -> IO ()
addOutside router pid proto = do
  addPeer router pid proto False fixedTime
  atomically $
    modifyTVar' (gsPeers router) $
      Map.adjust (\ps -> ps{psTopics = Set.singleton topic}) pid

meshOf :: GossipSubRouter -> IO (Set.Set PeerId)
meshOf router = do
  mesh <- readTVarIO (gsMesh router)
  pure (Map.findWithDefault Set.empty topic mesh)

grafted :: [(PeerId, RPC)] -> PeerId -> Bool
grafted sent pid = any (\(p, rpc) -> p == pid && hasGraft rpc) sent
 where
  hasGraft rpc = case rpcControl rpc of
    Just ctrl -> any (\g -> graftTopic g == topic) (ctrlGraft ctrl)
    Nothing -> False

scoreMap :: [(PeerId, Double)] -> PeerId -> Double
scoreMap pairs pid = Map.findWithDefault 0 pid (Map.fromList pairs)

spec :: Spec
spec = describe "GossipSub opportunistic grafting (#291)" $ do
  it
    "grafts up to the configured extra peers after N heartbeats when the median is below the threshold" $ do
    let meshPeers = map mkPeerId [1, 2]
        eligible = map mkPeerId [3 .. 6]
        params = isolatedParams 3 2
        scores = scoreMap [(pid, 5) | pid <- eligible]
    (router, logRef) <- mkRouter params scores
    subscribe router
    mapM_ (addMeshPeer router) meshPeers
    mapM_ (\pid -> addOutside router pid GossipSubPeer) eligible
    mapM_ (\_ -> heartbeatOnce router) [1, 2 :: Int]
    meshBefore <- meshOf router
    meshBefore `shouldBe` Set.fromList meshPeers
    heartbeatOnce router
    meshAfter <- meshOf router
    let added = Set.difference meshAfter meshBefore
    Set.size added `shouldBe` 2
    added `shouldSatisfy` (`Set.isSubsetOf` Set.fromList eligible)
    sent <- readIORef logRef
    length (filter (grafted sent) eligible) `shouldBe` 2
    mapM_ (\pid -> grafted sent pid `shouldBe` Set.member pid added) eligible

  it "does not opportunistically graft when the median is at the threshold" $ do
    let meshPeers = map mkPeerId [1, 2]
        outsider = mkPeerId 3
        scores = scoreMap [(mkPeerId 1, 1), (mkPeerId 2, 1), (outsider, 5)]
    (router, logRef) <- mkRouter (isolatedParams 1 2) scores
    subscribe router
    mapM_ (addMeshPeer router) meshPeers
    addOutside router outsider GossipSubPeer
    heartbeatOnce router
    meshOf router >>= (`shouldBe` Set.fromList meshPeers)
    sent <- readIORef logRef
    grafted sent outsider `shouldBe` False

  it "does not opportunistically graft when the median is above the threshold" $ do
    let meshPeers = map mkPeerId [1, 2]
        outsider = mkPeerId 3
        scores = scoreMap [(mkPeerId 1, 2), (mkPeerId 2, 4), (outsider, 10)]
    (router, logRef) <- mkRouter (isolatedParams 1 2) scores
    subscribe router
    mapM_ (addMeshPeer router) meshPeers
    addOutside router outsider GossipSubPeer
    heartbeatOnce router
    meshOf router >>= (`shouldBe` Set.fromList meshPeers)
    sent <- readIORef logRef
    grafted sent outsider `shouldBe` False

  it "does not graft direct, floodsub, or backoff peers" $ do
    let meshPeers = map mkPeerId [1, 2]
        direct = mkPeerId 3
        flood = mkPeerId 4
        backedOff = mkPeerId 5
        good = mkPeerId 6
        params = (isolatedParams 1 2){paramDirectPeers = Set.singleton direct}
        scores =
          scoreMap
            [ (direct, 10)
            , (flood, 10)
            , (backedOff, 10)
            , (good, 5)
            ]
    (router, logRef) <- mkRouter params scores
    subscribe router
    mapM_ (addMeshPeer router) meshPeers
    addOutside router direct GossipSubPeer
    addOutside router flood FloodSubPeer
    addOutside router backedOff GossipSubPeer
    addOutside router good GossipSubPeer
    atomically $
      modifyTVar' (gsBackoff router) $
        Map.insert (backedOff, topic) (addUTCTime 60 fixedTime)
    heartbeatOnce router
    mesh <- meshOf router
    mesh `shouldBe` Set.fromList (good : meshPeers)
    sent <- readIORef logRef
    grafted sent good `shouldBe` True
    mapM_ (\pid -> grafted sent pid `shouldBe` False) [direct, flood, backedOff]

  it "does not graft a negative-score peer even when its score is above the median" $ do
    let directPeers = map mkPeerId [1, 2]
        negative = mkPeerId 3
        good = mkPeerId 4
        params =
          (isolatedParams 1 2)
            { paramDirectPeers = Set.fromList directPeers
            }
        scores =
          scoreMap
            [ (mkPeerId 1, -2)
            , (mkPeerId 2, -2)
            , (negative, -0.5)
            , (good, 3)
            ]
    (router, logRef) <- mkRouter params scores
    subscribe router
    mapM_ (addMeshPeer router) directPeers
    addOutside router negative GossipSubPeer
    addOutside router good GossipSubPeer
    heartbeatOnce router
    meshOf router >>= (`shouldBe` Set.fromList (good : directPeers))
    sent <- readIORef logRef
    grafted sent negative `shouldBe` False
    grafted sent good `shouldBe` True

  it "still fills an undersubscribed mesh on a non-opportunistic heartbeat" $ do
    fillsWhenTicks 3

  it "still fills an undersubscribed mesh on an opportunistic heartbeat" $ do
    fillsWhenTicks 1

  it "skips a mesh of one peer" $ do
    let only = mkPeerId 1
        outsider = mkPeerId 2
        params = (isolatedParams 1 2){paramDlo = 1, paramD = 1}
        scores = scoreMap [(outsider, 10)]
    (router, logRef) <- mkRouter params scores
    subscribe router
    addMeshPeer router only
    addOutside router outsider GossipSubPeer
    heartbeatOnce router
    meshOf router >>= (`shouldBe` Set.singleton only)
    sent <- readIORef logRef
    grafted sent outsider `shouldBe` False

  it "does not graft a topic the router is not subscribed to" $ do
    let meshPeers = map mkPeerId [1, 2]
        outsider = mkPeerId 3
        scores = scoreMap [(outsider, 10)]
    (router, logRef) <- mkRouter (isolatedParams 1 2) scores
    mapM_ (addMeshPeer router) meshPeers
    addOutside router outsider GossipSubPeer
    heartbeatOnce router
    meshOf router >>= (`shouldBe` Set.fromList meshPeers)
    sent <- readIORef logRef
    grafted sent outsider `shouldBe` False

  it "uses the upper median, so an even mesh at the threshold is not grafted" $ do
    -- Sorted scores [0, 0, 1, 5], index len/2 = 2, median 1.
    -- A lower median or a mean would be below the threshold and graft.
    let meshPeers = map mkPeerId [1 .. 4]
        outsider = mkPeerId 5
        scores =
          scoreMap
            [ (mkPeerId 1, 0)
            , (mkPeerId 2, 0)
            , (mkPeerId 3, 1)
            , (mkPeerId 4, 5)
            , (outsider, 10)
            ]
    (router, logRef) <- mkRouter (isolatedParams 1 2) scores
    subscribe router
    mapM_ (addMeshPeer router) meshPeers
    addOutside router outsider GossipSubPeer
    heartbeatOnce router
    meshOf router >>= (`shouldBe` Set.fromList meshPeers)
    sent <- readIORef logRef
    grafted sent outsider `shouldBe` False

  it "does not crash when opportunistic graft ticks are zero" $ do
    let meshPeers = map mkPeerId [1, 2]
        outsider = mkPeerId 3
        scores = scoreMap [(outsider, 5)]
    (router, logRef) <- mkRouter (isolatedParams 0 2) scores
    subscribe router
    mapM_ (addMeshPeer router) meshPeers
    addOutside router outsider GossipSubPeer
    heartbeatOnce router
    meshOf router >>= (`shouldBe` Set.fromList meshPeers)
    sent <- readIORef logRef
    grafted sent outsider `shouldBe` False

  it "starts the mesh clock for an opportunistically grafted peer" $ do
    let meshPeers = map mkPeerId [1, 2]
        outsider = mkPeerId 3
        scores = scoreMap [(outsider, 5)]
    (router, _) <- mkRouter (isolatedParams 1 1) scores
    subscribe router
    mapM_ (addMeshPeer router) meshPeers
    addOutside router outsider GossipSubPeer
    heartbeatOnce router
    peers <- readTVarIO (gsPeers router)
    let inMesh =
          fmap
            (tpsInMesh . Map.findWithDefault defaultTopicPeerState topic . psTopicState)
            (Map.lookup outsider peers)
    inMesh `shouldBe` Just True

fillsWhenTicks :: Int -> IO ()
fillsWhenTicks ticks = do
  let params = defaultGossipSubParams{paramOpportunisticGraftTicks = ticks}
      meshPeers = map mkPeerId [1, 2]
      outside = map mkPeerId [3 .. 6]
  (router, _) <- mkRouter params (const 0)
  subscribe router
  mapM_ (addMeshPeer router) meshPeers
  mapM_ (\pid -> addOutside router pid GossipSubPeer) outside
  heartbeatOnce router
  mesh <- meshOf router
  Set.size mesh `shouldBe` 6
  mesh `shouldSatisfy` (Set.fromList meshPeers `Set.isSubsetOf`)
