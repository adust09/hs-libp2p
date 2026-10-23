module LibP2P.Protocol.GossipSub.ScoreSpec (spec) where

import Test.Hspec

import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import Data.Time (UTCTime, addUTCTime)
import Data.Time.Clock.POSIX (posixSecondsToUTCTime)

import LibP2P.Crypto.PeerId (PeerId (..))
import LibP2P.Protocol.GossipSub.Types
import LibP2P.Protocol.GossipSub.Score

-- | Fixed reference time for deterministic tests.
fixedTime :: UTCTime
fixedTime = posixSecondsToUTCTime 1000000

-- | Helper to create a dummy PeerId from a byte.
mkPeerId :: Int -> PeerId
mkPeerId n = PeerId (BS.pack [fromIntegral n])

-- | Helper to create a PeerState with specific topic state.
mkPeerState :: Map.Map Topic TopicPeerState -> PeerState
mkPeerState topicState = PeerState
  { psProtocol        = GossipSubPeer
  , psTopics          = Map.keysSet topicState
  , psPartialTopics   = Map.empty
  , psIsOutbound      = False
  , psConnectedAt     = fixedTime
  , psTopicState      = topicState
  , psBehaviorPenalty = 0
  , psIPAddress       = Nothing
  , psCachedScore     = 0
  }

-- | Helper: default peer score params with topic params for a given topic.
mkScoreParams :: Topic -> TopicScoreParams -> PeerScoreParams
mkScoreParams topic tsp = defaultPeerScoreParams
  { pspTopicParams = Map.singleton topic tsp }

-- | No-op IP peer count map (empty).
emptyIPMap :: Map.Map BS.ByteString (Set.Set PeerId)
emptyIPMap = Map.empty

spec :: Spec
spec = do
  describe "GossipSub.Score" $ do

    -- P1: Time in Mesh
    describe "P1 (Time in Mesh)" $ do
      it "returns 0 when peer is not in mesh" $ do
        let tps = defaultTopicPeerState { tpsInMesh = False, tpsMeshTime = 10 }
        computeP1 defaultTopicScoreParams tps `shouldBe` 0

      it "increases linearly with mesh time up to cap" $ do
        -- quantum=1s, so meshTime 5s => min(5, cap=100) = 5
        let tps = defaultTopicPeerState { tpsInMesh = True, tpsMeshTime = 5 }
        computeP1 defaultTopicScoreParams tps `shouldBe` 5

      it "is capped at TimeInMeshCap" $ do
        let tps = defaultTopicPeerState { tpsInMesh = True, tpsMeshTime = 200 }
        computeP1 defaultTopicScoreParams tps `shouldBe` 100  -- cap=100

    -- P2: First Message Deliveries
    describe "P2 (First Message Deliveries)" $ do
      it "returns 0 with no deliveries" $ do
        let tps = defaultTopicPeerState
        computeP2 defaultTopicScoreParams tps `shouldBe` 0

      it "returns counter value when below cap" $ do
        let tps = defaultTopicPeerState { tpsFirstMessageDeliveries = 10 }
        computeP2 defaultTopicScoreParams tps `shouldBe` 10

      it "is capped at FirstMessageDeliveriesCap" $ do
        let tps = defaultTopicPeerState { tpsFirstMessageDeliveries = 200 }
        computeP2 defaultTopicScoreParams tps `shouldBe` 100  -- cap=100

      it "decays correctly" $ do
        -- decay=0.5 => 10*0.5 = 5
        decayCounter 0.5 10 `shouldBe` 5

    -- P3: Mesh Message Deliveries
    describe "P3 (Mesh Message Deliveries)" $ do
      it "returns 0 when above threshold" $ do
        -- threshold=1, deliveries=5 => deficit=0 => P3=0
        let tps = defaultTopicPeerState
              { tpsInMesh = True
              , tpsMeshMessageDeliveries = 5
              , tpsGraftTime = Just (addUTCTime (-10) fixedTime)  -- 10s ago
              }
        -- activation=5s, been in mesh 10s => activated
        computeP3 defaultTopicScoreParams tps fixedTime `shouldBe` 0

      it "returns negative squared deficit when below threshold" $ do
        -- threshold=1, deliveries=0 => deficit=1 => P3 = -(1^2) = -1
        let tps = defaultTopicPeerState
              { tpsInMesh = True
              , tpsMeshMessageDeliveries = 0
              , tpsGraftTime = Just (addUTCTime (-10) fixedTime)
              }
        computeP3 defaultTopicScoreParams tps fixedTime `shouldBe` 1  -- deficit^2 (weight applied elsewhere)

      it "returns 0 before activation period" $ do
        -- graftTime only 2s ago, activation=5s => not activated => P3=0
        let tps = defaultTopicPeerState
              { tpsInMesh = True
              , tpsMeshMessageDeliveries = 0
              , tpsGraftTime = Just (addUTCTime (-2) fixedTime)
              }
        computeP3 defaultTopicScoreParams tps fixedTime `shouldBe` 0

    -- P3b: Mesh Failure Penalty
    describe "P3b (Mesh Failure Penalty)" $ do
      it "captures deficit squared at prune time" $ do
        -- penalty captured as deficit^2
        let tps = defaultTopicPeerState { tpsMeshFailurePenalty = 4 }  -- (deficit=2)^2
        computeP3b tps `shouldBe` 4

      it "decays over time" $ do
        -- decay factor 0.5: 4 * 0.5 = 2
        decayCounter 0.5 4 `shouldBe` 2

    -- P4: Invalid Messages
    describe "P4 (Invalid Messages)" $ do
      it "returns 0 with no invalid messages" $ do
        computeP4 defaultTopicPeerState `shouldBe` 0

      it "returns counter squared" $ do
        let tps = defaultTopicPeerState { tpsInvalidMessages = 3 }
        computeP4 tps `shouldBe` 9  -- 3^2

      it "decays correctly" $ do
        decayCounter 0.5 9 `shouldBe` 4.5

    -- P6: IP Colocation
    describe "P6 (IP Colocation)" $ do
      it "returns 0 when below threshold" $ do
        -- threshold=3, only 2 peers on IP => P6=0
        let ipMap = Map.singleton (BS.pack [1,2,3,4]) (Set.fromList [mkPeerId 1, mkPeerId 2])
            ps = (mkPeerState Map.empty) { psIPAddress = Just (BS.pack [1,2,3,4]) }
        computeP6 defaultPeerScoreParams ps ipMap `shouldBe` 0

      it "returns negative squared excess above threshold" $ do
        -- threshold=3, 5 peers => excess=2, P6 = 2^2 = 4
        let pids = map mkPeerId [1..5]
            ipMap = Map.singleton (BS.pack [1,2,3,4]) (Set.fromList pids)
            ps = (mkPeerState Map.empty) { psIPAddress = Just (BS.pack [1,2,3,4]) }
        computeP6 defaultPeerScoreParams ps ipMap `shouldBe` 4  -- (5-3)^2

    -- P7: Behavioral Penalty
    describe "P7 (Behavioral Penalty)" $ do
      it "returns 0 with no penalty" $ do
        let ps = mkPeerState Map.empty
        computeP7 ps `shouldBe` 0

      it "returns counter squared" $ do
        let ps = (mkPeerState Map.empty) { psBehaviorPenalty = 3 }
        computeP7 ps `shouldBe` 9  -- 3^2

      it "decays correctly" $ do
        decayCounter 0.99 3 `shouldSatisfy` (\v -> abs (v - 2.97) < 0.001)

      it "addP7Penalty increments counter" $ do
        let ps = mkPeerState Map.empty
            ps' = addP7Penalty ps
        psBehaviorPenalty ps' `shouldBe` 1
        let ps'' = addP7Penalty ps'
        psBehaviorPenalty ps'' `shouldBe` 2

    -- Aggregate score computation
    describe "Aggregate score" $ do
      it "returns 0 for all-zero counters" $ do
        let ps = mkPeerState (Map.singleton "t" defaultTopicPeerState)
            params = mkScoreParams "t" defaultTopicScoreParams
        computeScore params (mkPeerId 1) ps emptyIPMap fixedTime `shouldBe` 0

      it "computes positive score for first deliveries" $ do
        let tps = defaultTopicPeerState
              { tpsFirstMessageDeliveries = 10
              , tpsInMesh = True
              , tpsMeshTime = 5
              }
            ps = mkPeerState (Map.singleton "t" tps)
            params = mkScoreParams "t" defaultTopicScoreParams
        -- P1 = min(5/1, 100) = 5, w1=0.01 => 0.05
        -- P2 = min(10, 100) = 10, w2=1.0 => 10
        -- Topic score = 1.0 * (0.05 + 10) = 10.05
        let score = computeScore params (mkPeerId 1) ps emptyIPMap fixedTime
        score `shouldSatisfy` (> 0)
        abs (score - 10.05) `shouldSatisfy` (< 0.01)

      it "computes negative score for invalid messages" $ do
        let tps = defaultTopicPeerState { tpsInvalidMessages = 2 }
            ps = mkPeerState (Map.singleton "t" tps)
            tsp = defaultTopicScoreParams
            params = mkScoreParams "t" tsp
        -- P4 = 2^2 = 4, w4=-100 => -400
        -- Topic score = 1.0 * (-400) = -400
        let score = computeScore params (mkPeerId 1) ps emptyIPMap fixedTime
        score `shouldSatisfy` (< 0)

      it "applies TopicScoreCap to topic portion" $ do
        let tps = defaultTopicPeerState { tpsFirstMessageDeliveries = 100 }
            ps = mkPeerState (Map.singleton "t" tps)
            tsp = defaultTopicScoreParams
            params = (mkScoreParams "t" tsp) { pspTopicScoreCap = 10 }
        -- P2 = 100, w2=1 => 100, but TopicCap=10
        let score = computeScore params (mkPeerId 1) ps emptyIPMap fixedTime
        score `shouldSatisfy` (<= 10)

      -- Issue #156: P5 was omitted from computeScore entirely
      it "includes the P5 application-specific score" $ do
        let ps = mkPeerState Map.empty
            params = defaultPeerScoreParams
              { pspAppSpecificScore = \pid -> if pid == mkPeerId 1 then 42 else 0
              , pspAppSpecificWeight = 2
              }
        computeScore params (mkPeerId 1) ps emptyIPMap fixedTime `shouldBe` 84
        computeScore params (mkPeerId 2) ps emptyIPMap fixedTime `shouldBe` 0

    -- Mesh membership marking (issue #156: tpsInMesh/tpsGraftTime were
    -- assigned only in defaultTopicPeerState and never updated)
    describe "mesh membership marking" $ do
      it "markPeerInMesh starts the mesh clock" $ do
        let ps = mkPeerState Map.empty
            ps' = markPeerInMesh "t" fixedTime ps
        case Map.lookup "t" (psTopicState ps') of
          Just tps -> do
            tpsInMesh tps `shouldBe` True
            tpsGraftTime tps `shouldBe` Just fixedTime
            tpsMeshTime tps `shouldBe` 0
          Nothing -> expectationFailure "topic state not created"

      it "unmarkPeerInMesh stops the clock but keeps counters" $ do
        let tps0 = defaultTopicPeerState
              { tpsInMesh = True
              , tpsGraftTime = Just fixedTime
              , tpsFirstMessageDeliveries = 7
              }
            ps = mkPeerState (Map.singleton "t" tps0)
            ps' = unmarkPeerInMesh "t" ps
        case Map.lookup "t" (psTopicState ps') of
          Just tps -> do
            tpsInMesh tps `shouldBe` False
            tpsGraftTime tps `shouldBe` Nothing
            tpsFirstMessageDeliveries tps `shouldBe` 7
          Nothing -> expectationFailure "topic state lost"

      it "refreshMeshTime accrues time since graft for in-mesh peers" $ do
        let tps0 = defaultTopicPeerState
              { tpsInMesh = True, tpsGraftTime = Just fixedTime }
            ps = mkPeerState (Map.singleton "t" tps0)
            ps' = refreshMeshTime (addUTCTime 30 fixedTime) ps
        case Map.lookup "t" (psTopicState ps') of
          Just tps -> tpsMeshTime tps `shouldBe` 30
          Nothing  -> expectationFailure "topic state lost"

      it "refreshMeshTime leaves non-mesh peers untouched" $ do
        let ps = mkPeerState (Map.singleton "t" defaultTopicPeerState)
            ps' = refreshMeshTime (addUTCTime 30 fixedTime) ps
        case Map.lookup "t" (psTopicState ps') of
          Just tps -> tpsMeshTime tps `shouldBe` 0
          Nothing  -> expectationFailure "topic state lost"

    -- Decay
    describe "decayScores" $ do
      it "decays P2 counter" $ do
        let tps = defaultTopicPeerState { tpsFirstMessageDeliveries = 10 }
            ps = mkPeerState (Map.singleton "t" tps)
            tsp = defaultTopicScoreParams { tspFirstMessageDeliveriesDecay = 0.5 }
            params = mkScoreParams "t" tsp
            ps' = decayPeerCounters params ps
        case Map.lookup "t" (psTopicState ps') of
          Just tps' -> tpsFirstMessageDeliveries tps' `shouldBe` 5
          Nothing -> expectationFailure "topic state not found"

      it "decays P7 counter" $ do
        let ps = (mkPeerState Map.empty)
              { psBehaviorPenalty = 10 }
            params = defaultPeerScoreParams { pspBehaviorPenaltyDecay = 0.5 }
            ps' = decayPeerCounters params ps
        psBehaviorPenalty ps' `shouldBe` 5

      it "zeros counters below DecayToZero threshold" $ do
        let tps = defaultTopicPeerState { tpsFirstMessageDeliveries = 0.005 }
            ps = mkPeerState (Map.singleton "t" tps)
            tsp = defaultTopicScoreParams { tspFirstMessageDeliveriesDecay = 0.9 }
            params = (mkScoreParams "t" tsp) { pspDecayToZero = 0.01 }
            ps' = decayPeerCounters params ps
        -- 0.005 * 0.9 = 0.0045, which is < 0.01, so should be zeroed
        case Map.lookup "t" (psTopicState ps') of
          Just tps' -> tpsFirstMessageDeliveries tps' `shouldBe` 0
          Nothing -> expectationFailure "topic state not found"

    -- Counter recording helpers
    describe "Counter recording" $ do
      it "recordFirstDelivery increments P2" $ do
        let tps = defaultTopicPeerState { tpsFirstMessageDeliveries = 5 }
            tps' = recordFirstDelivery defaultTopicScoreParams tps
        tpsFirstMessageDeliveries tps' `shouldBe` 6

      it "recordFirstDelivery respects cap" $ do
        let tps = defaultTopicPeerState { tpsFirstMessageDeliveries = 100 }
            tps' = recordFirstDelivery defaultTopicScoreParams tps
        tpsFirstMessageDeliveries tps' `shouldBe` 100  -- cap=100

      it "recordMeshDelivery increments P3" $ do
        let tps = defaultTopicPeerState { tpsMeshMessageDeliveries = 5 }
            tps' = recordMeshDelivery defaultTopicScoreParams tps
        tpsMeshMessageDeliveries tps' `shouldBe` 6

      it "recordInvalidMessage increments P4" $ do
        let tps = defaultTopicPeerState { tpsInvalidMessages = 2 }
            tps' = recordInvalidMessage tps
        tpsInvalidMessages tps' `shouldBe` 3

      it "recordMeshFailure captures deficit squared" $ do
        -- threshold=1, deliveries=0 => deficit=1, P3b += 1^2 = 1
        let tps = defaultTopicPeerState { tpsMeshMessageDeliveries = 0 }
            tps' = recordMeshFailure defaultTopicScoreParams tps
        tpsMeshFailurePenalty tps' `shouldBe` 1  -- (1-0)^2

      it "recordMeshFailure with partial delivery" $ do
        -- threshold=1, deliveries=0.5 => deficit=0.5, P3b += 0.5^2 = 0.25
        let tps = defaultTopicPeerState { tpsMeshMessageDeliveries = 0.5 }
            tps' = recordMeshFailure defaultTopicScoreParams tps
        tpsMeshFailurePenalty tps' `shouldBe` 0.25
