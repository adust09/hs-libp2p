module LibP2P.Protocol.GossipSub.DuplicateValidationSpec (spec) where

import Control.Concurrent (newEmptyMVar, putMVar, takeMVar)
import Control.Concurrent.Async (cancel, replicateConcurrently_, wait, withAsync)
import Control.Concurrent.STM
import Control.Monad (forM_)
import Data.IORef
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import Data.Time (UTCTime, addUTCTime)
import Data.Time.Clock.POSIX (posixSecondsToUTCTime)
import LibP2P.Crypto.PeerId (PeerId (..))
import LibP2P.Protocol.GossipSub.Heartbeat (heartbeatOnce)
import LibP2P.Protocol.GossipSub.Router
import LibP2P.Protocol.GossipSub.Types
import System.Timeout (timeout)
import Test.Hspec

spec :: Spec
spec = describe "duplicate validation outcomes" $ do
  outcomeSpec
  acceptedWindowSpec
  acceptedSourceSpec
  pendingSpec
  expirySpec
  retainedScoreSpec

outcomeSpec :: Spec
outcomeSpec = do
  it "should penalize both sources when a rejected message is repeated" $ do
    (router, _) <- fixture
    registerValidator router topic (\_ _ -> pure ValidationReject)
    deliver router firstPeer
    deliver router secondPeer
    counters router firstPeer `shouldReturn` (0, 0, 1)
    counters router secondPeer `shouldReturn` (0, 0, 1)
    deliver router secondPeer
    counters router secondPeer `shouldReturn` (0, 0, 2)

  it "should neither credit nor penalize duplicates when a message is ignored" $ do
    (router, _) <- fixture
    registerValidator router topic (\_ _ -> pure ValidationIgnore)
    deliver router firstPeer
    deliver router secondPeer
    counters router firstPeer `shouldReturn` (0, 0, 0)
    counters router secondPeer `shouldReturn` (0, 0, 0)

acceptedWindowSpec :: Spec
acceptedWindowSpec = do
  it "should preserve near-first duplicate credit only for accepted messages" $ do
    (router, clock) <- fixture
    deliver router firstPeer
    deliver router secondPeer
    writeIORef clock (addUTCTime 2 epoch)
    deliver router thirdPeer
    counters router firstPeer `shouldReturn` (1, 1, 0)
    counters router secondPeer `shouldReturn` (0, 1, 0)
    counters router thirdPeer `shouldReturn` (0, 0, 0)

  it "should credit a duplicate that arrives during slow validation" $ do
    (router, clock) <- fixture
    entered <- newEmptyMVar
    release <- newEmptyMVar
    registerValidator router topic $ \_ _ -> do
      putMVar entered ()
      takeMVar release
      pure ValidationAccept
    withAsync (deliver router firstPeer) $ \worker -> do
      within (takeMVar entered)
      writeIORef clock (addUTCTime 0.050 epoch)
      within (deliver router secondPeer)
      writeIORef clock (addUTCTime 0.100 epoch)
      putMVar release ()
      within (wait worker)
    counters router secondPeer `shouldReturn` (0, 1, 0)

  it "should credit a duplicate within 5 ms of validation completing" $ do
    (router, clock) <- fixture
    registerValidator router topic $ \_ _ -> do
      writeIORef clock (addUTCTime 0.100 epoch)
      pure ValidationAccept
    deliver router firstPeer
    writeIORef clock (addUTCTime 0.102 epoch)
    deliver router secondPeer
    counters router secondPeer `shouldReturn` (0, 1, 0)

acceptedSourceSpec :: Spec
acceptedSourceSpec = do
  it "should credit a peer once when it repeats an accepted duplicate" $ do
    (router, _) <- fixture
    deliver router firstPeer
    deliver router secondPeer
    deliver router secondPeer
    counters router secondPeer `shouldReturn` (0, 1, 0)

  it "should credit the first sender once when it replays an accepted message" $ do
    (router, _) <- fixture
    deliver router firstPeer
    deliver router firstPeer
    counters router firstPeer `shouldReturn` (1, 1, 0)

  it "should credit a peer once when accepted duplicates arrive concurrently" $ do
    (router, _) <- fixture
    deliver router firstPeer
    replicateConcurrently_ 20 (deliver router secondPeer)
    counters router secondPeer `shouldReturn` (0, 1, 0)

  it "should retain source deduplication after pending validation completes" $ do
    (router, clock) <- fixture
    entered <- newEmptyMVar
    release <- newEmptyMVar
    registerValidator router topic $ \_ _ -> do
      putMVar entered ()
      takeMVar release
      pure ValidationAccept
    withAsync (deliver router firstPeer) $ \worker -> do
      within (takeMVar entered)
      writeIORef clock (addUTCTime 0.001 epoch)
      within (deliver router secondPeer)
      writeIORef clock (addUTCTime 0.002 epoch)
      putMVar release ()
      within (wait worker)
    counters router secondPeer `shouldReturn` (0, 1, 0)
    deliver router secondPeer
    counters router secondPeer `shouldReturn` (0, 1, 0)

pendingSpec :: Spec
pendingSpec = do
  forM_ [(ValidationAccept, (0, 1, 0)), (ValidationReject, (0, 0, 1)),
         (ValidationIgnore, (0, 0, 0))] $ \(outcome, expected) ->
    it ("should defer pending duplicate scoring until " ++ show outcome) $ do
      (router, clock) <- fixture
      entered <- newEmptyMVar
      release <- newEmptyMVar
      registerValidator router topic $ \_ _ -> do
        putMVar entered ()
        takeMVar release
        pure outcome
      withAsync (deliver router firstPeer) $ \worker -> do
        within (takeMVar entered)
        within (deliver router secondPeer)
        within (deliver router secondPeer)
        counters router secondPeer `shouldReturn` (0, 0, 0)
        writeIORef clock (addUTCTime 2 epoch)
        putMVar release ()
        within (wait worker)
      counters router secondPeer `shouldReturn` expected

  it "should not reward a pending duplicate when the validator is cancelled" $ do
    (router, _) <- fixture
    entered <- newEmptyMVar
    release <- newEmptyMVar
    registerValidator router topic $ \_ _ -> do
      putMVar entered ()
      takeMVar release
      pure ValidationAccept
    withAsync (deliver router firstPeer) $ \worker -> do
      within (takeMVar entered)
      within (deliver router secondPeer)
      cancel worker
    within (deliver router thirdPeer)
    counters router secondPeer `shouldReturn` (0, 0, 0)
    counters router thirdPeer `shouldReturn` (0, 0, 0)

expirySpec :: Spec
expirySpec = do
  it "should expire rejected outcomes together with the seen entry" $ do
    (router, clock) <- fixture
    registerValidator router topic (\_ _ -> pure ValidationReject)
    deliver router firstPeer
    writeIORef clock (addUTCTime 121 epoch)
    heartbeatOnce router
    registerValidator router topic (\_ _ -> pure ValidationAccept)
    deliver router secondPeer
    counters router secondPeer `shouldReturn` (1, 1, 0)

  it "should not overwrite a newer outcome when an expired validation completes" $ do
    (router, clock) <- fixture
    entered <- newEmptyMVar
    release <- newEmptyMVar
    delivered <- newIORef (0 :: Int)
    atomically $ writeTVar (gsOnMessage router) (\_ _ -> modifyIORef' delivered (+ 1))
    registerValidator router topic $ \_ _ -> do
      putMVar entered ()
      takeMVar release
      pure ValidationAccept
    withAsync (deliver router firstPeer) $ \worker -> do
      within (takeMVar entered)
      writeIORef clock (addUTCTime 121 epoch)
      heartbeatOnce router
      registerValidator router topic (\_ _ -> pure ValidationIgnore)
      deliver router secondPeer
      putMVar release ()
      within (wait worker)
    deliver router thirdPeer
    readIORef delivered `shouldReturn` 0
    counters router thirdPeer `shouldReturn` (0, 0, 0)

retainedScoreSpec :: Spec
retainedScoreSpec = forM_
  [ ("should retain a pending rejection when its source reconnects", 0.1, 0.2, 2)
  , ("should not extend score retention when a pending rejection completes", 0.5, 1.1, 0)
  ] $ \(label, completion, reconnection, expected) -> it label $ do
    (base, clock) <- fixture
    let router = base { gsScoreParams = (gsScoreParams base) { pspRetainScore = 1 } }
    registerValidator router topic (\_ _ -> pure ValidationReject)
    handleRPC router secondPeer emptyRPC
      { rpcPublish = [PubSubMessage Nothing "earlier-rejection" Nothing topic Nothing Nothing] }
    counters router secondPeer `shouldReturn` (0, 0, 1)
    entered <- newEmptyMVar
    release <- newEmptyMVar
    registerValidator router topic $ \_ _ -> do
      putMVar entered ()
      takeMVar release
      pure ValidationReject
    withAsync (deliver router firstPeer) $ \worker -> do
      within (takeMVar entered)
      within (deliver router secondPeer)
      removePeer router secondPeer
      writeIORef clock (addUTCTime completion epoch)
      putMVar release ()
      within (wait worker)
    writeIORef clock (addUTCTime reconnection epoch)
    addPeer router secondPeer GossipSubPeer False (addUTCTime reconnection epoch)
    counters router secondPeer `shouldReturn` (0, 0, expected)

fixture :: IO (GossipSubRouter, IORef UTCTime)
fixture = do
  clock <- newIORef epoch
  base <- newRouter
    (defaultGossipSubParams { paramSignaturePolicy = StrictNoSign })
    (PeerId "local") (\_ _ -> pure ()) (readIORef clock)
  let router = base { gsScoreParams = defaultPeerScoreParams
        { pspTopicParams = Map.singleton topic defaultTopicScoreParams
            { tspMeshMessageDeliveryWindow = 0.005 } } }
  mapM_ (\pid -> addPeer router pid GossipSubPeer False epoch) peers
  atomically $ do
    modifyTVar' (gsMesh router) (Map.insert topic (Set.fromList peers))
    modifyTVar' (gsSubscriptions router) (Set.insert topic)
  pure (router, clock)

counters :: GossipSubRouter -> PeerId -> IO (Double, Double, Double)
counters router pid = do
  states <- readTVarIO (gsPeers router)
  let state = Map.findWithDefault defaultTopicPeerState topic
        (psTopicState (states Map.! pid))
  pure (tpsFirstMessageDeliveries state, tpsMeshMessageDeliveries state,
        tpsInvalidMessages state)

deliver :: GossipSubRouter -> PeerId -> IO ()
deliver router pid = handleRPC router pid emptyRPC
  { rpcPublish = [PubSubMessage Nothing "payload" Nothing topic Nothing Nothing] }

within :: IO a -> IO a
within action = timeout 1000000 action >>= maybe (fail "operation timed out") pure

topic :: Topic
topic = "duplicate-validation"

epoch :: UTCTime
epoch = posixSecondsToUTCTime 1000000

firstPeer, secondPeer, thirdPeer :: PeerId
firstPeer = PeerId "first"
secondPeer = PeerId "second"
thirdPeer = PeerId "third"

peers :: [PeerId]
peers = [firstPeer, secondPeer, thirdPeer]
