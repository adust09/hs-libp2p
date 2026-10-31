module LibP2P.DHT.MaintenanceSpec (spec) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.STM
import Data.IORef (newIORef, readIORef, writeIORef)
import qualified Data.Map.Strict as Map
import Data.Time (UTCTime, addUTCTime, getCurrentTime)
import LibP2P.DHT.Maintenance
import LibP2P.DHT.Message (DHTRecord (..))
import Test.Hspec
import System.Timeout (timeout)

spec :: Spec
spec = describe "LibP2P.DHT.Maintenance" $ do
  describe "value record expiry" $ do
    it "lazily deletes records older than the configured maximum age" $ do
      initialNow <- getCurrentTime
      clock <- newIORef initialNow
      state <- newDHTMaintenanceState $ testConfig (readIORef clock)
      records <- newTVarIO Map.empty
      let record = DHTRecord "/example/old" "value" ""

      storeReceivedRecord state records record
      writeIORef clock (addUTCTime 2 initialNow)

      lookupLiveRecord state records (recKey record) `shouldReturn` Nothing
      readTVarIO records `shouldReturn` Map.empty

    it "treats malformed receive timestamps as expired" $ do
      state <- newDHTMaintenanceState $ testConfig getCurrentTime
      let record = DHTRecord "/example/malformed" "value" "not-a-time"
      records <- newTVarIO (Map.singleton (recKey record) record)

      lookupLiveRecord state records (recKey record) `shouldReturn` Nothing

    it "limits each GC tick and rotates across the record store" $ do
      initialNow <- getCurrentTime
      clock <- newIORef initialNow
      state <- newDHTMaintenanceState $ (testConfig (readIORef clock))
        { dmcValueGCBatchSize = 1 }
      records <- newTVarIO Map.empty
      storeReceivedRecord state records (DHTRecord "a" "one" "")
      storeReceivedRecord state records (DHTRecord "b" "two" "")
      writeIORef clock (addUTCTime 2 initialNow)

      runValueGCTick state records
      (Map.size <$> readTVarIO records) `shouldReturn` 1
      runValueGCTick state records
      readTVarIO records `shouldReturn` Map.empty

  describe "workers" $ do
    it "garbage-collects expired values and remains stopped after shutdown" $ do
      initialNow <- getCurrentTime
      clock <- newIORef initialNow
      state <- newDHTMaintenanceState $ (testConfig (readIORef clock))
        { dmcValueGCIntervalMicros = 10000 }
      stopped <- newTVarIO False
      records <- newTVarIO Map.empty
      storeReceivedRecord state records (DHTRecord "old" "value" "")
      writeIORef clock (addUTCTime 2 initialNow)
      startValueGCWorker state stopped records

      collected <- timeout 1000000 $ atomically $ do
        current <- readTVar records
        check (Map.null current)
      collected `shouldBe` Just ()

      atomically $ writeTVar stopped True
      stopDHTMaintenance state
      currentNow <- readIORef clock
      storeReceivedRecord state records (DHTRecord "after-stop" "value" "")
      writeIORef clock (addUTCTime 2 currentNow)
      threadDelay 50000
      (Map.member "after-stop" <$> readTVarIO records) `shouldReturn` True

  describe "provider batches" $ do
    it "bounds and rotates republish work across locally provided keys" $ do
      state <- newDHTMaintenanceState $ (testConfig getCurrentTime)
        { dmcProviderBatchSize = 1 }
      rememberLocalProvider state "a" []
      rememberLocalProvider state "b" []

      first <- nextLocalProviderBatch state
      second <- nextLocalProviderBatch state
      fmap fst (first <> second) `shouldMatchList` ["a", "b"]

testConfig :: IO UTCTime -> DHTMaintenanceConfig
testConfig now = defaultDHTMaintenanceConfig
  { dmcProviderRepublishIntervalMicros = 10000
  , dmcValueGCIntervalMicros = 0
  , dmcRecordMaxAge = 1
  , dmcProviderBatchSize = 1
  , dmcValueGCBatchSize = 16
  , dmcNow = now
  }
