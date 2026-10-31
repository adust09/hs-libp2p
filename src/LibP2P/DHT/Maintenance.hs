-- | DHT provider republishing and value-record expiry maintenance.
module LibP2P.DHT.Maintenance
  ( DHTMaintenanceConfig (..)
  , defaultDHTMaintenanceConfig
  , DHTMaintenanceState
  , newDHTMaintenanceState
  , startValueGCWorker
  , runValueGCTick
  , ensureProviderWorker
  , stopDHTMaintenance
  , storeReceivedRecord
  , lookupLiveRecord
  , recordIsExpired
  , rememberLocalProvider
  , nextLocalProviderBatch
  ) where

import Control.Concurrent (threadDelay, yield)
import Control.Concurrent.Async (Async, async, cancel)
import Control.Concurrent.MVar (MVar, newMVar, withMVar)
import Control.Concurrent.STM
import Control.Monad (unless, when)
import Data.ByteString (ByteString)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (isNothing)
import qualified Data.Text as T
import Data.Time (NominalDiffTime, UTCTime, diffUTCTime, getCurrentTime)
import Data.Time.Format.ISO8601 (iso8601ParseM, iso8601Show)
import LibP2P.DHT.Message (DHTRecord (..))
import LibP2P.Multiaddr (Multiaddr)

-- | Scheduling, expiry, and per-tick work limits for DHT maintenance.
data DHTMaintenanceConfig = DHTMaintenanceConfig
  { dmcProviderRepublishIntervalMicros :: !Int
    -- ^ Delay between complete provider republish cycles, in microseconds.
  , dmcValueGCIntervalMicros :: !Int
    -- ^ Delay between bounded value GC ticks. Non-positive disables GC.
  , dmcRecordMaxAge :: !NominalDiffTime
    -- ^ Receiver-side value-record TTL. Non-positive disables age expiry.
  , dmcProviderBatchSize :: !Int
    -- ^ Maximum provider announcements started before yielding.
  , dmcValueGCBatchSize :: !Int
    -- ^ Maximum value records inspected by one GC tick.
  , dmcNow :: !(IO UTCTime)
    -- ^ Wall clock used for receive timestamps and expiry checks.
  }

-- | go-libp2p Amino DHT defaults: providers republish every 22 hours,
-- value records expire after 48 hours, and value GC runs every 24 hours.
defaultDHTMaintenanceConfig :: DHTMaintenanceConfig
defaultDHTMaintenanceConfig = DHTMaintenanceConfig
  { dmcProviderRepublishIntervalMicros = 22 * hour
  , dmcValueGCIntervalMicros = 24 * hour
  , dmcRecordMaxAge = 48 * 3600
  , dmcProviderBatchSize = 64
  , dmcValueGCBatchSize = 256
  , dmcNow = getCurrentTime
  }
  where
    hour = 60 * 60 * 1000000

-- | Mutable worker state owned by one DHT node.
data DHTMaintenanceState = DHTMaintenanceState
  { dmsConfig :: !DHTMaintenanceConfig
  , dmsLocalProviders :: !(TVar (Map ByteString [Multiaddr]))
  , dmsProviderWorker :: !(TVar (Maybe (Async ())))
  , dmsProviderCursor :: !(TVar (Maybe ByteString))
  , dmsValueGCWorker :: !(TVar (Maybe (Async ())))
  , dmsValueGCCursor :: !(TVar (Maybe ByteString))
  , dmsWorkerLock :: !(MVar ())
  }

newDHTMaintenanceState :: DHTMaintenanceConfig -> IO DHTMaintenanceState
newDHTMaintenanceState config = do
  validateConfig config
  DHTMaintenanceState config
    <$> newTVarIO Map.empty
    <*> newTVarIO Nothing
    <*> newTVarIO Nothing
    <*> newTVarIO Nothing
    <*> newTVarIO Nothing
    <*> newMVar ()

validateConfig :: DHTMaintenanceConfig -> IO ()
validateConfig config
  | dmcProviderRepublishIntervalMicros config <= 0 = invalid "provider interval must be positive"
  | dmcProviderBatchSize config <= 0 = invalid "provider batch size must be positive"
  | dmcValueGCBatchSize config <= 0 = invalid "value GC batch size must be positive"
  | otherwise = pure ()
  where
    invalid = ioError . userError . ("invalid DHT maintenance configuration: " ++)

-- | Start the bounded value-record GC loop. Non-positive age or interval
-- disables the worker, matching go-libp2p's configuration semantics.
startValueGCWorker
  :: DHTMaintenanceState
  -> TVar Bool
  -> TVar (Map ByteString DHTRecord)
  -> IO ()
startValueGCWorker state stopped records
  | dmcRecordMaxAge config <= 0 = pure ()
  | dmcValueGCIntervalMicros config <= 0 = pure ()
  | otherwise = withMVar (dmsWorkerLock state) $ \_ -> do
      existing <- readTVarIO (dmsValueGCWorker state)
      when (isNothing existing) $ do
        worker <- async (valueGCLoop state stopped records)
        atomically $ writeTVar (dmsValueGCWorker state) (Just worker)
  where
    config = dmsConfig state

valueGCLoop
  :: DHTMaintenanceState
  -> TVar Bool
  -> TVar (Map ByteString DHTRecord)
  -> IO ()
valueGCLoop state stopped records = do
  threadDelay (dmcValueGCIntervalMicros (dmsConfig state))
  isStopped <- readTVarIO stopped
  unless isStopped $ do
    runValueGCTick state records
    valueGCLoop state stopped records

-- | Start the provider worker once. After each configured interval it walks
-- every locally provided key in bounded batches, yielding between batches.
ensureProviderWorker :: DHTMaintenanceState -> TVar Bool -> IO Int -> IO ()
ensureProviderWorker state stopped tick =
  withMVar (dmsWorkerLock state) $ \_ -> do
    isStopped <- readTVarIO stopped
    existing <- readTVarIO (dmsProviderWorker state)
    when (not isStopped && isNothing existing) $ do
      worker <- async (providerLoop state stopped tick)
      atomically $ writeTVar (dmsProviderWorker state) (Just worker)

providerLoop :: DHTMaintenanceState -> TVar Bool -> IO Int -> IO ()
providerLoop state stopped tick = do
  threadDelay (dmcProviderRepublishIntervalMicros (dmsConfig state))
  providerCount <- Map.size <$> readTVarIO (dmsLocalProviders state)
  runCycle providerCount
  where
    runCycle remaining
      | remaining <= 0 = providerLoop state stopped tick
      | otherwise = do
          isStopped <- readTVarIO stopped
          unless isStopped $ do
            processed <- tick
            if processed <= 0
              then providerLoop state stopped tick
              else yield >> runCycle (remaining - processed)

-- | Cancel every maintenance worker and clear their handles.
stopDHTMaintenance :: DHTMaintenanceState -> IO ()
stopDHTMaintenance state = withMVar (dmsWorkerLock state) $ \_ -> do
  workers <- atomically $ do
    provider <- readTVar (dmsProviderWorker state)
    valueGC <- readTVar (dmsValueGCWorker state)
    writeTVar (dmsProviderWorker state) Nothing
    writeTVar (dmsValueGCWorker state) Nothing
    pure [provider, valueGC]
  mapM_ (mapM_ cancel) workers

-- | Store a value record with a receiver-controlled timestamp.
storeReceivedRecord
  :: DHTMaintenanceState
  -> TVar (Map ByteString DHTRecord)
  -> DHTRecord
  -> IO ()
storeReceivedRecord state records record = do
  now <- dmcNow (dmsConfig state)
  let stored = record { recTimeReceived = T.pack (iso8601Show now) }
  atomically $ modifyTVar' records (Map.insert (recKey stored) stored)

-- | Read a live record, deleting malformed, misfiled, or expired data.
lookupLiveRecord
  :: DHTMaintenanceState
  -> TVar (Map ByteString DHTRecord)
  -> ByteString
  -> IO (Maybe DHTRecord)
lookupLiveRecord state records key = do
  now <- dmcNow (dmsConfig state)
  atomically $ do
    stored <- readTVar records
    case Map.lookup key stored of
      Nothing -> pure Nothing
      Just record
        | recKey record /= key || recordIsExpired state now record -> do
            writeTVar records (Map.delete key stored)
            pure Nothing
        | otherwise -> pure (Just record)

-- | Whether a record is older than the configured maximum age. Missing or
-- malformed receive times are expired when age checking is enabled.
recordIsExpired :: DHTMaintenanceState -> UTCTime -> DHTRecord -> Bool
recordIsExpired state now record
  | maxAge <= 0 = False
  | otherwise = case iso8601ParseM (T.unpack (recTimeReceived record)) of
      Nothing -> True
      Just received -> diffUTCTime now received > maxAge
  where
    maxAge = dmcRecordMaxAge (dmsConfig state)

-- | Track a key that this node still provides.
rememberLocalProvider
  :: DHTMaintenanceState -> ByteString -> [Multiaddr] -> IO ()
rememberLocalProvider state key addrs = atomically $
  modifyTVar' (dmsLocalProviders state) (Map.insert key addrs)

-- | Select the next bounded provider batch, rotating through the keyspace so
-- a large provider set cannot starve keys beyond the first batch.
nextLocalProviderBatch
  :: DHTMaintenanceState -> IO [(ByteString, [Multiaddr])]
nextLocalProviderBatch state = atomically $ do
  providers <- readTVar (dmsLocalProviders state)
  cursor <- readTVar (dmsProviderCursor state)
  let batch = selectBatch (dmcProviderBatchSize (dmsConfig state)) cursor providers
  writeTVar (dmsProviderCursor state) (fst <$> lastMaybe batch)
  pure batch

-- | Delete at most one configured batch of expired records.
runValueGCTick
  :: DHTMaintenanceState -> TVar (Map ByteString DHTRecord) -> IO ()
runValueGCTick state records = do
  now <- dmcNow (dmsConfig state)
  atomically $ do
    stored <- readTVar records
    cursor <- readTVar (dmsValueGCCursor state)
    let batch = selectBatch (dmcValueGCBatchSize (dmsConfig state)) cursor stored
        expired =
          [ key
          | (key, record) <- batch
          , recKey record /= key || recordIsExpired state now record
          ]
    writeTVar records (foldr Map.delete stored expired)
    writeTVar (dmsValueGCCursor state) (fst <$> lastMaybe batch)

selectBatch :: Int -> Maybe ByteString -> Map ByteString a -> [(ByteString, a)]
selectBatch limit Nothing entries = take limit (Map.toAscList entries)
selectBatch limit (Just previous) entries = after <> wrapped
  where
    (_, _, greater) = Map.splitLookup previous entries
    after = take limit (Map.toAscList greater)
    wrapped = take (limit - length after) (Map.toAscList entries)

lastMaybe :: [a] -> Maybe a
lastMaybe = foldl (\_ value -> Just value) Nothing
