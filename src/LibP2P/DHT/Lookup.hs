-- | Iterative lookup algorithms for the Kademlia DHT.
--
-- Implements FIND_NODE, GET_VALUE, and GET_PROVIDERS iterative lookups
-- per specs/kad-dht. Uses STM for shared state and async for concurrent
-- queries (alpha=10 parallelism).
--
-- Candidates are maintained as a list sorted by XOR distance to the
-- target key, ensuring the closest peers are always queried first.
--
-- Bootstrap performs a self-lookup followed by per-bucket random refresh.
module LibP2P.DHT.Lookup
  ( -- * Lookup results
    LookupResult (..)
    -- * Iterative lookups
  , iterativeFindNode
  , iterativeGetValue
  , iterativeGetProviders
    -- * Bootstrap
  , bootstrap
  , startBootstrap
  , defaultBootstrapIntervalMicros
  ) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.Async (async, cancel, mapConcurrently)
import Control.Concurrent.STM
import Control.Exception (SomeException, catch)
import Control.Monad (forever, void)
import Crypto.Random (getRandomBytes)
import Data.Bits (clearBit, setBit, shiftL, testBit, (.&.), (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Maybe (fromMaybe)
import Data.Set (Set)
import qualified Data.Set as Set
import Data.Time (UTCTime, getCurrentTime)
import Data.Word (Word8)
import LibP2P.Crypto.PeerId (PeerId (..), peerIdBytes)
import LibP2P.DHT
  ( DHTNode (..)
  , ProviderEntry (..)
  , Validator (..)
  , addPeerToTable
  , decodePeerAddrs
  , lookupRecord
  )
import LibP2P.DHT.Distance (keyToDHTKey, peerIdToKey, sortByDistance)
import LibP2P.DHT.Message
import LibP2P.DHT.RoutingTable (closestPeers, occupiedBuckets)
import LibP2P.DHT.Types
import System.Timeout (timeout)

-- | Result of an iterative lookup.
data LookupResult
  = FoundPeers ![BucketEntry]
  | FoundValue !DHTRecord ![BucketEntry]
  | FoundProviders ![ProviderEntry] ![BucketEntry]
  deriving (Show)

-- | Run an action with the node's query timeout, returning @fallback@ on expiry.
withQueryTimeout :: DHTNode -> a -> IO a -> IO a
withQueryTimeout node fallback action = do
  m <- timeout (dhtQueryTimeout node) action
  pure (fromMaybe fallback m)

-- | Iterative FIND_NODE: find the k closest peers to a target peer.
--
-- Per specs/kad-dht, the FIND_NODE wire key must be the target's binary
-- Peer ID; XOR distance is computed over SHA-256 digests, so only local
-- comparisons use the hashed key.
--
-- Bounded by 'dhtQueryTimeout' (default 10s). Outstanding parallel
-- queries are cancelled when the deadline expires.
--
-- Algorithm:
-- 1. Seed candidates with k closest from local routing table
-- 2. Query up to alpha unqueried candidates in parallel
-- 3. Merge returned closerPeers into candidates
-- 4. Terminate when top-k candidates all queried or no unqueried remain
iterativeFindNode :: DHTNode -> PeerId -> IO [BucketEntry]
iterativeFindNode node targetPid =
  withQueryTimeout node [] (findNodeUncapped node targetPid)

findNodeUncapped :: DHTNode -> PeerId -> IO [BucketEntry]
findNodeUncapped node targetPid = do
  rt <- readTVarIO (dhtRoutingTable node)
  let wireKey = peerIdBytes targetPid   -- raw peer ID on the wire
      targetKey = peerIdToKey targetPid -- SHA-256 for distance
      seeds = closestPeers targetKey kValue rt
  now <- getCurrentTime

  -- State: candidates sorted by XOR distance, queried set, known set (for dedup)
  candidatesVar <- newTVarIO (sortByDistance targetKey seeds)
  queriedVar    <- newTVarIO Set.empty
  knownVar      <- newTVarIO (Set.fromList (map entryPeerId seeds))

  lookupLoop node wireKey targetKey candidatesVar queriedVar knownVar now FindNode

-- | Core lookup loop shared by FIND_NODE, GET_VALUE, GET_PROVIDERS.
lookupLoop
  :: DHTNode
  -> ByteString           -- ^ Raw wire key sent in requests
  -> DHTKey               -- ^ SHA-256 of the wire key, for distance
  -> TVar [BucketEntry]   -- ^ Candidates sorted by XOR distance to target
  -> TVar (Set PeerId)    -- ^ Already queried peers
  -> TVar (Set PeerId)    -- ^ Known peers (all candidates ever seen, for dedup)
  -> UTCTime              -- ^ Lookup start time (last-seen for new entries)
  -> MessageType          -- ^ Query type
  -> IO [BucketEntry]
lookupLoop node wireKey targetKey candidatesVar queriedVar knownVar now queryType = go
  where
    go = do
      -- Pick up to alpha unqueried candidates closest to target
      toQuery <- atomically $ do
        candidates <- readTVar candidatesVar
        queried <- readTVar queriedVar
        let unqueried = filter (\e -> not (Set.member (entryPeerId e) queried)) candidates
            batch = take alphaValue unqueried
        -- Mark them as queried
        let newQueried = Set.union queried (Set.fromList (map entryPeerId batch))
        writeTVar queriedVar newQueried
        pure batch

      if null toQuery
        then do
          -- No more unqueried candidates -> return top k
          candidates <- readTVarIO candidatesVar
          pure (take kValue candidates)
        else do
          -- Query each peer in parallel
          results <- mapConcurrently (queryPeer node wireKey queryType) toQuery

          -- Merge results
          newEntries <- atomically $ do
            known <- readTVar knownVar
            candidates <- readTVar candidatesVar
            let newPeers = concatMap (either (const []) id) results
                -- Convert DHTPeers to BucketEntries, excluding already known
                newEntries = filter (\e -> not (Set.member (entryPeerId e) known))
                           $ map (dhtPeerToEntry now) newPeers
                -- Mark new entries as known
                newKnown = Set.union known (Set.fromList (map entryPeerId newEntries))
                -- Merge and re-sort by XOR distance
                merged = sortByDistance targetKey (candidates ++ newEntries)
            writeTVar candidatesVar merged
            writeTVar knownVar newKnown
            pure newEntries

          -- Peers encountered throughout the search are inserted in the
          -- routing table, as per usual business (specs/kad-dht,
          -- bootstrap process); responders are refreshed as live.
          insertLookupPeers node
            [e | (e, Right _) <- zip toQuery results]
            newEntries

          -- Check termination: have we queried top-k?
          shouldContinue <- atomically $ do
            candidates <- readTVar candidatesVar
            queried <- readTVar queriedVar
            let topK = take kValue candidates
                allQueried = all (\e -> Set.member (entryPeerId e) queried) topK
            pure (not allQueried)

          if shouldContinue
            then go
            else do
              candidates <- readTVarIO candidatesVar
              pure (take kValue candidates)

-- | Query a single peer and return the closerPeers from the response.
--
-- The request carries the raw wire key (e.g. the binary Peer ID for
-- FIND_NODE), never a SHA-256 digest: the remote hashes the key itself
-- when computing distances (specs/kad-dht).
queryPeer :: DHTNode -> ByteString -> MessageType -> BucketEntry -> IO (Either String [DHTPeer])
queryPeer node wireKey queryType entry = do
  let request = emptyDHTMessage
        { msgType = queryType
        , msgKey  = wireKey
        }
  result <- (dhtSendRequest node) (entryPeerId entry) request
    `catch` (\(e :: SomeException) -> pure (Left (show e)))
  pure $ case result of
    Left err -> Left err
    Right resp -> Right (msgCloserPeers resp)

-- | Iterative GET_VALUE: find a value by key, with convergence repair.
--
-- Same as FIND_NODE but also tracks the best value found and which peers
-- returned it. On completion, sends PUT_VALUE to peers with outdated values.
iterativeGetValue :: DHTNode -> Validator -> ByteString -> IO (Either String DHTRecord)
iterativeGetValue node validator key = do
  stored <- lookupRecord node key
  let local = stored >>= validRecord
      timeoutResult = maybe (Left "query timed out") Right local
  withQueryTimeout node timeoutResult (getValueUncapped node validator key local)
  where
    validRecord record = case valValidate validator key (recValue record) of
      Left _ -> Nothing
      Right () -> Just record

getValueUncapped
  :: DHTNode
  -> Validator
  -> ByteString
  -> Maybe DHTRecord
  -> IO (Either String DHTRecord)
getValueUncapped node validator key local = do
  rt <- readTVarIO (dhtRoutingTable node)
  -- The raw record key goes on the wire; distance uses its SHA-256.
  let targetKey = keyToDHTKey key
      seeds = closestPeers targetKey kValue rt
  now <- getCurrentTime

  candidatesVar <- newTVarIO (sortByDistance targetKey seeds)
  queriedVar    <- newTVarIO Set.empty
  knownVar      <- newTVarIO (Set.fromList (map entryPeerId seeds))
  bestVar       <- newTVarIO local
  bestPeersVar  <- newTVarIO (Set.empty :: Set PeerId)
  outdatedVar   <- newTVarIO (Set.empty :: Set PeerId)

  valueLoop node key targetKey candidatesVar queriedVar knownVar bestVar bestPeersVar outdatedVar validator now

-- | Value lookup loop with best/outdated tracking.
valueLoop
  :: DHTNode
  -> ByteString           -- ^ Raw wire key sent in requests
  -> DHTKey               -- ^ SHA-256 of the wire key, for distance
  -> TVar [BucketEntry]
  -> TVar (Set PeerId)
  -> TVar (Set PeerId)    -- ^ Known peers (dedup)
  -> TVar (Maybe DHTRecord)
  -> TVar (Set PeerId)    -- ^ Peers that returned best value
  -> TVar (Set PeerId)    -- ^ Peers with outdated values
  -> Validator
  -> UTCTime              -- ^ Lookup start time (last-seen for new entries)
  -> IO (Either String DHTRecord)
valueLoop node wireKey targetKey candidatesVar queriedVar knownVar bestVar bestPeersVar outdatedVar validator now = go
  where
    go = do
      toQuery <- atomically $ do
        candidates <- readTVar candidatesVar
        queried <- readTVar queriedVar
        let unqueried = filter (\e -> not (Set.member (entryPeerId e) queried)) candidates
            batch = take alphaValue unqueried
        let newQueried = Set.union queried (Set.fromList (map entryPeerId batch))
        writeTVar queriedVar newQueried
        pure batch

      if null toQuery
        then finalize
        else do
          results <- mapConcurrently (queryPeerForValue node wireKey) toQuery

          -- Process each result
          mapM_ (processValueResult node targetKey bestVar bestPeersVar outdatedVar validator now) results

          -- Merge closer peers from responses
          newEntries <- atomically $ do
            known <- readTVar knownVar
            candidates <- readTVar candidatesVar
            let newPeers = concatMap (\(_, peers, _) -> either (const []) id peers) results
                newEntries = filter (\e -> not (Set.member (entryPeerId e) known))
                           $ map (dhtPeerToEntry now) newPeers
                newKnown = Set.union known (Set.fromList (map entryPeerId newEntries))
                merged = sortByDistance targetKey (candidates ++ newEntries)
            writeTVar candidatesVar merged
            writeTVar knownVar newKnown
            pure newEntries

          -- Grow the routing table from peers seen this round.
          insertLookupPeers node
            [e | (e, (_, Right _, _)) <- zip toQuery results]
            newEntries

          -- Check termination
          shouldContinue <- atomically $ do
            candidates <- readTVar candidatesVar
            queried <- readTVar queriedVar
            let topK = take kValue candidates
                allQueried = all (\e -> Set.member (entryPeerId e) queried) topK
            pure (not allQueried)

          if shouldContinue then go else finalize

    finalize = do
      best <- readTVarIO bestVar
      outdated <- readTVarIO outdatedVar

      -- Convergence repair: PUT_VALUE to outdated peers
      case best of
        Nothing -> pure (Left "value not found")
        Just rec -> do
          let putMsg = emptyDHTMessage
                { msgType = PutValue
                , msgKey = recKey rec
                , msgRecord = Just rec
                }
          mapM_ (\pid -> (dhtSendRequest node) pid putMsg
                          `catch` (\(_ :: SomeException) -> pure (Left "repair failed")))
                (Set.toList outdated)
          pure (Right rec)

-- | Query a peer for a value and return (peerId, closerPeers, Maybe record).
queryPeerForValue :: DHTNode -> ByteString -> BucketEntry
                  -> IO (PeerId, Either String [DHTPeer], Maybe DHTRecord)
queryPeerForValue node wireKey entry = do
  let request = emptyDHTMessage { msgType = GetValue, msgKey = wireKey }
  result <- (dhtSendRequest node) (entryPeerId entry) request
    `catch` (\(e :: SomeException) -> pure (Left (show e)))
  pure $ case result of
    Left err -> (entryPeerId entry, Left err, Nothing)
    Right resp -> (entryPeerId entry, Right (msgCloserPeers resp), msgRecord resp)

-- | Process a value result: update best/bestPeers/outdated.
--
-- Per specs/kad-dht (Entry validation), values retrieved in a GET_VALUE
-- query are validated before being considered; records failing the
-- validator are ignored as if the peer had returned no record.
processValueResult
  :: DHTNode -> DHTKey
  -> TVar (Maybe DHTRecord)
  -> TVar (Set PeerId)
  -> TVar (Set PeerId)
  -> Validator
  -> UTCTime
  -> (PeerId, Either String [DHTPeer], Maybe DHTRecord)
  -> IO ()
processValueResult _ _ bestVar bestPeersVar outdatedVar validator _ (pid, _, Just rec)
  | Left _ <- valValidate validator (recKey rec) (recValue rec) = pure ()
  | otherwise = do
  atomically $ do
    best <- readTVar bestVar
    case best of
      Nothing -> do
        writeTVar bestVar (Just rec)
        writeTVar bestPeersVar (Set.singleton pid)
      Just currentBest -> do
        case valSelect validator (recKey rec) [recValue currentBest, recValue rec] of
          Right 0 -> do
            -- Current best is still best; this peer has outdated value
            modifyTVar' outdatedVar (Set.insert pid)
          Right 1 -> do
            -- New value is better
            oldBestPeers <- readTVar bestPeersVar
            modifyTVar' outdatedVar (Set.union oldBestPeers)
            writeTVar bestVar (Just rec)
            writeTVar bestPeersVar (Set.singleton pid)
          _ -> do
            -- Same or error: add to bestPeers
            modifyTVar' bestPeersVar (Set.insert pid)
processValueResult _ _ _ _ _ _ _ (_, _, Nothing) = pure ()

-- | Iterative GET_PROVIDERS: find providers for a content key.
iterativeGetProviders :: DHTNode -> ByteString -> IO [ProviderEntry]
iterativeGetProviders node key =
  withQueryTimeout node [] (getProvidersUncapped node key)

getProvidersUncapped :: DHTNode -> ByteString -> IO [ProviderEntry]
getProvidersUncapped node key = do
  rt <- readTVarIO (dhtRoutingTable node)
  -- The raw content key goes on the wire; distance uses its SHA-256.
  let targetKey = keyToDHTKey key
      seeds = closestPeers targetKey kValue rt
  now <- getCurrentTime

  candidatesVar <- newTVarIO (sortByDistance targetKey seeds)
  queriedVar    <- newTVarIO Set.empty
  knownVar      <- newTVarIO (Set.fromList (map entryPeerId seeds))
  providersVar  <- newTVarIO ([] :: [ProviderEntry])

  providerLoop node key targetKey candidatesVar queriedVar knownVar providersVar now

-- | Provider lookup loop.
providerLoop
  :: DHTNode
  -> ByteString           -- ^ Raw wire key sent in requests
  -> DHTKey               -- ^ SHA-256 of the wire key, for distance
  -> TVar [BucketEntry]
  -> TVar (Set PeerId)
  -> TVar (Set PeerId)    -- ^ Known peers (dedup)
  -> TVar [ProviderEntry]
  -> UTCTime              -- ^ Lookup start time (last-seen for new entries)
  -> IO [ProviderEntry]
providerLoop node wireKey targetKey candidatesVar queriedVar knownVar providersVar now = go
  where
    go = do
      toQuery <- atomically $ do
        candidates <- readTVar candidatesVar
        queried <- readTVar queriedVar
        let unqueried = filter (\e -> not (Set.member (entryPeerId e) queried)) candidates
            batch = take alphaValue unqueried
        let newQueried = Set.union queried (Set.fromList (map entryPeerId batch))
        writeTVar queriedVar newQueried
        pure batch

      if null toQuery
        then readTVarIO providersVar
        else do
          results <- mapConcurrently (queryPeerForProviders node wireKey) toQuery

          -- Collect providers and closer peers
          newEntries <- atomically $ do
            known <- readTVar knownVar
            candidates <- readTVar candidatesVar
            currentProviders <- readTVar providersVar
            let allCloser = concatMap (\(_, closer, _) -> either (const []) id closer) results
                allProviders = concatMap (\(_, _, provs) -> provs) results
                newEntries = filter (\e -> not (Set.member (entryPeerId e) known))
                           $ map (dhtPeerToEntry now) allCloser
                newKnown = Set.union known (Set.fromList (map entryPeerId newEntries))
                merged = sortByDistance targetKey (candidates ++ newEntries)
                newProviderEntries = map (dhtPeerToProvider now) allProviders
            writeTVar candidatesVar merged
            writeTVar knownVar newKnown
            writeTVar providersVar (currentProviders ++ newProviderEntries)
            pure newEntries

          -- Grow the routing table from peers seen this round.
          insertLookupPeers node
            [e | (e, (_, Right _, _)) <- zip toQuery results]
            newEntries

          shouldContinue <- atomically $ do
            candidates <- readTVar candidatesVar
            queried <- readTVar queriedVar
            let topK = take kValue candidates
                allQueried = all (\e -> Set.member (entryPeerId e) queried) topK
            pure (not allQueried)

          if shouldContinue then go else readTVarIO providersVar

-- | Query a peer for providers.
queryPeerForProviders :: DHTNode -> ByteString -> BucketEntry
                      -> IO (PeerId, Either String [DHTPeer], [DHTPeer])
queryPeerForProviders node wireKey entry = do
  let request = emptyDHTMessage { msgType = GetProviders, msgKey = wireKey }
  result <- (dhtSendRequest node) (entryPeerId entry) request
    `catch` (\(e :: SomeException) -> pure (Left (show e)))
  pure $ case result of
    Left err -> (entryPeerId entry, Left err, [])
    Right resp -> (entryPeerId entry, Right (msgCloserPeers resp), msgProviderPeers resp)

-- | Default periodic bootstrap interval: 10 minutes (specs/kad-dht).
defaultBootstrapIntervalMicros :: Int
defaultBootstrapIntervalMicros = 600000000

-- | Bootstrap the DHT: insert seeds, self-lookup, refresh every non-empty bucket.
--
-- Startup is explicit: call 'bootstrap' or 'startBootstrap'. 'newDHTNode'
-- does not start a loop, matching go-libp2p's @IpfsDHT.Bootstrap@.
-- The whole run is bounded by 'dhtQueryTimeout' (default 10s).
bootstrap :: DHTNode -> [PeerId] -> IO ()
bootstrap node seeds =
  void $ timeout (dhtQueryTimeout node) (bootstrapRun node seeds)

bootstrapRun :: DHTNode -> [PeerId] -> IO ()
bootstrapRun node seeds = do
  now <- getCurrentTime
  let seedEntries = map (\pid -> BucketEntry pid (peerIdToKey pid) [] now NotConnected) seeds
  mapM_ (addPeerToTable node) seedEntries
  _ <- findNodeUncapped node (dhtLocalPeerId node)
  rt <- readTVarIO (dhtRoutingTable node)
  mapM_ (refreshBucket node (dhtLocalKey node)) (occupiedBuckets rt)

-- | FIND_NODE a random key in the bucket's XOR range (specs/kad-dht).
refreshBucket :: DHTNode -> DHTKey -> Int -> IO ()
refreshBucket node selfKey cpl = do
  target <- randomKadKeyInBucket selfKey cpl
  let DHTKey wireKey = target
  void $
    lookupByKey node wireKey target
      `catch` (\(_ :: SomeException) -> pure [])

-- | FIND_NODE whose local distance uses @targetKey@ as-is (already a
-- kad-id) so a bucket refresh actually queries that bucket.
lookupByKey :: DHTNode -> ByteString -> DHTKey -> IO [BucketEntry]
lookupByKey node wireKey targetKey = do
  rt <- readTVarIO (dhtRoutingTable node)
  let seeds = closestPeers targetKey kValue rt
  now <- getCurrentTime
  candidatesVar <- newTVarIO (sortByDistance targetKey seeds)
  queriedVar    <- newTVarIO Set.empty
  knownVar      <- newTVarIO (Set.fromList (map entryPeerId seeds))
  lookupLoop node wireKey targetKey candidatesVar queriedVar knownVar now FindNode

-- | Start a periodic bootstrap loop. Runs one refresh immediately, then
-- every @intervalMicros@. Cancelled by 'stopDHTNode'.
startBootstrap :: DHTNode -> [PeerId] -> Int -> IO ()
startBootstrap node seeds intervalMicros = do
  mPrev <- atomically $ do
    prev <- readTVar (dhtBootstrapWorker node)
    writeTVar (dhtBootstrapWorker node) Nothing
    pure prev
  mapM_ cancel mPrev
  worker <- async $ forever $ do
    bootstrap node seeds
    threadDelay intervalMicros
  atomically $ writeTVar (dhtBootstrapWorker node) (Just worker)

-- | A kad-id whose XOR with @self@ has common prefix length @cpl@.
-- Bit @cpl@ is flipped so the key falls in that bucket; remaining bits
-- are random so successive refreshes explore the range.
randomKadKeyInBucket :: DHTKey -> Int -> IO DHTKey
randomKadKeyInBucket (DHTKey self) cpl = do
  noise <- getRandomBytes 32
  let cpl' = max 0 (min 255 cpl)
      keepBytes = cpl' `div` 8
      bitInByte = cpl' `mod` 8
      prefix = BS.take keepBytes self
      selfByte = BS.index self keepBytes
      noiseByte = BS.index noise keepBytes
      keepMask :: Word8
      keepMask = if bitInByte == 0 then 0 else 0xFF `shiftL` (8 - bitInByte)
      kept = selfByte .&. keepMask
      flipBit = 7 - bitInByte
      flipped = if testBit selfByte flipBit then clearBit kept flipBit else setBit kept flipBit
      lowerMask :: Word8
      lowerMask = (1 `shiftL` flipBit) - 1
      mixed = flipped .|. (noiseByte .&. lowerMask)
      rest = BS.drop (keepBytes + 1) noise
  pure (DHTKey (prefix <> BS.singleton mixed <> rest))

-- Helpers

-- | Insert peers observed during a lookup round into the routing table:
-- peers that answered our query (refreshed with a new last-seen time)
-- and newly discovered candidates from closerPeers. Insertion applies
-- the full-bucket eviction policy of 'addPeerToTable'.
insertLookupPeers :: DHTNode -> [BucketEntry] -> [BucketEntry] -> IO ()
insertLookupPeers node responders discovered = do
  now <- getCurrentTime
  mapM_ (\e -> addPeerToTable node e { entryLastSeen = now }) responders
  mapM_ (addPeerToTable node) discovered

-- | Convert a DHTPeer to a BucketEntry seen at the given time.
-- Per specs/kad-dht, multiaddrs carried by Peer records are decoded and
-- kept so the learned peers can be dialled in follow-up queries.
dhtPeerToEntry :: UTCTime -> DHTPeer -> BucketEntry
dhtPeerToEntry now peer = BucketEntry
  { entryPeerId   = PeerId (dhtPeerId peer)
  , entryKey      = peerIdToKey (PeerId (dhtPeerId peer))
  , entryAddrs    = decodePeerAddrs (dhtPeerAddrs peer)
  , entryLastSeen = now
  , entryConnType = dhtPeerConnType peer
  }

-- | Convert a DHTPeer to a ProviderEntry seen at the given time.
dhtPeerToProvider :: UTCTime -> DHTPeer -> ProviderEntry
dhtPeerToProvider now peer = ProviderEntry
  { peProvider  = PeerId (dhtPeerId peer)
  , peAddrs     = decodePeerAddrs (dhtPeerAddrs peer)
  , peTimestamp = now
  }
