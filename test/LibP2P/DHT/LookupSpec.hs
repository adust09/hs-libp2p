module LibP2P.DHT.LookupSpec (spec) where

import Test.Hspec

import Control.Concurrent (threadDelay)
import Control.Concurrent.STM
import Control.Monad (forever, unless)
import Data.Bits ((.&.))
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef)
import Data.List (nub)
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import Data.Time (diffUTCTime, getCurrentTime)
import Data.Word (Word8)
import LibP2P.Crypto.PeerId (PeerId (..), peerIdBytes)
import LibP2P.DHT
import LibP2P.DHT.Distance
  ( commonPrefixLength
  , keyToDHTKey
  , peerIdToKey
  , sortByDistance
  )
import LibP2P.DHT.Lookup
import LibP2P.DHT.Message
import LibP2P.DHT.RoutingTable (bucketForPeer, insertPeer, allPeers, newRoutingTable)
import LibP2P.DHT.Types
import LibP2P.Multiaddr (fromText, toBytes)

-- Reuse mock Switch helpers from DHTSpec
import LibP2P.DHT.DHTSpec (mkTestNode, mkPeerId, localPid)

-- | Create a mock DHTNode with a custom sendRequest function.
mkNodeWithMock :: PeerId -> (PeerId -> DHTMessage -> IO (Either String DHTMessage)) -> IO DHTNode
mkNodeWithMock pid mockSend = do
  node <- mkTestNode pid
  pure node { dhtSendRequest = mockSend }

-- Issue #173: wire-level mock plumbing -----------------------------------
--
-- The old mocks were constant functions that never read the request, so a
-- lookup could put any bytes in any field and every test stayed green.
-- Every mock sender now behaves like a spec-conformant remote peer:
--
--   1. the outbound DHTMessage is serialized through the real
--      uvarint-framed protobuf encoding (as it would go on the wire),
--   2. the frame and the spec field tags for type/key are checked against
--      hand-computed constants (independent of the implementation),
--   3. the payload is re-parsed with the real decoder, and the handler
--      answers based on the decoded request's type and key,
--   4. the handler's response is delivered back through the same wire
--      encoding, as the real dhtSendRequest would deliver it.
--
-- A wire-format regression in the request or response path now turns the
-- lookup tests red instead of being invisible.

-- | Spec enum value per request type, hand-transcribed from
-- specs/kad-dht dht.proto. Deliberately NOT derived from the Haskell
-- 'Enum' instance: reordering the constructors must fail here.
specTypeCode :: MessageType -> Word8
specTypeCode PutValue     = 0
specTypeCode GetValue     = 1
specTypeCode AddProvider  = 2
specTypeCode GetProviders = 3
specTypeCode FindNode     = 4

-- | Minimal independent uvarint decoder (deliberately not
-- 'LibP2P.Core.Varint', which the code under test uses).
uvarint :: BS.ByteString -> Either String (Int, BS.ByteString)
uvarint = go (0 :: Int) 0
  where
    go shift acc bs = case BS.uncons bs of
      Nothing -> Left "mock: truncated uvarint"
      Just (b, rest) ->
        let acc' = acc + fromIntegral (b .&. 0x7F) * (2 ^ shift)
        in if b < 0x80 then Right (acc', rest) else go (shift + 7) acc' rest

-- | Decode an outbound request exactly as a remote peer would receive it.
decodeWireRequest :: DHTMessage -> Either String DHTMessage
decodeWireRequest msg = do
  let framed = encodeFramed msg
  (frameLen, body) <- uvarint framed
  unless (BS.length body == frameLen) $
    Left "mock: frame length prefix does not match payload length"
  let key = msgKey msg
  unless (not (BS.null key)) $
    Left "mock: request carries no wire key"
  -- Golden prefix, hand-computed from the protobuf spec: tag 0x08
  -- (field 1, varint) + type code, then tag 0x12 (field 2,
  -- length-delimited) + key length + key bytes. Request keys in these
  -- tests are < 128 bytes, so the length fits a single varint byte.
  let expectedPrefix =
        BS.pack [0x08, specTypeCode (msgType msg), 0x12, fromIntegral (BS.length key)]
          <> key
  unless (BS.length key >= 128 || expectedPrefix `BS.isPrefixOf` body) $
    Left "mock: request bytes do not carry spec field tags 1 (type) and 2 (key)"
  decodeFramed maxDHTMessageSize framed

-- | Deliver a handler's response the way the real sender would: encoded
-- to the wire and parsed back. Non-empty peer lists must be encoded at
-- the spec field numbers (closerPeers = 8, tag 0x42; providerPeers = 9,
-- tag 0x4A) — a necessary condition that breaks encoder/decoder symmetry.
deliverWireResponse :: DHTMessage -> Either String DHTMessage
deliverWireResponse resp = do
  let framed = encodeFramed resp
  (frameLen, body) <- uvarint framed
  unless (BS.length body == frameLen) $
    Left "mock: response frame length prefix does not match payload length"
  unless (null (msgCloserPeers resp) || BS.elem 0x42 body) $
    Left "mock: closerPeers not encoded at spec field 8 (tag 0x42)"
  unless (null (msgProviderPeers resp) || BS.elem 0x4A body) $
    Left "mock: providerPeers not encoded at spec field 9 (tag 0x4A)"
  decodeFramed maxDHTMessageSize framed

-- | Create a mock network: a map from PeerId to their request handler.
-- Handlers receive the request as decoded off the wire and may reject it.
type MockNetwork = Map.Map PeerId (DHTMessage -> Either String DHTMessage)

-- | Build a mock sendRequest from a MockNetwork.
mockSendFromNetwork :: MockNetwork -> PeerId -> DHTMessage -> IO (Either String DHTMessage)
mockSendFromNetwork network pid msg = pure $ do
  req <- decodeWireRequest msg
  handler <- maybe (Left "peer not found in mock network") Right (Map.lookup pid network)
  resp <- handler req
  deliverWireResponse resp

-- | Handler that validates the decoded request's type and wire key
-- before answering. Anything unexpected fails the query, which the
-- test then observes as missing peers/values.
expecting :: MessageType -> BS.ByteString -> DHTMessage -> DHTMessage -> Either String DHTMessage
expecting wantType wantKey resp = expectingOneOf wantType [wantKey] resp

-- | Like 'expecting' but accepts any of several wire keys (bootstrap
-- issues one lookup per bucket representative, each with its own key).
expectingOneOf :: MessageType -> [BS.ByteString] -> DHTMessage -> DHTMessage -> Either String DHTMessage
expectingOneOf wantType wantKeys resp req
  | msgType req /= wantType =
      Left $ "mock: expected " ++ show wantType ++ " request, got " ++ show (msgType req)
  | msgKey req `notElem` wantKeys =
      Left $ "mock: wrong wire key in " ++ show wantType ++ " request: " ++ show (BS.unpack (msgKey req))
  | otherwise = Right resp

-- | A FIND_NODE response carrying the given closer peers.
findNodeReply :: [DHTPeer] -> DHTMessage
findNodeReply closer = emptyDHTMessage { msgType = FindNode, msgCloserPeers = closer }

-- | A mock sender that records something about each decoded request
-- before responding; wire decoding failures propagate to the lookup.
recordingSend
  :: (PeerId -> DHTMessage -> IO ())        -- ^ observe the decoded request
  -> (DHTMessage -> Either String DHTMessage) -- ^ answer it
  -> PeerId -> DHTMessage -> IO (Either String DHTMessage)
recordingSend observe respond pid msg =
  case decodeWireRequest msg of
    Left err -> pure (Left err)
    Right req -> do
      observe pid req
      pure (respond req >>= deliverWireResponse)

-- | Record the decoded wire key of each request into an IORef.
recordKeys :: IORef [BS.ByteString] -> PeerId -> DHTMessage -> IO ()
recordKeys ref _pid req =
  atomicModifyIORef' ref (\ks -> (ks ++ [msgKey req], ()))

spec :: Spec
spec = do
  describe "iterativeFindNode" $ do
    -- Issue #146: per specs/kad-dht the FIND_NODE wire key must be the
    -- binary Peer ID. The old code sent sha256(peer id); a remote hashes
    -- the key again, landing the query at sha256(sha256(peer id)).
    it "sends the raw target peer ID as the wire key, not its SHA-256 digest" $ do
      now <- getCurrentTime
      sentKeysRef <- newIORef ([] :: [BS.ByteString])
      let targetPid = mkPeerId (BS.pack [42, 42, 42, 42])
          mockSend = recordingSend (recordKeys sentKeysRef)
                                   (\_ -> Right (findNodeReply []))
      node <- mkNodeWithMock localPid mockSend
      let pidA = mkPeerId (BS.pack [10])
          entryA = BucketEntry pidA (peerIdToKey pidA) [] now NotConnected
      atomically $ modifyTVar' (dhtRoutingTable node) $ \rt ->
        fst (insertPeer entryA rt)

      _ <- iterativeFindNode node targetPid
      sentKeys <- readIORef sentKeysRef
      sentKeys `shouldSatisfy` (not . null)
      mapM_ (`shouldBe` peerIdBytes targetPid) sentKeys

    it "should return no peers when every routing-table candidate fails" $ do
      now <- getCurrentTime
      -- Node with peers in the routing table, all network queries fail —
      -- but even a failing mock validates the request's wire format first.
      node <- mkNodeWithMock localPid
        (\_ msg -> pure (decodeWireRequest msg >> Left "no network"))
      let peers = [mkPeerId (BS.pack [i]) | i <- [2..6]]
          entries = map (\pid -> BucketEntry pid (peerIdToKey pid) [] now NotConnected) peers
      atomically $ modifyTVar' (dhtRoutingTable node) $ \rt ->
        foldl (\r e -> fst (insertPeer e r)) rt entries

      result <- iterativeFindNode node (mkPeerId (BS.pack [42]))
      result `shouldBe` []

    it "converges through mock network (3-hop)" $ do
      now <- getCurrentTime
      -- Setup: localNode knows A, A knows B, B knows C (closer to target)
      let pidA = mkPeerId (BS.pack [10])
          pidB = mkPeerId (BS.pack [20])
          pidC = mkPeerId (BS.pack [30])
          targetPid = mkPeerId (BS.pack [42, 42, 42, 42])
          wantKey = peerIdBytes targetPid
          -- Mock network: A returns B as closer, B returns C as closer.
          -- Each hop checks the decoded request targets the right key.
          network = Map.fromList
            [ (pidA, expecting FindNode wantKey
                (findNodeReply [DHTPeer (peerIdBytes pidB) [] NotConnected]))
            , (pidB, expecting FindNode wantKey
                (findNodeReply [DHTPeer (peerIdBytes pidC) [] NotConnected]))
            , (pidC, expecting FindNode wantKey (findNodeReply []))  -- terminus
            ]
      node <- mkNodeWithMock localPid (mockSendFromNetwork network)
      -- Seed routing table with A
      let entryA = BucketEntry pidA (peerIdToKey pidA) [] now NotConnected
      atomically $ modifyTVar' (dhtRoutingTable node) $ \rt ->
        fst (insertPeer entryA rt)

      result <- iterativeFindNode node targetPid
      -- Should have discovered A, B, C through the lookup chain
      let foundPids = map entryPeerId result
      foundPids `shouldSatisfy` (\ps -> pidA `elem` ps)
      -- B and C should also have been discovered
      length result `shouldSatisfy` (>= 2)

    it "terminates when all k-closest queried" $ do
      now <- getCurrentTime
      -- All peers return empty closerPeers → terminates after querying seeds
      let targetPid = mkPeerId (BS.pack [0xFF, 0xFF])
          peers = [mkPeerId (BS.pack [i]) | i <- [2..6]]
          network = Map.fromList
            [(pid, expecting FindNode (peerIdBytes targetPid) (findNodeReply []))
            | pid <- peers]
      node <- mkNodeWithMock localPid (mockSendFromNetwork network)
      let entries = map (\pid -> BucketEntry pid (peerIdToKey pid) [] now NotConnected) peers
      atomically $ modifyTVar' (dhtRoutingTable node) $ \rt ->
        foldl (\r e -> fst (insertPeer e r)) rt entries

      result <- iterativeFindNode node targetPid
      length result `shouldBe` length peers

    it "should discard candidates when their requests are refused" $ do
      now <- getCurrentTime
      -- All queries fail (after wire-format validation)
      node <- mkNodeWithMock localPid
        (\_ msg -> pure (decodeWireRequest msg >> Left "connection refused"))
      let peers = [mkPeerId (BS.pack [i]) | i <- [2..4]]
          entries = map (\pid -> BucketEntry pid (peerIdToKey pid) [] now NotConnected) peers
      atomically $ modifyTVar' (dhtRoutingTable node) $ \rt ->
        foldl (\r e -> fst (insertPeer e r)) rt entries

      result <- iterativeFindNode node (mkPeerId (BS.pack [42]))
      result `shouldBe` []

    it "terminates early when total peers < k" $ do
      now <- getCurrentTime
      -- Only 3 peers, all return empty
      let targetPid = mkPeerId (BS.pack [99])
          peers = [mkPeerId (BS.pack [i]) | i <- [2..4]]
          network = Map.fromList
            [(pid, expecting FindNode (peerIdBytes targetPid) (findNodeReply []))
            | pid <- peers]
      node <- mkNodeWithMock localPid (mockSendFromNetwork network)
      let entries = map (\pid -> BucketEntry pid (peerIdToKey pid) [] now NotConnected) peers
      atomically $ modifyTVar' (dhtRoutingTable node) $ \rt ->
        foldl (\r e -> fst (insertPeer e r)) rt entries

      result <- iterativeFindNode node targetPid
      length result `shouldBe` 3  -- only 3 peers total, less than k=20

    it "queries peers in XOR distance order, not lexicographic key order" $ do
      now <- getCurrentTime
      queryOrderRef <- newIORef ([] :: [PeerId])

      -- Create 15 peers so that alpha (10) < total, forcing batch selection
      let peers = [mkPeerId (BS.pack [i]) | i <- [10..24]]
          targetPid = mkPeerId (BS.replicate 32 0xFF)
          -- Distance is over sha256(key) (specs/kad-dht), so the expected
          -- ordering must use the hashed target, matching the lookup.
          targetKey = peerIdToKey targetPid

      -- Compute expected first batch: the 10 closest by XOR distance
      let entries = map (\pid -> BucketEntry pid (peerIdToKey pid) [] now NotConnected) peers
          sortedByDist = sortByDistance targetKey entries
          closestAlpha = Set.fromList $ map entryPeerId (take alphaValue sortedByDist)

      -- Mock network: each peer records the query order, then checks the
      -- decoded request before returning an empty reply.
      let mockSend = recordingSend
            (\pid _req -> atomicModifyIORef' queryOrderRef (\xs -> (xs ++ [pid], ())))
            (expecting FindNode (peerIdBytes targetPid) (findNodeReply []))

      node <- mkNodeWithMock localPid mockSend
      atomically $ modifyTVar' (dhtRoutingTable node) $ \rt ->
        foldl (\r e -> fst (insertPeer e r)) rt entries

      _ <- iterativeFindNode node targetPid

      -- The first alpha peers queried should be the closest by XOR distance
      -- (mapConcurrently doesn't preserve order within batch, so compare as sets)
      queriedOrder <- readIORef queryOrderRef
      let firstBatch = Set.fromList (take alphaValue queriedOrder)
      firstBatch `shouldBe` closestAlpha

    it "returns results sorted by XOR distance to target" $ do
      now <- getCurrentTime
      let peers = [mkPeerId (BS.pack [i]) | i <- [10..20]]
          targetPid = mkPeerId (BS.replicate 32 0xAA)
          -- Expected order uses sha256(target peer id), the spec metric.
          targetKey = peerIdToKey targetPid
          entries = map (\pid -> BucketEntry pid (peerIdToKey pid) [] now NotConnected) peers
          expectedOrder = map entryPeerId (sortByDistance targetKey entries)
          network = Map.fromList
            [(pid, expecting FindNode (peerIdBytes targetPid) (findNodeReply []))
            | pid <- peers]

      node <- mkNodeWithMock localPid (mockSendFromNetwork network)
      atomically $ modifyTVar' (dhtRoutingTable node) $ \rt ->
        foldl (\r e -> fst (insertPeer e r)) rt entries

      result <- iterativeFindNode node targetPid
      -- Results should be sorted by XOR distance to the target
      map entryPeerId result `shouldBe` expectedOrder

    -- Issue #147 (receive side): multiaddrs carried by closerPeers must be
    -- decoded into the resulting entries instead of being dropped —
    -- otherwise the peers we learn about cannot be dialled.
    it "decodes closerPeers' multiaddrs into lookup results" $ do
      now <- getCurrentTime
      let pidA = mkPeerId (BS.pack [10])
          pidB = mkPeerId (BS.pack [20])
          addrB = either error id (fromText "/ip4/192.0.2.1/tcp/4001")
          targetPid = mkPeerId (BS.pack [42])
          wantKey = peerIdBytes targetPid
          network = Map.fromList
            [ (pidA, expecting FindNode wantKey
                (findNodeReply [DHTPeer (peerIdBytes pidB) [toBytes addrB] NotConnected]))
            , (pidB, expecting FindNode wantKey (findNodeReply []))
            ]
      node <- mkNodeWithMock localPid (mockSendFromNetwork network)
      let entryA = BucketEntry pidA (peerIdToKey pidA) [] now NotConnected
      atomically $ modifyTVar' (dhtRoutingTable node) $ \rt ->
        fst (insertPeer entryA rt)

      result <- iterativeFindNode node targetPid
      let entriesB = filter ((== pidB) . entryPeerId) result
      map entryAddrs entriesB `shouldBe` [[addrB]]

    -- Issue #148 (4): "Peers encountered throughout the search are
    -- inserted in the routing table, as per usual business."
    it "inserts peers discovered during the lookup into the routing table" $ do
      now <- getCurrentTime
      let pidA = mkPeerId (BS.pack [10])
          pidB = mkPeerId (BS.pack [20])
          pidC = mkPeerId (BS.pack [30])
          targetPid = mkPeerId (BS.pack [42, 42, 42, 42])
          wantKey = peerIdBytes targetPid
          network = Map.fromList
            [ (pidA, expecting FindNode wantKey
                (findNodeReply [DHTPeer (peerIdBytes pidB) [] NotConnected]))
            , (pidB, expecting FindNode wantKey
                (findNodeReply [DHTPeer (peerIdBytes pidC) [] NotConnected]))
            , (pidC, expecting FindNode wantKey (findNodeReply []))
            ]
      node <- mkNodeWithMock localPid (mockSendFromNetwork network)
      let entryA = BucketEntry pidA (peerIdToKey pidA) [] now NotConnected
      atomically $ modifyTVar' (dhtRoutingTable node) $ \rt ->
        fst (insertPeer entryA rt)

      _ <- iterativeFindNode node targetPid
      rt <- readTVarIO (dhtRoutingTable node)
      let tablePids = map entryPeerId (allPeers rt)
      tablePids `shouldContain` [pidB]
      tablePids `shouldContain` [pidC]

  describe "iterativeGetValue" $ do
    -- Issue #148 (1): the validator must also gate values retrieved in
    -- GET_VALUE queries, not just PUT_VALUE storage.
    it "ignores retrieved records that fail validation" $ do
      now <- getCurrentTime
      let pidA = mkPeerId (BS.pack [10])
          pidB = mkPeerId (BS.pack [20])
          key = BS.pack [0xCA, 0xFE]
          badRecord = DHTRecord key (BS.pack [0xBA, 0xD0]) ""
          goodRecord = DHTRecord key (BS.pack [0x60, 0x0D]) ""
          network = Map.fromList
            [ (pidA, expecting GetValue key (emptyDHTMessage
                { msgType = GetValue
                , msgRecord = Just badRecord
                , msgCloserPeers = [DHTPeer (peerIdBytes pidB) [] NotConnected]
                }))
            , (pidB, \req -> case msgType req of
                GetValue -> expecting GetValue key (emptyDHTMessage
                  { msgType = GetValue
                  , msgRecord = Just goodRecord
                  , msgCloserPeers = []
                  }) req
                -- The invalid record's holder may receive a repair.
                PutValue -> expecting PutValue key
                  (emptyDHTMessage { msgType = PutValue, msgKey = key }) req
                other -> Left $ "mock: unexpected request type " ++ show other)
            ]
          validator = Validator
            { valValidate = \_ value ->
                if value == recValue badRecord
                  then Left "invalid record"
                  else Right ()
            , valSelect = \_ _ -> Right 0
            }
      node <- mkNodeWithMock localPid (mockSendFromNetwork network)
      let entryA = BucketEntry pidA (peerIdToKey pidA) [] now NotConnected
      atomically $ modifyTVar' (dhtRoutingTable node) $ \rt ->
        fst (insertPeer entryA rt)

      result <- iterativeGetValue node validator key
      case result of
        Right rec -> recValue rec `shouldBe` recValue goodRecord
        Left err -> expectationFailure $ "Expected the valid record, got: " ++ err
    it "sends the raw record key as the wire key" $ do
      now <- getCurrentTime
      sentKeysRef <- newIORef ([] :: [BS.ByteString])
      let key = BS.pack [0xCA, 0xFE]
          record = DHTRecord key (BS.pack [0xDE, 0xAD]) "2024-01-01T00:00:00Z"
          mockSend = recordingSend (recordKeys sentKeysRef)
            (\_ -> Right (emptyDHTMessage
              { msgType = GetValue, msgRecord = Just record, msgCloserPeers = [] }))
          validator = Validator (\_ _ -> Right ()) (\_ _ -> Right 0)
      node <- mkNodeWithMock localPid mockSend
      let pidA = mkPeerId (BS.pack [10])
          entryA = BucketEntry pidA (peerIdToKey pidA) [] now NotConnected
      atomically $ modifyTVar' (dhtRoutingTable node) $ \rt ->
        fst (insertPeer entryA rt)

      _ <- iterativeGetValue node validator key
      sentKeys <- readIORef sentKeysRef
      sentKeys `shouldSatisfy` (not . null)
      mapM_ (`shouldBe` key) sentKeys

    it "finds value from mock network" $ do
      now <- getCurrentTime
      let pidA = mkPeerId (BS.pack [10])
          key = BS.pack [0xCA, 0xFE]
          record = DHTRecord key (BS.pack [0xDE, 0xAD]) "2024-01-01T00:00:00Z"
          network = Map.fromList
            [ (pidA, expecting GetValue key (emptyDHTMessage
                { msgType = GetValue
                , msgRecord = Just record
                , msgCloserPeers = []
                }))
            ]
          validator = Validator
            { valValidate = \_ _ -> Right ()
            , valSelect = \_ _vals -> Right 0  -- always pick first
            }
      node <- mkNodeWithMock localPid (mockSendFromNetwork network)
      let entryA = BucketEntry pidA (peerIdToKey pidA) [] now NotConnected
      atomically $ modifyTVar' (dhtRoutingTable node) $ \rt ->
        fst (insertPeer entryA rt)

      result <- iterativeGetValue node validator key
      result `shouldBe` Right record

    it "corrects outdated peers with PUT_VALUE carrying the best record" $ do
      now <- getCurrentTime
      putCalls <- newTVarIO ([] :: [(PeerId, DHTMessage)])
      let pidA = mkPeerId (BS.pack [10])
          pidB = mkPeerId (BS.pack [20])
          key = BS.pack [0xCA, 0xFE]
          oldRecord = DHTRecord key (BS.pack [0x01]) "2024-01-01T00:00:00Z"
          newRecord = DHTRecord key (BS.pack [0x02]) "2024-06-01T00:00:00Z"
          -- A has old value (and must later accept the repair), B has new.
          network = Map.fromList
            [ (pidA, \req -> case msgType req of
                GetValue -> expecting GetValue key (emptyDHTMessage
                  { msgType = GetValue
                  , msgRecord = Just oldRecord
                  , msgCloserPeers = [DHTPeer (peerIdBytes pidB) [] NotConnected]
                  }) req
                PutValue -> expecting PutValue key
                  (emptyDHTMessage { msgType = PutValue, msgKey = key }) req
                other -> Left $ "mock: unexpected request type " ++ show other)
            , (pidB, expecting GetValue key (emptyDHTMessage
                { msgType = GetValue
                , msgRecord = Just newRecord
                , msgCloserPeers = []
                }))
            ]
          -- Custom sender that also captures decoded PUT_VALUE requests
          mockSend pid msg = case decodeWireRequest msg of
            Left err -> pure (Left err)
            Right req -> do
              case msgType req of
                PutValue -> atomically $ modifyTVar' putCalls ((pid, req) :)
                _ -> pure ()
              mockSendFromNetwork network pid msg
          validator = Validator
            { valValidate = \_ _ -> Right ()
            , valSelect = \_ vals ->
                -- Select second value (index 1) as better
                if length vals >= 2 then Right 1 else Right 0
            }
      node <- mkNodeWithMock localPid mockSend
      let entryA = BucketEntry pidA (peerIdToKey pidA) [] now NotConnected
      atomically $ modifyTVar' (dhtRoutingTable node) $ \rt ->
        fst (insertPeer entryA rt)

      result <- iterativeGetValue node validator key
      case result of
        Right rec -> recValue rec `shouldBe` BS.pack [0x02]
        Left err -> expectationFailure $ "Expected value, got: " ++ err
      -- The repair PUT_VALUE must go to peer A (outdated) and carry the
      -- winning record under the same key, as decoded off the wire.
      puts <- readTVarIO putCalls
      case lookup pidA puts of
        Nothing -> expectationFailure "no PUT_VALUE repair sent to outdated peer A"
        Just req -> do
          msgKey req `shouldBe` key
          msgRecord req `shouldBe` Just newRecord

    it "selects best value via Validator.select" $ do
      now <- getCurrentTime
      let pidA = mkPeerId (BS.pack [10])
          pidB = mkPeerId (BS.pack [20])
          key = BS.pack [0xBB]
          recA = DHTRecord key (BS.pack [1]) "2024-01-01T00:00:00Z"
          recB = DHTRecord key (BS.pack [2]) "2024-06-01T00:00:00Z"
          network = Map.fromList
            [ (pidA, expecting GetValue key (emptyDHTMessage
                { msgType = GetValue
                , msgRecord = Just recA
                , msgCloserPeers = [DHTPeer (peerIdBytes pidB) [] NotConnected]
                }))
            , (pidB, \req -> case msgType req of
                GetValue -> expecting GetValue key (emptyDHTMessage
                  { msgType = GetValue
                  , msgRecord = Just recB
                  , msgCloserPeers = []
                  }) req
                -- B returned the losing value, so it receives the repair.
                PutValue -> expecting PutValue key
                  (emptyDHTMessage { msgType = PutValue, msgKey = key }) req
                other -> Left $ "mock: unexpected request type " ++ show other)
            ]
          -- Always select index 0 (first = current best)
          validator = Validator
            { valValidate = \_ _ -> Right ()
            , valSelect = \_ _ -> Right 0
            }
      node <- mkNodeWithMock localPid (mockSendFromNetwork network)
      let entryA = BucketEntry pidA (peerIdToKey pidA) [] now NotConnected
      atomically $ modifyTVar' (dhtRoutingTable node) $ \rt ->
        fst (insertPeer entryA rt)

      result <- iterativeGetValue node validator key
      -- With Select always returning 0, the first value found (recA) should be kept
      case result of
        Right rec -> recValue rec `shouldBe` BS.pack [1]
        Left err -> expectationFailure $ "Expected value, got: " ++ err

  describe "iterativeGetProviders" $ do
    it "sends the raw content key as the wire key" $ do
      now <- getCurrentTime
      sentKeysRef <- newIORef ([] :: [BS.ByteString])
      let key = BS.pack [0xDD, 0xEE, 0xFF]
          mockSend = recordingSend (recordKeys sentKeysRef)
            (\_ -> Right (emptyDHTMessage
              { msgType = GetProviders, msgCloserPeers = [], msgProviderPeers = [] }))
      node <- mkNodeWithMock localPid mockSend
      let pidA = mkPeerId (BS.pack [10])
          entryA = BucketEntry pidA (peerIdToKey pidA) [] now NotConnected
      atomically $ modifyTVar' (dhtRoutingTable node) $ \rt ->
        fst (insertPeer entryA rt)

      _ <- iterativeGetProviders node key
      sentKeys <- readIORef sentKeysRef
      sentKeys `shouldSatisfy` (not . null)
      mapM_ (`shouldBe` key) sentKeys

    it "collects providers from multiple hops" $ do
      now <- getCurrentTime
      let pidA = mkPeerId (BS.pack [10])
          pidB = mkPeerId (BS.pack [20])
          key = BS.pack [0xDD]
          providerPeer1 = DHTPeer (BS.pack [50]) [] Connected
          providerPeer2 = DHTPeer (BS.pack [60]) [] Connected
          network = Map.fromList
            [ (pidA, expecting GetProviders key (emptyDHTMessage
                { msgType = GetProviders
                , msgCloserPeers = [DHTPeer (peerIdBytes pidB) [] NotConnected]
                , msgProviderPeers = [providerPeer1]
                }))
            , (pidB, expecting GetProviders key (emptyDHTMessage
                { msgType = GetProviders
                , msgCloserPeers = []
                , msgProviderPeers = [providerPeer2]
                }))
            ]
      node <- mkNodeWithMock localPid (mockSendFromNetwork network)
      let entryA = BucketEntry pidA (peerIdToKey pidA) [] now NotConnected
      atomically $ modifyTVar' (dhtRoutingTable node) $ \rt ->
        fst (insertPeer entryA rt)

      result <- iterativeGetProviders node key
      -- Should have collected providers from both hops
      length result `shouldSatisfy` (>= 2)

    -- Issue #147 (receive side): provider records carry multiaddrs that
    -- must be decoded so the provider can be dialled.
    it "decodes provider multiaddrs into provider entries" $ do
      now <- getCurrentTime
      let pidA = mkPeerId (BS.pack [10])
          key = BS.pack [0xD1]
          providerAddr = either error id (fromText "/ip4/192.0.2.7/tcp/4001")
          providerPeer = DHTPeer (BS.pack [50]) [toBytes providerAddr] Connected
          network = Map.fromList
            [ (pidA, expecting GetProviders key (emptyDHTMessage
                { msgType = GetProviders
                , msgCloserPeers = []
                , msgProviderPeers = [providerPeer]
                }))
            ]
      node <- mkNodeWithMock localPid (mockSendFromNetwork network)
      let entryA = BucketEntry pidA (peerIdToKey pidA) [] now NotConnected
      atomically $ modifyTVar' (dhtRoutingTable node) $ \rt ->
        fst (insertPeer entryA rt)

      result <- iterativeGetProviders node key
      map peAddrs result `shouldBe` [[providerAddr]]

  describe "bootstrap" $ do
    it "self-lookup sends raw peer IDs as wire keys" $ do
      sentKeysRef <- newIORef ([] :: [BS.ByteString])
      let seedPid = mkPeerId (BS.pack [10])
          mockSend = recordingSend (recordKeys sentKeysRef)
                                   (\_ -> Right (findNodeReply []))
      node <- mkNodeWithMock localPid mockSend

      bootstrap node [seedPid]

      sentKeys <- readIORef sentKeysRef
      sentKeys `shouldSatisfy` (not . null)
      -- The self-lookup queries for our own binary peer ID (not its digest).
      take 1 sentKeys `shouldBe` [peerIdBytes localPid]

    it "performs self-lookup and populates nearby buckets" $ do
      let seedPid = mkPeerId (BS.pack [10])
          pidB = mkPeerId (BS.pack [20])
          pidC = mkPeerId (BS.pack [30])
          -- Seed returns B and C as closer peers. Refresh keys are random
          -- kad-ids, so the mock accepts any FIND_NODE.
          acceptFindNode resp req
            | msgType req == FindNode = Right resp
            | otherwise = Left "mock: expected FIND_NODE"
          network = Map.fromList
            [ (seedPid, acceptFindNode
                (findNodeReply [ DHTPeer (peerIdBytes pidB) [] NotConnected
                               , DHTPeer (peerIdBytes pidC) [] NotConnected
                               ]))
            , (pidB, acceptFindNode (findNodeReply []))
            , (pidC, acceptFindNode (findNodeReply []))
            ]
      node <- mkNodeWithMock localPid (mockSendFromNetwork network)
      bootstrap node [seedPid]
      rt <- readTVarIO (dhtRoutingTable node)
      length (allPeers rt) `shouldSatisfy` (>= 1)

    it "a permanently blocked peer cannot hold bootstrap past the configured deadline" $ do
      let seedPid = mkPeerId (BS.pack [10])
          mockSend _ _ = forever (threadDelay 1000000) >> pure (Left "unreachable")
      node0 <- mkNodeWithMock localPid mockSend
      let node = node0 { dhtQueryTimeout = 100000 }
      start <- getCurrentTime
      bootstrap node [seedPid]
      elapsed <- diffUTCTime <$> getCurrentTime <*> pure start
      elapsed `shouldSatisfy` (< 1)

    it "refreshes every non-empty bucket with a key in that bucket's range" $ do
      sentKeysRef <- newIORef ([] :: [BS.ByteString])
      let mockSend = recordingSend (recordKeys sentKeysRef)
                                   (\_ -> Right (findNodeReply []))
      node <- mkNodeWithMock localPid mockSend
      now <- getCurrentTime
      let rt0 = newRoutingTable localPid
          candidates = [mkPeerId (BS.pack [i]) | i <- [1 .. 40]]
          tagged = [ (pid, bucketForPeer (peerIdToKey pid) rt0) | pid <- candidates ]
          (pidA, bucketA) = head tagged
          (pidB, bucketB) = head (filter (\(_, b) -> b /= bucketA) tagged)
      atomically $ modifyTVar' (dhtRoutingTable node) $ \rt ->
        let eA = BucketEntry pidA (peerIdToKey pidA) [] now NotConnected
            eB = BucketEntry pidB (peerIdToKey pidB) [] now NotConnected
        in fst (insertPeer eB (fst (insertPeer eA rt)))
      bootstrap node []
      sentKeys <- readIORef sentKeysRef
      let selfKey = peerIdToKey localPid
          refreshKeys = filter (/= peerIdBytes localPid) sentKeys
          refreshCpls =
            [ commonPrefixLength selfKey (keyToDHTKey rawKey)
            | rawKey <- refreshKeys
            ]
          expectedPeerIds = [peerIdBytes pidA, peerIdBytes pidB]
      refreshKeys `shouldSatisfy` all (`elem` expectedPeerIds)
      nub refreshCpls `shouldMatchList` [bucketA, bucketB]
      keyToDHTKey "raw-refresh-fixture" `shouldBe` DHTKey (BS.pack
        [ 0xde, 0x8a, 0x6c, 0x10, 0x58, 0xf0, 0x89, 0x4b
        , 0x31, 0x46, 0x0c, 0x8a, 0xdc, 0x5a, 0xc9, 0x1b
        , 0x71, 0xc9, 0x80, 0x4f, 0x16, 0xd1, 0x64, 0x24
        , 0x2e, 0x61, 0x28, 0x53, 0x08, 0xb1, 0xbf, 0x70
        ])

    it "periodic refresh runs more than once under a short test interval" $ do
      sentKeysRef <- newIORef ([] :: [BS.ByteString])
      let seedPid = mkPeerId (BS.pack [10])
          mockSend = recordingSend (recordKeys sentKeysRef)
                                   (\_ -> Right (findNodeReply []))
      node <- mkNodeWithMock localPid mockSend
      startBootstrap node [seedPid] 50000
      threadDelay 180000
      stopDHTNode node
      sentKeys <- readIORef sentKeysRef
      let selfLookups = filter (== peerIdBytes localPid) sentKeys
      length selfLookups `shouldSatisfy` (>= 2)
      threadDelay 80000
      sentKeysAfter <- readIORef sentKeysRef
      length (filter (== peerIdBytes localPid) sentKeysAfter)
        `shouldBe` length selfLookups
