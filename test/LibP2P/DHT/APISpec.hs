module LibP2P.DHT.APISpec (spec) where

import Test.Hspec

import Control.Concurrent (threadDelay)
import Control.Concurrent.STM
import Data.IORef (newIORef, readIORef, writeIORef)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import Data.Time (addUTCTime, getCurrentTime)
import LibP2P.Crypto.PeerId (PeerId (..), peerIdBytes)

import LibP2P.DHT
import LibP2P.DHT.API
import LibP2P.DHT.Distance (peerIdToKey)
import LibP2P.DHT.Maintenance (newDHTMaintenanceState)
import LibP2P.DHT.Message
  ( DHTMessage (..)
  , DHTPeer (..)
  , DHTRecord (..)
  , MessageType (..)
  , emptyDHTMessage
  )
import LibP2P.DHT.Types (BucketEntry (..), ConnectionType (..))
import LibP2P.DHT.RoutingTable (insertPeer, newRoutingTable)
import LibP2P.Crypto.Ed25519 (generateKeyPair)
import LibP2P.Crypto.Key (KeyPair)
import LibP2P.Multiaddr (Multiaddr, fromText)
import LibP2P.Switch.Types (Switch (..), defaultConnectionGater, defaultSwitchConfig)
import LibP2P.Switch.ResourceManager (ResourceManager, newResourceManager, DefaultLimits (..), noLimits)
import qualified Data.Map.Strict as Map
import System.Timeout (timeout)

-- Peer IDs for testing
localPid :: PeerId
localPid = PeerId (BS.pack [0])

peerA :: PeerId
peerA = PeerId (BS.pack [1])

testAddr :: Multiaddr
testAddr = either error id (fromText "/ip4/127.0.0.1/tcp/4001")

-- | Create a DHTNode with a custom send function that records messages.
mkAPITestNode
  :: PeerId
  -> TVar [(PeerId, DHTMessage)]  -- ^ Record of sent messages (peer, msg)
  -> IO DHTNode
mkAPITestNode = mkAPITestNodeWithConfig defaultDHTMaintenanceConfig

mkAPITestNodeWithConfig
  :: DHTMaintenanceConfig
  -> PeerId
  -> TVar [(PeerId, DHTMessage)]
  -> IO DHTNode
mkAPITestNodeWithConfig maintenanceConfig pid sentLog = do
  rt    <- newTVarIO (newRoutingTable pid)
  recs  <- newTVarIO Map.empty
  provs <- newTVarIO Map.empty
  ks     <- newTVarIO Map.empty
  hook   <- newIORef Nothing
  stopped <- newTVarIO False
  worker <- newTVarIO Nothing
  maintenance <- newDHTMaintenanceState maintenanceConfig
  let sendFunc target msg = do
        atomically $ modifyTVar' sentLog ((target, msg) :)
        -- Simulate successful FIND_NODE response returning ourselves
        -- as the closest peer for any lookup
        case msgType msg of
          FindNode -> do
            let selfEntry = DHTPeer
                  { dhtPeerId = peerIdBytes pid
                  , dhtPeerAddrs = []
                  , dhtPeerConnType = Connected
                  }
            pure $ Right emptyDHTMessage
              { msgType = FindNode
              , msgCloserPeers = [selfEntry]
              }
          GetValue -> do
            -- Return a record if we have one
            storedRecs <- readTVarIO recs
            case Map.lookup (msgKey msg) storedRecs of
              Just rec -> pure $ Right emptyDHTMessage
                { msgType = GetValue
                , msgRecord = Just rec
                }
              Nothing -> pure $ Right emptyDHTMessage
                { msgType = GetValue
                , msgCloserPeers = []
                }
          _ -> pure $ Right emptyDHTMessage
  sw <- mkMockSwitch pid
  localKey <- peerIdToKey <$> pure pid
  let node = DHTNode
        { dhtSwitch        = sw
        , dhtRoutingTable  = rt
        , dhtRecordStore   = recs
        , dhtProviderStore = provs
        , dhtLocalKey      = localKey
        , dhtLocalPeerId   = pid
        , dhtMode          = DHTServer
        , dhtValidator     = defaultPermissiveValidator
        , dhtStreams        = ks
        , dhtSendRequest    = sendFunc
        , dhtDisconnectHook  = hook
        , dhtStopped         = stopped
        , dhtQueryTimeout    = defaultQueryTimeoutMicros
        , dhtBootstrapWorker = worker
        , dhtMaintenance     = maintenance
        }
  pure node

-- | Like mkAPITestNode but seeds the routing table with given peers and
-- mocks the FindNode response to return them.
mkAPITestNodeWithPeers :: PeerId -> TVar [(PeerId, DHTMessage)] -> [PeerId] -> IO DHTNode
mkAPITestNodeWithPeers =
  mkAPITestNodeWithPeersAndConfig defaultDHTMaintenanceConfig

mkAPITestNodeWithPeersAndConfig
  :: DHTMaintenanceConfig
  -> PeerId
  -> TVar [(PeerId, DHTMessage)]
  -> [PeerId]
  -> IO DHTNode
mkAPITestNodeWithPeersAndConfig maintenanceConfig pid sentLog seedPeers = do
  node <- mkAPITestNodeWithConfig maintenanceConfig pid sentLog
  now <- getCurrentTime
  -- Insert seed peers into the routing table
  atomically $ modifyTVar' (dhtRoutingTable node) $ \rt ->
    foldl' (\rt' p ->
      let entry = BucketEntry
            { entryPeerId   = p
            , entryKey      = peerIdToKey p
            , entryAddrs    = [testAddr]
            , entryLastSeen = now
            , entryConnType = Connected
            }
          (rt'', _) = insertPeer entry rt'
      in rt''
    ) rt seedPeers
  pure node


spec :: Spec
spec = describe "LibP2P.DHT.API" $ do

  describe "provide" $ do
    it "announces the local node as a provider for the given key" $ do
      sentLog <- newTVarIO []
      node <- mkAPITestNode localPid sentLog

      -- When we call provide
      provide node [testAddr] (BSC.pack "test-key")

      -- Then the local provider store should have the entry
      providers <- readTVarIO (dhtProviderStore node)
      let mEntry = Map.lookup (BSC.pack "test-key") providers
      case mEntry of
        Nothing -> expectationFailure "Expected provider entry"
        Just ents -> do
          length ents `shouldBe` 1
          peProvider (head ents) `shouldBe` localPid

    it "sends ADD_PROVIDER messages to closest peers when lookup returns peers" $ do
      sentLog <- newTVarIO []
      node <- mkAPITestNodeWithPeers localPid sentLog [peerA]
      provide node [testAddr] (BSC.pack "test-key")

      -- Verify ADD_PROVIDER was sent (the lookup finds peerA and sends
      -- ADD_PROVIDER to it)
      msgs <- readTVarIO sentLog
      let addProviderMsgs = filter (\(_, m) -> msgType m == AddProvider) msgs
      -- provide sends ADD_PROVIDER to the closest peer(s) found by the
      -- iterative lookup. target peerA should be in the list.
      length addProviderMsgs `shouldSatisfy` (> 0)
      let targets = map fst addProviderMsgs
      peerA `elem` targets `shouldBe` True

    it "reannounces provided keys and stops after stopDHTNode" $ do
      sentLog <- newTVarIO []
      let config = defaultDHTMaintenanceConfig
            { dmcProviderRepublishIntervalMicros = 50000
            , dmcProviderBatchSize = 1
            , dmcValueGCIntervalMicros = 0
            }
          keys = map BSC.pack ["republished-a", "republished-b"]
      node <- mkAPITestNodeWithPeersAndConfig config localPid sentLog [peerA]
      mapM_ (provide node [testAddr]) keys
      atomically $ writeTVar sentLog []

      reannounced <- timeout 1000000 $ atomically $ do
        messages <- readTVar sentLog
        let announcedKeys =
              [msgKey message | (_, message) <- messages, msgType message == AddProvider]
        check (all (`elem` announcedKeys) keys)
      reannounced `shouldBe` Just ()

      stopDHTNode node
      atomically $ writeTVar sentLog []
      threadDelay 100000
      messagesAfterStop <- readTVarIO sentLog
      any ((== AddProvider) . msgType . snd) messagesAfterStop `shouldBe` False

  describe "putValue" $ do
    it "stores a value locally on success" $ do
      sentLog <- newTVarIO []
      node <- mkAPITestNode localPid sentLog
      let validator = namespacedValidator (Map.fromList
            [(BSC.pack "example", defaultPermissiveValidator)])
          key = BSC.pack "/example/data/test-key"
          val = BSC.pack "test-value"

      result <- putValue node validator key val
      result `shouldBe` Right ()

      -- Value should be in local store
      records <- readTVarIO (dhtRecordStore node)
      Map.lookup key records `shouldSatisfy` isJust

    it "rejects invalid values" $ do
      sentLog <- newTVarIO []
      node <- mkAPITestNode localPid sentLog
      let validator = namespacedValidator (Map.fromList
            [(BSC.pack "example", defaultPermissiveValidator)])
          -- Key outside any known namespace should fail
          key = BSC.pack "/unknown/key"
          val = BSC.pack "value"

      result <- putValue node validator key val
      result `shouldSatisfy` isLeft

  describe "getValue" $ do
    it "retrieves a record stored via putValue" $ do
      sentLog <- newTVarIO []
      node <- mkAPITestNodeWithPeers localPid sentLog [peerA]
      let validator = namespacedValidator (Map.fromList
            [(BSC.pack "example", defaultPermissiveValidator)])
          key = BSC.pack "/example/data/test-key"
          val = BSC.pack "test-value"

      putResult <- putValue node validator key val
      putResult `shouldBe` Right ()

      getResult <- getValue node validator key
      fmap recValue getResult `shouldBe` Right val

    it "does not return a local record past its maximum age" $ do
      sentLog <- newTVarIO []
      initialNow <- getCurrentTime
      clock <- newIORef initialNow
      let config = defaultDHTMaintenanceConfig
            { dmcValueGCIntervalMicros = 0
            , dmcNow = readIORef clock
            }
          validator = namespacedValidator (Map.fromList
            [(BSC.pack "example", defaultPermissiveValidator)])
          key = BSC.pack "/example/data/expired-key"
      node <- mkAPITestNodeWithConfig config localPid sentLog

      putValue node validator key (BSC.pack "expired-value")
        `shouldReturn` Right ()
      writeIORef clock (addUTCTime (49 * 3600) initialNow)

      getValue node validator key `shouldReturn` Left "value not found"
      lookupRecord node key `shouldReturn` Nothing

  describe "findProviders" $ do
    it "returns providers found by iterative lookup" $ do
      sentLog <- newTVarIO []
      node <- mkAPITestNodeWithPeers localPid sentLog [peerA]

      -- Search for providers
      providers <- findProviders node (BSC.pack "test-key")
      -- The lookup returns no providers because the mock sendFunc
      -- returns FIND_NODE-style responses (closerPeers) not provider
      -- entries. The test verifies that the function completes without
      -- error and returns a proper type; provider discovery is tested
      -- in LookupSpec.hs.
      length providers `shouldBe` 0

  describe "findPeer" $ do
    it "returns the closest known peers for a target peer ID" $ do
      sentLog <- newTVarIO []
      node <- mkAPITestNodeWithPeers localPid sentLog [peerA]

      peers <- findPeer node peerA

      map entryPeerId peers `shouldContain` [peerA]

-- | Create a mock Switch with just a local peer ID.
mkMockSwitch :: PeerId -> IO Switch
mkMockSwitch pid = do
  transports <- newTVarIO []
  pool <- newTVarIO Map.empty
  protocols <- newTVarIO Map.empty
  events <- newBroadcastTChanIO
  closed <- newTVarIO False
  backoffs <- newTVarIO Map.empty
  pendingDials <- newTVarIO Map.empty
  connectionGater <- newTVarIO defaultConnectionGater
  resMgr <- mkMockResourceMgr
  peerStore <- newTVarIO Map.empty
  certifiedRecords <- newTVarIO Map.empty
  notifiers <- newTVarIO []
  disconnectNotifiers <- newTVarIO []
  listeners <- newTVarIO []
  shutdownActions <- newTVarIO []
  kp <- getDummyKeyPair
  pure Switch
    { swLocalPeerId  = pid
    , swIdentityKey  = kp
    , swTransports   = transports
    , swConnPool     = pool
    , swProtocols    = protocols
    , swEvents       = events
    , swClosed       = closed
    , swDialBackoffs = backoffs
    , swPendingDials = pendingDials
    , swConnectionGater = connectionGater
    , swResourceMgr  = resMgr
    , swPeerStore    = peerStore
    , swCertifiedRecords = certifiedRecords
    , swNotifiers    = notifiers
    , swDisconnectNotifiers = disconnectNotifiers
    , swListeners    = listeners
    , swShutdownActions = shutdownActions
    , swConfig       = defaultSwitchConfig
    }

mkMockResourceMgr :: IO ResourceManager
mkMockResourceMgr = newResourceManager
  (DefaultLimits noLimits noLimits noLimits noLimits)

getDummyKeyPair :: IO KeyPair
getDummyKeyPair = do
  result <- generateKeyPair
  case result of
    Left err -> error $ "failed to generate test key: " ++ err
    Right kp -> pure kp

-- | A permissive validator that accepts everything.
defaultPermissiveValidator :: Validator
defaultPermissiveValidator = Validator
  { valValidate = \_ _ -> Right ()
  , valSelect   = \_ _ -> Right 0
  }

-- | Check if an Either is Left.
isLeft :: Either a b -> Bool
isLeft (Left _) = True
isLeft _        = False

-- | Check if a Maybe is Just.
isJust :: Maybe a -> Bool
isJust (Just _) = True
isJust Nothing  = False
