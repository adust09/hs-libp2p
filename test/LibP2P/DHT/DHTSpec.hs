module LibP2P.DHT.DHTSpec
  ( spec
  , mkTestNode
  , mkPeerId
  , localPid
  ) where

import Test.Hspec

import Control.Concurrent (ThreadId, myThreadId, threadDelay)
import Control.Concurrent.Async (async, concurrently, wait)
import Control.Concurrent.MVar (newEmptyMVar, putMVar, takeMVar)
import Control.Concurrent.STM
import Control.Monad (when)
import Crypto.Hash (Digest, SHA256, hash)
import Data.ByteArray (convert)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import Data.IORef (newIORef, readIORef, writeIORef)
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import Data.Time (addUTCTime, getCurrentTime)
import Data.Word (Word8)
import LibP2P.Crypto.Ed25519 (generateKeyPair)
import LibP2P.Crypto.Key (KeyPair (..), PublicKey (..), PrivateKey (..), KeyType (..))
import LibP2P.Crypto.PeerId (PeerId (..), fromPublicKey, peerIdBytes)
import LibP2P.Crypto.Protobuf (encodePublicKey)
import LibP2P.DHT
import LibP2P.DHT.Distance (peerIdToKey, sortByDistance)
import LibP2P.DHT.Message
import LibP2P.DHT.RoutingTable (allPeers, bucketForPeer, insertPeer, newRoutingTable)
import LibP2P.DHT.Types
import LibP2P.Multiaddr (Multiaddr (..), fromText, toBytes)
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.MultistreamSelect.Negotiation (StreamIO (..), mkByteStreamIO, negotiateResponder)
import LibP2P.Switch.Connection (closeConnection)
import LibP2P.Switch.ConnPool (addConn)
import LibP2P.Switch.Types
  ( ConnState (..)
  , Connection (..)
  , Direction (..)
  , MuxerSession (..)
  , Switch (..)
  , defaultConnectionGater
  )
import LibP2P.Switch.ResourceManager (ResourceManager, newResourceManager, DefaultLimits (..), noLimits)
import System.Timeout (timeout)

-- | Helper: create a PeerId from raw bytes.
mkPeerId :: BS.ByteString -> PeerId
mkPeerId = PeerId

-- | The local peer used for testing.
localPid :: PeerId
localPid = mkPeerId (BS.pack [0])

-- | Remote peer for handler tests.
remotePid :: PeerId
remotePid = mkPeerId (BS.pack [1])

-- | Create a minimal DHTNode for testing (no real Switch).
mkTestNode :: PeerId -> IO DHTNode
mkTestNode pid = do
  sw <- mkMockSwitch pid
  newDHTNode sw DHTServer

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
  pure Switch
    { swLocalPeerId  = pid
    , swIdentityKey  = dummyKeyPair
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
    }

-- | Create a mock resource manager with no limits (tests don't need resource enforcement).
mkMockResourceMgr :: IO ResourceManager
mkMockResourceMgr = newResourceManager (DefaultLimits noLimits noLimits)

-- | Independent SHA-256 (not via DHT.Distance) for asserting the spec metric.
sha256 :: BS.ByteString -> BS.ByteString
sha256 bs = convert (hash bs :: Digest SHA256)

-- | Dummy key pair for mock Switch (DHT never accesses identity key).
dummyKeyPair :: KeyPair
dummyKeyPair = KeyPair
  (PublicKey Ed25519 (BS.replicate 32 0))
  (PrivateKey Ed25519 (BS.replicate 64 0))

-- | A test multiaddr for address propagation assertions.
testAddr :: Multiaddr
testAddr = either error id (fromText "/ip4/127.0.0.1/tcp/4001")

-- | Build a valid /pk/ record: key is "/pk/" ++ peer ID multihash,
-- value is the serialized PublicKey protobuf that hashes to that ID.
mkPkRecord :: IO (BS.ByteString, BS.ByteString)
mkPkRecord = do
  ekp <- generateKeyPair
  case ekp of
    Left err -> fail ("keypair generation failed: " ++ err)
    Right kp -> do
      let pub = kpPublic kp
          pid = fromPublicKey pub
      pure (BSC.pack "/pk/" <> peerIdBytes pid, encodePublicKey pub)

-- | A bucket entry with no addresses for routing-table tests.
mkEntry :: PeerId -> IO BucketEntry
mkEntry pid = do
  now <- getCurrentTime
  pure (BucketEntry pid (peerIdToKey pid) [] now NotConnected)

-- | Peer IDs that all land in the same k-bucket (index 0) of localPid's
-- routing table, used to fill a bucket to capacity.
sameBucketPeers :: Int -> [PeerId]
sameBucketPeers n =
  let rt = newRoutingTable localPid
      candidates = [mkPeerId (BS.pack [10, i]) | i <- [0 .. 255]]
      inBucket pid = bucketForPeer (peerIdToKey pid) rt == 0
  in take n (filter inBucket candidates)

-- | Create a stream pair for testing, with close/EOF support.
-- Closing one end makes reads on the other end fail once the in-flight
-- bytes are drained, mimicking a real muxer stream reaching EOF.
mkStreamPair :: IO (StreamIO, StreamIO)
mkStreamPair = do
  q1 <- newTQueueIO :: IO (TQueue Word8)  -- A -> B
  q2 <- newTQueueIO :: IO (TQueue Word8)  -- B -> A
  closedAtoB <- newTVarIO False
  closedBtoA <- newTVarIO False
  let writeAll q bs = mapM_ (\b -> atomically (writeTQueue q b)) (BS.unpack bs)
      readOrEOF q closedVar = atomically $ do
        mb <- tryReadTQueue q
        case mb of
          Just b -> pure b
          Nothing -> do
            closed <- readTVar closedVar
            if closed then throwSTM (userError "stream closed") else retry
      streamA = mkByteStreamIO
        (writeAll q1)
        (readOrEOF q2 closedBtoA)
        (atomically (writeTVar closedAtoB True))
      streamB = mkByteStreamIO
        (writeAll q2)
        (readOrEOF q1 closedAtoB)
        (atomically (writeTVar closedBtoA True))
  pure (streamA, streamB)

-- | A mock Connection that hands out the given stream on the first
-- muxOpenStream call and counts opens; later opens fail so tests can
-- assert that the sender reuses one stream per peer.
mkMockConnection :: PeerId -> StreamIO -> TVar Int -> IO Connection
mkMockConnection pid stream openCountVar = do
  stateVar <- newTVarIO ConnOpen
  handedOut <- newTVarIO False
  let openOnce = do
        first <- atomically $ do
          done <- readTVar handedOut
          if done
            then pure False
            else do
              writeTVar handedOut True
              modifyTVar' openCountVar (+ 1)
              pure True
        if first then pure stream else fail "mock: stream already opened"
  pure Connection
    { connPeerId     = pid
    , connDirection  = Outbound
    , connLocalAddr  = testAddr
    , connRemoteAddr = testAddr
    , connSecurity   = "/noise"
    , connMuxer      = "/yamux/1.0.0"
    , connSession    = MuxerSession
        { muxOpenStream   = openOnce
        , muxAcceptStream = fail "mock: no inbound streams"
        , muxClose        = pure ()
        }
    , connState      = stateVar
    }

spec :: Spec
spec = do
  describe "handleDHTRequest" $ do
    it "FIND_NODE returns closest peers" $ do
      node <- mkTestNode localPid
      now <- getCurrentTime
      let peers = [mkPeerId (BS.pack [i]) | i <- [2..10]]
          entries = map (\pid -> BucketEntry pid (peerIdToKey pid) [] now NotConnected) peers
      atomically $ modifyTVar' (dhtRoutingTable node) $ \rt ->
        foldl (\r e -> fst (insertPeer e r)) rt entries

      (clientStream, serverStream) <- mkStreamPair
      let request = emptyDHTMessage
            { msgType = FindNode
            , msgKey = BS.pack [42, 42, 42]
            }
      writeFramedMessage clientStream request
      streamClose clientStream
      handleDHTRequest node serverStream remotePid testAddr

      result <- readFramedMessage clientStream maxDHTMessageSize
      case result of
        Right resp -> do
          msgType resp `shouldBe` FindNode
          length (msgCloserPeers resp) `shouldSatisfy` (> 0)
        Left err -> expectationFailure $ "Failed to read response: " ++ err

    it "FIND_NODE with unknown target returns whatever is closest" $ do
      node <- mkTestNode localPid
      now <- getCurrentTime
      let pid2 = mkPeerId (BS.pack [2])
          entry = BucketEntry pid2 (peerIdToKey pid2) [] now NotConnected
      atomically $ modifyTVar' (dhtRoutingTable node) $ \rt ->
        fst (insertPeer entry rt)

      (clientStream, serverStream) <- mkStreamPair
      let request = emptyDHTMessage
            { msgType = FindNode
            , msgKey = BS.pack [0xFF, 0xFF]
            }
      writeFramedMessage clientStream request
      streamClose clientStream
      handleDHTRequest node serverStream remotePid testAddr

      result <- readFramedMessage clientStream maxDHTMessageSize
      case result of
        -- Issue #173: the old assertion here was `length >= 0`, a
        -- tautology. The only entry in the table is pid2, and an unknown
        -- target must still yield it as the closest peer.
        Right resp -> map dhtPeerId (msgCloserPeers resp) `shouldBe` [peerIdBytes pid2]
        Left err -> expectationFailure $ "Failed: " ++ err

    -- Per specs/kad-dht: "the distance between two keys is
    -- XOR(sha256(key1), sha256(key2))". The wire key arrives raw and must be
    -- hashed before comparing against routing-table entries (which cache
    -- sha256 of the peer ID). Wrapping raw wire bytes in DHTKey (the old
    -- behaviour) sorts by a different, non-spec metric.
    it "FIND_NODE orders closerPeers by XOR distance over SHA-256 of the wire key" $ do
      node <- mkTestNode localPid
      now <- getCurrentTime
      let peers = [mkPeerId (BS.pack [i]) | i <- [2..10]]
          entries = map (\pid -> BucketEntry pid (peerIdToKey pid) [] now NotConnected) peers
      atomically $ modifyTVar' (dhtRoutingTable node) $ \rt ->
        foldl (\r e -> fst (insertPeer e r)) rt entries

      -- Raw wire key, as a remote peer would send it (a binary peer ID).
      let wireKey = BS.pack [42, 42, 42]
          hashedTarget = DHTKey (sha256 wireKey)
          expectedOrder = map (peerIdBytes . entryPeerId) (sortByDistance hashedTarget entries)

      (clientStream, serverStream) <- mkStreamPair
      let request = emptyDHTMessage { msgType = FindNode, msgKey = wireKey }
      writeFramedMessage clientStream request
      streamClose clientStream
      handleDHTRequest node serverStream remotePid testAddr

      result <- readFramedMessage clientStream maxDHTMessageSize
      case result of
        Right resp -> map dhtPeerId (msgCloserPeers resp) `shouldBe` expectedOrder
        Left err -> expectationFailure $ "Failed: " ++ err

    it "GET_VALUE orders closerPeers by XOR distance over SHA-256 of the wire key" $ do
      node <- mkTestNode localPid
      now <- getCurrentTime
      let peers = [mkPeerId (BS.pack [i]) | i <- [2..10]]
          entries = map (\pid -> BucketEntry pid (peerIdToKey pid) [] now NotConnected) peers
      atomically $ modifyTVar' (dhtRoutingTable node) $ \rt ->
        foldl (\r e -> fst (insertPeer e r)) rt entries

      let wireKey = BS.pack [0xCA, 0xFE, 0x01]
          hashedTarget = DHTKey (sha256 wireKey)
          expectedOrder = map (peerIdBytes . entryPeerId) (sortByDistance hashedTarget entries)

      (clientStream, serverStream) <- mkStreamPair
      let request = emptyDHTMessage { msgType = GetValue, msgKey = wireKey }
      writeFramedMessage clientStream request
      streamClose clientStream
      handleDHTRequest node serverStream remotePid testAddr

      result <- readFramedMessage clientStream maxDHTMessageSize
      case result of
        Right resp -> map dhtPeerId (msgCloserPeers resp) `shouldBe` expectedOrder
        Left err -> expectationFailure $ "Failed: " ++ err

    it "GET_PROVIDERS orders closerPeers by XOR distance over SHA-256 of the wire key" $ do
      node <- mkTestNode localPid
      now <- getCurrentTime
      let peers = [mkPeerId (BS.pack [i]) | i <- [2..10]]
          entries = map (\pid -> BucketEntry pid (peerIdToKey pid) [] now NotConnected) peers
      atomically $ modifyTVar' (dhtRoutingTable node) $ \rt ->
        foldl (\r e -> fst (insertPeer e r)) rt entries

      let wireKey = BS.pack [0xDD, 0xEE]
          hashedTarget = DHTKey (sha256 wireKey)
          expectedOrder = map (peerIdBytes . entryPeerId) (sortByDistance hashedTarget entries)

      (clientStream, serverStream) <- mkStreamPair
      let request = emptyDHTMessage { msgType = GetProviders, msgKey = wireKey }
      writeFramedMessage clientStream request
      streamClose clientStream
      handleDHTRequest node serverStream remotePid testAddr

      result <- readFramedMessage clientStream maxDHTMessageSize
      case result of
        Right resp -> map dhtPeerId (msgCloserPeers resp) `shouldBe` expectedOrder
        Left err -> expectationFailure $ "Failed: " ++ err

    it "GET_VALUE with stored record returns it" $ do
      node <- mkTestNode localPid
      let key = BS.pack [0xCA, 0xFE]
          rec = DHTRecord key (BS.pack [0xDE, 0xAD]) "2024-01-01T00:00:00Z"
      storeRecord node rec

      (clientStream, serverStream) <- mkStreamPair
      let request = emptyDHTMessage { msgType = GetValue, msgKey = key }
      writeFramedMessage clientStream request
      streamClose clientStream
      handleDHTRequest node serverStream remotePid testAddr

      result <- readFramedMessage clientStream maxDHTMessageSize
      case result of
        Right resp -> msgRecord resp `shouldBe` Just rec
        Left err -> expectationFailure $ "Failed: " ++ err

    it "GET_VALUE without record returns closerPeers only" $ do
      node <- mkTestNode localPid
      (clientStream, serverStream) <- mkStreamPair
      let request = emptyDHTMessage { msgType = GetValue, msgKey = BS.pack [1, 2, 3] }
      writeFramedMessage clientStream request
      streamClose clientStream
      handleDHTRequest node serverStream remotePid testAddr

      result <- readFramedMessage clientStream maxDHTMessageSize
      case result of
        Right resp -> do
          msgRecord resp `shouldBe` Nothing
          msgType resp `shouldBe` GetValue
        Left err -> expectationFailure $ "Failed: " ++ err

    it "PUT_VALUE stores a valid /pk/ record and stamps timeReceived" $ do
      node <- mkTestNode localPid
      (key, value) <- mkPkRecord
      let rec = DHTRecord key value "2024-06-15T12:00:00Z"

      (clientStream, serverStream) <- mkStreamPair
      let request = emptyDHTMessage
            { msgType = PutValue
            , msgKey = key
            , msgRecord = Just rec
            }
      writeFramedMessage clientStream request
      streamClose clientStream
      handleDHTRequest node serverStream remotePid testAddr
      _ <- readFramedMessage clientStream maxDHTMessageSize

      stored <- lookupRecord node key
      fmap recKey stored `shouldBe` Just key
      fmap recValue stored `shouldBe` Just value
      -- Spec: "Time the record was received, set by receiver" — the
      -- sender's claimed timestamp must be replaced, not echoed into
      -- the store.
      fmap recTimeReceived stored `shouldNotBe` Just "2024-06-15T12:00:00Z"
      fmap (T.null . recTimeReceived) stored `shouldBe` Just False

    it "ADD_PROVIDER rejects mismatched sender" $ do
      node <- mkTestNode localPid
      let key = BS.pack [0xAA]
          fakePeer = DHTPeer (BS.pack [99, 99]) [] Connected

      (clientStream, serverStream) <- mkStreamPair
      let request = emptyDHTMessage
            { msgType = AddProvider
            , msgKey = key
            , msgProviderPeers = [fakePeer]
            }
      writeFramedMessage clientStream request
      streamClose clientStream
      handleDHTRequest node serverStream remotePid testAddr

      result <- readFramedMessage clientStream maxDHTMessageSize
      case result of
        Right resp -> msgType resp `shouldBe` AddProvider
        Left err -> expectationFailure $ "Failed: " ++ err

      -- Mismatched provider must NOT be stored
      stored <- getProviders node key
      stored `shouldBe` []

    it "ADD_PROVIDER with valid sender persists provider record" $ do
      node <- mkTestNode localPid
      let key = BS.pack [0xAA, 0xBB]
          -- remotePid has raw bytes [1], so dhtPeerId must match
          validPeer = DHTPeer (peerIdBytes remotePid) [] Connected

      (clientStream, serverStream) <- mkStreamPair
      let request = emptyDHTMessage
            { msgType = AddProvider
            , msgKey = key
            , msgProviderPeers = [validPeer]
            }
      writeFramedMessage clientStream request
      streamClose clientStream
      handleDHTRequest node serverStream remotePid testAddr

      result <- readFramedMessage clientStream maxDHTMessageSize
      case result of
        Right resp -> msgType resp `shouldBe` AddProvider
        Left err -> expectationFailure $ "Failed: " ++ err

      -- Provider should now be persisted
      stored <- getProviders node key
      length stored `shouldBe` 1
      peProvider (head stored) `shouldBe` remotePid

    it "ADD_PROVIDER round-trip via GET_PROVIDERS" $ do
      node <- mkTestNode localPid
      let key = BS.pack [0xCC, 0xDD]
          validPeer = DHTPeer (peerIdBytes remotePid) [] Connected

      -- Send ADD_PROVIDER
      (clientStream1, serverStream1) <- mkStreamPair
      let addReq = emptyDHTMessage
            { msgType = AddProvider
            , msgKey = key
            , msgProviderPeers = [validPeer]
            }
      writeFramedMessage clientStream1 addReq
      streamClose clientStream1
      handleDHTRequest node serverStream1 remotePid testAddr
      _ <- readFramedMessage clientStream1 maxDHTMessageSize

      -- Send GET_PROVIDERS for the same key
      (clientStream2, serverStream2) <- mkStreamPair
      let getReq = emptyDHTMessage
            { msgType = GetProviders
            , msgKey = key
            }
      writeFramedMessage clientStream2 getReq
      streamClose clientStream2
      handleDHTRequest node serverStream2 remotePid testAddr

      result <- readFramedMessage clientStream2 maxDHTMessageSize
      case result of
        Right resp -> do
          msgType resp `shouldBe` GetProviders
          length (msgProviderPeers resp) `shouldBe` 1
          dhtPeerId (head (msgProviderPeers resp)) `shouldBe` peerIdBytes remotePid
        Left err -> expectationFailure $ "Failed: " ++ err

    -- Issue #147: specs/kad-dht requires handling additional RPC request
    -- messages on the same inbound stream — go-libp2p keeps one long-lived
    -- stream per peer and pipelines requests over it.
    it "serves multiple consecutive requests on a single stream" $ do
      node <- mkTestNode localPid
      let key = BS.pack [0xCA, 0xFE]
          rec = DHTRecord key (BS.pack [0xDE, 0xAD]) "2024-01-01T00:00:00Z"
      storeRecord node rec

      (clientStream, serverStream) <- mkStreamPair
      handler <- async (handleDHTRequest node serverStream remotePid testAddr)

      writeFramedMessage clientStream
        (emptyDHTMessage { msgType = FindNode, msgKey = BS.pack [1] })
      r1 <- timeout 2000000 (readFramedMessage clientStream maxDHTMessageSize)
      case r1 of
        Just (Right resp) -> msgType resp `shouldBe` FindNode
        _ -> expectationFailure "no response to first request"

      writeFramedMessage clientStream
        (emptyDHTMessage { msgType = GetValue, msgKey = key })
      r2 <- timeout 2000000 (readFramedMessage clientStream maxDHTMessageSize)
      case r2 of
        Just (Right resp) -> msgRecord resp `shouldBe` Just rec
        _ -> expectationFailure
               "handler did not serve a second request on the same stream"

      streamClose clientStream
      wait handler

    -- Issue #147: Peer records must carry the peer's known multiaddrs so
    -- the requester can dial them (go-libp2p filters address-less peers).
    it "FIND_NODE returns closerPeers with their known multiaddrs" $ do
      node <- mkTestNode localPid
      now <- getCurrentTime
      let pid2 = mkPeerId (BS.pack [2])
          entry = BucketEntry pid2 (peerIdToKey pid2) [testAddr] now Connected
      atomically $ modifyTVar' (dhtRoutingTable node) $ \rt ->
        fst (insertPeer entry rt)

      (clientStream, serverStream) <- mkStreamPair
      let request = emptyDHTMessage { msgType = FindNode, msgKey = BS.pack [42] }
      writeFramedMessage clientStream request
      streamClose clientStream
      handleDHTRequest node serverStream remotePid testAddr

      result <- readFramedMessage clientStream maxDHTMessageSize
      case result of
        Right resp -> map dhtPeerAddrs (msgCloserPeers resp)
                        `shouldBe` [[toBytes testAddr]]
        Left err -> expectationFailure $ "Failed: " ++ err

    it "GET_PROVIDERS returns provider peers with their multiaddrs" $ do
      node <- mkTestNode localPid
      now <- getCurrentTime
      let key = BS.pack [0xAB]
      addProvider node key (ProviderEntry (mkPeerId (BS.pack [7])) [testAddr] now)

      (clientStream, serverStream) <- mkStreamPair
      let request = emptyDHTMessage { msgType = GetProviders, msgKey = key }
      writeFramedMessage clientStream request
      streamClose clientStream
      handleDHTRequest node serverStream remotePid testAddr

      result <- readFramedMessage clientStream maxDHTMessageSize
      case result of
        Right resp -> map dhtPeerAddrs (msgProviderPeers resp)
                        `shouldBe` [[toBytes testAddr]]
        Left err -> expectationFailure $ "Failed: " ++ err

    it "ADD_PROVIDER decodes provider multiaddrs into the provider store" $ do
      node <- mkTestNode localPid
      let key = BS.pack [0xAA, 0xCC]
          validPeer = DHTPeer (peerIdBytes remotePid) [toBytes testAddr] Connected

      (clientStream, serverStream) <- mkStreamPair
      let request = emptyDHTMessage
            { msgType = AddProvider
            , msgKey = key
            , msgProviderPeers = [validPeer]
            }
      writeFramedMessage clientStream request
      streamClose clientStream
      handleDHTRequest node serverStream remotePid testAddr

      stored <- getProviders node key
      map peAddrs stored `shouldBe` [[testAddr]]

    it "registerDHTHandler registers protocol on Switch" $ do
      node <- mkTestNode localPid
      registerDHTHandler node
      protos <- readTVarIO (swProtocols (dhtSwitch node))
      Map.member dhtProtocolId protos `shouldBe` True

  -- Issue #168: newDHTNode must wire an outbound sender that opens a
  -- /ipfs/kad/1.0.0 stream via the Switch. Previously the default sender
  -- was a permanent failure and only a test mock ever assigned the field.
  describe "dhtSendRequest (production wiring)" $ do
    it "opens a stream via the Switch, negotiates the protocol, and exchanges framed messages, reusing the stream" $ do
      clientNode <- mkTestNode localPid
      serverNode <- mkTestNode remotePid
      (clientEnd, serverEnd) <- mkStreamPair
      openCountVar <- newTVarIO (0 :: Int)
      conn <- mkMockConnection remotePid clientEnd openCountVar
      atomically $ addConn (swConnPool (dhtSwitch clientNode)) conn

      -- Remote side: multistream-select responder, then the DHT handler.
      server <- async $ do
        _ <- negotiateResponder serverEnd [dhtProtocolId]
        handleDHTRequest serverNode serverEnd localPid testAddr

      let req1 = emptyDHTMessage { msgType = FindNode, msgKey = BS.pack [42] }
      r1 <- timeout 2000000 (dhtSendRequest clientNode remotePid req1)
      case r1 of
        Just (Right resp) -> msgType resp `shouldBe` FindNode
        Just (Left err) -> expectationFailure $ "send failed: " ++ err
        Nothing -> expectationFailure "send timed out"

      -- A second request must reuse the cached stream: the mock connection
      -- only allows a single muxOpenStream call.
      let key = BS.pack [0xCA]
          rec = DHTRecord key (BS.pack [1]) "2024-01-01T00:00:00Z"
      storeRecord serverNode rec
      let req2 = emptyDHTMessage { msgType = GetValue, msgKey = key }
      r2 <- timeout 2000000 (dhtSendRequest clientNode remotePid req2)
      case r2 of
        Just (Right resp) -> msgRecord resp `shouldBe` Just rec
        Just (Left err) -> expectationFailure $ "second send failed: " ++ err
        Nothing -> expectationFailure "second send timed out"

      opens <- readTVarIO openCountVar
      opens `shouldBe` 1

      streamClose clientEnd
      wait server

    it "fails with Left when there is no connection to the peer" $ do
      node <- mkTestNode localPid
      let request = emptyDHTMessage { msgType = FindNode, msgKey = BS.pack [1] }
      result <- dhtSendRequest node (mkPeerId (BS.pack [9])) request
      case result of
        Left _ -> pure ()
        Right _ -> expectationFailure "expected failure without a connection"

  -- Issue #253: Kademlia RPC messages carry no request identifier, so
  -- two exchanges interleaved on one cached stream cannot be
  -- reassociated afterwards. The full write + read exchange must be
  -- serialized per peer, and only per peer.
  describe "cached stream exchange serialization" $ do
    it "gives each concurrent caller the response to its own request over a shared cached stream" $ do
      sw <- mkMockSwitch localPid
      node <- newDHTNode sw DHTServer
      stream <- mkCrossingProbeStream
      session <- newPeerSession (Just stream)
      atomically $ writeTVar (dhtStreams node) (Map.singleton remotePid session)
      let ask key = dhtSendRequest node remotePid (probeRequest key)
      outcome <- timeout 5000000 $
        concurrently (ask (BSC.pack "key-a")) (ask (BSC.pack "key-b"))
      case outcome of
        Nothing -> expectationFailure "concurrent exchanges deadlocked"
        Just (ra, rb) -> do
          fmap msgKey ra `shouldBe` Right (BSC.pack "key-a")
          fmap msgKey rb `shouldBe` Right (BSC.pack "key-b")

    it "keeps exchanges with different peers concurrent" $ do
      sw <- mkMockSwitch localPid
      node <- newDHTNode sw DHTServer
      -- Each stream refuses to answer until both peers have been written
      -- to, so a lock any coarser than per-peer cannot make progress.
      arrived <- newTVarIO (0 :: Int)
      streamA <- mkRendezvousStream arrived
      streamB <- mkRendezvousStream arrived
      sessionA <- newPeerSession (Just streamA)
      sessionB <- newPeerSession (Just streamB)
      atomically $ writeTVar (dhtStreams node) $
        Map.fromList [(remotePid, sessionA), (thirdPid, sessionB)]
      let ask peer key = dhtSendRequest node peer (probeRequest key)
      outcome <- timeout 2000000 $
        concurrently (ask remotePid (BSC.pack "key-a")) (ask thirdPid (BSC.pack "key-b"))
      case outcome of
        Nothing -> expectationFailure "exchanges with distinct peers were serialized against each other"
        Just (ra, rb) -> do
          fmap msgKey ra `shouldBe` Right (BSC.pack "key-a")
          fmap msgKey rb `shouldBe` Right (BSC.pack "key-b")

  -- Issue #279: a cached session must not outlive the peer's last
  -- connection, and an in-flight exchange must not resurrect it.
  describe "cached session disconnect" $ do
    it "removes the session and closes its stream after the last connection closes" $ do
      node <- mkTestNode localPid
      closed <- newIORef False
      (stream, _) <- mkStreamPair
      let tracked = stream { streamClose = writeIORef closed True >> streamClose stream }
      session <- newPeerSession (Just tracked)
      atomically $ writeTVar (dhtStreams node) (Map.singleton remotePid session)
      openCountVar <- newTVarIO (0 :: Int)
      conn <- mkMockConnection remotePid tracked openCountVar
      atomically $ addConn (swConnPool (dhtSwitch node)) conn
      closeConnection (dhtSwitch node) conn
      sessions <- readTVarIO (dhtStreams node)
      Map.member remotePid sessions `shouldBe` False
      readIORef closed `shouldReturn` True

    it "keeps the session when a second connection to the peer remains" $ do
      node <- mkTestNode localPid
      closed <- newIORef False
      (stream, _) <- mkStreamPair
      let tracked = stream { streamClose = writeIORef closed True >> streamClose stream }
      session <- newPeerSession (Just tracked)
      atomically $ writeTVar (dhtStreams node) (Map.singleton remotePid session)
      openCountVar <- newTVarIO (0 :: Int)
      conn1 <- mkMockConnection remotePid tracked openCountVar
      conn2 <- mkMockConnection remotePid tracked openCountVar
      atomically $ do
        addConn (swConnPool (dhtSwitch node)) conn1
        addConn (swConnPool (dhtSwitch node)) conn2
      closeConnection (dhtSwitch node) conn1
      sessionsAfterFirst <- readTVarIO (dhtStreams node)
      Map.member remotePid sessionsAfterFirst `shouldBe` True
      readIORef closed `shouldReturn` False
      closeConnection (dhtSwitch node) conn2
      sessionsAfterLast <- readTVarIO (dhtStreams node)
      Map.member remotePid sessionsAfterLast `shouldBe` False
      readIORef closed `shouldReturn` True

    it "does not resurrect a session removed during an in-flight exchange" $ do
      node <- mkTestNode localPid
      closed <- newIORef False
      (clientEnd, serverEnd) <- mkStreamPair
      let tracked = clientEnd { streamClose = writeIORef closed True >> streamClose clientEnd }
          -- Session teardown fails both directions, like muxClose on a
          -- real Yamux session; half-closing only the local end would
          -- leave the in-flight read blocked.
          killSession = streamClose tracked >> streamClose serverEnd
      session <- newPeerSession (Just tracked)
      atomically $ writeTVar (dhtStreams node) (Map.singleton remotePid session)
      openCountVar <- newTVarIO (0 :: Int)
      conn <- mkMockConnection remotePid tracked openCountVar
      let conn' = conn { connSession = (connSession conn) { muxClose = killSession } }
      atomically $ addConn (swConnPool (dhtSwitch node)) conn'
      started <- newEmptyMVar
      done <- async $ do
        putMVar started ()
        dhtSendRequest node remotePid (emptyDHTMessage { msgType = FindNode, msgKey = BS.pack [1] })
      takeMVar started
      threadDelay 50000
      closeConnection (dhtSwitch node) conn'
      outcome <- timeout 2000000 (wait done)
      case outcome of
        Nothing -> expectationFailure "in-flight exchange did not finish after disconnect"
        Just result -> result `shouldSatisfy` either (const True) (const False)
      sessions <- readTVarIO (dhtStreams node)
      Map.member remotePid sessions `shouldBe` False
      readIORef closed `shouldReturn` True

    it "does not drop a session after stopDHTNode deregisters the notifier" $ do
      node <- mkTestNode localPid
      stopDHTNode node
      (stream, _) <- mkStreamPair
      session <- newPeerSession (Just stream)
      atomically $ writeTVar (dhtStreams node) (Map.singleton remotePid session)
      openCountVar <- newTVarIO (0 :: Int)
      conn <- mkMockConnection remotePid stream openCountVar
      atomically $ addConn (swConnPool (dhtSwitch node)) conn
      closeConnection (dhtSwitch node) conn
      sessions <- readTVarIO (dhtStreams node)
      Map.member remotePid sessions `shouldBe` True

  describe "Store operations" $ do
    it "storeRecord + lookupRecord round-trip" $ do
      node <- mkTestNode localPid
      let key = BS.pack [1, 2, 3]
          rec = DHTRecord key (BS.pack [4, 5, 6]) "2024-01-01T00:00:00Z"
      storeRecord node rec
      result <- lookupRecord node key
      result `shouldBe` Just rec

    it "lookupRecord for missing key returns Nothing" $ do
      node <- mkTestNode localPid
      result <- lookupRecord node (BS.pack [99])
      result `shouldBe` Nothing

    it "addProvider + getProviders round-trip" $ do
      node <- mkTestNode localPid
      now <- getCurrentTime
      let key = BS.pack [0xAA, 0xBB]
          provider = ProviderEntry (mkPeerId (BS.pack [5])) [] now
      addProvider node key provider
      result <- getProviders node key
      length result `shouldBe` 1

    it "getProviders for missing key returns []" $ do
      node <- mkTestNode localPid
      result <- getProviders node (BS.pack [0xFF])
      result `shouldBe` []

  -- Issue #148 (1): PUT_VALUE must validate records before storing them.
  describe "PUT_VALUE validation" $ do
    it "rejects a record under an unregistered namespace" $ do
      node <- mkTestNode localPid
      let key = BS.pack [0xBE, 0xEF]
          rec = DHTRecord key (BS.pack [1, 2, 3]) ""

      (clientStream, serverStream) <- mkStreamPair
      let request = emptyDHTMessage
            { msgType = PutValue, msgKey = key, msgRecord = Just rec }
      writeFramedMessage clientStream request
      streamClose clientStream
      handleDHTRequest node serverStream remotePid testAddr
      resp <- readFramedMessage clientStream maxDHTMessageSize

      stored <- lookupRecord node key
      stored `shouldBe` Nothing
      -- The rejected record must not be echoed back as accepted.
      fmap msgRecord resp `shouldBe` Right Nothing

    it "rejects a /pk/ record bound to a different peer" $ do
      node <- mkTestNode localPid
      (_, value) <- mkPkRecord
      (otherKey, _) <- mkPkRecord
      let rec = DHTRecord otherKey value ""

      (clientStream, serverStream) <- mkStreamPair
      let request = emptyDHTMessage
            { msgType = PutValue, msgKey = otherKey, msgRecord = Just rec }
      writeFramedMessage clientStream request
      streamClose clientStream
      handleDHTRequest node serverStream remotePid testAddr
      _ <- readFramedMessage clientStream maxDHTMessageSize

      stored <- lookupRecord node otherKey
      stored `shouldBe` Nothing

    it "rejects a record whose embedded key differs from the message key" $ do
      node <- mkTestNode localPid
      (key, value) <- mkPkRecord
      (msgOnlyKey, _) <- mkPkRecord
      let rec = DHTRecord key value ""

      (clientStream, serverStream) <- mkStreamPair
      let request = emptyDHTMessage
            { msgType = PutValue, msgKey = msgOnlyKey, msgRecord = Just rec }
      writeFramedMessage clientStream request
      streamClose clientStream
      handleDHTRequest node serverStream remotePid testAddr
      _ <- readFramedMessage clientStream maxDHTMessageSize

      storedUnderMsgKey <- lookupRecord node msgOnlyKey
      storedUnderRecKey <- lookupRecord node key
      storedUnderMsgKey `shouldBe` Nothing
      storedUnderRecKey `shouldBe` Nothing

  -- Issue #148 (5): provider records must expire after the 48h TTL and
  -- must not duplicate when a provider republishes.
  describe "provider TTL" $ do
    it "getProviders drops entries older than the provider TTL" $ do
      node <- mkTestNode localPid
      now <- getCurrentTime
      let key = BS.pack [0xAA]
          stalePid = mkPeerId (BS.pack [5])
          freshPid = mkPeerId (BS.pack [6])
          stale = ProviderEntry stalePid [] (addUTCTime (negate (49 * 3600)) now)
          fresh = ProviderEntry freshPid [] now
      addProvider node key stale
      addProvider node key fresh
      result <- getProviders node key
      map peProvider result `shouldBe` [freshPid]

    it "GET_PROVIDERS omits expired providers" $ do
      node <- mkTestNode localPid
      now <- getCurrentTime
      let key = BS.pack [0xAB]
          stale = ProviderEntry (mkPeerId (BS.pack [5])) []
                    (addUTCTime (negate (49 * 3600)) now)
      addProvider node key stale

      (clientStream, serverStream) <- mkStreamPair
      let request = emptyDHTMessage { msgType = GetProviders, msgKey = key }
      writeFramedMessage clientStream request
      streamClose clientStream
      handleDHTRequest node serverStream remotePid testAddr
      resp <- readFramedMessage clientStream maxDHTMessageSize
      fmap msgProviderPeers resp `shouldBe` Right []

    it "addProvider replaces an existing entry for the same provider" $ do
      node <- mkTestNode localPid
      now <- getCurrentTime
      let key = BS.pack [0xAC]
          pid = mkPeerId (BS.pack [7])
          older = ProviderEntry pid [] (addUTCTime (negate 60) now)
          newer = ProviderEntry pid [] now
      addProvider node key older
      addProvider node key newer
      result <- getProviders node key
      result `shouldBe` [newer]

  -- Issue #148 (4, 6): the routing table must grow from observed peers,
  -- with the LRS ping-or-drop policy when a bucket is full.
  describe "routing-table growth" $ do
    it "an inbound request adds the sender to the routing table" $ do
      node <- mkTestNode localPid
      (clientStream, serverStream) <- mkStreamPair
      let request = emptyDHTMessage { msgType = FindNode, msgKey = BS.pack [7] }
      writeFramedMessage clientStream request
      streamClose clientStream
      handleDHTRequest node serverStream remotePid testAddr
      rt <- readTVarIO (dhtRoutingTable node)
      map entryPeerId (allPeers rt) `shouldContain` [remotePid]

    -- Issue #284: the sender must be stored with the authenticated
    -- connection address, and a later FIND_NODE must hand that address
    -- out. A relayed or non-IP remote address must not replace a richer
    -- list already in the table.
    it "stores the sender with the connection address" $ do
      node <- mkTestNode localPid
      (clientStream, serverStream) <- mkStreamPair
      writeFramedMessage clientStream
        (emptyDHTMessage { msgType = FindNode, msgKey = BS.pack [7] })
      streamClose clientStream
      handleDHTRequest node serverStream remotePid testAddr
      rt <- readTVarIO (dhtRoutingTable node)
      let sender = [e | e <- allPeers rt, entryPeerId e == remotePid]
      map entryAddrs sender `shouldBe` [[testAddr]]

    it "includes that address in a subsequent FIND_NODE response" $ do
      node <- mkTestNode localPid
      (seedClient, seedServer) <- mkStreamPair
      writeFramedMessage seedClient
        (emptyDHTMessage { msgType = FindNode, msgKey = BS.pack [1] })
      streamClose seedClient
      handleDHTRequest node seedServer remotePid testAddr

      (clientStream, serverStream) <- mkStreamPair
      writeFramedMessage clientStream
        (emptyDHTMessage { msgType = FindNode, msgKey = peerIdBytes remotePid })
      streamClose clientStream
      handleDHTRequest node serverStream remotePid testAddr
      result <- readFramedMessage clientStream maxDHTMessageSize
      case result of
        Left err -> expectationFailure $ "Failed to read response: " ++ err
        Right resp -> do
          let mine = filter (\p -> dhtPeerId p == peerIdBytes remotePid) (msgCloserPeers resp)
          map dhtPeerAddrs mine `shouldBe` [[toBytes testAddr]]

    it "does not reduce a richer address list to the connection address" $ do
      node <- mkTestNode localPid
      now <- getCurrentTime
      let extra = Multiaddr [IP4 0x0A000008, TCP 4001]
          entry = BucketEntry remotePid (peerIdToKey remotePid) [extra, testAddr] now NotConnected
      atomically $ modifyTVar' (dhtRoutingTable node) $ \rt -> fst (insertPeer entry rt)
      (clientStream, serverStream) <- mkStreamPair
      writeFramedMessage clientStream
        (emptyDHTMessage { msgType = FindNode, msgKey = BS.pack [9] })
      streamClose clientStream
      handleDHTRequest node serverStream remotePid testAddr
      rt <- readTVarIO (dhtRoutingTable node)
      let sender = [e | e <- allPeers rt, entryPeerId e == remotePid]
      map entryAddrs sender `shouldBe` [[extra, testAddr]]

    it "does not store a relayed or non-IP connection address" $ do
      node <- mkTestNode localPid
      now <- getCurrentTime
      let extra = Multiaddr [IP4 0x0A000008, TCP 4001]
          relayed = Multiaddr [IP4 0xCB007101, TCP 4001, P2P (BS.pack [1, 2, 3]), P2PCircuit]
          emptyAddr = Multiaddr []
          entry = BucketEntry remotePid (peerIdToKey remotePid) [extra] now NotConnected
      atomically $ modifyTVar' (dhtRoutingTable node) $ \rt -> fst (insertPeer entry rt)
      (clientStream, serverStream) <- mkStreamPair
      writeFramedMessage clientStream
        (emptyDHTMessage { msgType = FindNode, msgKey = BS.pack [3] })
      streamClose clientStream
      handleDHTRequest node serverStream remotePid relayed
      (clientStream2, serverStream2) <- mkStreamPair
      writeFramedMessage clientStream2
        (emptyDHTMessage { msgType = FindNode, msgKey = BS.pack [4] })
      streamClose clientStream2
      handleDHTRequest node serverStream2 remotePid emptyAddr
      rt <- readTVarIO (dhtRoutingTable node)
      let sender = [e | e <- allPeers rt, entryPeerId e == remotePid]
      map entryAddrs sender `shouldBe` [[extra]]

    it "does not store a relayed address for a previously unknown sender" $ do
      node <- mkTestNode localPid
      let relayed = Multiaddr [IP4 0xCB007101, TCP 4001, P2P (BS.pack [1, 2, 3]), P2PCircuit]
      (clientStream, serverStream) <- mkStreamPair
      writeFramedMessage clientStream
        (emptyDHTMessage { msgType = FindNode, msgKey = BS.pack [5] })
      streamClose clientStream
      handleDHTRequest node serverStream remotePid relayed
      rt <- readTVarIO (dhtRoutingTable node)
      let sender = [e | e <- allPeers rt, entryPeerId e == remotePid]
      map entryAddrs sender `shouldBe` [[]]

    it "addPeerToTable evicts an unresponsive LRS peer from a full bucket" $ do
      node0 <- mkTestNode localPid
      let node = node0 { dhtSendRequest = \_ _ -> pure (Left "unreachable") }
          bucketPeers = sameBucketPeers (kValue + 1)
          initial = take kValue bucketPeers
          newcomer = last bucketPeers
          lrs = head initial
      mapM_ (\pid -> do
               e <- mkEntry pid
               atomically $ modifyTVar' (dhtRoutingTable node) (fst . insertPeer e))
            initial
      entry <- mkEntry newcomer
      result <- addPeerToTable node entry
      result `shouldBe` Inserted
      rt <- readTVarIO (dhtRoutingTable node)
      let pids = map entryPeerId (allPeers rt)
      pids `shouldContain` [newcomer]
      pids `shouldNotContain` [lrs]

    it "addPeerToTable keeps a responsive LRS peer and drops the newcomer" $ do
      node0 <- mkTestNode localPid
      let node = node0
            { dhtSendRequest = \_ _ ->
                pure (Right (emptyDHTMessage { msgType = FindNode })) }
          bucketPeers = sameBucketPeers (kValue + 1)
          initial = take kValue bucketPeers
          newcomer = last bucketPeers
          lrs = head initial
      mapM_ (\pid -> do
               e <- mkEntry pid
               atomically $ modifyTVar' (dhtRoutingTable node) (fst . insertPeer e))
            initial
      entry <- mkEntry newcomer
      result <- addPeerToTable node entry
      result `shouldBe` BucketFull lrs
      rt <- readTVarIO (dhtRoutingTable node)
      let pids = map entryPeerId (allPeers rt)
      pids `shouldContain` [lrs]
      pids `shouldNotContain` [newcomer]

  -- Issue #148 (3): client-mode nodes must not offer the Kademlia
  -- protocol for incoming streams.
  describe "client/server mode" $ do
    it "registerDHTHandler is a no-op for a client-mode node" $ do
      sw <- mkMockSwitch localPid
      node <- newDHTNode sw DHTClient
      registerDHTHandler node
      protos <- readTVarIO (swProtocols sw)
      Map.member dhtProtocolId protos `shouldBe` False

    it "registerDHTHandler registers the protocol for a server-mode node" $ do
      sw <- mkMockSwitch localPid
      node <- newDHTNode sw DHTServer
      registerDHTHandler node
      protos <- readTVarIO (swProtocols sw)
      Map.member dhtProtocolId protos `shouldBe` True

-- | Third peer, for asserting that serialization stays per peer.
thirdPid :: PeerId
thirdPid = mkPeerId (BS.pack [2])

-- | Request/response pair used by the cached-stream probes: the response
-- echoes the request key, so a caller can tell its own response from
-- somebody else\'s.
probeRequest :: BS.ByteString -> DHTMessage
probeRequest key = emptyDHTMessage { msgType = GetValue, msgKey = key }

probeResponse :: BS.ByteString -> BS.ByteString
probeResponse key = encodeFramed (emptyDHTMessage { msgType = GetValue, msgKey = key })

-- | Size of one framed probe response. All probe keys have the same
-- length, so this is how many bytes a caller consumes for a full reply.
probeResponseSize :: Int
probeResponseSize = BS.length (probeResponse (BSC.pack "key-a"))

-- | How long the first caller is held at its first read waiting for a
-- second caller to overtake it. Serialized, nobody can, and this is
-- simply the (one-off) cost of the test.
crossingBarrierMicros :: Int
crossingBarrierMicros = 200000

-- | A mock cached DHT stream that reproduces the response-crossing
-- window deterministically.
--
-- Responses queue on one shared FIFO, exactly as they do on a real
-- stream. The first caller to write is then held at its first read until
-- a second caller has consumed a whole response, which is the only
-- ordering that crosses the two replies. Serialized, the second caller
-- cannot reach the stream at all, the barrier expires, and each caller
-- reads its own response.
mkCrossingProbeStream :: IO StreamIO
mkCrossingProbeStream = do
  wire     <- newTVarIO BS.empty
  roles    <- newTVarIO (Map.empty :: Map.Map ThreadId Int)
  consumed <- newTVarIO (Map.empty :: Map.Map ThreadId Int)
  overtaken <- newTVarIO False
  let write bs = do
        tid <- myThreadId
        reply <- either (fail . ("probe got an undecodable request: " ++)) (pure . probeResponse . msgKey)
                   (decodeFramed maxDHTMessageSize bs)
        atomically $ do
          assigned <- readTVar roles
          writeTVar roles (Map.insertWith (\_ old -> old) tid (Map.size assigned) assigned)
          modifyTVar' wire (<> reply)

      readByte = do
        tid <- myThreadId
        (role, alreadyRead) <- atomically $ do
          r <- Map.findWithDefault 0 tid <$> readTVar roles
          c <- Map.findWithDefault 0 tid <$> readTVar consumed
          pure (r, c)
        when (role == 0 && alreadyRead == 0) $ do
          expired <- registerDelay crossingBarrierMicros
          atomically $ do
            crossed <- readTVar overtaken
            timedOut <- readTVar expired
            check (crossed || timedOut)
        atomically $ do
          buf <- readTVar wire
          check (not (BS.null buf))
          writeTVar wire (BS.drop 1 buf)
          let taken = alreadyRead + 1
          modifyTVar' consumed (Map.insert tid taken)
          when (role /= 0 && taken >= probeResponseSize) $ writeTVar overtaken True
          pure (BS.head buf)

  pure (mkByteStreamIO write readByte (pure ()))

-- | A mock cached DHT stream that answers only once @arrived@ reports
-- that every participating peer has been written to.
mkRendezvousStream :: TVar Int -> IO StreamIO
mkRendezvousStream arrived = do
  wire <- newTVarIO BS.empty
  let write bs = do
        reply <- either (fail . ("rendezvous got an undecodable request: " ++)) (pure . probeResponse . msgKey)
                   (decodeFramed maxDHTMessageSize bs)
        atomically $ do
          modifyTVar' wire (<> reply)
          modifyTVar' arrived (+ 1)

      readByte = atomically $ do
        both <- readTVar arrived
        check (both >= 2)
        buf <- readTVar wire
        check (not (BS.null buf))
        writeTVar wire (BS.drop 1 buf)
        pure (BS.head buf)

  pure (mkByteStreamIO write readByte (pure ()))
