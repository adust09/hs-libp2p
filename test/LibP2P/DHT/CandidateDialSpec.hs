module LibP2P.DHT.CandidateDialSpec (spec) where

import Control.Concurrent.Async (mapConcurrently, wait, withAsync)
import Control.Concurrent.STM
import Control.Exception (bracket, bracketOnError, finally)
import Control.Monad (void, when)
import qualified Data.ByteString as BS
import Data.Either (isLeft)
import qualified Data.Map.Strict as Map
import Data.Maybe (isJust, isNothing)
import Data.Time (getCurrentTime)
import LibP2P.Crypto.Ed25519 (generateKeyPair)
import LibP2P.Crypto.Key (publicKey)
import LibP2P.Crypto.PeerId (PeerId, fromPublicKey, peerIdBytes)
import LibP2P.Crypto.Protobuf (encodePublicKey)
import LibP2P.DHT
import LibP2P.DHT.API (findPeer, findProviders, getValue)
import LibP2P.DHT.Distance (peerIdToKey)
import LibP2P.DHT.Message
import LibP2P.DHT.RoutingTable (insertPeer, removePeer)
import LibP2P.DHT.Types
import LibP2P.Multiaddr (Multiaddr (..), toBytes)
import LibP2P.MultistreamSelect.Negotiation (StreamIO (..))
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.Protocol.Identify.Message (IdentifyInfo (..))
import LibP2P.Switch (addTransport, newSwitch, setConnectionGater, setStreamHandler, switchClose)
import LibP2P.Switch.ConnPool (lookupConn)
import LibP2P.Switch.Dial (dial)
import LibP2P.Switch.Listen (switchListen)
import LibP2P.Switch.Types (Connection (..), ConnectionGater (..), Switch (..), defaultConnectionGater)
import LibP2P.Switch.ResourceManager (ResourceScope (..), ResourceUsage (..))
import LibP2P.Transport (Transport (..))
import LibP2P.Transport.TCP (newTCPTransport)
import System.Timeout (timeout)
import Test.Hspec

data TestNode = TestNode
  { tnDHT :: DHTNode
  , tnAddress :: Multiaddr
  , tnRecord :: DHTRecord
  }

spec :: Spec
spec = describe "DHT candidate dialing over TCP" $ do
  valueLookupSpec
  addressLookupSpec
  addressBoundSpec
  admissionSpec
  ownershipSpec
  cancellationSpec

valueLookupSpec :: Spec
valueLookupSpec = do
  it "should retrieve a record through B when A has never connected to C" $
    withTopology $ \a _ c -> do
      connectedTo a c `shouldReturn` False
      storeRecord (tnDHT c) (tnRecord c)
      result <- within $ getValue (tnDHT a) pkValidator (recKey (tnRecord c))
      fmap recValue result `shouldBe` Right (recValue (tnRecord c))
      connectedTo a c `shouldReturn` True

  it "should query a discovered FIND_NODE candidate before returning it" $
    withTopology $ \a _ c -> do
      result <- within $ findPeer (tnDHT a) (peer c)
      map entryPeerId result `shouldContain` [peer c]
      connectedTo a c `shouldReturn` True

  it "should retrieve providers by dialing a GET_PROVIDERS candidate" $
    withTopology $ \a _ c -> do
      now <- getCurrentTime
      addProvider (tnDHT c) contentKey (ProviderEntry (peer c) [tnAddress c] now)
      result <- within $ findProviders (tnDHT a) contentKey
      map peProvider result `shouldContain` [peer c]
      connectedTo a c `shouldReturn` True

addressLookupSpec :: Spec
addressLookupSpec = do
  it "should use peer-store addresses when a direct RPC has no connection or routing entry" $
    withTopology $ \a _ c -> do
      let info = IdentifyInfo Nothing Nothing Nothing [toBytes (tnAddress c)] Nothing [] Nothing
      atomically $ modifyTVar' (swPeerStore (switch a)) (Map.insert (peer c) info)
      result <- within $ dhtSendRequest (tnDHT a) (peer c)
        (emptyDHTMessage { msgType = FindNode, msgKey = peerIdBytes (peer a) })
      fmap msgType result `shouldBe` Right FindNode
      connectedTo a c `shouldReturn` True

  it "should retain a learned address when the candidate leaves the routing table before its RPC" $
    withTopology $ \a _ c -> do
      let node = tnDHT a
          sender pid message = do
            when (pid == peer c) $ atomically $
              modifyTVar' (dhtRoutingTable node) (removePeer pid)
            dhtSendRequest node pid message
      result <- within $ findPeer (node { dhtSendRequest = sender }) (peer c)
      map entryPeerId result `shouldContain` [peer c]
      connectedTo a c `shouldReturn` True

addressBoundSpec :: Spec
addressBoundSpec =
  it "should bound cached third-party addresses while retaining a usable candidate address" $
    withTopology $ \a b c -> do
      now <- getCurrentTime
      let addresses = tnAddress c : [Multiaddr [IP4 0x7f000001, TCP port] | port <- [1 .. 100]]
          entry = BucketEntry (peer c) (peerIdToKey (peer c)) addresses now NotConnected
      atomically $ modifyTVar' (dhtRoutingTable (tnDHT b)) (fst . insertPeer entry)
      result <- within $ findPeer (tnDHT a) (peer c)
      map entryPeerId result `shouldContain` [peer c]
      store <- readTVarIO (swPeerStore (switch a))
      let cached = maybe [] idListenAddrs (Map.lookup (peer c) store)
      length cached `shouldBe` 64
      cached `shouldContain` [toBytes (tnAddress c)]

admissionSpec :: Spec
admissionSpec = do
  it "should exclude a candidate when its authenticated identity differs from the advertised ID" $
    withTopology $ \a b c -> do
      Right keys <- generateKeyPair
      let wrongPeer = fromPublicKey (publicKey keys)
      now <- getCurrentTime
      atomically $ modifyTVar' (dhtRoutingTable (tnDHT b)) $
        fst . insertPeer (BucketEntry wrongPeer (peerIdToKey wrongPeer) [tnAddress c] now NotConnected)
      result <- within $ findPeer (tnDHT a) wrongPeer
      map entryPeerId result `shouldNotContain` [wrongPeer]
      connection <- atomically $ lookupConn (swConnPool (switch a)) wrongPeer
      isNothing connection `shouldBe` True

  it "should respect the Switch address gater for learned candidates" $
    withTopology $ \a _ c -> do
      setConnectionGater (switch a) defaultConnectionGater
        { gateDialAddr = \address -> pure (address /= tnAddress c) }
      result <- within $ findPeer (tnDHT a) (peer c)
      map entryPeerId result `shouldNotContain` [peer c]
      connectedTo a c `shouldReturn` False

  it "should reuse one connection for concurrent discoveries of the same peer" $
    withTopology $ \a _ c -> do
      results <- within $ mapConcurrently (\_ -> findPeer (tnDHT a) (peer c)) [1 :: Int .. 3]
      mapM_ (\entries -> map entryPeerId entries `shouldContain` [peer c]) results
      pool <- readTVarIO (swConnPool (switch a))
      length (Map.findWithDefault [] (peer c) pool) `shouldBe` 1

ownershipSpec :: Spec
ownershipSpec =
  it "should leave Switch-owned connections reusable when DHT stops during a dial" $
    withTopology $ \a _ c -> do
      entered <- newEmptyTMVarIO
      permitted <- newEmptyTMVarIO
      seed (tnDHT a) c
      setConnectionGater (switch a) defaultConnectionGater
        { gateDialAddr = \_ -> do
            atomically $ putTMVar entered ()
            atomically $ takeTMVar permitted
            pure True }
      let request = emptyDHTMessage { msgType = FindNode, msgKey = peerIdBytes (peer c) }
      withAsync (dhtSendRequest (tnDHT a) (peer c) request) $ \worker -> do
        within $ atomically $ takeTMVar entered
        stopDHTNode (tnDHT a)
        atomically $ putTMVar permitted ()
        within (wait worker) >>= (`shouldSatisfy` isLeft)
      connectedTo a c `shouldReturn` True
      bracket (newDHTNode (switch a) DHTClient) stopDHTNode $ \otherDHT -> do
        result <- within $ dhtSendRequest otherDHT (peer c) request
        fmap msgType result `shouldBe` Right FindNode

cancellationSpec :: Spec
cancellationSpec = do
  it "should cancel an in-flight candidate dial when the lookup deadline expires" $
    withTopology $ \a _ c -> do
      entered <- newEmptyTMVarIO
      dialExited <- newEmptyTMVarIO
      tcp <- newTCPTransport
      let blocked = tcp { transportDialFrom = \_ _ ->
            (`finally` atomically (putTMVar dialExited ())) $ do
              atomically $ void (tryPutTMVar entered ())
              atomically retry }
      atomically $ writeTVar (swTransports (switch a)) [blocked]
      let node = (tnDHT a) { dhtQueryTimeout = 100000 }
      withAsync (findPeer node (peer c)) $ \lookupWorker -> do
        timeout 1000000 (atomically $ takeTMVar entered) `shouldReturn` Just ()
        timeout 1000000 (wait lookupWorker) `shouldReturn` Just []
      timeout 1000000 (atomically $ takeTMVar dialExited) `shouldReturn` Just ()
      pendingDials <- readTVarIO (swPendingDials (switch a))
      Map.null pendingDials `shouldBe` True
      connectedTo a c `shouldReturn` False

  it "should release a candidate stream when the deadline cancels a blocked RPC" $
    withTopology $ \a _ c -> do
      entered <- newEmptyTMVarIO
      setStreamHandler (switch c) dhtProtocolId $ \_ stream ->
        (`finally` streamClose stream) $ do
          void $ readFramedMessage stream maxDHTMessageSize
          atomically $ putTMVar entered ()
          void $ readFramedMessage stream maxDHTMessageSize
      let node = (tnDHT a) { dhtQueryTimeout = 100000 }
      withAsync (findPeer node (peer c)) $ \lookupWorker -> do
        timeout 1000000 (atomically $ takeTMVar entered) `shouldReturn` Just ()
        timeout 1000000 (wait lookupWorker) `shouldReturn` Just []
      Just connection <- atomically $ lookupConn (swConnPool (switch a)) (peer c)
      within $ atomically $ do
        usage <- readTVar (rsUsage (connResourceScope connection))
        check (ruStreamsOutbound usage == 0)

withTopology :: (TestNode -> TestNode -> TestNode -> IO a) -> IO a
withTopology action = withNode $ \a -> withNode $ \b -> withNode $ \c -> do
  connected <- within $ dial (switch a) (peer b) [tnAddress b]
  either (fail . show) (const (pure ())) connected
  seed (tnDHT a) b
  seed (tnDHT b) c
  action a b c

withNode :: (TestNode -> IO a) -> IO a
withNode = bracket acquire release
  where
    acquire = do
      Right keys <- generateKeyPair
      let identity = fromPublicKey (publicKey keys)
      bracketOnError (newSwitch identity keys) switchClose $ \sw -> do
        newTCPTransport >>= addTransport sw
        [address] <- switchListen sw defaultConnectionGater [Multiaddr [IP4 0x7f000001, TCP 0]]
        bracketOnError (newDHTNode sw DHTServer) stopDHTNode $ \node -> do
          registerDHTHandler node
          pure $ TestNode node address (DHTRecord ("/pk/" <> peerIdBytes identity)
            (encodePublicKey (publicKey keys)) "")
    release node = stopDHTNode (tnDHT node) `finally` switchClose (switch node)

seed :: DHTNode -> TestNode -> IO ()
seed node other = do
  now <- getCurrentTime
  let entry = BucketEntry (peer other) (peerIdToKey (peer other)) [tnAddress other] now NotConnected
  atomically $ modifyTVar' (dhtRoutingTable node) (fst . insertPeer entry)

peer :: TestNode -> PeerId
peer = dhtLocalPeerId . tnDHT

switch :: TestNode -> Switch
switch = dhtSwitch . tnDHT

connectedTo :: TestNode -> TestNode -> IO Bool
connectedTo a b = isJust <$> atomically (lookupConn (swConnPool (switch a)) (peer b))

within :: IO a -> IO a
within action = withAsync action $ \worker -> do
  result <- timeout 5000000 (wait worker)
  maybe (fail "DHT candidate operation timed out") pure result

contentKey :: BS.ByteString
contentKey = BS.pack [0x12, 0x20] <> BS.replicate 32 0x52
