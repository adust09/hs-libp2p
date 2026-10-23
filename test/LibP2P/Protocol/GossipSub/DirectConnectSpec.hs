module LibP2P.Protocol.GossipSub.DirectConnectSpec (spec) where

import Test.Hspec

import Control.Concurrent (threadDelay)
import Control.Concurrent.Async (concurrently_)
import Control.Concurrent.STM
import Control.Exception (throwIO)
import Control.Monad (when)
import qualified Data.ByteString as BS
import Data.IORef
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import Data.Time (UTCTime)
import Data.Time.Clock.POSIX (posixSecondsToUTCTime)
import LibP2P.Crypto.Ed25519 (generateKeyPair)
import LibP2P.Crypto.Key (KeyPair, publicKey)
import LibP2P.Crypto.PeerId (PeerId (..), fromPublicKey)
import LibP2P.Protocol.GossipSub.DirectConnect (connectMissingDirectPeers)
import LibP2P.Multiaddr (Multiaddr (..), fromText, toBytes)
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.Protocol.GossipSub.Handler
  ( GossipSubNode
  , gsnDirectSlots
  , gsnRouter
  , newGossipSubNode
  , startGossipSub
  , stopGossipSub
  )
import LibP2P.Protocol.GossipSub.Heartbeat (heartbeatOnce)
import LibP2P.Protocol.GossipSub.Router (addPeer, newRouter, publish)
import LibP2P.Protocol.GossipSub.Types
import LibP2P.Switch (addTransport, newSwitch)
import LibP2P.Switch.CertifiedRecords (CertifiedRecord (..))
import LibP2P.Switch.ConnPool (addConn, removeConn)
import LibP2P.Switch.ResourceManager (reserveConnection)
import LibP2P.Switch.Types
import LibP2P.Transport (Transport (..))

spec :: Spec
spec = describe "GossipSub direct peer connections (#259)" $ do
  it "dials a configured direct peer that has stored addresses" $ do
    (sw, node, peer, ref) <- fixture
    connectMissingDirectPeers sw (gsnRouter node) (gsnDirectSlots node)
    await ref
    readIORef ref `shouldReturn` [loopback]

  it "does not dial a direct peer with no stored addresses" $ do
    (sw, node, _peer, ref) <- fixtureNoAddrs
    connectMissingDirectPeers sw (gsnRouter node) (gsnDirectSlots node)
    pause
    readIORef ref `shouldReturn` []

  it "does not dial an already-connected direct peer" $ do
    (sw, node, peer, ref) <- fixture
    conn <- openConn sw peer
    atomically $ addConn (swConnPool sw) conn
    connectMissingDirectPeers sw (gsnRouter node) (gsnDirectSlots node)
    pause
    readIORef ref `shouldReturn` []

  it "does not redial while the failed dial is in backoff" $ do
    (sw, node, _peer, ref) <- fixture
    let slots = gsnDirectSlots node
        router = gsnRouter node
    connectMissingDirectPeers sw router slots
    await ref
    pause
    writeIORef ref []
    connectMissingDirectPeers sw router slots
    pause
    readIORef ref `shouldReturn` []

  it "does not spawn a second dial while one is in flight" $ do
    (sw, node, _peer, ref) <- fixtureSlow
    let go = connectMissingDirectPeers sw (gsnRouter node) (gsnDirectSlots node)
    concurrently_ go go
    await ref
    pause
    fmap length (readIORef ref) `shouldReturn` 1

  it "redials after the direct connection drops" $ do
    (sw, node, peer, ref) <- fixture
    conn <- openConn sw peer
    atomically $ addConn (swConnPool sw) conn
    startGossipSub node
    pause
    readIORef ref `shouldReturn` []
    atomically $ removeConn (swConnPool sw) conn
    notifiers <- readTVarIO (swDisconnectNotifiers sw)
    mapM_ ($ conn) notifiers
    await ref
    readIORef ref `shouldReturn` [loopback]
    stopGossipSub node

  it "does not redial after shutdown" $ do
    (sw, node, peer, ref) <- fixture
    conn <- openConn sw peer
    atomically $ addConn (swConnPool sw) conn
    startGossipSub node
    stopGossipSub node
    atomically $ removeConn (swConnPool sw) conn
    notifiers <- readTVarIO (swDisconnectNotifiers sw)
    mapM_ ($ conn) notifiers
    pause
    readIORef ref `shouldReturn` []

  it "does not put a direct peer in the mesh or fanout" $ do
    (router, _log, peer) <- routerWithDirect
    addPeer router peer GossipSubPeer False =<< gsGetTime router
    atomically $ modifyTVar' (gsPeers router) $
      Map.adjust (\ps -> ps { psTopics = Set.singleton "t" }) peer
    atomically $ modifyTVar' (gsSubscriptions router) (Set.insert "t")
    heartbeatOnce router
    mesh <- readTVarIO (gsMesh router)
    Set.member peer (Map.findWithDefault Set.empty "t" mesh) `shouldBe` False
    publish router "t" (BS.pack [1]) Nothing
    fanout <- readTVarIO (gsFanout router)
    Set.member peer (Map.findWithDefault Set.empty "t" fanout) `shouldBe` False

  it "forwards to a direct peer below the publish threshold" $ do
    (router, logRef, peer) <- routerWithDirect
    let bad = mkPeer 2
    now <- gsGetTime router
    addPeer router peer GossipSubPeer False now
    addPeer router bad GossipSubPeer False now
    atomically $ modifyTVar' (gsPeers router) $
      Map.adjust (\ps -> ps { psTopics = Set.singleton "t" }) peer
        . Map.adjust (\ps -> ps { psTopics = Set.singleton "t" }) bad
    let scored = router
          { gsScoreParams = defaultPeerScoreParams { pspAppSpecificScore = const (-1000000) } }
    publish scored "t" (BS.pack [1]) Nothing
    sent <- readIORef logRef
    fmap fst sent `shouldBe` [peer]

fixture :: IO (Switch, GossipSubNode, PeerId, IORef [Multiaddr])
fixture = fixtureWith (recordingTransport 0)

fixtureSlow :: IO (Switch, GossipSubNode, PeerId, IORef [Multiaddr])
fixtureSlow = fixtureWith (recordingTransport 300000)

fixtureNoAddrs :: IO (Switch, GossipSubNode, PeerId, IORef [Multiaddr])
fixtureNoAddrs = do
  (local, kp) <- identity
  (peer, _) <- identity
  sw <- newSwitch local kp
  ref <- newIORef []
  addTransport sw (recordingTransport 0 ref)
  let params = defaultGossipSubParams
        { paramDirectPeers = Set.singleton peer
        , paramHeartbeatInterval = 3600
        , paramDirectConnectInterval = 3600
        }
  node <- newGossipSubNode sw params
  pure (sw, node, peer, ref)

fixtureWith :: (IORef [Multiaddr] -> Transport) -> IO (Switch, GossipSubNode, PeerId, IORef [Multiaddr])
fixtureWith mkTransport = do
  (local, kp) <- identity
  (peer, _) <- identity
  sw <- newSwitch local kp
  ref <- newIORef []
  addTransport sw (mkTransport ref)
  atomically $ modifyTVar' (swCertifiedRecords sw) $
    Map.insert peer (CertifiedRecord 1 (BS.pack [1]) [toBytes loopback])
  let params = defaultGossipSubParams
        { paramDirectPeers = Set.singleton peer
        , paramHeartbeatInterval = 3600
        , paramDirectConnectInterval = 3600
        }
  node <- newGossipSubNode sw params
  pure (sw, node, peer, ref)

recordingTransport :: Int -> IORef [Multiaddr] -> Transport
recordingTransport delayUs ref = Transport
  { transportDial = note
  , transportDialFrom = \_ addr -> note addr
  , transportListen = \_ -> fail "direct-connect test transport does not listen"
  , transportCanDial = const True
  }
  where
    note addr = do
      when (delayUs > 0) $ threadDelay delayUs
      modifyIORef' ref (addr :)
      throwIO (userError "stop before upgrade")

routerWithDirect :: IO (GossipSubRouter, IORef [(PeerId, RPC)], PeerId)
routerWithDirect = do
  sent <- newIORef []
  (peer, _) <- identity
  let params = defaultGossipSubParams
        { paramDirectPeers = Set.singleton peer
        , paramSignaturePolicy = StrictNoSign
        , paramFloodPublish = True
        }
  router <- newRouter params (mkPeer 1) (\pid rpc -> modifyIORef' sent ((pid, rpc) :)) (pure fixedTime)
  pure (router, sent, peer)

unsigned :: Topic -> BS.ByteString -> PubSubMessage
unsigned topic payload = PubSubMessage
  { msgFrom = Nothing
  , msgData = payload
  , msgSeqNo = Nothing
  , msgTopic = topic
  , msgSignature = Nothing
  , msgKey = Nothing
  }

openConn :: Switch -> PeerId -> IO Connection
openConn sw pid = do
  stateVar <- newTVarIO ConnOpen
  scope <- atomically (reserveConnection (swResourceMgr sw) pid Inbound)
    >>= either (fail . show) pure
  pure Connection
    { connPeerId = pid
    , connDirection = Inbound
    , connLocalAddr = Multiaddr [IP4 0x7f000001, TCP 1]
    , connRemoteAddr = Multiaddr [IP4 0x7f000001, TCP 2]
    , connSecurity = "/noise"
    , connMuxer = "/yamux/1.0.0"
    , connSession = MuxerSession
        { muxOpenStream = \_ -> fail "unused"
        , muxAcceptStream = fail "unused"
        , muxClose = pure ()
        }
    , connState = stateVar
    , connResourceScope = scope
    }

loopback :: Multiaddr
loopback = case fromText "/ip4/127.0.0.1/tcp/4001" of
  Right addr -> addr
  Left err -> error err

identity :: IO (PeerId, KeyPair)
identity = do
  Right kp <- generateKeyPair
  pure (fromPublicKey (publicKey kp), kp)

mkPeer :: Int -> PeerId
mkPeer n = PeerId (BS.pack [fromIntegral n])

fixedTime :: UTCTime
fixedTime = posixSecondsToUTCTime 1000000

pause :: IO ()
pause = threadDelay 200000

await :: IORef [Multiaddr] -> IO ()
await ref = go (50 :: Int)
  where
    go 0 = readIORef ref >>= (`shouldSatisfy` (not . null))
    go n = do
      seen <- readIORef ref
      if null seen then threadDelay 10000 >> go (n - 1) else pure ()
