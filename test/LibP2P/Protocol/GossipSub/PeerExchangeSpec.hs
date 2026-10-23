module LibP2P.Protocol.GossipSub.PeerExchangeSpec (spec) where

import Test.Hspec

import Control.Concurrent (threadDelay)
import Control.Concurrent.STM
import Control.Exception (throwIO)
import qualified Data.ByteString as BS
import Data.IORef
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import Data.Time (addUTCTime)
import Data.Word (Word64)
import LibP2P.Crypto.Ed25519 (generateKeyPair)
import LibP2P.Crypto.Key (KeyPair (..), publicKey)
import LibP2P.Crypto.PeerId (PeerId, fromPublicKey, peerIdBytes)
import LibP2P.Crypto.PeerRecord (PeerRecord (..), sealPeerRecord)
import LibP2P.Crypto.SignedEnvelope (encodeSignedEnvelope)
import LibP2P.Multiaddr (Multiaddr (..), fromText, toBytes)
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.Protocol.GossipSub.Heartbeat (heartbeatOnce)
import LibP2P.Protocol.GossipSub.Handler (GossipSubNode, gsnRouter, newGossipSubNode)
import LibP2P.Protocol.GossipSub.PeerExchange (dialAcceptedPX, pxMaxInFlight)
import LibP2P.Protocol.GossipSub.Router (addPeer, handlePrune)
import LibP2P.Protocol.GossipSub.Types
import LibP2P.Switch (addTransport, newSwitch)
import LibP2P.Switch.CertifiedRecords (CertifiedRecord (..))
import LibP2P.Switch.ConnPool (addConn)
import LibP2P.Switch.ResourceManager (reserveConnection)
import LibP2P.Switch.Types
import LibP2P.Transport (Transport (..))

spec :: Spec
spec = describe "GossipSub accepted PX dialing (#247)" $ do
  it "does not dial when the sender is below AcceptPXThreshold" $ do
    (sw, node, sender, ref) <- fixture
    (peer, entry) <- advertise 1
    prune node sender 0 [entry]
    pause
    readIORef ref `shouldReturn` []
    stored <- atomically $ Map.lookup peer <$> readTVar (swCertifiedRecords sw)
    stored `shouldBe` Nothing

  it "dials a valid PX peer from the production node" $ do
    (_sw, node, sender, ref) <- fixture
    (_peer, entry) <- advertise 1
    prune node sender 200 [entry]
    await ref
    readIORef ref `shouldReturn` [loopback]

  it "does not dial a forged record" $ do
    (_sw, node, sender, ref) <- fixture
    Right evil <- generateKeyPair
    Right claimed <- generateKeyPair
    let claimedPid = fromPublicKey (publicKey claimed)
    Right forged <- pure $ sealPeerRecord evil
      (PeerRecord (peerIdBytes claimedPid) 1 [toBytes loopback])
    let entry = PeerExchangeInfo (peerIdBytes claimedPid)
          (Just (encodeSignedEnvelope forged))
    prune node sender 200 [entry]
    pause
    readIORef ref `shouldReturn` []

  it "does not dial a stale record or replace the retained one" $ do
    (sw, node, sender, ref) <- fixture
    (peer, entry) <- advertise 1
    atomically $ modifyTVar' (swCertifiedRecords sw) $
      Map.insert peer (CertifiedRecord 10 (BS.pack [1]) [toBytes loopback])
    prune node sender 200 [entry]
    pause
    readIORef ref `shouldReturn` []
    retained <- atomically $ Map.lookup peer <$> readTVar (swCertifiedRecords sw)
    fmap crSeq retained `shouldBe` Just 10

  it "dials a duplicate advertisement only once" $ do
    (_sw, node, sender, ref) <- fixture
    (_peer, entry) <- advertise 1
    prune node sender 200 [entry, entry]
    await ref
    pause
    readIORef ref `shouldReturn` [loopback]

  it "does not dial self" $ do
    (sw, node, sender, ref) <- fixture
    entry <- advertiseWith (swIdentityKey sw) 1
    prune node sender 200 [entry]
    pause
    readIORef ref `shouldReturn` []

  it "does not dial an already-connected peer" $ do
    (sw, node, sender, ref) <- fixture
    (peer, entry) <- advertise 1
    conn <- openConn sw peer
    atomically $ addConn (swConnPool sw) conn
    prune node sender 200 [entry]
    pause
    readIORef ref `shouldReturn` []

  it "does not dial a peer in gossipsub backoff" $ do
    (_sw, node, sender, ref) <- fixture
    (peer, entry) <- advertise 1
    let router = gsnRouter node
    now <- gsGetTime router
    atomically $ modifyTVar' (gsBackoff router) $
      Map.insert (peer, "t") (addUTCTime 60 now)
    prune node sender 200 [entry]
    pause
    readIORef ref `shouldReturn` []

  it "does not dial a peer in dial backoff" $ do
    (sw, node, sender, ref) <- fixture
    (peer, entry) <- advertise 1
    now <- gsGetTime (gsnRouter node)
    atomically $ modifyTVar' (swDialBackoffs sw) $
      Map.insert peer (BackoffEntry (addUTCTime 60 now) 1)
    prune node sender 200 [entry]
    pause
    readIORef ref `shouldReturn` []

  it "dials an unsigned peer only when ambient addresses are already stored" $ do
    (sw, node, sender, ref) <- fixture
    (known, _) <- identity
    (unknown, _) <- identity
    atomically $ modifyTVar' (swCertifiedRecords sw) $
      Map.insert known (CertifiedRecord 1 (BS.pack [1]) [toBytes loopback])
    prune node sender 200
      [ PeerExchangeInfo (peerIdBytes unknown) Nothing
      , PeerExchangeInfo (peerIdBytes known) Nothing
      ]
    await ref
    readIORef ref `shouldReturn` [loopback]

  it "does not dial when the in-flight cap is full" $ do
    (sw, node, _sender, ref) <- fixture
    (_peer, entry) <- advertise 1
    slots <- newTVarIO pxMaxInFlight
    dialAcceptedPX sw (gsnRouter node) slots "t" [entry]
    pause
    readIORef ref `shouldReturn` []

  it "grafts a dialed PX peer once that peer is connected and subscribed" $ do
    (_sw, node, sender, ref) <- fixture
    (peer, entry) <- advertise 1
    prune node sender 200 [entry]
    await ref
    let router = gsnRouter node
    now <- gsGetTime router
    addPeer router peer GossipSubPeer False now
    atomically $ do
      modifyTVar' (gsSubscriptions router) (Set.insert "t")
      modifyTVar' (gsPeers router) $
        Map.adjust (\ps -> ps { psTopics = Set.singleton "t" }) peer
    heartbeatOnce router
    mesh <- readTVarIO (gsMesh router)
    Set.member peer (Map.findWithDefault Set.empty "t" mesh) `shouldBe` True

fixture :: IO (Switch, GossipSubNode, PeerId, IORef [Multiaddr])
fixture = do
  (local, localKp) <- identity
  sw <- newSwitch local localKp
  ref <- newIORef []
  addTransport sw (recordingTransport ref)
  node <- newGossipSubNode sw defaultGossipSubParams
  (sender, _) <- identity
  now <- gsGetTime (gsnRouter node)
  addPeer (gsnRouter node) sender GossipSubPeer False now
  pure (sw, node, sender, ref)

recordingTransport :: IORef [Multiaddr] -> Transport
recordingTransport ref = Transport
  { transportDial = note
  , transportDialFrom = \_ addr -> note addr
  , transportListen = \_ -> fail "px test transport does not listen"
  , transportCanDial = const True
  }
  where
    note addr = modifyIORef' ref (addr :) >> throwIO (userError "stop before upgrade")

prune :: GossipSubNode -> PeerId -> Double -> [PeerExchangeInfo] -> IO ()
prune node sender score entries =
  handlePrune (withScore node score) sender [Prune "t" entries (Just 60)]

withScore :: GossipSubNode -> Double -> GossipSubRouter
withScore node score = (gsnRouter node)
  { gsScoreParams = defaultPeerScoreParams { pspAppSpecificScore = const score } }

advertise :: Word64 -> IO (PeerId, PeerExchangeInfo)
advertise seqNo = do
  (peer, kp) <- identity
  entry <- advertiseWith kp seqNo
  pure (peer, entry)

advertiseWith :: KeyPair -> Word64 -> IO PeerExchangeInfo
advertiseWith kp seqNo = do
  let peer = fromPublicKey (publicKey kp)
  Right env <- pure $ sealPeerRecord kp
    (PeerRecord (peerIdBytes peer) seqNo [toBytes loopback])
  pure $ PeerExchangeInfo (peerIdBytes peer) (Just (encodeSignedEnvelope env))

loopback :: Multiaddr
loopback = case fromText "/ip4/127.0.0.1/tcp/4001" of
  Right addr -> addr
  Left err -> error err

identity :: IO (PeerId, KeyPair)
identity = do
  Right kp <- generateKeyPair
  pure (fromPublicKey (publicKey kp), kp)

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
    , connRelayLimit = Nothing
    }

pause :: IO ()
pause = threadDelay 200000

await :: IORef [Multiaddr] -> IO ()
await ref = go (50 :: Int)
  where
    go 0 = readIORef ref >>= (`shouldSatisfy` (not . null))
    go n = do
      seen <- readIORef ref
      if null seen then threadDelay 10000 >> go (n - 1) else pure ()
