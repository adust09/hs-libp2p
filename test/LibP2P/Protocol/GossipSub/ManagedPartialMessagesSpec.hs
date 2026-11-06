module LibP2P.Protocol.GossipSub.ManagedPartialMessagesSpec (spec) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.Async (Async, async, cancel)
import Control.Concurrent.MVar (newEmptyMVar, putMVar, takeMVar)
import Control.Concurrent.STM
import Control.Exception (bracket, finally)
import qualified Data.ByteString as BS
import Data.IORef
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import LibP2P.Crypto.Ed25519 (generateKeyPair)
import LibP2P.Crypto.Key (KeyPair, publicKey)
import LibP2P.Crypto.PeerId (PeerId, fromPublicKey)
import LibP2P.Multiaddr (Multiaddr (..))
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.MultistreamSelect.Negotiation
  ( NegotiationResult (..)
  , ProtocolId
  , StreamIO (..)
  , negotiateResponder
  )
import LibP2P.Protocol.GossipSub.Extensions (peerSupportsPartialExtension)
import LibP2P.Protocol.GossipSub.Handler
import LibP2P.Protocol.GossipSub.PartialMessages
import LibP2P.Protocol.GossipSub.Types hiding
  ( floodSubProtocolId
  , gossipSubProtocolId
  , gossipSubProtocolIdV10
  , gossipSubProtocolIdV11
  , gossipSubProtocolIdV12
  )
import LibP2P.Switch (newSwitch, switchClose)
import LibP2P.Switch.ResourceManager (MemoryAccount (..), reserveConnection)
import LibP2P.Switch.Types
import System.Timeout (timeout)
import Test.Hspec

data ManagedPair = ManagedPair
  { pairNodeA :: !GossipSubNode
  , pairNodeB :: !GossipSubNode
  , pairPeerA :: !PeerId
  , pairPeerB :: !PeerId
  , pairExtensionA :: !(PartialMessagesExtension Int)
  , pairExtensionB :: !(PartialMessagesExtension Int)
  , pairReceivedA :: !(IORef [PartialMessage])
  , pairReceivedB :: !(IORef [PartialMessage])
  , pairConnectionA :: !Connection
  , pairConnectionB :: !Connection
  , pairWorkers :: !(IORef [Async ()])
  }

spec :: Spec
spec = describe "managed GossipSub v1.3 partial-message streams" $ do
  it "advertises modes and exchanges partial, metadata, and full messages both ways" $
    withManagedPair $ \pair -> do
      let nodeA = pairNodeA pair
          nodeB = pairNodeB pair
          pidA = pairPeerA pair
          pidB = pairPeerB pair
          routerA = gsnRouter nodeA
          routerB = gsnRouter nodeB
      waitForPeerMode routerB pidA (Just RequestsPartialMessages) `shouldReturn` True
      waitForPeerMode routerA pidB (Just SupportsPartialMessages) `shouldReturn` True
      peerSupportsPartialExtension routerA pidB `shouldReturn` True
      peerSupportsPartialExtension routerB pidA `shouldReturn` True
      setMesh routerA pidB
      setMesh routerB pidA

      publishForPeer (pairExtensionB pair) pidA True "data-group" "part" "meta"
      waitForPartial (pairReceivedA pair) "data-group"
        `shouldReturn` Just (PartialMessage topic "data-group" (Just "part") (Just "meta"))

      gossipJoinPartial nodeA topic SupportsPartialMessages `shouldReturn` Right ()
      waitForPeerMode routerB pidA (Just SupportsPartialMessages) `shouldReturn` True
      publishForPeer (pairExtensionB pair) pidA False "metadata-group" "hidden" "metadata"
      waitForPartial (pairReceivedA pair) "metadata-group"
        `shouldReturn` Just (PartialMessage topic "metadata-group" Nothing (Just "metadata"))

      fullMessage <- newEmptyMVar
      atomically $ writeTVar (gsOnMessage routerA)
        (\receivedTopic message -> putMVar fullMessage (receivedTopic, msgData message))
      gossipLeave nodeA topic
      gossipJoin nodeA topic
      waitForPeerMode routerB pidA Nothing `shouldReturn` True
      gossipPublish nodeB topic "full-message"
      timeout 2000000 (takeMVar fullMessage)
        `shouldReturn` Just (topic, "full-message")

      gossipJoinPartial nodeA topic SupportsPartialMessages `shouldReturn` Right ()
      gossipJoinPartial nodeB topic RequestsPartialMessages `shouldReturn` Right ()
      waitForPeerMode routerA pidB (Just RequestsPartialMessages) `shouldReturn` True
      setMesh routerA pidB
      publishForPeer (pairExtensionA pair) pidB True "reverse-group" "reverse" "reverse-meta"
      waitForPartial (pairReceivedB pair) "reverse-group"
        `shouldReturn` Just (PartialMessage topic "reverse-group" (Just "reverse") (Just "reverse-meta"))

      disconnectManaged (gsnSwitch nodeA) (pairConnectionA pair)
      disconnectManaged (gsnSwitch nodeB) (pairConnectionB pair)
      waitForPeerAbsentWithDetails nodeA pidB `shouldReturn` True
      waitForPeerAbsentWithDetails nodeB pidA `shouldReturn` True
      stopGossipSub nodeA
      stopGossipSub nodeB
      startGossipSub nodeA
      startGossipSub nodeB
      _ <- connectManaged (pairWorkers pair) (gsnSwitch nodeA) pidB nodeB pidA
      _ <- connectManaged (pairWorkers pair) (gsnSwitch nodeB) pidA nodeA pidB
      waitForPeerMode routerA pidB (Just RequestsPartialMessages) `shouldReturn` True
      waitForPeerMode routerB pidA (Just SupportsPartialMessages) `shouldReturn` True
      setMesh routerA pidB
      setMesh routerB pidA
      writeIORef (pairReceivedB pair) []
      publishForPeer (pairExtensionA pair) pidB True "reconnected-group" "new" "new-meta"
      waitForPartial (pairReceivedB pair) "reconnected-group"
        `shouldReturn` Just (PartialMessage topic "reconnected-group" (Just "new") (Just "new-meta"))

withManagedPair :: (ManagedPair -> IO a) -> IO a
withManagedPair = bracket newManagedPair closeManagedPair

newManagedPair :: IO ManagedPair
newManagedPair = do
  (pidA, keyA) <- generateIdentity
  (pidB, keyB) <- generateIdentity
  switchA <- newSwitch pidA keyA
  switchB <- newSwitch pidB keyB
  nodeA <- newGossipSubNode switchA params
  nodeB <- newGossipSubNode switchB params
  receivedA <- newIORef []
  receivedB <- newIORef []
  extensionA <- recordingExtension receivedA
  extensionB <- recordingExtension receivedB
  enablePartialMessages nodeA extensionA `shouldReturn` Right ()
  enablePartialMessages nodeB extensionB `shouldReturn` Right ()
  gossipJoinPartial nodeA topic RequestsPartialMessages `shouldReturn` Right ()
  gossipJoinPartial nodeB topic SupportsPartialMessages `shouldReturn` Right ()
  startGossipSub nodeA
  startGossipSub nodeB
  workers <- newIORef []
  connectionA <- connectManaged workers switchA pidB nodeB pidA
  connectionB <- connectManaged workers switchB pidA nodeA pidB
  pure ManagedPair
    { pairNodeA = nodeA
    , pairNodeB = nodeB
    , pairPeerA = pidA
    , pairPeerB = pidB
    , pairExtensionA = extensionA
    , pairExtensionB = extensionB
    , pairReceivedA = receivedA
    , pairReceivedB = receivedB
    , pairConnectionA = connectionA
    , pairConnectionB = connectionB
    , pairWorkers = workers
    }

closeManagedPair :: ManagedPair -> IO ()
closeManagedPair pair = do
  stopGossipSub (pairNodeA pair)
  stopGossipSub (pairNodeB pair)
  readIORef (pairWorkers pair) >>= mapM_ cancel
  switchClose (gsnSwitch (pairNodeA pair))
  switchClose (gsnSwitch (pairNodeB pair))

connectManaged
  :: IORef [Async ()]
  -> Switch
  -> PeerId
  -> GossipSubNode
  -> PeerId
  -> IO Connection
connectManaged workers owner remotePid remoteNode ownerPid = do
  connection <- managedConnection workers owner remotePid remoteNode ownerPid
  notifiers <- atomically $ readTVar (swNotifiers owner)
  mapM_ ($ connection) notifiers
  pure connection

disconnectManaged :: Switch -> Connection -> IO ()
disconnectManaged owner connection = do
  notifiers <- atomically $ readTVar (swDisconnectNotifiers owner)
  mapM_ ($ connection) notifiers

managedConnection
  :: IORef [Async ()]
  -> Switch
  -> PeerId
  -> GossipSubNode
  -> PeerId
  -> IO Connection
managedConnection workers owner remotePid remoteNode ownerPid = do
  stateVar <- newTVarIO ConnOpen
  scope <- atomically (reserveConnection (swResourceMgr owner) remotePid Outbound)
    >>= either (fail . show) pure
  pure Connection
    { connPeerId = remotePid
    , connDirection = Outbound
    , connLocalAddr = Multiaddr [IP4 0x7f000001, TCP 4000]
    , connRemoteAddr = Multiaddr [IP4 0x7f000001, TCP 4001]
    , connSecurity = "/noise"
    , connMuxer = "/yamux/1.0.0"
    , connSession = MuxerSession
        { muxOpenStream = openManagedStream workers remoteNode ownerPid
        , muxAcceptStream = fail "managed test does not accept mux streams directly"
        , muxClose = pure ()
        }
    , connState = stateVar
    , connResourceScope = scope
    , connRelayLimit = Nothing
    }

openManagedStream
  :: IORef [Async ()]
  -> GossipSubNode
  -> PeerId
  -> MemoryAccount
  -> IO StreamIO
openManagedStream workers remoteNode ownerPid account = do
  (localStream, remoteStream) <- mkClosableMemoryStreamPair
  worker <- async $ do
    result <- negotiateResponder remoteStream protocolIds
    case result of
      Accepted protocol
        | protocol == gossipSubProtocolId ->
            handleGossipSubStream remoteNode remoteStream ownerPid GossipSubV13Peer Nothing
      _ -> streamClose remoteStream
  atomicModifyIORef' workers (\current -> (worker : current, ()))
  pure localStream
    { streamClose = streamClose localStream `finally` atomically (maClose account)
    }

mkClosableMemoryStreamPair :: IO (StreamIO, StreamIO)
mkClosableMemoryStreamPair = do
  queueAtoB <- newTQueueIO
  queueBtoA <- newTQueueIO
  pure
    ( mkEndpoint queueAtoB queueBtoA
    , mkEndpoint queueBtoA queueAtoB
    )
 where
  mkEndpoint outgoing incoming = StreamIO
    { streamWrite = \bytes -> atomically $
        mapM_ (writeTQueue outgoing . Just) (BS.unpack bytes)
    , streamReadByte = readByte incoming
    , streamReadChunk = \_ -> BS.singleton <$> readByte incoming
    , streamClose = atomically $ writeTQueue outgoing Nothing
    }
  readByte queue = do
    next <- atomically $ readTQueue queue
    maybe (ioError $ userError "managed test stream closed") pure next

recordingExtension :: IORef [PartialMessage] -> IO (PartialMessagesExtension Int)
recordingExtension received =
  newPartialMessagesExtension $ defaultPartialMessagesConfig 0 onIncoming noGossip
 where
  onIncoming _ states partial = do
    modifyIORef' received (partial :)
    pure (PartialCallbackResult states [])
  noGossip _ _ _ states = pure (PartialCallbackResult states [])

publishForPeer
  :: PartialMessagesExtension Int
  -> PeerId
  -> Bool
  -> BS.ByteString
  -> BS.ByteString
  -> BS.ByteString
  -> IO ()
publishForPeer extension peer expectedRequests groupId payload metadata =
  publishPartial extension topic groupId plan `shouldReturn` Right ()
 where
  plan states requests = do
    (groupId, requests peer) `shouldBe` (groupId, expectedRequests)
    pure PartialCallbackResult
      { partialUpdatedPeerStates = states
      , partialPublishActions =
          [PartialPublishAction peer (Just payload) (Just metadata)]
      }

waitForPeerMode
  :: GossipSubRouter
  -> PeerId
  -> Maybe PartialTopicMode
  -> IO Bool
waitForPeerMode router peer expected = do
  result <- timeout 2000000 $ atomically $ do
    peers <- readTVar (gsPeers router)
    let mode = Map.lookup peer peers >>= Map.lookup topic . psPartialTopics
    check (mode == expected)
  pure (maybe False (const True) result)

waitForPeerAbsentWithDetails :: GossipSubNode -> PeerId -> IO Bool
waitForPeerAbsentWithDetails node peer = do
  let router = gsnRouter node
  result <- timeout 2000000 $ atomically $ do
    peers <- readTVar (gsPeers router)
    check (Map.notMember peer peers)
  case result of
    Just () -> pure True
    Nothing -> do
      peers <- readTVarIO (gsPeers router)
      streams <- readTVarIO (gsnStreams node)
      expectationFailure $ "peer remained after disconnect; peers=" <> show (Map.keys peers)
        <> ", streams=" <> show (Map.keys streams)
      pure False

waitForPartial :: IORef [PartialMessage] -> BS.ByteString -> IO (Maybe PartialMessage)
waitForPartial received groupId = timeout 2000000 loop
 where
  loop = do
    messages <- readIORef received
    case filter ((== groupId) . partialGroupId) messages of
      message : _ -> pure message
      [] -> threadDelay 10000 >> loop

setMesh :: GossipSubRouter -> PeerId -> IO ()
setMesh router peer =
  atomically $ writeTVar (gsMesh router) (Map.singleton topic (Set.singleton peer))

generateIdentity :: IO (PeerId, KeyPair)
generateIdentity = do
  result <- generateKeyPair
  keyPair <- either fail pure result
  pure (fromPublicKey (publicKey keyPair), keyPair)

params :: GossipSubParams
params = defaultGossipSubParams
  { paramHeartbeatInterval = 10
  , paramSignaturePolicy = StrictNoSign
  }

topic :: Topic
topic = "managed-partials"

protocolIds :: [ProtocolId]
protocolIds =
  [ gossipSubProtocolId
  , gossipSubProtocolIdV12
  , gossipSubProtocolIdV11
  , gossipSubProtocolIdV10
  , floodSubProtocolId
  ]
