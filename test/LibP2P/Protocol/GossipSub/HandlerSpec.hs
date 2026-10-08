-- | Tests for GossipSub Switch Handler (Phase 10b).
--
-- Tests the Handler module that bridges Router ↔ Switch for persistent
-- bidirectional RPC streams.
module LibP2P.Protocol.GossipSub.HandlerSpec (spec) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.Async (Async, async, cancel)
import Control.Concurrent.MVar (newEmptyMVar, putMVar, takeMVar)
import Control.Concurrent.STM
  ( atomically
  , newTVarIO
  , readTVar
  , writeTVar
  )
import Control.Monad (unless)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import LibP2P.Multiaddr (Multiaddr (..))
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.Crypto.Ed25519 (generateKeyPair)
import LibP2P.Crypto.Key (KeyPair (..), publicKey, sign)
import LibP2P.Crypto.PeerId (PeerId (..), fromPublicKey, peerIdBytes)
import LibP2P.Crypto.PeerRecord (PeerRecord (..), sealPeerRecord)
import LibP2P.Crypto.SignedEnvelope (encodeSignedEnvelope)
import LibP2P.Crypto.Protobuf (encodePublicKey)
import LibP2P.MultistreamSelect.Negotiation
  ( NegotiationResult (..)
  , StreamIO (..)
  , mkByteStreamIO
  , mkMemoryStreamPair
  , negotiateResponder
  )
import LibP2P.Protocol.GossipSub.Handler
  ( GossipSubNode (..)
  , floodSubProtocolId
  , gossipJoin
  , gossipLeave
  , gossipPublish
  , gossipSubProtocolId
  , gossipSubProtocolIdV10
  , handleGossipSubStream
  , newGossipSubNode
  , sendCurrentSubscriptions
  , startGossipSub
  , stopGossipSub
  )
import LibP2P.Protocol.GossipSub.Message
  ( readRPCMessage
  , writeRPCMessage
  )
import LibP2P.Protocol.Identify.Message (IdentifyInfo (..))
import LibP2P.Protocol.GossipSub.Router (addPeer)
import LibP2P.Protocol.GossipSub.Validation (signingBytes)
import LibP2P.Protocol.GossipSub.Types
  ( GossipSubParams (..)
  , GossipSubRouter (..)
  , PeerProtocol (..)
  , PubSubMessage (..)
  , RPC (..)
  , SubOpts (..)
  , Topic
  , defaultGossipSubParams
  , maxRPCSize
  )
import LibP2P.Switch (lookupStreamHandler, newSwitch, setStreamHandler)
import LibP2P.Switch.Types
  ( ConnState (..)
  , Connection (..)
  , Direction (..)
  , MuxerSession (..)
  , Switch (..)
  )
import System.Timeout (timeout)
import Test.Hspec
import Data.Time.Clock (getCurrentTime)

-- | Generate a test identity (PeerId, KeyPair).
mkTestIdentity :: IO (PeerId, KeyPair)
mkTestIdentity = do
  Right kp <- generateKeyPair
  let pid = fromPublicKey (publicKey kp)
  pure (pid, kp)

-- | Build a correctly signed message, as a remote peer would publish it.
signedMessage :: KeyPair -> Topic -> BS.ByteString -> PubSubMessage
signedMessage kp topic payload =
  let PeerId from = fromPublicKey (publicKey kp)
      unsigned = PubSubMessage
        { msgFrom      = Just from
        , msgData      = payload
        , msgSeqNo     = Just (BS.pack [0, 0, 0, 0, 0, 0, 0, 1])
        , msgTopic     = topic
        , msgSignature = Nothing
        , msgKey       = Just (encodePublicKey (publicKey kp))
        }
  in case sign (kpPrivate kp) (signingBytes unsigned) of
       Left err  -> error ("test fixture signing failed: " <> err)
       Right sig -> unsigned { msgSignature = Just sig }

-- | Create a test Switch (no transport needed for handler unit tests).
mkTestSwitch :: IO (Switch, PeerId)
mkTestSwitch = do
  (pid, kp) <- mkTestIdentity
  sw <- newSwitch pid kp
  pure (sw, pid)

-- | Simple params with short heartbeat (1s) for testing.
testParams :: GossipSubParams
testParams = defaultGossipSubParams
  { paramHeartbeatInterval = 10.0  -- Long interval so heartbeat doesn't interfere
  }

-- | Connection whose muxer yields one stream that accepts GossipSub.
mkGossipConn :: PeerId -> IO (Connection, Async NegotiationResult)
mkGossipConn pid = do
  (localStream, remoteStream) <- mkMemoryStreamPair
  responder <- async $ negotiateResponder remoteStream
    [gossipSubProtocolId, gossipSubProtocolIdV10, floodSubProtocolId]
  stateVar <- newTVarIO ConnOpen
  let conn = Connection
        { connPeerId     = pid
        , connDirection  = Inbound
        , connLocalAddr  = Multiaddr [IP4 0x7f000001, TCP 0]
        , connRemoteAddr = Multiaddr [IP4 0x7f000001, TCP 4001]
        , connSecurity   = "/noise"
        , connMuxer      = "/yamux/1.0.0"
        , connSession    = MuxerSession
            { muxOpenStream   = pure localStream
            , muxAcceptStream = fail "test: no accept"
            , muxClose        = pure ()
            }
        , connState      = stateVar
        }
  pure (conn, responder)

-- | Run every Switch connection notifier, as a new connection would.
fireNotifiers :: Switch -> Connection -> IO ()
fireNotifiers sw conn = do
  notifiers <- atomically $ readTVar (swNotifiers sw)
  mapM_ ($ conn) notifiers

-- | Poll until the peer has a cached outbound GossipSub stream.
waitForCachedStream :: GossipSubNode -> PeerId -> Int -> IO Bool
waitForCachedStream node pid left
  | left <= 0 = pure False
  | otherwise = do
      streams <- atomically $ readTVar (gsnStreams node)
      if Map.member pid streams
        then pure True
        else threadDelay 50000 >> waitForCachedStream node pid (left - 1)

-- | Empty RPC for testing.
emptyRPC :: RPC
emptyRPC = RPC
  { rpcSubscriptions = []
  , rpcPublish       = []
  , rpcControl       = Nothing
  }

-- | Create an RPC with a subscription announcement.
subscribeRPC :: Topic -> RPC
subscribeRPC topic = emptyRPC
  { rpcSubscriptions = [SubOpts True topic]
  }

-- | Create an RPC with an unsubscription announcement.
unsubscribeRPC :: Topic -> RPC
unsubscribeRPC topic = emptyRPC
  { rpcSubscriptions = [SubOpts False topic]
  }

spec :: Spec
spec = do
  describe "newGossipSubNode" $ do
    it "creates node with empty state" $ do
      (sw, _pid) <- mkTestSwitch
      node <- newGossipSubNode sw testParams
      streams <- atomically $ readTVar (gsnStreams node)
      Map.null streams `shouldBe` True
      hb <- atomically $ readTVar (gsnHeartbeat node)
      case hb of
        Nothing -> pure ()
        Just _  -> expectationFailure "heartbeat should not be running"

  describe "handleGossipSubStream" $ do
    it "processes subscription RPCs via memory streams" $ do
      (sw, _localPid) <- mkTestSwitch
      node <- newGossipSubNode sw testParams
      (remotePid, _kp) <- mkTestIdentity
      -- Create memory stream pair: remote side writes, handler reads
      (remoteStream, handlerStream) <- mkMemoryStreamPair
      -- Spawn handler in background (blocks on read loop)
      _ <- async $ handleGossipSubStream node handlerStream remotePid GossipSubPeer Nothing
      -- Send a subscription RPC from remote
      writeRPCMessage remoteStream (subscribeRPC "test-topic")
      -- Give handler time to process
      threadDelay 200000
      -- Verify peer is registered in router
      peers <- atomically $ readTVar (gsPeers (gsnRouter node))
      Map.member remotePid peers `shouldBe` True

    it "keeps the outbound cache when the independent inbound stream ends" $ do
      (sw, _localPid) <- mkTestSwitch
      node <- newGossipSubNode sw testParams
      (remotePid, _kp) <- mkTestIdentity
      (cached, _) <- mkMemoryStreamPair
      atomically $ writeTVar (gsnStreams node) (Map.singleton remotePid cached)
      let eofStream = mkByteStreamIO (const (pure ())) (pure 0x80) (pure ())
      handleGossipSubStream node eofStream remotePid GossipSubPeer Nothing
      streams <- atomically $ readTVar (gsnStreams node)
      Map.member remotePid streams `shouldBe` True

    it "feeds the peer's identify signed peer record into the router (#230)" $ do
      (sw, _localPid) <- mkTestSwitch
      node <- newGossipSubNode sw testParams
      (remotePid, remoteKp) <- mkTestIdentity
      -- Identify already stored a signed peer record for this peer
      Right env <- pure (sealPeerRecord remoteKp
        (PeerRecord (peerIdBytes remotePid) 1 []))
      let envBytes = encodeSignedEnvelope env
          storedInfo = IdentifyInfo
            { idProtocolVersion  = Nothing
            , idAgentVersion     = Nothing
            , idPublicKey        = Nothing
            , idListenAddrs      = []
            , idObservedAddr     = Nothing
            , idProtocols        = []
            , idSignedPeerRecord = Just envBytes
            }
      atomically $ do
        store <- readTVar (swPeerStore sw)
        writeTVar (swPeerStore sw) (Map.insert remotePid storedInfo store)
      (remoteStream, handlerStream) <- mkMemoryStreamPair
      _ <- async $ handleGossipSubStream node handlerStream remotePid GossipSubPeer Nothing
      writeRPCMessage remoteStream (subscribeRPC "test-topic")
      threadDelay 200000
      recs <- atomically $ readTVar (gsSignedPeerRecords (gsnRouter node))
      Map.lookup remotePid recs `shouldBe` Just envBytes

    it "processes publish RPCs and delivers to onMessage callback" $ do
      (sw, _localPid) <- mkTestSwitch
      node <- newGossipSubNode sw testParams
      (remotePid, remoteKp) <- mkTestIdentity
      -- Set up message callback
      msgMVar <- newEmptyMVar
      atomically $ writeTVar (gsOnMessage (gsnRouter node))
        (\topic msg -> putMVar msgMVar (topic, msgData msg))
      -- Subscribe the router to the topic so it accepts messages
      gossipJoin node "pub-topic"
      -- Register remote peer and subscribe them
      now <- getCurrentTime
      addPeer (gsnRouter node) remotePid GossipSubPeer False now
      (remoteStream, handlerStream) <- mkMemoryStreamPair
      -- Spawn handler
      _ <- async $ handleGossipSubStream node handlerStream remotePid GossipSubPeer Nothing
      -- Send a publish RPC
      let msg = signedMessage remoteKp "pub-topic" "hello gossipsub"
      writeRPCMessage remoteStream (emptyRPC { rpcPublish = [msg] })
      -- Wait for callback
      result <- timeout 2000000 $ takeMVar msgMVar
      case result of
        Nothing -> expectationFailure "onMessage callback not invoked"
        Just (topic, dat) -> do
          topic `shouldBe` "pub-topic"
          dat `shouldBe` "hello gossipsub"

  describe "sendRPC" $ do
    it "opens outbound stream and writes framed RPC" $ do
      (sw, _localPid) <- mkTestSwitch
      node <- newGossipSubNode sw testParams
      (remotePid, _kp) <- mkTestIdentity
      -- Simulate: manually set up a mock connection in the pool
      -- For unit testing sendRPC, we inject a stream directly
      (nodeStream, remoteReadStream) <- mkMemoryStreamPair
      atomically $ do
        streams <- readTVar (gsnStreams node)
        writeTVar (gsnStreams node) (Map.insert remotePid nodeStream streams)
      -- Send RPC via the cached stream
      let rpc = subscribeRPC "outbound-topic"
      gsSendRPC (gsnRouter node) remotePid rpc
      -- Read from the other side
      result <- timeout 2000000 $ readRPCMessage remoteReadStream maxRPCSize
      case result of
        Nothing -> expectationFailure "timeout reading RPC"
        Just (Left err) -> expectationFailure $ "decode error: " ++ err
        Just (Right received) -> do
          rpcSubscriptions received `shouldBe` [SubOpts True "outbound-topic"]

    it "reuses cached stream on second call" $ do
      (sw, _localPid) <- mkTestSwitch
      node <- newGossipSubNode sw testParams
      (remotePid, _kp) <- mkTestIdentity
      -- Pre-cache a stream
      (nodeStream, remoteReadStream) <- mkMemoryStreamPair
      atomically $ do
        streams <- readTVar (gsnStreams node)
        writeTVar (gsnStreams node) (Map.insert remotePid nodeStream streams)
      -- Send two RPCs
      gsSendRPC (gsnRouter node) remotePid (subscribeRPC "topic1")
      gsSendRPC (gsnRouter node) remotePid (subscribeRPC "topic2")
      -- Read both from remote side
      r1 <- timeout 2000000 $ readRPCMessage remoteReadStream maxRPCSize
      r2 <- timeout 2000000 $ readRPCMessage remoteReadStream maxRPCSize
      case (r1, r2) of
        (Just (Right rpc1), Just (Right rpc2)) -> do
          rpcSubscriptions rpc1 `shouldBe` [SubOpts True "topic1"]
          rpcSubscriptions rpc2 `shouldBe` [SubOpts True "topic2"]
        _ -> expectationFailure "failed to read both RPCs"

  describe "sendCurrentSubscriptions" $ do
    -- Issue #155: a topic joined while no peers were known must still be
    -- announced to peers that connect afterwards (the "hello packet",
    -- pubsub/README.md). Before the fix, subscriptions were derived from
    -- mesh-map keys and a peerless join left no trace.
    it "announces a topic joined with no known peers to a later-connecting peer" $ do
      (sw, _pid) <- mkTestSwitch
      node <- newGossipSubNode sw testParams
      -- Join while the router knows no peers at all
      gossipJoin node "early-topic"
      -- A peer connects afterwards; its hello packet must carry the topic
      (nodeStream, remoteReadStream) <- mkMemoryStreamPair
      sendCurrentSubscriptions node nodeStream
      result <- timeout 2000000 $ readRPCMessage remoteReadStream maxRPCSize
      case result of
        Just (Right rpc) ->
          rpcSubscriptions rpc `shouldBe` [SubOpts True "early-topic"]
        _ -> expectationFailure "expected a subscription announcement RPC"

  describe "startGossipSub" $ do
    it "registers handler and starts heartbeat" $ do
      (sw, _pid) <- mkTestSwitch
      node <- newGossipSubNode sw testParams
      -- Before start: no handler, no heartbeat
      handlerBefore <- lookupStreamHandler sw gossipSubProtocolId
      case handlerBefore of
        Nothing -> pure ()
        Just _  -> expectationFailure "handler should not be registered before start"
      hbBefore <- atomically $ readTVar (gsnHeartbeat node)
      case hbBefore of
        Nothing -> pure ()
        Just _  -> expectationFailure "heartbeat should not be running before start"
      -- Start
      startGossipSub node
      -- After start: handler registered, heartbeat running
      handlerAfter <- lookupStreamHandler sw gossipSubProtocolId
      case handlerAfter of
        Nothing -> expectationFailure "handler should be registered"
        Just _  -> pure ()
      hbAfter <- atomically $ readTVar (gsnHeartbeat node)
      case hbAfter of
        Nothing -> expectationFailure "heartbeat should be running"
        Just _  -> pure ()
      -- Cleanup
      stopGossipSub node

    -- Issue #157: peers speaking only /meshsub/1.0.0 must still get a
    -- pubsub stream — both protocol versions are registered and accepted.
    it "registers handlers for both /meshsub/1.1.0 and /meshsub/1.0.0" $ do
      (sw, _pid) <- mkTestSwitch
      node <- newGossipSubNode sw testParams
      startGossipSub node
      h11 <- lookupStreamHandler sw gossipSubProtocolId
      h10 <- lookupStreamHandler sw gossipSubProtocolIdV10
      case (h11, h10) of
        (Just _, Just _) -> pure ()
        _ -> expectationFailure "both protocol versions should be registered"
      stopGossipSub node
      h11' <- lookupStreamHandler sw gossipSubProtocolId
      h10' <- lookupStreamHandler sw gossipSubProtocolIdV10
      case (h11', h10') of
        (Nothing, Nothing) -> pure ()
        _ -> expectationFailure "both protocol versions should be unregistered after stop"

    -- Issue #157 last item: floodsub compatibility — /floodsub/1.0.0 is
    -- registered alongside the meshsub protocols so floodsub-only peers
    -- get a pubsub stream.
    it "registers a handler for /floodsub/1.0.0 and removes it on stop" $ do
      (sw, _pid) <- mkTestSwitch
      node <- newGossipSubNode sw testParams
      startGossipSub node
      hFs <- lookupStreamHandler sw floodSubProtocolId
      case hFs of
        Just _  -> pure ()
        Nothing -> expectationFailure "/floodsub/1.0.0 should be registered"
      stopGossipSub node
      hFs' <- lookupStreamHandler sw floodSubProtocolId
      case hFs' of
        Nothing -> pure ()
        Just _  -> expectationFailure "/floodsub/1.0.0 should be unregistered after stop"

  describe "stopGossipSub" $ do
    it "cancels heartbeat and unregisters handler" $ do
      (sw, _pid) <- mkTestSwitch
      node <- newGossipSubNode sw testParams
      startGossipSub node
      -- Verify running state
      hbRunning <- atomically $ readTVar (gsnHeartbeat node)
      case hbRunning of
        Nothing -> expectationFailure "heartbeat should be running after start"
        Just _  -> pure ()
      -- Stop
      stopGossipSub node
      -- Verify stopped state
      handlerAfter <- lookupStreamHandler sw gossipSubProtocolId
      case handlerAfter of
        Nothing -> pure ()
        Just _  -> expectationFailure "handler should be unregistered after stop"
      hbAfter <- atomically $ readTVar (gsnHeartbeat node)
      case hbAfter of
        Nothing -> pure ()
        Just _  -> expectationFailure "heartbeat should not be running after stop"

    -- Issue #283: stop must detach the connection notifier. A later
    -- connection must not open a GossipSub stream or call addPeer, and
    -- a second start must not stack notifiers.
    it "does not stack connection notifiers when started twice" $ do
      (sw, _pid) <- mkTestSwitch
      node <- newGossipSubNode sw testParams
      notifiersBefore <- atomically $ length <$> readTVar (swNotifiers sw)
      startGossipSub node
      startGossipSub node
      notifiersAfter <- atomically $ length <$> readTVar (swNotifiers sw)
      (notifiersAfter - notifiersBefore) `shouldBe` 1
      stopGossipSub node

    it "opens a stream while started and ignores connections after stop" $ do
      (sw, _pid) <- mkTestSwitch
      (livePid, _) <- mkTestIdentity
      (latePid, _) <- mkTestIdentity
      node <- newGossipSubNode sw testParams
      startGossipSub node
      (liveConn, liveResponder) <- mkGossipConn livePid
      fireNotifiers sw liveConn
      opened <- waitForCachedStream node livePid 40
      opened `shouldBe` True
      cancel liveResponder
      stopGossipSub node
      (lateConn, lateResponder) <- mkGossipConn latePid
      fireNotifiers sw lateConn
      -- Give a stopped notifier time to misbehave if it is still live.
      threadDelay 300000
      streams <- atomically $ readTVar (gsnStreams node)
      Map.member latePid streams `shouldBe` False
      peers <- atomically $ readTVar (gsPeers (gsnRouter node))
      unless (Map.notMember latePid peers) $ do
        expectationFailure "stopped node must not addPeer"
      cancel lateResponder

    it "opens a stream again after stop and start" $ do
      (sw, _pid) <- mkTestSwitch
      (pid, _) <- mkTestIdentity
      node <- newGossipSubNode sw testParams
      notifiersBefore <- atomically $ length <$> readTVar (swNotifiers sw)
      startGossipSub node
      stopGossipSub node
      startGossipSub node
      notifiersAfter <- atomically $ length <$> readTVar (swNotifiers sw)
      (notifiersAfter - notifiersBefore) `shouldBe` 1
      (conn, responder) <- mkGossipConn pid
      fireNotifiers sw conn
      opened <- waitForCachedStream node pid 40
      opened `shouldBe` True
      peers <- atomically $ readTVar (gsPeers (gsnRouter node))
      Map.member pid peers `shouldBe` True
      cancel responder
      stopGossipSub node

  describe "Two-node exchange" $ do
    it "two nodes exchange subscription announcements via memory streams" $ do
      -- Node A
      (swA, pidA) <- mkTestSwitch
      nodeA <- newGossipSubNode swA testParams
      -- Node B
      (swB, pidB) <- mkTestSwitch
      nodeB <- newGossipSubNode swB testParams
      -- Create paired streams (A→B and B→A)
      (streamAtoB, streamBfromA) <- mkMemoryStreamPair
      (streamBtoA, streamAfromB) <- mkMemoryStreamPair
      -- Spawn stream handlers
      _ <- async $ handleGossipSubStream nodeB streamBfromA pidA GossipSubPeer Nothing
      _ <- async $ handleGossipSubStream nodeA streamAfromB pidB GossipSubPeer Nothing
      -- Inject cached outbound streams for sendRPC
      atomically $ do
        writeTVar (gsnStreams nodeA) (Map.singleton pidB streamAtoB)
        writeTVar (gsnStreams nodeB) (Map.singleton pidA streamBtoA)
      -- Node A subscribes to topic, which sends subscription RPCs
      gossipJoin nodeA "shared-topic"
      -- Give time for RPCs to propagate
      threadDelay 500000
      -- Node B should see A's subscription
      peersB <- atomically $ readTVar (gsPeers (gsnRouter nodeB))
      case Map.lookup pidA peersB of
        Nothing -> expectationFailure "nodeB should know about nodeA"
        Just _  -> pure ()  -- Peer registered by handleGossipSubStream

    it "publish on one node delivers message to the other" $ do
      -- Node A (publisher)
      (swA, pidA) <- mkTestSwitch
      nodeA <- newGossipSubNode swA testParams
      -- Node B (subscriber)
      (swB, pidB) <- mkTestSwitch
      nodeB <- newGossipSubNode swB testParams
      -- Set up message callback on Node B
      msgMVar <- newEmptyMVar
      atomically $ writeTVar (gsOnMessage (gsnRouter nodeB))
        (\topic msg -> putMVar msgMVar (topic, msgData msg))
      -- Create paired streams
      (streamAtoB, streamBfromA) <- mkMemoryStreamPair
      (streamBtoA, streamAfromB) <- mkMemoryStreamPair
      -- Spawn stream handlers (registers peers in each router)
      _ <- async $ handleGossipSubStream nodeB streamBfromA pidA GossipSubPeer Nothing
      _ <- async $ handleGossipSubStream nodeA streamAfromB pidB GossipSubPeer Nothing
      -- Inject cached outbound streams
      atomically $ do
        writeTVar (gsnStreams nodeA) (Map.singleton pidB streamAtoB)
        writeTVar (gsnStreams nodeB) (Map.singleton pidA streamBtoA)
      -- Let handlers register peers
      threadDelay 200000
      -- Both subscribe to the topic (this notifies known peers)
      gossipJoin nodeA "pubtest"
      gossipJoin nodeB "pubtest"
      threadDelay 500000  -- Let subscription RPCs propagate
      -- Verify: nodeA's router should know B subscribes to "pubtest"
      -- (because B's join sent subscription RPC to A via stream)
      -- Now publish from A. With floodPublish=True, publish sends to
      -- ALL peers subscribed to the topic. B should receive it.
      gossipPublish nodeA "pubtest" "hello from A"
      -- Wait for B to receive via handleRPC -> onMessage callback
      result <- timeout 3000000 $ takeMVar msgMVar
      case result of
        Nothing -> expectationFailure "nodeB did not receive message"
        Just (topic, dat) -> do
          topic `shouldBe` "pubtest"
          dat `shouldBe` "hello from A"
