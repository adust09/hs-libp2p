-- | End-to-end integration tests for the libp2p stack (Phase 10c).
--
-- Tests the complete protocol pipeline over real TCP connections:
-- TCP transport → Noise XX → Yamux → multistream-select → protocols.
module LibP2P.IntegrationSpec (spec) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.Async (forConcurrently)
import Control.Concurrent.MVar (newEmptyMVar, putMVar, takeMVar)
import Control.Concurrent.STM
  ( atomically
  , modifyTVar'
  , readTVar
  , retry
  , writeTVar
  )
import Control.Exception (SomeException, bracket, try)
import Control.Monad (replicateM)
import qualified Data.ByteString as BS
import Data.IORef (modifyIORef', newIORef, readIORef)
import qualified Data.Map.Strict as Map
import Data.Time.Clock (getCurrentTime)
import LibP2P.Crypto.Ed25519 (generateKeyPair)
import LibP2P.Crypto.Key (KeyPair, publicKey)
import LibP2P.Crypto.PeerId (PeerId, fromPublicKey, peerIdBytes)
import LibP2P.DHT
  ( DHTMode (..)
  , DHTNode (..)
  , decodePeerAddrs
  , newDHTNode
  , registerDHTHandler
  )
import LibP2P.DHT.Distance (peerIdToKey)
-- Qualified: DHTMessage's msgKey clashes with PubSubMessage's msgKey.
import qualified LibP2P.DHT.Message as DHTMsg
import LibP2P.DHT.RoutingTable (insertPeer)
import LibP2P.DHT.Types (BucketEntry (..), ConnectionType (..))
import LibP2P.Multiaddr (Multiaddr (..), toBytes)
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.MultistreamSelect.Negotiation
  ( NegotiationResult (..)
  , StreamIO (..)
  , negotiateInitiator
  )
import LibP2P.Protocol.GossipSub.Handler
  ( gossipJoin
  , gossipPublish
  , newGossipSubNode
  , startGossipSub
  , stopGossipSub
  , GossipSubNode (..)
  )
import LibP2P.Protocol.GossipSub.Types
  ( GossipSubRouter (..)
  , PubSubMessage (..)
  , defaultGossipSubParams
  , GossipSubParams (..)
  )
import LibP2P.Protocol.Identify
  ( registerIdentifyHandlers
  , requestIdentify
  )
import LibP2P.Protocol.Identify.Message (IdentifyInfo (..))
import LibP2P.Protocol.Ping
  ( PingResult (..)
  , ping
  , registerPingHandler
  , sendPing
  , withPingSession
  )
import LibP2P.Switch.ConnPool (lookupConn)
import LibP2P.Switch.Dial (dial)
import LibP2P.Switch.Listen
  ( ConnectionGater (..)
  , defaultConnectionGater
  , switchListen
  )
import LibP2P.Switch (addTransport, newSwitch, setStreamHandler, switchClose)
import LibP2P.Switch.Types
  ( Connection (..)
  , DialError (..)
  , MuxerSession (..)
  , Switch (..)
  )
import LibP2P.Transport.TCP (newTCPTransport)
import System.Timeout (timeout)
import Test.Hspec

-- | Generate a test identity (PeerId, KeyPair).
mkTestIdentity :: IO (PeerId, KeyPair)
mkTestIdentity = do
  Right kp <- generateKeyPair
  let pid = fromPublicKey (publicKey kp)
  pure (pid, kp)

-- | Loopback address with port 0 (OS assigns ephemeral port).
loopbackAddr :: Multiaddr
loopbackAddr = Multiaddr [IP4 0x7f000001, TCP 0]

-- | Read exactly n bytes from a stream.
readN :: StreamIO -> Int -> IO BS.ByteString
readN stream n = BS.pack <$> replicateM n (streamReadByte stream)

-- | Create a test node: Switch + TCP transport + Identify + Ping.
-- Returns the Switch, PeerId, and KeyPair.
withTestNode :: (Switch -> PeerId -> IO a) -> IO a
withTestNode action = bracket setup teardown (\(sw, pid, _kp) -> action sw pid)
  where
    setup = do
      (pid, kp) <- mkTestIdentity
      sw <- newSwitch pid kp
      tcp <- newTCPTransport
      addTransport sw tcp
      registerIdentifyHandlers sw
      registerPingHandler sw
      pure (sw, pid, kp)
    teardown (sw, _pid, _kp) = switchClose sw

-- | Create a listening test node: Switch + TCP + Identify + Ping,
-- bound to a loopback address. The Switch is closed on exit, even
-- when the action throws.
withListeningNode :: ((Switch, PeerId, Multiaddr) -> IO a) -> IO a
withListeningNode action = bracket setup teardown action
  where
    setup = do
      (pid, kp) <- mkTestIdentity
      sw <- newSwitch pid kp
      tcp <- newTCPTransport
      addTransport sw tcp
      registerIdentifyHandlers sw
      registerPingHandler sw
      addrs <- switchListen sw defaultConnectionGater [loopbackAddr]
      pure (sw, pid, head addrs)
    teardown (sw, _pid, _addr) = switchClose sw

-- | Block until the given peer shows up in the switch's connection pool.
-- Replaces the previous fixed 300ms sleep: the pool is STM state, so the
-- test can wait on the exact condition instead of a wall-clock guess.
waitForPeerInPool :: Switch -> PeerId -> IO ()
waitForPeerInPool sw pid = do
  seen <- timeout 5000000 $ atomically $ do
    mConn <- lookupConn (swConnPool sw) pid
    maybe retry (const (pure ())) mConn
  case seen of
    Just () -> pure ()
    Nothing -> fail "waitForPeerInPool: peer never appeared in the pool"

-- | Create two connected test nodes: node B listens, node A dials.
-- Returns both Switches, PeerIds, and the connection from A to B.
-- Both Switches are torn down via bracket even when the action fails,
-- so a failing assertion cannot leak listeners into later tests.
withConnectedPair :: ((Switch, PeerId) -> (Switch, PeerId) -> Connection -> IO a) -> IO a
withConnectedPair action =
  withListeningNode $ \(swB, pidB, listenAddr) ->
    withTestNode $ \swA pidA -> do
      dialResult <- dial swA pidB [listenAddr]
      case dialResult of
        Left err -> fail $ "withConnectedPair: dial failed: " ++ show err
        Right conn -> do
          -- The dialer returns before the listener finishes pool insertion;
          -- wait on the pool itself rather than sleeping.
          waitForPeerInPool swB pidA
          action (swA, pidA) (swB, pidB) conn

spec :: Spec
spec = do
  describe "TCP + Upgrade" $ do
    it "two nodes: switchListen + dial -> connection in pool, correct PeerIds" $ do
      withConnectedPair $ \(swA, pidA) (swB, pidB) conn -> do
        -- A's connection points to B
        connPeerId conn `shouldBe` pidB
        -- B should see A in its pool
        poolConn <- atomically $ lookupConn (swConnPool swB) pidA
        case poolConn of
          Nothing -> expectationFailure "listener should see dialer in pool"
          Just c  -> connPeerId c `shouldBe` pidA

    it "upgraded connection records /noise security and /yamux/1.0.0 muxing on both sides" $ do
      withConnectedPair $ \(_swA, pidA) (swB, _pidB) conn -> do
        connSecurity conn `shouldBe` "/noise"
        connMuxer conn `shouldBe` "/yamux/1.0.0"
        poolConn <- atomically $ lookupConn (swConnPool swB) pidA
        case poolConn of
          Nothing -> expectationFailure "listener should see dialer in pool"
          Just c -> do
            connSecurity c `shouldBe` "/noise"
            connMuxer c `shouldBe` "/yamux/1.0.0"

  describe "Ping over real TCP" $ do
    it "sendPing returns valid RTT (>0, <1s for loopback)" $ do
      withConnectedPair $ \(swA, _pidA) _nodeB conn -> do
        result <- timeout 5000000 $ sendPing swA conn
        case result of
          Nothing -> expectationFailure "ping timed out"
          Just (Left err) -> expectationFailure $ "ping failed: " ++ show err
          Just (Right (PingResult rtt)) -> do
            rtt `shouldSatisfy` (> 0)
            rtt `shouldSatisfy` (< 1)  -- < 1 second for loopback

  describe "Identify over real TCP" $ do
    it "requestIdentify returns correct protocols and agentVersion" $ do
      withConnectedPair $ \(swA, _pidA) _nodeB conn -> do
        result <- timeout 5000000 $ requestIdentify swA conn
        case result of
          Nothing -> expectationFailure "identify timed out"
          Just (Left err) -> expectationFailure $ "identify failed: " ++ err
          Just (Right info) -> do
            idAgentVersion info `shouldBe` Just "hs-libp2p/0.1.0"
            idProtocols info `shouldSatisfy` (not . null)

    it "idListenAddrs populated after switchListen" $ do
      withConnectedPair $ \(swA, _pidA) _nodeB conn -> do
        result <- timeout 5000000 $ requestIdentify swA conn
        case result of
          Nothing -> expectationFailure "identify timed out"
          Just (Left err) -> expectationFailure $ "identify failed: " ++ err
          Just (Right info) -> do
            -- B is listening, so idListenAddrs should be non-empty
            idListenAddrs info `shouldSatisfy` (not . null)

    it "observedAddr echoes the dialer's own address as seen by the listener" $ do
      -- Regression for #167: the responder must fill observedAddr with the
      -- initiator's source address. On loopback that address is exactly the
      -- dialer's local socket address (ephemeral port included).
      withConnectedPair $ \(swA, _pidA) _nodeB conn -> do
        result <- timeout 5000000 $ requestIdentify swA conn
        case result of
          Nothing -> expectationFailure "identify timed out"
          Just (Left err) -> expectationFailure $ "identify failed: " ++ err
          Just (Right info) ->
            idObservedAddr info `shouldBe` Just (toBytes (connLocalAddr conn))

    it "switchListen pushes the new listen address to already-connected peers" $ do
      -- specs/identify push: when local state advertised via identify
      -- changes (here: listen addresses), connected peers are updated
      -- proactively over /ipfs/id/push/1.0.0 — B's peer store must gain
      -- A's new address without B ever calling requestIdentify.
      withConnectedPair $ \(swA, pidA) (swB, _pidB) _conn -> do
        newAddrs <- switchListen swA defaultConnectionGater [loopbackAddr]
        let expected = toBytes (head newAddrs)
        seen <- timeout 5000000 $ atomically $ do
          store <- readTVar (swPeerStore swB)
          case Map.lookup pidA store of
            Just info | expected `elem` idListenAddrs info -> pure ()
            _ -> retry
        case seen of
          Just () -> pure ()
          Nothing -> expectationFailure
            "B never received A's pushed listen address"

  describe "Multi-protocol" $ do
    it "successive pings reuse a single outbound stream over the same connection" $ do
      -- Regression for #163. specs/ping/ping.md: "The dialing peer MUST
      -- NOT keep more than one outbound stream for the ping protocol per
      -- peer." Both pings must run on one stream, opened exactly once.
      withConnectedPair $ \(swA, _pidA) _nodeB conn -> do
        opensRef <- newIORef (0 :: Int)
        let realSession = connSession conn
            countingSession = realSession
              { muxOpenStream = do
                  modifyIORef' opensRef (+ 1)
                  muxOpenStream realSession
              }
            countingConn = conn { connSession = countingSession }
        result <- timeout 10000000 $ withPingSession swA countingConn $ \sess -> do
          r1 <- ping sess
          r2 <- ping sess
          pure (r1, r2)
        case result of
          Nothing -> expectationFailure "ping session timed out"
          Just (Left err) ->
            expectationFailure $ "ping session failed to open: " ++ show err
          Just (Right (r1, r2)) -> do
            case r1 of
              Left err -> expectationFailure $ "ping 1 failed: " ++ show err
              Right (PingResult rtt1) -> rtt1 `shouldSatisfy` (> 0)
            case r2 of
              Left err -> expectationFailure $ "ping 2 failed: " ++ show err
              Right (PingResult rtt2) -> rtt2 `shouldSatisfy` (> 0)
        opens <- readIORef opensRef
        opens `shouldBe` 1

    it "10 concurrent pings on one session share a single outbound stream" $ do
      -- ping.md: "The dialing peer MUST NOT keep more than one outbound
      -- stream for the ping protocol per peer" — even when callers ping
      -- concurrently, the session serializes them on its one stream and
      -- every ping still gets its own matching echo.
      withConnectedPair $ \(swA, _pidA) _nodeB conn -> do
        opensRef <- newIORef (0 :: Int)
        let realSession = connSession conn
            countingSession = realSession
              { muxOpenStream = do
                  modifyIORef' opensRef (+ 1)
                  muxOpenStream realSession
              }
            countingConn = conn { connSession = countingSession }
        result <- timeout 30000000 $ withPingSession swA countingConn $ \sess ->
          forConcurrently [1 .. 10 :: Int] $ \_ -> ping sess
        case result of
          Nothing -> expectationFailure "concurrent ping session timed out"
          Just (Left err) ->
            expectationFailure $ "ping session failed to open: " ++ show err
          Just (Right results) -> do
            length results `shouldBe` 10
            mapM_
              (\r -> case r of
                 Right (PingResult rtt) -> rtt `shouldSatisfy` (> 0)
                 Left err -> expectationFailure $ "concurrent ping failed: " ++ show err)
              results
        opens <- readIORef opensRef
        opens `shouldBe` 1

    it "unknown protocol gets na over real TCP and the connection stays usable" $ do
      withConnectedPair $ \(swA, _pidA) _nodeB conn -> do
        stream <- muxOpenStream (connSession conn)
        result <- timeout 5000000 $
          negotiateInitiator stream ["/test/does-not-exist/1.0.0"]
        result `shouldBe` Just NoProtocol
        -- The failed negotiation must not poison the muxed connection.
        pingAfter <- timeout 5000000 $ sendPing swA conn
        case pingAfter of
          Just (Right (PingResult rtt)) -> rtt `shouldSatisfy` (> 0)
          Just (Left err) ->
            expectationFailure $ "ping after failed negotiation: " ++ show err
          Nothing ->
            expectationFailure "connection unusable after failed negotiation"

  describe "DHT over real TCP" $ do
    it "FIND_NODE returns the responder's routing table entries with addresses" $ do
      -- Regression for #168/#194: the outbound RPC path must reach a real
      -- peer over the Switch, and Peer records must carry multiaddrs.
      withConnectedPair $ \(swA, _pidA) (swB, pidB) _conn -> do
        dhtB <- newDHTNode swB DHTServer
        registerDHTHandler dhtB
        dhtA <- newDHTNode swA DHTClient
        -- Seed B's routing table with a fabricated third peer.
        (pidC, _kpC) <- mkTestIdentity
        now <- getCurrentTime
        let addrC = Multiaddr [IP4 0x7f000001, TCP 4001]
            entryC = BucketEntry pidC (peerIdToKey pidC) [addrC] now NotConnected
        atomically $ modifyTVar' (dhtRoutingTable dhtB) (fst . insertPeer entryC)
        let request = DHTMsg.emptyDHTMessage
              { DHTMsg.msgType = DHTMsg.FindNode
              , DHTMsg.msgKey = peerIdBytes pidC
              }
        result <- timeout 10000000 $ dhtSendRequest dhtA pidB request
        case result of
          Nothing -> expectationFailure "FIND_NODE timed out"
          Just (Left err) -> expectationFailure $ "FIND_NODE failed: " ++ err
          Just (Right resp) -> do
            DHTMsg.msgType resp `shouldBe` DHTMsg.FindNode
            map DHTMsg.dhtPeerId (DHTMsg.msgCloserPeers resp)
              `shouldContain` [peerIdBytes pidC]
            concatMap DHTMsg.dhtPeerAddrs (DHTMsg.msgCloserPeers resp)
              `shouldContain` [toBytes addrC]

    it "three nodes: dialer learns a third peer via FIND_NODE, dials it, and pings it" $ do
      -- A full discovery walk over three real nodes: A asks B for C,
      -- decodes C's address from the wire response, dials C, and pings.
      withListeningNode $ \(_swC, pidC, addrC) ->
        withConnectedPair $ \(swA, _pidA) (swB, pidB) _conn -> do
          dhtB <- newDHTNode swB DHTServer
          registerDHTHandler dhtB
          dhtA <- newDHTNode swA DHTClient
          now <- getCurrentTime
          let entryC = BucketEntry pidC (peerIdToKey pidC) [addrC] now NotConnected
          atomically $ modifyTVar' (dhtRoutingTable dhtB) (fst . insertPeer entryC)
          let request = DHTMsg.emptyDHTMessage
                { DHTMsg.msgType = DHTMsg.FindNode
                , DHTMsg.msgKey = peerIdBytes pidC
                }
          result <- timeout 10000000 $ dhtSendRequest dhtA pidB request
          case result of
            Nothing -> expectationFailure "FIND_NODE timed out"
            Just (Left err) -> expectationFailure $ "FIND_NODE failed: " ++ err
            Just (Right resp) -> do
              let records = filter
                    ((== peerIdBytes pidC) . DHTMsg.dhtPeerId)
                    (DHTMsg.msgCloserPeers resp)
                  learnedAddrs =
                    decodePeerAddrs (concatMap DHTMsg.dhtPeerAddrs records)
              learnedAddrs `shouldBe` [addrC]
              dialResult <- timeout 10000000 $ dial swA pidC learnedAddrs
              case dialResult of
                Just (Right connC) -> do
                  pingResult <- timeout 5000000 $ sendPing swA connC
                  case pingResult of
                    Just (Right (PingResult rtt)) -> rtt `shouldSatisfy` (> 0)
                    other -> expectationFailure $
                      "ping to discovered peer failed: " ++ show other
                Just (Left err) -> expectationFailure $
                  "dial to discovered peer failed: " ++ show err
                Nothing ->
                  expectationFailure "dial to discovered peer timed out"

  describe "Concurrent streams over real TCP" $ do
    it "4 concurrent streams echo distinct payloads larger than one noise frame" $ do
      -- 66000 bytes exceeds the 65535-byte noise frame limit, so a single
      -- stream write must be chunked across noise frames (#183) and
      -- reassembled intact — on four streams at once.
      withConnectedPair $ \_nodeA (swB, _pidB) conn -> do
        let echoProto = "/hs-libp2p/test-echo/1.0.0"
            payloadSize = 66000
        setStreamHandler swB echoProto $ \_c stream -> do
          payload <- readN stream payloadSize
          streamWrite stream payload
        result <- timeout 60000000 $
          forConcurrently [0 .. 3 :: Int] $ \i -> do
            stream <- muxOpenStream (connSession conn)
            negotiated <- negotiateInitiator stream [echoProto]
            negotiated `shouldBe` Accepted echoProto
            let payload = BS.replicate payloadSize (fromIntegral (0x41 + i))
            streamWrite stream payload
            echoed <- readN stream payloadSize
            pure (echoed == payload)
        result `shouldBe` Just [True, True, True, True]

  describe "GossipSub over real TCP" $ do
    it "two nodes join topic, publish -> receive" $ do
      let gsParams = defaultGossipSubParams
            { paramHeartbeatInterval = 60.0  -- Very long to avoid interference
            }
      -- Node B (listener)
      (pidB, kpB) <- mkTestIdentity
      swB <- newSwitch pidB kpB
      tcpB <- newTCPTransport
      addTransport swB tcpB
      gsNodeB <- newGossipSubNode swB gsParams
      startGossipSub gsNodeB
      -- Message callback on B
      msgMVar <- newEmptyMVar
      atomically $ writeTVar (gsOnMessage (gsnRouter gsNodeB))
        (\topic msg -> putMVar msgMVar (topic, msgData msg))
      addrs <- switchListen swB defaultConnectionGater [loopbackAddr]
      let listenAddr = head addrs
      -- Node A (dialer)
      (_pidA, kpA) <- mkTestIdentity
      swA <- newSwitch (fromPublicKey (publicKey kpA)) kpA
      tcpA <- newTCPTransport
      addTransport swA tcpA
      gsNodeA <- newGossipSubNode swA gsParams
      startGossipSub gsNodeA
      -- Dial A -> B: establish connection
      dialResult <- timeout 5000000 $ dial swA pidB [listenAddr]
      case dialResult of
        Nothing -> do
          stopGossipSub gsNodeA; stopGossipSub gsNodeB
          switchClose swA; switchClose swB
          expectationFailure "dial timed out"
        Just (Left err) -> do
          stopGossipSub gsNodeA; stopGossipSub gsNodeB
          switchClose swA; switchClose swB
          expectationFailure $ "dial failed: " ++ show err
        Just (Right conn) -> do
          -- Wait for mux + stream accept loop to start on both sides
          threadDelay 500000
          -- Both nodes join the topic
          gossipJoin gsNodeB "test-topic"
          threadDelay 200000
          gossipJoin gsNodeA "test-topic"
          -- Let subscription RPCs propagate over the real streams
          threadDelay 1000000
          -- Publish from A (floodPublish=True sends to all subscribed peers)
          gossipPublish gsNodeA "test-topic" "integration test message"
          -- Wait for B to receive
          result <- timeout 5000000 $ takeMVar msgMVar
          -- Cleanup
          stopGossipSub gsNodeA; stopGossipSub gsNodeB
          switchClose swA; switchClose swB
          case result of
            Nothing -> expectationFailure "nodeB did not receive message"
            Just (topic, dat) -> do
              topic `shouldBe` "test-topic"
              dat `shouldBe` "integration test message"

  describe "Connection gating" $ do
    it "gateSecured=False rejects peer, no pool entry" $ do
      -- Listener with secured rejection
      (pidB, kpB) <- mkTestIdentity
      swB <- newSwitch pidB kpB
      tcpB <- newTCPTransport
      addTransport swB tcpB
      let securedRejectGater = ConnectionGater
            { gateAccept  = \_ -> pure True
            , gateSecured = \_ -> pure False
            }
      addrs <- switchListen swB securedRejectGater [loopbackAddr]
      let listenAddr = head addrs
      -- Dialer
      (pidA, kpA) <- mkTestIdentity
      swA <- newSwitch pidA kpA
      tcpA <- newTCPTransport
      addTransport swA tcpA
      _dialResult <- timeout 5000000 $ dial swA pidB [listenAddr]
      threadDelay 500000
      -- Verify B does NOT have A in its pool
      poolConn <- atomically $ lookupConn (swConnPool swB) pidA
      case poolConn of
        Nothing -> pure ()
        Just _  -> expectationFailure "connection should not be in pool"
      switchClose swA
      switchClose swB

  describe "Lifecycle" $ do
    it "switchClose cleanly tears down listeners and connections" $ do
      withTestNode $ \sw _pid -> do
        _addrs <- switchListen sw defaultConnectionGater [loopbackAddr]
        -- Verify listening
        listeners <- atomically $ readTVar (swListeners sw)
        length listeners `shouldBe` 1
        -- Close
        switchClose sw
        -- Verify teardown
        listenersAfter <- atomically $ readTVar (swListeners sw)
        length listenersAfter `shouldBe` 0
        closed <- atomically $ readTVar (swClosed sw)
        closed `shouldBe` True

    it "dial after switchClose fails with DialSwitchClosed" $ do
      (pidB, kpB) <- mkTestIdentity
      swB <- newSwitch pidB kpB
      -- Create a switch and close it
      (pidA, kpA) <- mkTestIdentity
      swA <- newSwitch pidA kpA
      tcpA <- newTCPTransport
      addTransport swA tcpA
      switchClose swA
      -- Dial should fail
      result <- dial swA pidB [loopbackAddr]
      case result of
        Left DialSwitchClosed -> pure ()
        Left err -> expectationFailure $ "expected DialSwitchClosed, got: " ++ show err
        Right _ -> expectationFailure "dial should fail after switchClose"
      switchClose swB
