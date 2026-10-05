-- | GossipSub Switch integration handler (Phase 10b).
--
-- Bridges the GossipSub Router with the Switch by:
-- 1. Registering a StreamHandler for inbound /meshsub/1.1.0 streams
-- 2. Providing a sendRPC callback that opens/reuses outbound streams
-- 3. Managing lifecycle (heartbeat start/stop)
--
-- GossipSub maintains persistent bidirectional RPC streams, unlike
-- Identify/Ping which are one-shot. Each peer has at most one cached
-- outbound stream.
module LibP2P.Protocol.GossipSub.Handler
  ( -- * Types
    GossipSubNode (..)
    -- * Construction
  , newGossipSubNode
    -- * Stream handling
  , handleGossipSubStream
  , sendCurrentSubscriptions
    -- * Lifecycle
  , startGossipSub
  , stopGossipSub
    -- * Convenience API
  , gossipJoin
  , gossipLeave
  , gossipPublish
    -- * Constants
  , gossipSubProtocolId
  , gossipSubProtocolIdV10
  , floodSubProtocolId
  ) where

import Control.Concurrent.Async (Async, async, cancel)
import Control.Concurrent.STM
  ( TVar
  , atomically
  , newTVarIO
  , readTVar
  , writeTVar
  , modifyTVar'
  )
import Control.Exception (SomeException, catch)
import Control.Monad (when)
import Data.ByteString (ByteString)
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import qualified Data.Map.Strict as Map
import Data.Time.Clock (getCurrentTime)
import LibP2P.Crypto.PeerId (PeerId)
import LibP2P.MultistreamSelect.Negotiation
  ( NegotiationResult (..)
  , ProtocolId
  , StreamIO (..)
  , negotiateInitiator
  )
import LibP2P.Protocol.GossipSub.Heartbeat (runHeartbeat)
import LibP2P.Protocol.GossipSub.Message (readRPCMessage, writeRPCMessage)
import LibP2P.Core.Binary (word32BE)
import LibP2P.Multiaddr (protocols)
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.Protocol.GossipSub.Router
  ( addPeer
  , handleRPC
  , join
  , leave
  , newRouter
  , publish
  , removePeer
  , setPeerIP
  , setSignedPeerRecord
  )
import LibP2P.Protocol.Identify.Message (IdentifyInfo (..))
import qualified Data.Set as Set
import LibP2P.Protocol.GossipSub.Types
  ( GossipSubParams
  , GossipSubRouter (..)
  , PeerProtocol (..)
  , RPC (..)
  , SubOpts (..)
  , Topic
  , emptyRPC
  , maxRPCSize
  )
import LibP2P.Switch.ConnPool (lookupConn)
import LibP2P.Switch (removeStreamHandler, setStreamHandler)
import LibP2P.Switch.Types
  ( Connection (..)
  , MuxerSession (..)
  , Switch (..)
  )

-- | GossipSub v1.1 protocol ID (preferred).
gossipSubProtocolId :: ProtocolId
gossipSubProtocolId = "/meshsub/1.1.0"

-- | GossipSub v1.0 protocol ID, advertised alongside v1.1 so that
-- v1.0-only peers still get a pubsub stream (#157).
gossipSubProtocolIdV10 :: ProtocolId
gossipSubProtocolIdV10 = "/meshsub/1.0.0"

-- | FloodSub protocol ID, advertised alongside the meshsub protocols so
-- that floodsub-only peers still get a pubsub stream (#157,
-- gossipsub-v1.0.md "Compatibility with FloodSub").
floodSubProtocolId :: ProtocolId
floodSubProtocolId = "/floodsub/1.0.0"

-- | All protocol IDs we register and offer, preferred first.
gossipSubProtocolIds :: [ProtocolId]
gossipSubProtocolIds =
  [gossipSubProtocolId, gossipSubProtocolIdV10, floodSubProtocolId]

-- | Map a negotiated protocol ID to the peer's protocol version.
protocolFor :: ProtocolId -> PeerProtocol
protocolFor proto
  | proto == gossipSubProtocolIdV10 = GossipSubV10Peer
  | proto == floodSubProtocolId     = FloodSubPeer
  | otherwise                       = GossipSubPeer

-- | A GossipSub node: Router + Switch integration.
data GossipSubNode = GossipSubNode
  { gsnRouter    :: !GossipSubRouter
  , gsnSwitch    :: !Switch
  , gsnHeartbeat :: !(TVar (Maybe (Async ())))
  , gsnStreams   :: !(TVar (Map.Map PeerId StreamIO))  -- ^ Cached outbound streams per peer
  , gsnConnectHook :: !(IORef (Maybe (Connection -> IO ())))
    -- ^ Connection notifier body. 'stopGossipSub' clears it so a stopped
    -- node cannot open streams for connections that arrive later (#283).
  , gsnNotifierInstalled :: !(TVar Bool)
    -- ^ The Switch holds one wrapper. Start is idempotent so a second
    -- start does not stack another wrapper on 'swNotifiers'.
  , gsnStarted :: !(TVar Bool)
    -- ^ True between a successful start and stop. A second start does
    -- not register another handler set or heartbeat.
  }

-- | Create a new GossipSub node with a Router wired to the Switch.
--
-- The Router's gsSendRPC callback opens/reuses outbound streams to peers
-- via the Switch's connection pool.
newGossipSubNode :: Switch -> GossipSubParams -> IO GossipSubNode
newGossipSubNode sw params = do
  streamsVar <- newTVarIO Map.empty
  hbVar <- newTVarIO Nothing
  hook <- newIORef Nothing
  installed <- newTVarIO False
  started <- newTVarIO False
  -- Create router with real sendRPC that uses the Switch
  let localPid = swLocalPeerId sw
  router <- newRouter params localPid (sendRPCviaSwitch sw streamsVar) getCurrentTime
  pure GossipSubNode
    { gsnRouter    = router
    , gsnSwitch    = sw
    , gsnHeartbeat = hbVar
    , gsnStreams   = streamsVar
    , gsnConnectHook = hook
    , gsnNotifierInstalled = installed
    , gsnStarted = started
    }

-- | Send an RPC to a peer via cached or newly opened stream.
sendRPCviaSwitch :: Switch -> TVar (Map.Map PeerId StreamIO) -> PeerId -> RPC -> IO ()
sendRPCviaSwitch sw streamsVar pid rpc = do
  -- Try to use cached stream
  mCached <- atomically $ Map.lookup pid <$> readTVar streamsVar
  case mCached of
    Just stream -> do
      -- Try sending on cached stream; reopen on failure
      sendResult <- trySend stream rpc
      case sendResult of
        Right () -> pure ()
        Left _ -> do
          atomically $ modifyTVar' streamsVar (Map.delete pid)
          openAndSend sw streamsVar pid rpc
    Nothing -> openAndSend sw streamsVar pid rpc

-- | Open a new outbound stream to a peer and send an RPC.
openAndSend :: Switch -> TVar (Map.Map PeerId StreamIO) -> PeerId -> RPC -> IO ()
openAndSend sw streamsVar pid rpc = do
  mStream <- openStreamToPeer sw pid
  case mStream of
    Nothing -> pure ()  -- No connection to peer; fire-and-forget
    Just stream -> do
      atomically $ modifyTVar' streamsVar (Map.insert pid stream)
      _ <- trySend stream rpc
      pure ()

-- | Open a new mux stream to a peer and negotiate GossipSub protocol.
openStreamToPeer :: Switch -> PeerId -> IO (Maybe StreamIO)
openStreamToPeer sw pid = do
  mConn <- atomically $ lookupConn (swConnPool sw) pid
  case mConn of
    Nothing -> pure Nothing
    Just conn -> do
      result <- (Right <$> openAndNegotiate conn) `catch`
                  (\(_ :: SomeException) -> pure (Left ()))
      case result of
        Left () -> pure Nothing
        Right mStream -> pure (fst <$> mStream)

-- | Open a mux stream and negotiate a GossipSub protocol, preferring
-- /meshsub/1.1.0 and falling back to /meshsub/1.0.0 (#157).
openAndNegotiate :: Connection -> IO (Maybe (StreamIO, PeerProtocol))
openAndNegotiate conn = do
  stream <- muxOpenStream (connSession conn)
  negResult <- negotiateInitiator stream gossipSubProtocolIds
  case negResult of
    Accepted proto -> pure (Just (stream, protocolFor proto))
    NoProtocol -> pure Nothing

-- | Extract the remote IP bytes (4 for IPv4, 16 for IPv6) from a
-- connection's multiaddr, for P6 IP colocation scoring.
remoteIPBytes :: Connection -> Maybe ByteString
remoteIPBytes conn = go (protocols (connRemoteAddr conn))
  where
    go (IP4 w  : _)   = Just (word32BE w)
    go (IP6 bs : _)   = Just bs
    go (_      : ps)  = go ps
    go []             = Nothing

-- | Try to send an RPC on a stream, catching exceptions.
trySend :: StreamIO -> RPC -> IO (Either () ())
trySend stream rpc =
  (writeRPCMessage stream rpc >> pure (Right ()))
    `catch` (\(_ :: SomeException) -> pure (Left ()))

-- | Handle an inbound GossipSub stream.
--
-- Reads framed RPCs in a loop and dispatches each to the Router's handleRPC.
-- The peer's negotiated protocol version gates v1.1 control extensions.
-- On error or EOF, cleans up the peer's cached stream and removes the peer.
handleGossipSubStream :: GossipSubNode -> StreamIO -> PeerId -> PeerProtocol
                      -> Maybe ByteString -> IO ()
handleGossipSubStream node stream pid proto mIP = do
  -- Register peer with router (IP feeds P6 colocation scoring)
  now <- getCurrentTime
  addPeer (gsnRouter node) pid proto False now
  mapM_ (setPeerIP (gsnRouter node) pid) mIP
  syncSignedPeerRecord node pid
  -- Read loop
  readLoop
  -- Cleanup on disconnect
  removePeer (gsnRouter node) pid
  atomically $ modifyTVar' (gsnStreams node) (Map.delete pid)
  where
    readLoop = do
      result <- readRPCMessage stream maxRPCSize
      case result of
        Left _ -> pure ()  -- Error/EOF: stop loop
        Right rpc -> do
          handleRPC (gsnRouter node) pid rpc
          readLoop

-- | Feed the peer's signed peer record (obtained via identify, already
-- verified against the authenticated peer id on receipt) from the
-- Switch's peer store into the router, so PRUNE-with-PX can attach it
-- when advertising this peer (#230).
syncSignedPeerRecord :: GossipSubNode -> PeerId -> IO ()
syncSignedPeerRecord node pid = do
  store <- atomically $ readTVar (swPeerStore (gsnSwitch node))
  mapM_ (setSignedPeerRecord (gsnRouter node) pid)
    (Map.lookup pid store >>= idSignedPeerRecord)

-- | Start the GossipSub node: register stream handler, notifier, and start heartbeat.
--
-- Idempotent. A second start does not stack connection notifiers or
-- heartbeats. 'stopGossipSub' clears the notifier body so a later
-- connection does not open a stream (#283).
startGossipSub :: GossipSubNode -> IO ()
startGossipSub node = do
  writeIORef (gsnConnectHook node) (Just (onNewConnection node))
  installConnectNotifier node
  claimed <- claimStart node
  when claimed $ do
    registerHandlers node
    hbAsync <- runHeartbeat (gsnRouter node)
    atomically $ writeTVar (gsnHeartbeat node) (Just hbAsync)

-- | Claim the start so two concurrent or repeated starts share one heartbeat.
claimStart :: GossipSubNode -> IO Bool
claimStart node = atomically $ do
  started <- readTVar (gsnStarted node)
  if started
    then pure False
    else do
      writeTVar (gsnStarted node) True
      pure True

-- | Install the connection-notifier wrapper once. Later starts reuse it.
installConnectNotifier :: GossipSubNode -> IO ()
installConnectNotifier node = do
  install <- atomically $ do
    installed <- readTVar (gsnNotifierInstalled node)
    if installed
      then pure False
      else do
        writeTVar (gsnNotifierInstalled node) True
        pure True
  when install $ atomically $
    modifyTVar' (swNotifiers (gsnSwitch node)) (runConnectHook node :)

-- | Run the current connect hook, or do nothing after stop.
runConnectHook :: GossipSubNode -> Connection -> IO ()
runConnectHook node conn = do
  mAct <- readIORef (gsnConnectHook node)
  mapM_ ($ conn) mAct

-- | Register inbound stream handlers for every advertised protocol id.
registerHandlers :: GossipSubNode -> IO ()
registerHandlers node =
  mapM_ (\protoId ->
      setStreamHandler (gsnSwitch node) protoId
        (\conn stream ->
          handleGossipSubStream node stream (connPeerId conn)
            (protocolFor protoId) (remoteIPBytes conn)))
    gossipSubProtocolIds

-- | Called on new connection: open a GossipSub stream to the peer.
-- Caches the stream for outbound writes and starts a read loop
-- on it to receive RPCs sent back by the remote peer (e.g. subscriptions).
onNewConnection :: GossipSubNode -> Connection -> IO ()
onNewConnection node conn = do
  let pid = connPeerId conn
  -- Open a mux stream and negotiate GossipSub protocol
  mStream <- openAndNegotiate conn
  case mStream of
    Nothing -> pure ()  -- Peer doesn't support GossipSub
    Just (stream, proto) -> do
      -- Cache the outbound stream
      atomically $ modifyTVar' (gsnStreams node) (Map.insert pid stream)
      -- Register peer with its negotiated protocol version
      -- (IP feeds P6 colocation scoring)
      now <- getCurrentTime
      addPeer (gsnRouter node) pid proto True now
      mapM_ (setPeerIP (gsnRouter node) pid) (remoteIPBytes conn)
      syncSignedPeerRecord node pid
      -- Send current subscriptions to the new peer
      sendCurrentSubscriptions node stream
      -- Start read loop on this stream to receive RPCs from the peer
      -- (e.g. subscription announcements sent back on the same yamux stream)
      _ <- async $ outboundReadLoop node stream pid
      pure ()

-- | Send current topic subscriptions to a newly connected peer.
-- This ensures peers joining after we've already subscribed still learn
-- about our subscriptions (standard GossipSub behavior).
-- Writes directly to the stream to avoid any routing issues.
sendCurrentSubscriptions :: GossipSubNode -> StreamIO -> IO ()
sendCurrentSubscriptions node stream = do
  let router = gsnRouter node
  -- Read the subscription set, not mesh keys: a topic joined before any
  -- peer was known has no mesh entry but must still be announced (#155).
  subs <- atomically $ readTVar (gsSubscriptions router)
  let topics = Set.toList subs
  if null topics
    then pure ()
    else do
      let subRPC = emptyRPC
            { rpcSubscriptions = map (\t -> SubOpts True t) topics }
      _ <- trySend stream subRPC
      pure ()

-- | Read loop on the outbound stream.
-- Handles RPCs sent back by the remote peer on the same yamux stream
-- (e.g. subscription announcements). Does NOT remove the peer on
-- EOF since the inbound handler or another mechanism manages peer lifecycle.
outboundReadLoop :: GossipSubNode -> StreamIO -> PeerId -> IO ()
outboundReadLoop node stream pid = loop
  where
    loop = do
      result <- readRPCMessage stream maxRPCSize
      case result of
        Left _ -> pure ()  -- EOF or error: stop
        Right rpc -> do
          handleRPC (gsnRouter node) pid rpc
          loop

-- | Stop the GossipSub node: disable the connection notifier, cancel
-- heartbeat, and unregister handlers.
--
-- The wrapper stays on 'swNotifiers' but reads a cleared hook, so a
-- connection established after stop does not open a stream or call
-- 'addPeer'. A later start re-arms the same wrapper (#283).
stopGossipSub :: GossipSubNode -> IO ()
stopGossipSub node = do
  writeIORef (gsnConnectHook node) Nothing
  atomically $ writeTVar (gsnStarted node) False
  mHb <- atomically $ do
    hb <- readTVar (gsnHeartbeat node)
    writeTVar (gsnHeartbeat node) Nothing
    pure hb
  case mHb of
    Just hbAsync -> cancel hbAsync `catch` (\(_ :: SomeException) -> pure ())
    Nothing -> pure ()
  mapM_ (removeStreamHandler (gsnSwitch node)) gossipSubProtocolIds

-- | Subscribe to a topic.
gossipJoin :: GossipSubNode -> Topic -> IO ()
gossipJoin node topic = join (gsnRouter node) topic

-- | Unsubscribe from a topic.
gossipLeave :: GossipSubNode -> Topic -> IO ()
gossipLeave node topic = leave (gsnRouter node) topic

-- | Publish a message to a topic (signed with the Switch's identity key).
gossipPublish :: GossipSubNode -> Topic -> ByteString -> IO ()
gossipPublish node topic payload =
  publish (gsnRouter node) topic payload (Just (swIdentityKey (gsnSwitch node)))
