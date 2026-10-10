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
import Control.Concurrent.MVar (MVar, newMVar, withMVar)
import Control.Concurrent.STM
  ( STM
  , TVar
  , atomically
  , newTVarIO
  , readTVar
  , writeTVar
  , modifyTVar'
  )
import Control.Exception (SomeException, catch, mask_, onException)
import Control.Monad (void, when)
import Data.ByteString (ByteString)
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import qualified Data.Map.Strict as Map
import Data.Maybe (isNothing)
import Data.Time.Clock (getCurrentTime)
import LibP2P.Crypto.PeerId (PeerId)
import LibP2P.MultistreamSelect.Negotiation
  ( NegotiationResult (..)
  , ProtocolId
  , StreamIO (..)
  , closeQuietly
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
import LibP2P.Switch.Connection (newStream)
import LibP2P.Switch.ConnPool (lookupConn)
import LibP2P.Switch (removeStreamHandler, setStreamHandler)
import LibP2P.Switch.Types
  ( ConnState
  , Connection (..)
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

-- | Identity and owning connection for a cached outbound stream.
data GossipStreamMeta = GossipStreamMeta
  { gsmOwner :: !(TVar ConnState)
  , gsmToken :: !(IORef ())
  }

-- | A GossipSub node: Router + Switch integration.
data GossipSubNode = GossipSubNode
  { gsnRouter    :: !GossipSubRouter
  , gsnSwitch    :: !Switch
  , gsnHeartbeat :: !(TVar (Maybe (Async ())))
  , gsnStreams   :: !(TVar (Map.Map PeerId StreamIO))  -- ^ Cached outbound streams per peer
  , gsnStreamMeta :: !(TVar (Map.Map PeerId GossipStreamMeta))
    -- ^ Owner and identity of each managed stream in 'gsnStreams'.
  , gsnConnectHook :: !(IORef (Maybe (Connection -> IO ())))
    -- ^ Connection notifier body. Cleared while the node is stopped.
  , gsnDisconnectHook :: !(IORef (Maybe (Connection -> IO ())))
    -- ^ Disconnect notifier body. Cleared while the node is stopped.
  , gsnNotifierInstalled :: !(TVar Bool)
    -- ^ The Switch holds one connect wrapper for this node.
  , gsnStarted :: !(TVar Bool)
    -- ^ True between a successful start and stop.
  , gsnLifecycleLock :: !(MVar ())
    -- ^ Serializes start and stop so heartbeat ownership cannot race.
  }

-- | Create a new GossipSub node with a Router wired to the Switch.
--
-- The Router's gsSendRPC callback opens/reuses outbound streams to peers
-- via the Switch's connection pool.
newGossipSubNode :: Switch -> GossipSubParams -> IO GossipSubNode
newGossipSubNode sw params = do
  streamsVar <- newTVarIO Map.empty
  streamMetaVar <- newTVarIO Map.empty
  hbVar <- newTVarIO Nothing
  connectHook <- newIORef Nothing
  disconnectHook <- newIORef Nothing
  installed <- newTVarIO False
  started <- newTVarIO False
  lifecycleLock <- newMVar ()
  -- Create router with real sendRPC that uses the Switch
  let localPid = swLocalPeerId sw
  router <- newRouter params localPid
    (sendRPCviaSwitch sw started streamsVar streamMetaVar) getCurrentTime
  let node = GossipSubNode
        { gsnRouter    = router
        , gsnSwitch    = sw
        , gsnHeartbeat = hbVar
        , gsnStreams   = streamsVar
        , gsnStreamMeta = streamMetaVar
        , gsnConnectHook = connectHook
        , gsnDisconnectHook = disconnectHook
        , gsnNotifierInstalled = installed
        , gsnStarted = started
        , gsnLifecycleLock = lifecycleLock
        }
  atomically $ modifyTVar' (swDisconnectNotifiers sw)
    (runGossipDisconnect disconnectHook :)
  pure node

-- | Send an RPC to a peer via cached or newly opened stream.
sendRPCviaSwitch
  :: Switch
  -> TVar Bool
  -> TVar (Map.Map PeerId StreamIO)
  -> TVar (Map.Map PeerId GossipStreamMeta)
  -> PeerId
  -> RPC
  -> IO ()
sendRPCviaSwitch sw startedVar streamsVar metaVar pid rpc = do
  mCached <- atomically $ lookupCachedStream streamsVar metaVar pid
  case mCached of
    Just (stream, token) -> do
      sent <- trySend stream rpc
      case sent of
        Right () -> pure ()
        Left () -> do
          evictCachedStream streamsVar metaVar pid token stream
          openAndSend sw startedVar streamsVar metaVar pid rpc
    Nothing -> openAndSend sw startedVar streamsVar metaVar pid rpc

-- | Open a new outbound stream to a peer and send an RPC.
openAndSend
  :: Switch
  -> TVar Bool
  -> TVar (Map.Map PeerId StreamIO)
  -> TVar (Map.Map PeerId GossipStreamMeta)
  -> PeerId
  -> RPC
  -> IO ()
openAndSend sw startedVar streamsVar metaVar pid rpc = do
  started <- atomically $ readTVar startedVar
  mOpened <- if started then openStreamToPeer sw pid else pure Nothing
  case mOpened of
    Nothing -> pure ()
    Just (conn, stream) -> do
      mToken <- cacheGossipStream startedVar streamsVar metaVar pid conn stream
      case mToken of
        Nothing -> pure ()
        Just token -> do
          sent <- trySend stream rpc
          case sent of
            Right () -> pure ()
            Left () -> evictCachedStream streamsVar metaVar pid (Just token) stream

-- | Open a new mux stream to a peer and negotiate GossipSub protocol.
openStreamToPeer :: Switch -> PeerId -> IO (Maybe (Connection, StreamIO))
openStreamToPeer sw pid = do
  mConn <- atomically $ lookupConn (swConnPool sw) pid
  case mConn of
    Nothing -> pure Nothing
    Just conn -> do
      result <- (Right <$> openAndNegotiate sw conn) `catch`
                  (\(_ :: SomeException) -> pure (Left ()))
      case result of
        Left () -> pure Nothing
        Right mStream -> pure $ (\(stream, _) -> (conn, stream)) <$> mStream

-- | Read a cached stream together with its identity token, when managed.
lookupCachedStream
  :: TVar (Map.Map PeerId StreamIO)
  -> TVar (Map.Map PeerId GossipStreamMeta)
  -> PeerId
  -> STM (Maybe (StreamIO, Maybe (IORef ())))
lookupCachedStream streamsVar metaVar pid = do
  streams <- readTVar streamsVar
  metadata <- readTVar metaVar
  pure $ (\stream -> (stream, gsmToken <$> Map.lookup pid metadata))
    <$> Map.lookup pid streams

-- | Cache a managed stream only while the node is active.
cacheGossipStream
  :: TVar Bool
  -> TVar (Map.Map PeerId StreamIO)
  -> TVar (Map.Map PeerId GossipStreamMeta)
  -> PeerId
  -> Connection
  -> StreamIO
  -> IO (Maybe (IORef ()))
cacheGossipStream startedVar streamsVar metaVar pid conn stream = mask_ $ do
  token <- newIORef ()
  result <- atomically $ do
    started <- readTVar startedVar
    if not started
      then pure (Left ())
      else do
        streams <- readTVar streamsVar
        metadata <- readTVar metaVar
        writeTVar streamsVar (Map.insert pid stream streams)
        writeTVar metaVar
          (Map.insert pid (GossipStreamMeta (connState conn) token) metadata)
        pure (Right (Map.lookup pid streams))
  case result of
    Left () -> closeQuietly stream >> pure Nothing
    Right mOld -> mapM_ closeQuietly mOld >> pure (Just token)

-- | Remove the currently cached stream for a peer.
removeCachedStream
  :: TVar (Map.Map PeerId StreamIO)
  -> TVar (Map.Map PeerId GossipStreamMeta)
  -> PeerId
  -> STM (Maybe StreamIO)
removeCachedStream streamsVar metaVar pid = do
  streams <- readTVar streamsVar
  metadata <- readTVar metaVar
  writeTVar streamsVar (Map.delete pid streams)
  writeTVar metaVar (Map.delete pid metadata)
  pure (Map.lookup pid streams)

-- | Close a stream and evict it only if its cache token is still current.
evictCachedStream
  :: TVar (Map.Map PeerId StreamIO)
  -> TVar (Map.Map PeerId GossipStreamMeta)
  -> PeerId
  -> Maybe (IORef ())
  -> StreamIO
  -> IO ()
evictCachedStream streamsVar metaVar pid expectedToken stream = mask_ $ do
  _ <- atomically $ do
    metadata <- readTVar metaVar
    let currentToken = gsmToken <$> Map.lookup pid metadata
        matches = case (expectedToken, currentToken) of
          (Nothing, Nothing) -> True
          (Just expected, Just current) -> expected == current
          _ -> False
    if matches
      then removeCachedStream streamsVar metaVar pid
      else pure Nothing
  closeQuietly stream

-- | Open a mux stream and negotiate a GossipSub protocol, preferring
-- /meshsub/1.1.0 and falling back to /meshsub/1.0.0 (#157).
openAndNegotiate :: Switch -> Connection -> IO (Maybe (StreamIO, PeerProtocol))
openAndNegotiate sw conn = do
  opened <- newStream sw conn
  case opened of
    Left _ -> pure Nothing
    Right stream -> do
      negResult <- negotiateInitiator stream gossipSubProtocolIds
        `onException` closeQuietly stream
      case negResult of
        Accepted proto -> pure (Just (stream, protocolFor proto))
        NoProtocol -> do
          closeQuietly stream
          pure Nothing

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
-- On error or EOF, removes the inbound peer state. The independent outbound
-- stream stays cached until its own loop fails or its connection closes.
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
  -- The inbound stream is distinct from the cached outbound stream.
  -- Do not evict the latter when only this direction reaches EOF.
  removePeer (gsnRouter node) pid
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
startGossipSub node = withMVar (gsnLifecycleLock node) $ \_ -> do
  claimed <- claimStart node
  when claimed $
    activateGossipSub node `onException` rollbackGossipSubStart node

-- | Arm callbacks, handlers, and heartbeat after claiming the lifecycle.
activateGossipSub :: GossipSubNode -> IO ()
activateGossipSub node = do
  writeIORef (gsnConnectHook node) (Just (onNewConnection node))
  writeIORef (gsnDisconnectHook node)
    (Just (dropCachedGossipStream node))
  installConnectNotifier node
  registerHandlers node
  hbAsync <- runHeartbeat (gsnRouter node)
  atomically $ writeTVar (gsnHeartbeat node) (Just hbAsync)

-- | Restore the stopped state if activation fails partway through.
rollbackGossipSubStart :: GossipSubNode -> IO ()
rollbackGossipSubStart node = do
  writeIORef (gsnConnectHook node) Nothing
  writeIORef (gsnDisconnectHook node) Nothing
  atomically $ writeTVar (gsnStarted node) False
  mapM_ (removeStreamHandler (gsnSwitch node)) gossipSubProtocolIds
  closeCachedStreams node

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
    modifyTVar' (swNotifiers (gsnSwitch node))
      (runConnectHook (gsnConnectHook node) :)

-- | Run the current connect hook, or do nothing after stop.
runConnectHook :: IORef (Maybe (Connection -> IO ())) -> Connection -> IO ()
runConnectHook hook conn = do
  mAct <- readIORef hook
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
  mStream <- openAndNegotiate (gsnSwitch node) conn
  case mStream of
    Nothing -> pure ()
    Just (stream, proto) -> withMVar (gsnLifecycleLock node) $ \_ -> do
      mToken <- cacheGossipStream
        (gsnStarted node) (gsnStreams node) (gsnStreamMeta node)
        pid conn stream
      case mToken of
        Nothing -> pure ()
        Just token -> do
          now <- getCurrentTime
          addPeer (gsnRouter node) pid proto True now
          mapM_ (setPeerIP (gsnRouter node) pid) (remoteIPBytes conn)
          syncSignedPeerRecord node pid
          sent <- sendCurrentSubscriptionsChecked node stream
          if sent
            then void $ async $ outboundReadLoop node stream pid token
            else evictCachedStream
              (gsnStreams node) (gsnStreamMeta node) pid (Just token) stream

-- | Send current topic subscriptions to a newly connected peer.
-- This ensures peers joining after we've already subscribed still learn
-- about our subscriptions (standard GossipSub behavior).
-- Writes directly to the stream to avoid any routing issues.
sendCurrentSubscriptions :: GossipSubNode -> StreamIO -> IO ()
sendCurrentSubscriptions node stream =
  void (sendCurrentSubscriptionsChecked node stream)

-- | Send subscriptions and report whether the stream stayed writable.
sendCurrentSubscriptionsChecked :: GossipSubNode -> StreamIO -> IO Bool
sendCurrentSubscriptionsChecked node stream = do
  let router = gsnRouter node
  -- Read the subscription set, not mesh keys: a topic joined before any
  -- peer was known has no mesh entry but must still be announced (#155).
  subs <- atomically $ readTVar (gsSubscriptions router)
  let topics = Set.toList subs
  if null topics
    then pure True
    else do
      let subRPC = emptyRPC
            { rpcSubscriptions = map (\t -> SubOpts True t) topics }
      either (const False) (const True) <$> trySend stream subRPC

-- | Read loop on the outbound stream.
-- Handles RPCs sent back by the remote peer on the same yamux stream
-- (e.g. subscription announcements). Does NOT remove the peer on
-- EOF since the inbound handler or another mechanism manages peer lifecycle.
outboundReadLoop :: GossipSubNode -> StreamIO -> PeerId -> IORef () -> IO ()
outboundReadLoop node stream pid token = loop
  where
    loop = do
      result <- readRPCMessage stream maxRPCSize
      case result of
        Left _ -> evictCachedStream
          (gsnStreams node) (gsnStreamMeta node) pid (Just token) stream
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
stopGossipSub node = withMVar (gsnLifecycleLock node) $ \_ -> do
  writeIORef (gsnConnectHook node) Nothing
  writeIORef (gsnDisconnectHook node) Nothing
  atomically $ writeTVar (gsnStarted node) False
  mHb <- atomically $ do
    hb <- readTVar (gsnHeartbeat node)
    writeTVar (gsnHeartbeat node) Nothing
    pure hb
  case mHb of
    Just hbAsync -> cancel hbAsync `catch` (\(_ :: SomeException) -> pure ())
    Nothing -> pure ()
  mapM_ (removeStreamHandler (gsnSwitch node)) gossipSubProtocolIds
  closeCachedStreams node

-- | Close every cached outbound stream, releasing its resource slot.
closeCachedStreams :: GossipSubNode -> IO ()
closeCachedStreams node = mask_ $ do
  streams <- atomically $ do
    m <- readTVar (gsnStreams node)
    writeTVar (gsnStreams node) Map.empty
    writeTVar (gsnStreamMeta node) Map.empty
    pure (Map.elems m)
  mapM_ closeQuietly streams

-- | Run the disconnect hook unless 'stopGossipSub' has cleared it.
runGossipDisconnect :: IORef (Maybe (Connection -> IO ())) -> Connection -> IO ()
runGossipDisconnect hook conn = do
  mAct <- readIORef hook
  mapM_ ($ conn) mAct

-- | Drop a cached stream when its owning connection closes.
dropCachedGossipStream :: GossipSubNode -> Connection -> IO ()
dropCachedGossipStream node conn = do
  let pid = connPeerId conn
  mStream <- atomically $ do
    metadata <- readTVar (gsnStreamMeta node)
    remaining <- lookupConn (swConnPool (gsnSwitch node)) pid
    let owned = maybe False ((== connState conn) . gsmOwner) (Map.lookup pid metadata)
        unownedLast = Map.notMember pid metadata && isNothing remaining
    if owned || unownedLast
      then removeCachedStream (gsnStreams node) (gsnStreamMeta node) pid
      else pure Nothing
  mapM_ closeQuietly mStream

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
