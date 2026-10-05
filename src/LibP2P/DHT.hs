-- | DHT node state, RPC handler, and record/provider stores.
--
-- The DHTNode is the top-level coordinator for Kademlia DHT operations.
-- It owns the routing table, record store, provider store, and handles
-- both inbound (as handler) and outbound (dhtSendRequest) RPC.
--
-- The outbound sender is wired to the Switch by 'newDHTNode'; it remains
-- a record field so tests can inject mocks without a real network.
module LibP2P.DHT
  ( -- * Types
    DHTNode (..)
  , DHTMode (..)
  , PeerSession
  , ProviderEntry (..)
  , Validator (..)
    -- * Validators
  , defaultValidator
  , namespacedValidator
  , pkValidator
    -- * Construction
  , newDHTNode
  , newPeerSession
  , stopDHTNode
  , defaultQueryTimeoutMicros
    -- * Handler registration
  , registerDHTHandler
    -- * Inbound RPC handler
  , handleDHTRequest
    -- * Routing table maintenance
  , addPeerToTable
    -- * Store operations
  , storeRecord
  , lookupRecord
  , addProvider
  , getProviders
    -- * Wire helpers
  , decodePeerAddrs
    -- * Constants
  , dhtProtocolId
  , providerRecordTTL
  ) where

import Control.Concurrent.Async (Async, cancel)
import Control.Concurrent.MVar (MVar, newMVar, putMVar, takeMVar, tryTakeMVar)
import Control.Concurrent.STM
import Control.Exception (SomeException, catch, mask, onException, try)
import Data.ByteString (ByteString)
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import Data.List (find)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time (NominalDiffTime, UTCTime, diffUTCTime, getCurrentTime)
import Data.Time.Format.ISO8601 (iso8601Show)
import LibP2P.Crypto.PeerId (PeerId (..), peerIdBytes)
import LibP2P.DHT.Distance (keyToDHTKey, peerIdToKey)
import LibP2P.DHT.Message
import LibP2P.DHT.RoutingTable
  ( RoutingTable
  , allPeers
  , closestPeers
  , insertPeer
  , newRoutingTable
  , removePeer
  )
import LibP2P.DHT.Types
import LibP2P.DHT.Validator
  ( Validator (..)
  , defaultValidator
  , namespacedValidator
  , pkValidator
  )
import LibP2P.Multiaddr (Multiaddr, fromBytes, isRelayedAddr, protocols, toBytes)
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.MultistreamSelect.Negotiation
  ( NegotiationResult (..)
  , StreamIO (..)
  , closeQuietly
  , negotiateInitiator
  )
import LibP2P.Switch (setStreamHandler)
import LibP2P.Switch.ConnPool (lookupConn)
import LibP2P.Switch.Types (Connection (..), MuxerSession (..), Switch (..))

-- | DHT protocol identifier for multistream-select.
dhtProtocolId :: Text
dhtProtocolId = "/ipfs/kad/1.0.0"

-- | Server or client mode.
data DHTMode = DHTServer | DHTClient
  deriving (Show, Eq)

-- | A provider record for content routing.
data ProviderEntry = ProviderEntry
  { peProvider  :: !PeerId
  , peAddrs     :: ![Multiaddr]
  , peTimestamp :: !UTCTime
  } deriving (Show, Eq)

-- | Provider record expiration interval, per specs/kad-dht (48 hours).
-- Expired entries are pruned on read in 'getProviders'.
providerRecordTTL :: NominalDiffTime
providerRecordTTL = 48 * 3600

-- | A cached outbound @/ipfs/kad/1.0.0@ stream together with its
-- exchange lock, held as a single 'MVar' that is both.
--
-- Kademlia RPC messages carry no request identifier, so two exchanges
-- interleaved on one stream cannot be reassociated afterwards: a caller
-- reads whichever response arrives next, not necessarily its own. The
-- complete write + read exchange therefore has to be serialized per
-- peer. go-libp2p pairs its per-peer cached stream with exactly this
-- kind of exchange-wide lock (@peerMessageSender.lk@).
--
-- Making the 'MVar' hold the stream slot rather than guard a separate
-- one means replacing a dead stream is, by construction, something only
-- the caller currently holding the exchange can do.
--
-- 'psInvalid' is set when the peer's last connection closes so a caller
-- that still holds the slot cannot put a live stream back into a map
-- entry that has already been removed (go-libp2p's @invalidate()@).
data PeerSession = PeerSession
  { psSlot    :: !(MVar (Maybe StreamIO))
  , psInvalid :: !(TVar Bool)
  }

-- | Top-level DHT node state.
data DHTNode = DHTNode
  { dhtSwitch        :: !Switch
  , dhtRoutingTable  :: !(TVar RoutingTable)
  , dhtRecordStore   :: !(TVar (Map ByteString DHTRecord))
  , dhtProviderStore :: !(TVar (Map ByteString [ProviderEntry]))
  , dhtLocalKey      :: !DHTKey
  , dhtLocalPeerId   :: !PeerId
  , dhtMode          :: !DHTMode
  , dhtValidator     :: !Validator
    -- ^ Record validator applied to PUT_VALUE records before storage
    -- (and available to GET_VALUE conflict resolution). Defaults to
    -- 'defaultValidator' (the @/pk/@ namespace).
  , dhtStreams       :: !(TVar (Map PeerId PeerSession))
    -- ^ Cached outbound @/ipfs/kad/1.0.0@ sessions, one per peer
    -- (go-libp2p reuses a single long-lived stream per peer)
  , dhtSendRequest   :: !(PeerId -> DHTMessage -> IO (Either String DHTMessage))
    -- ^ Outbound RPC sender. Wired to the Switch by 'newDHTNode';
    -- kept as a field so tests can inject mocks.
  , dhtDisconnectHook :: !(IORef (Maybe (Connection -> IO ())))
    -- ^ Disconnect notifier; 'stopDHTNode' clears it so a stopped node
    -- does not keep a callback alive on the Switch.
  , dhtQueryTimeout :: !Int
    -- ^ Deadline for one iterative lookup / bootstrap run, in microseconds.
    -- Default 'defaultQueryTimeoutMicros' (10s, specs/kad-dht QueryTimeout).
  , dhtBootstrapWorker :: !(TVar (Maybe (Async ())))
    -- ^ Periodic bootstrap loop; cancelled by 'stopDHTNode'.
  }

-- | Default query/bootstrap timeout: 10 seconds (specs/kad-dht).
defaultQueryTimeoutMicros :: Int
defaultQueryTimeoutMicros = 10000000

-- | Create an empty or pre-loaded peer session (tests inject the latter).
newPeerSession :: Maybe StreamIO -> IO PeerSession
newPeerSession slot = PeerSession <$> newMVar slot <*> newTVarIO False

-- | Create a new DHT node with the outbound sender wired to the Switch.
--
-- Registers a disconnect notifier so a cached session is dropped when
-- the peer's last connection closes (#279).
newDHTNode :: Switch -> DHTMode -> IO DHTNode
newDHTNode sw mode = do
  let localPid = swLocalPeerId sw
  rt <- newTVarIO (newRoutingTable localPid)
  records <- newTVarIO Map.empty
  providers <- newTVarIO Map.empty
  streams <- newTVarIO Map.empty
  hook <- newIORef Nothing
  worker <- newTVarIO Nothing
  let node = DHTNode
        { dhtSwitch           = sw
        , dhtRoutingTable     = rt
        , dhtRecordStore      = records
        , dhtProviderStore    = providers
        , dhtLocalKey         = peerIdToKey localPid
        , dhtLocalPeerId      = localPid
        , dhtMode             = mode
        , dhtValidator        = defaultValidator
        , dhtStreams          = streams
        , dhtSendRequest      = sendRequestViaSwitch sw streams
        , dhtDisconnectHook   = hook
        , dhtQueryTimeout     = defaultQueryTimeoutMicros
        , dhtBootstrapWorker  = worker
        }
  writeIORef hook (Just (dropCachedSession sw streams))
  atomically $ modifyTVar' (swDisconnectNotifiers sw) (runDisconnectHook hook :)
  pure node

-- | Stop the DHT node: drop cached sessions and deregister the disconnect
-- notifier so a stopped node cannot keep a callback alive on the Switch.
stopDHTNode :: DHTNode -> IO ()
stopDHTNode node = do
  writeIORef (dhtDisconnectHook node) Nothing
  mWorker <- atomically $ do
    w <- readTVar (dhtBootstrapWorker node)
    writeTVar (dhtBootstrapWorker node) Nothing
    pure w
  mapM_ cancel mWorker
  sessions <- atomically $ do
    m <- readTVar (dhtStreams node)
    writeTVar (dhtStreams node) Map.empty
    pure (Map.elems m)
  mapM_ invalidateHeldSession sessions

-- | Register the DHT handler on the Switch.
--
-- Per specs/kad-dht (client and server mode), nodes operating in client
-- mode do not offer the Kademlia protocol identifier for incoming
-- streams, so this is a no-op for 'DHTClient' nodes: they keep issuing
-- outbound queries via 'dhtSendRequest' but never serve inbound RPC.
registerDHTHandler :: DHTNode -> IO ()
registerDHTHandler node = case dhtMode node of
  DHTClient -> pure ()
  DHTServer ->
    setStreamHandler (dhtSwitch node) dhtProtocolId
      (\conn stream ->
        handleDHTRequest node stream (connPeerId conn) (connRemoteAddr conn))

-- | Handle an inbound DHT stream.
--
-- Per specs/kad-dht, implementations must handle additional RPC request
-- messages on the same incoming stream: go-libp2p keeps one long-lived
-- stream per peer and pipelines requests over it. Loop until the stream
-- errors, is reset, or reaches EOF.
handleDHTRequest :: DHTNode -> StreamIO -> PeerId -> Multiaddr -> IO ()
handleDHTRequest node stream remotePeerId remoteAddr = loop
  where
    loop = do
      result <- try $ do
        readResult <- readFramedMessage stream maxDHTMessageSize
        case readResult of
          Left err -> pure (Left err)
          Right msg -> do
            response <- processRequest node msg remotePeerId
            writeFramedMessage stream response
            -- Routing-table growth: a peer speaking the DHT protocol to
            -- us is a live contact; insert (or refresh) it. Note this
            -- cannot distinguish client-mode senders (the spec would
            -- exclude them) without identify-provided protocol lists.
            rememberSender node remotePeerId remoteAddr
            pure (Right ())
      case result of
        Left (_ :: SomeException) -> pure ()  -- Stream closed or reset
        Right (Left _err) -> pure ()          -- Framing/decode error: stop serving
        Right (Right ()) -> loop

-- | Process a single DHT request and produce a response.
processRequest :: DHTNode -> DHTMessage -> PeerId -> IO DHTMessage
processRequest node msg remotePeerId =
  case msgType msg of
    FindNode -> handleFindNode node msg
    GetValue -> handleGetValue node msg
    PutValue -> handlePutValue node msg
    AddProvider -> handleAddProvider node msg remotePeerId
    GetProviders -> handleGetProviders node msg

-- | Insert or refresh the RPC sender, seeding its dial address from
-- the authenticated connection.
--
-- A direct IP address is unioned into whatever the table already
-- holds. A relayed or address-less remote multiaddr is ignored so it
-- cannot replace a richer list (#284).
rememberSender :: DHTNode -> PeerId -> Multiaddr -> IO ()
rememberSender node remotePeerId remoteAddr = do
  now <- getCurrentTime
  existing <- atomically $ do
    rt <- readTVar (dhtRoutingTable node)
    pure $ find (\e -> entryPeerId e == remotePeerId) (allPeers rt)
  let addrs = mergeSenderAddrs (maybe [] entryAddrs existing) (usableRemoteAddr remoteAddr)
  _ <- addPeerToTable node BucketEntry
        { entryPeerId   = remotePeerId
        , entryKey      = peerIdToKey remotePeerId
        , entryAddrs    = addrs
        , entryLastSeen = now
        , entryConnType = Connected
        }
  pure ()

-- | Keep known addresses and append a new direct address at most once.
mergeSenderAddrs :: [Multiaddr] -> Maybe Multiaddr -> [Multiaddr]
mergeSenderAddrs existing Nothing = existing
mergeSenderAddrs existing (Just addr)
  | addr `elem` existing = existing
  | otherwise = existing ++ [addr]

-- | A connection address is usable as a dial target only when it is a
-- direct IP multiaddr. Relayed (/p2p-circuit) and non-IP addresses are
-- not stored.
usableRemoteAddr :: Multiaddr -> Maybe Multiaddr
usableRemoteAddr addr
  | isRelayedAddr addr = Nothing
  | not (any isIP (protocols addr)) = Nothing
  | otherwise = Just addr
  where
    isIP (IP4 _) = True
    isIP (IP6 _) = True
    isIP _ = False

-- | FIND_NODE: return k closest peers to the requested key.
handleFindNode :: DHTNode -> DHTMessage -> IO DHTMessage
handleFindNode node msg = do
  rt <- readTVarIO (dhtRoutingTable node)
  -- The wire key is raw (a binary peer ID); the spec distance metric is
  -- XOR over SHA-256 digests, so hash before comparing.
  let targetKey = keyToDHTKey (msgKey msg)
      closest = closestPeers targetKey kValue rt
      peers = map entryToDHTPeer closest
  pure emptyDHTMessage
    { msgType = FindNode
    , msgCloserPeers = peers
    }

-- | GET_VALUE: return stored record + k closest peers.
handleGetValue :: DHTNode -> DHTMessage -> IO DHTMessage
handleGetValue node msg = do
  rt <- readTVarIO (dhtRoutingTable node)
  records <- readTVarIO (dhtRecordStore node)
  let key = msgKey msg
      -- Store lookup uses the raw key; distance uses its SHA-256.
      targetKey = keyToDHTKey key
      closest = closestPeers targetKey kValue rt
      peers = map entryToDHTPeer closest
      rec = Map.lookup key records
  pure emptyDHTMessage
    { msgType = GetValue
    , msgRecord = rec
    , msgCloserPeers = peers
    }

-- | PUT_VALUE: validate, store with a receiver-set timestamp, and echo.
--
-- Per specs/kad-dht (Entry validation), incoming records are validated
-- before being stored: the record key must match the message key and
-- the configured 'dhtValidator' must accept the key/value binding
-- (e.g. @/pk/@ records must carry the public key hashing to the key's
-- multihash). Rejected records are neither stored nor echoed back.
--
-- The stored record's @timeReceived@ is set by the receiver (Record
-- field 5: "Time the record was received, set by receiver"), never
-- taken from the sender's claim.
handlePutValue :: DHTNode -> DHTMessage -> IO DHTMessage
handlePutValue node msg = do
  case msgRecord msg of
    Nothing -> pure rejected
    Just rec
      | recKey rec /= msgKey msg -> pure rejected
      | otherwise ->
          case valValidate (dhtValidator node) (recKey rec) (recValue rec) of
            Left _err -> pure rejected
            Right () -> do
              now <- getCurrentTime
              storeRecord node rec { recTimeReceived = T.pack (iso8601Show now) }
              pure emptyDHTMessage
                { msgType = PutValue
                , msgKey = msgKey msg
                , msgRecord = Just rec
                }
  where
    rejected = emptyDHTMessage { msgType = PutValue }

-- | ADD_PROVIDER: verify sender and store provider record.
handleAddProvider :: DHTNode -> DHTMessage -> PeerId -> IO DHTMessage
handleAddProvider node msg remotePeerId = do
  now <- getCurrentTime
  -- Verify that provider peers match sender's Peer ID
  let validProviders = filter (\p -> dhtPeerId p == peerIdBytes remotePeerId) (msgProviderPeers msg)
  -- Store each valid provider keyed by msgKey
  mapM_ (\p -> addProvider node (msgKey msg) (dhtPeerToProvider p now)) validProviders
  pure emptyDHTMessage { msgType = AddProvider }

-- | GET_PROVIDERS: return stored providers + k closest peers.
handleGetProviders :: DHTNode -> DHTMessage -> IO DHTMessage
handleGetProviders node msg = do
  rt <- readTVarIO (dhtRoutingTable node)
  let key = msgKey msg
      -- Store lookup uses the raw key; distance uses its SHA-256.
      targetKey = keyToDHTKey key
      closest = closestPeers targetKey kValue rt
      closerPeers = map entryToDHTPeer closest
  -- getProviders prunes entries past the 48h provider TTL on read.
  providers <- getProviders node key
  let providerPeers = map providerToDHTPeer providers
  pure emptyDHTMessage
    { msgType = GetProviders
    , msgCloserPeers = closerPeers
    , msgProviderPeers = providerPeers
    }

-- Routing table maintenance

-- | Insert a peer into the routing table, applying the Kademlia
-- full-bucket eviction policy.
--
-- When the target bucket is full, the least-recently-seen peer is
-- probed with a FIND_NODE request (the DHT liveness check; our
-- 'MessageType' has no PING, and go-libp2p likewise treats any
-- successful RPC as proof of liveness):
--
-- * if the LRS peer answers, it is kept (refreshed to
--   most-recently-seen) and the new peer is dropped ('BucketFull');
-- * if it does not answer, it is evicted and the new peer takes its
--   place ('Inserted').
addPeerToTable :: DHTNode -> BucketEntry -> IO InsertResult
addPeerToTable node entry = do
  result <- atomically $ do
    rt <- readTVar (dhtRoutingTable node)
    let (rt', res) = insertPeer entry rt
    writeTVar (dhtRoutingTable node) rt'
    pure res
  case result of
    BucketFull lrs -> evictOrKeep lrs
    other -> pure other
  where
    evictOrKeep lrs = do
      let ping = emptyDHTMessage { msgType = FindNode, msgKey = peerIdBytes lrs }
      response <- dhtSendRequest node lrs ping
        `catch` \(e :: SomeException) -> pure (Left (show e))
      case response of
        Right _ -> do
          -- LRS peer is alive: move it to most-recently-seen and drop
          -- the newcomer.
          now <- getCurrentTime
          atomically $ modifyTVar' (dhtRoutingTable node) (refreshPeer lrs now)
          pure (BucketFull lrs)
        Left _ -> do
          -- LRS peer is dead: evict it and insert the newcomer.
          atomically $ modifyTVar' (dhtRoutingTable node) $ \rt ->
            fst (insertPeer entry (removePeer lrs rt))
          pure Inserted

-- | Move an existing peer to the most-recently-seen position of its
-- bucket with a fresh last-seen timestamp. No-op if the peer is gone.
refreshPeer :: PeerId -> UTCTime -> RoutingTable -> RoutingTable
refreshPeer pid now rt =
  case filter ((== pid) . entryPeerId) (allPeers rt) of
    (e : _) -> fst (insertPeer e { entryLastSeen = now } rt)
    [] -> rt

-- Outbound RPC

-- | Send a DHT request to a peer over the Switch.
--
-- Reuses a cached @/ipfs/kad/1.0.0@ stream per peer when one exists
-- (go-libp2p also keeps one long-lived stream per peer); otherwise opens
-- a new muxer stream on an existing connection and negotiates the
-- protocol. A failed exchange on a cached stream evicts it and retries
-- once on a fresh stream.
--
-- Requests to one peer are serialized, not pipelined: the caller holds
-- the peer's 'PeerSession' for the whole write + read exchange. Requests
-- to different peers stay concurrent.
sendRequestViaSwitch
  :: Switch
  -> TVar (Map PeerId PeerSession)
  -> PeerId
  -> DHTMessage
  -> IO (Either String DHTMessage)
sendRequestViaSwitch sw sessionsVar pid request = do
  session <- peerSession sessionsVar pid
  -- Taking the session out for the duration of the exchange is what keeps
  -- a second caller from reading this caller's response. If the exchange
  -- is interrupted (a query deadline, say) the stream may be left holding
  -- a partial request or an unread reply, so it is closed and the slot
  -- put back empty rather than handed to the next caller.
  mask $ \restore -> do
    cached <- takeMVar (psSlot session)
    let abandon = do
          mapM_ closeQuietly cached
          putMVar (psSlot session) Nothing
    (slot, result) <- restore (exchange cached) `onException` abandon
    commitSession session slot
    pure result
  where
    exchange Nothing = openAndExchange
    exchange (Just stream) = do
      result <- exchangeFramed stream request
      case result of
        Right resp -> pure (Just stream, Right resp)
        Left _ -> do
          -- Cached stream is dead: close it and retry once on a fresh one.
          closeQuietly stream
          openAndExchange

    openAndExchange = do
      opened <- openDHTStream sw pid
      case opened of
        Left err -> pure (Nothing, Left err)
        Right stream ->
          (`onException` closeQuietly stream) $ do
            result <- exchangeFramed stream request
            case result of
              Left err -> do
                closeQuietly stream
                pure (Nothing, Left err)
              ok -> pure (Just stream, ok)

-- | Look up the peer's session, creating an empty one on first contact.
--
-- Two callers racing to create the same session agree on one: the loser
-- discards the 'MVar' it just allocated, so the exchange lock is never
-- split in two.
peerSession :: TVar (Map PeerId PeerSession) -> PeerId -> IO PeerSession
peerSession sessionsVar pid = do
  existing <- Map.lookup pid <$> readTVarIO sessionsVar
  case existing of
    Just session -> pure session
    Nothing -> do
      fresh <- newPeerSession Nothing
      atomically $ do
        sessions <- readTVar sessionsVar
        case Map.lookup pid sessions of
          Just winner -> pure winner
          Nothing -> do
            writeTVar sessionsVar (Map.insert pid fresh sessions)
            pure fresh

-- | Put a stream back only if the session is still valid. An invalidated
-- session has been removed from the map; caching into it would leak a
-- live stream that no later caller can close.
commitSession :: PeerSession -> Maybe StreamIO -> IO ()
commitSession session slot = do
  invalid <- readTVarIO (psInvalid session)
  if invalid
    then do
      mapM_ closeQuietly slot
      putMVar (psSlot session) Nothing
    else putMVar (psSlot session) slot

-- | Run the DHT disconnect hook if it has not been deregistered.
runDisconnectHook :: IORef (Maybe (Connection -> IO ())) -> Connection -> IO ()
runDisconnectHook hook conn = do
  mfn <- readIORef hook
  mapM_ ($ conn) mfn

-- | Drop the cached session when this was the peer's last connection.
dropCachedSession
  :: Switch -> TVar (Map PeerId PeerSession) -> Connection -> IO ()
dropCachedSession sw sessionsVar conn = do
  remaining <- atomically $ lookupConn (swConnPool sw) (connPeerId conn)
  case remaining of
    Just _  -> pure ()
    Nothing -> invalidatePeerSession sessionsVar (connPeerId conn)

-- | Remove the peer's session from the map, mark it invalid, and close
-- the stream if no exchange currently holds it.
invalidatePeerSession :: TVar (Map PeerId PeerSession) -> PeerId -> IO ()
invalidatePeerSession sessionsVar pid = do
  mSession <- atomically $ do
    sessions <- readTVar sessionsVar
    case Map.lookup pid sessions of
      Nothing -> pure Nothing
      Just session -> do
        writeTVar (psInvalid session) True
        writeTVar sessionsVar (Map.delete pid sessions)
        pure (Just session)
  mapM_ invalidateHeldSession mSession

-- | Close a held session's stream unless an in-flight exchange owns the slot.
invalidateHeldSession :: PeerSession -> IO ()
invalidateHeldSession session = do
  atomically $ writeTVar (psInvalid session) True
  mSlot <- tryTakeMVar (psSlot session)
  case mSlot of
    Nothing -> pure ()
    Just slot -> do
      mapM_ closeQuietly slot
      putMVar (psSlot session) Nothing

-- | Write a framed request and read the framed response, capturing IO errors.
exchangeFramed :: StreamIO -> DHTMessage -> IO (Either String DHTMessage)
exchangeFramed stream request = do
  result <- try $ do
    writeFramedMessage stream request
    readFramedMessage stream maxDHTMessageSize
  pure $ case result of
    Left (e :: SomeException) -> Left ("DHT stream I/O failed: " ++ show e)
    Right r -> r

-- | Open a new muxer stream to the peer and negotiate @/ipfs/kad/1.0.0@.
openDHTStream :: Switch -> PeerId -> IO (Either String StreamIO)
openDHTStream sw pid = do
  mConn <- atomically $ lookupConn (swConnPool sw) pid
  case mConn of
    Nothing -> pure (Left "no open connection to peer")
    Just conn -> do
      result <- try $ do
        stream <- muxOpenStream (connSession conn)
        negotiated <- negotiateInitiator stream [dhtProtocolId]
        pure (stream, negotiated)
      pure $ case result of
        Left (e :: SomeException) -> Left ("failed to open DHT stream: " ++ show e)
        Right (stream, Accepted _) -> Right stream
        Right (_, NoProtocol) -> Left "peer does not support /ipfs/kad/1.0.0"

-- Store operations

-- | Store a record in the local datastore.
storeRecord :: DHTNode -> DHTRecord -> IO ()
storeRecord node rec = atomically $
  modifyTVar' (dhtRecordStore node) (Map.insert (recKey rec) rec)

-- | Look up a record by key.
lookupRecord :: DHTNode -> ByteString -> IO (Maybe DHTRecord)
lookupRecord node key = Map.lookup key <$> readTVarIO (dhtRecordStore node)

-- | Add a provider entry for a content key.
--
-- A provider republishing on schedule replaces its previous entry
-- (deduplicated by peer ID) instead of appending a duplicate, so the
-- entry's timestamp is refreshed and GET_PROVIDERS responses stay
-- bounded.
addProvider :: DHTNode -> ByteString -> ProviderEntry -> IO ()
addProvider node key entry = atomically $
  modifyTVar' (dhtProviderStore node) $ \m ->
    Map.insertWith merge key [entry] m
  where
    merge new old = new ++ filter (\e -> peProvider e /= peProvider entry) old

-- | Get providers for a content key, pruning entries older than
-- 'providerRecordTTL' (48h expiration interval per specs/kad-dht).
getProviders :: DHTNode -> ByteString -> IO [ProviderEntry]
getProviders node key = do
  now <- getCurrentTime
  atomically $ do
    m <- readTVar (dhtProviderStore node)
    let live = filter (\e -> diffUTCTime now (peTimestamp e) < providerRecordTTL)
                      (Map.findWithDefault [] key m)
        m' = if null live then Map.delete key m else Map.insert key live m
    writeTVar (dhtProviderStore node) m'
    pure live

-- Helpers

-- | Convert a BucketEntry to a DHTPeer protobuf message.
-- Per specs/kad-dht, Peer records carry the peer's known multiaddrs so
-- the requester can dial them (go-libp2p filters address-less peers).
entryToDHTPeer :: BucketEntry -> DHTPeer
entryToDHTPeer entry = DHTPeer
  { dhtPeerId = peerIdBytes (entryPeerId entry)
  , dhtPeerAddrs = map toBytes (entryAddrs entry)
  , dhtPeerConnType = entryConnType entry
  }

-- | Convert a DHTPeer from ADD_PROVIDER into a ProviderEntry.
dhtPeerToProvider :: DHTPeer -> UTCTime -> ProviderEntry
dhtPeerToProvider peer now = ProviderEntry
  { peProvider  = PeerId (dhtPeerId peer)
  , peAddrs     = decodePeerAddrs (dhtPeerAddrs peer)
  , peTimestamp = now
  }

-- | Convert a ProviderEntry to a DHTPeer protobuf message.
providerToDHTPeer :: ProviderEntry -> DHTPeer
providerToDHTPeer pe = DHTPeer
  { dhtPeerId = peerIdBytes (peProvider pe)
  , dhtPeerAddrs = map toBytes (peAddrs pe)
  , dhtPeerConnType = Connected
  }

-- | Decode raw wire multiaddrs from a Peer record, dropping any that fail
-- to parse: a malformed address from a remote peer must not poison the
-- rest of the record.
decodePeerAddrs :: [ByteString] -> [Multiaddr]
decodePeerAddrs raw = [addr | Right addr <- map fromBytes raw]
