{- | Rendezvous protocol (specs/rendezvous/README.md), protocol id
/rendezvous/1.0.0.

Peers connect to a rendezvous point and register their presence in
one or more namespaces with a signed peer record (RFC 0003, see
\"LibP2P.Crypto.PeerRecord\"); other peers discover registrations by
namespace with cookie-based pagination for progressive refresh.

This module implements both sides:

  * server — 'registerRendezvousPoint' registers a stream handler on
    the Switch, turning this node into a rendezvous point.
    Registrations carry signed peer record envelopes, expire by TTL,
    and are bounded by the rendezvous-point recommendations
    (namespace length, TTL range, per-peer and per-query limits).
    Only the peer initiating a registration may register itself.
  * client — 'registerSelf', 'unregisterSelf' and 'discover' operate
    over an existing connection to a rendezvous point.

On the wire every message is varint-length-delimited protobuf
(uvarint(len) ++ protobuf), the framing go-libp2p, rust-libp2p and
js-libp2p use for rendezvous streams, and the same framing this
codebase uses for Identify.
-}
module LibP2P.Discovery.Rendezvous (
  -- * Types
  RendezvousPoint,
  RendezvousConfig (..),
  defaultRendezvousConfig,
  RendezvousError (..),

  -- * Events
  DiscoveryEvent (..),
  newDiscoveryQueue,
  tryReadDiscoveryQueue,
  drainDiscoveryQueue,

  -- * Server (rendezvous point)
  newRendezvousPoint,
  registerRendezvousPoint,
  handleRendezvousStream,
  registeredCount,

  -- * Client
  rendezvousProtocolId,
  rendezvousTimeoutMicros,
  registerSelf,
  unregisterSelf,
  discover,
  inspectRegistration,
  pushDiscoverEvents,

  -- * Wire framing
  encodeFramedMessage,
  readFramedMessage,
) where

import Control.Concurrent.STM (
  TQueue,
  TVar,
  atomically,
  newTVarIO,
  readTVar,
  readTVarIO,
  writeTQueue,
  writeTVar,
 )
import Control.Exception (SomeException, bracket, finally, try)
import Control.Monad (forM_)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.List (sortBy)
import Data.Map.Strict (Map)
import Data.Map.Strict qualified as Map
import Data.Maybe (mapMaybe, maybeToList)
import Data.Ord (comparing)
import Data.Text (Text)
import Data.Text qualified as T
import Data.Time.Clock (UTCTime, addUTCTime, getCurrentTime)
import Data.Word (Word64, Word8)
import LibP2P.Core.Varint (decodeUvarint, encodeUvarint)
import LibP2P.Crypto.PeerId (PeerId (..), peerIdBytes)
import LibP2P.Crypto.PeerRecord (
  PeerRecord (..),
  openPeerRecordEnvelope,
  sealPeerRecord,
  timestampSeq,
 )
import LibP2P.Crypto.SignedEnvelope (encodeSignedEnvelope)
import LibP2P.Discovery.Rendezvous.Message (
  DiscoverLimit (..),
  RegistrationInfo (..),
  RendezvousMessage (..),
  ResponseStatus (..),
  decodeRendezvousMessage,
  encodeRendezvousMessage,
  maxRendezvousMessageSize,
 )
import LibP2P.Discovery.Types (
  DiscoveryEvent (..),
  drainDiscoveryQueue,
  newDiscoveryQueue,
  tryReadDiscoveryQueue,
 )
import LibP2P.Multiaddr (Multiaddr (..), fromBytes)
import LibP2P.Multiaddr.Codec (encodeProtocols)
import LibP2P.MultistreamSelect.Negotiation (
  NegotiationResult (..),
  ProtocolId,
  StreamIO (..),
  closeQuietly,
  negotiateInitiator,
  readExactBounded,
 )
import LibP2P.Switch (setStreamHandler)
import LibP2P.Switch.Connection (newStream)
import LibP2P.Switch.Types (
  ActiveListener (..),
  Connection (..),
  Switch (..),
 )
import System.Timeout (timeout)

-- | Protocol ID (specs/rendezvous/README.md §The Protocol).
rendezvousProtocolId :: ProtocolId
rendezvousProtocolId = "/rendezvous/1.0.0"

{- | Timeout for one rendezvous exchange: 5 seconds, the same bound as
this codebase's Identify interaction. Discovery calls are
interactive; a rendezvous point that negotiates and never answers
must not pin a stream and a thread forever.
-}
rendezvousTimeoutMicros :: Int
rendezvousTimeoutMicros = 5000000

{- | Rendezvous point configuration. Defaults follow the spec's
"Recommendations for Rendezvous Points configurations": minimum TTL
2h, maximum TTL 72h, namespace length 255, 1000 registrations per
peer, 1000 registrations returned per namespace query.
-}
data RendezvousConfig = RendezvousConfig
  { rcMinTTL :: !Word64
  -- ^ Minimum acceptable TTL (seconds)
  , rcMaxTTL :: !Word64
  -- ^ Maximum acceptable TTL (seconds); larger requests are clamped
  , rcDefaultTTL :: !Word64
  -- ^ TTL for registrations without one
  , rcMaxNamespaceLength :: !Int
  -- ^ Maximum namespace length
  , rcMaxPerPeer :: !Int
  -- ^ Maximum live registrations per peer
  , rcMaxResults :: !Int
  -- ^ Maximum registrations per DISCOVER
  }
  deriving (Show, Eq)

defaultRendezvousConfig :: RendezvousConfig
defaultRendezvousConfig =
  RendezvousConfig
    { rcMinTTL = 2 * 3600 -- 2h
    , rcMaxTTL = 72 * 3600 -- 72h
    , rcDefaultTTL = 2 * 3600 -- 2h
    , rcMaxNamespaceLength = 255
    , rcMaxPerPeer = 1000
    , rcMaxResults = 1000
    }

{- | A live registration: the signed peer record envelope as received,
the TTL it was granted, when it expires, and the rendezvous point's
version at the time it was (last) written. The version is the
substance of the discovery cookie: a DISCOVER carrying a cookie from
a previous response only returns registrations written since
(specs/rendezvous §The Protocol).
-}
data Registration = Registration
  { regRecord :: !ByteString
  -- ^ Signed peer-record envelope
  , regTTL :: !Word64
  -- ^ Granted TTL in seconds
  , regExpires :: !UTCTime
  , regVersion :: !Word64
  -- ^ Version counter value at write time
  }
  deriving (Eq)

instance Show Registration where
  show r =
    "Registration {regTTL = "
      <> show (regTTL r)
      <> ", regVersion = "
      <> show (regVersion r)
      <> ", regRecord = "
      <> show (BS.length (regRecord r))
      <> " bytes}"

-- | The rendezvous point's mutable state.
data RendezvousPoint = RendezvousPoint
  { rvConfig :: !RendezvousConfig
  , rvRegs :: !(TVar (Map Text (Map PeerId Registration)))
  {- ^ Registrations per namespace, the inner map keyed by the
  registered peer id
  -}
  , rvVersion :: !(TVar Word64)
  -- ^ Monotonic registration counter
  }

{- | Client-side failure. Rejections carry the rendezvous point's
status ('LibP2P.Discovery.Rendezvous.Message.ResponseStatus') so the
application can distinguish, say, an invalid TTL from an
unauthorized registration.
-}
data RendezvousError
  = -- | No answer within the exchange timeout
    RendezvousTimeout
  | -- | Stream/negotiation failure
    RendezvousTransport !String
  | -- | Rendezvous point rejected the request, with its status text
    RendezvousRejected !ResponseStatus !(Maybe Text)
  | -- | Malformed response
    RendezvousDecode !String
  deriving (Show, Eq)

--------------------------------------------------------------------------------
-- Server
--------------------------------------------------------------------------------

-- | Create an in-memory rendezvous point.
newRendezvousPoint :: RendezvousConfig -> IO RendezvousPoint
newRendezvousPoint cfg =
  RendezvousPoint cfg <$> newTVarIO Map.empty <*> newTVarIO 0

{- | Serve /rendezvous/1.0.0 on the Switch, making this node act as a
rendezvous point. Returns the point so callers can query state
('registeredCount') for tests and observability.
-}
registerRendezvousPoint :: Switch -> RendezvousConfig -> IO RendezvousPoint
registerRendezvousPoint sw cfg = do
  point <- newRendezvousPoint cfg
  setStreamHandler
    sw
    rendezvousProtocolId
    (\conn stream -> handleRendezvousStream point stream (connPeerId conn))
  pure point

{- | Number of currently valid registrations across all namespaces,
excluding expired ones. Expired entries are pruned lazily (on
discovery; nothing scans in the background), so 'rcMaxPerPeer'
counts live registrations: a peer that keeps re-registering a fresh
record keeps one slot per namespace.
-}
registeredCount :: RendezvousPoint -> IO Int
registeredCount point = do
  now <- getCurrentTime
  regs <- readTVarIO (rvRegs point)
  pure
    ( sum
        [ 1
        | nsRegs <- Map.elems regs
        , reg <- Map.elems nsRegs
        , regExpires reg > now
        ]
    )

{- | Handle an inbound rendezvous stream (server side).

Clients open one stream per operation in practice (go-libp2p), but
the stream is a message channel: pipelined messages are served until
the stream ends. Framing or decode errors stop serving the stream; a
disconnect (EOF, reset) ends it too. Either way the local side is
closed so a half-open Yamux stream cannot leak ('handleDHTRequest'
follows the same loop shape).
-}
handleRendezvousStream :: RendezvousPoint -> StreamIO -> PeerId -> IO ()
handleRendezvousStream point stream remotePeer =
  loop `finally` closeQuietly stream
 where
  loop = do
    cont <- try goServe
    case cont :: Either SomeException Bool of
      Right True -> loop
      -- EOF/reset, framing or decode error, or a dead write: end the
      -- interaction. The exception never escapes; the stream is
      -- closed below.
      _ -> pure ()

  goServe = do
    readResult <- try (readFramedMessage stream maxRendezvousMessageSize)
    case readResult :: Either SomeException (Either String RendezvousMessage) of
      Left _ -> pure False -- client hung up mid-message
      Right (Left _err) -> pure False -- framing/decode error
      Right (Right msg) -> do
        responses <- processMessage point remotePeer msg
        -- Frame every response: a rendezvous stream is a channel of
        -- varint-length-delimited messages, and the client's framing
        -- read (readFramedMessage) consumes uvarint(len) ++ protobuf.
        all (== True) <$> mapM (writeServe stream . encodeFramedMessage) responses

  writeServe st resp = do
    outcome <- try (streamWrite st resp)
    case outcome :: Either SomeException () of
      Right () -> pure True
      Left _ -> pure False

{- | Process one client message (server side); the loop frames each
response on the way out.
-}
processMessage ::
  RendezvousPoint -> PeerId -> RendezvousMessage -> IO [RendezvousMessage]
processMessage point remotePeer msg = case msg of
  RMRegister ns record mTTL ->
    (: []) <$> acceptRegistration point remotePeer ns record mTTL
  RMUnregister ns -> do
    unregisterRegistration point remotePeer ns
    pure [] -- no response (specs/rendezvous §Registration Lifetime)
  RMDiscover ns limit cookie ->
    (: []) <$> handleDiscover point ns limit cookie
  -- REGISTER_RESPONSE / DISCOVER_RESPONSE coming from the client side
  -- are protocol violations; ignore them and keep serving the stream
  -- rather than tearing down a connection over garbage.
  _ -> pure []

{- | Remove the peer's registration from a namespace. An unknown
namespace or peer is a no-op (spec: "UNREGISTER messages for a
namespace that a client is not registered for should be treated as a
no-op").
-}
unregisterRegistration :: RendezvousPoint -> PeerId -> Text -> IO ()
unregisterRegistration point peer ns = atomically $ do
  regs <- readTVar (rvRegs point)
  case Map.lookup ns regs of
    Nothing -> pure ()
    Just nsRegs ->
      writeTVar (rvRegs point) (Map.insert ns (Map.delete peer nsRegs) regs)

{- | Validate a REGISTER and record it. Validation order follows the
status codes: namespace, signed peer record, self-registration rule,
TTL. Re-registration overwrites the peer's slot in the namespace (a
new REGISTER supersedes previous registrations, per spec).
-}
acceptRegistration ::
  RendezvousPoint ->
  PeerId ->
  Text ->
  ByteString ->
  Maybe Word64 ->
  IO RendezvousMessage
acceptRegistration point peer ns record mTTL
  | T.null ns || T.length ns > maxNs =
      pure (reject StatusInvalidNamespace)
  | otherwise = case openPeerRecordEnvelope record of
      Left _ -> pure (reject StatusInvalidSignedPeerRecord)
      Right (_, rec)
        | prPeerId rec /= peerIdBytes peer ->
            pure (reject StatusNotAuthorized) -- only self-registration
        | otherwise -> do
            granted <- checkTTL
            case granted of
              Nothing -> pure (reject StatusInvalidTTL)
              Just ttl -> do
                stored <- storeRegistration point peer ns record ttl
                pure $ case stored of
                  Nothing -> reject StatusNotAuthorized -- per-peer limit
                  Just () -> RMRegisterResponse StatusOK (Just "OK") (Just ttl)
 where
  cfg = rvConfig point
  maxNs = rcMaxNamespaceLength cfg
  reject status = RMRegisterResponse status (Just (statusText status)) Nothing

  -- 'Nothing' means inadmissible (E_INVALID_TTL); a TTL above the
  -- configured maximum is clamped down, matching the spec's
  -- "rendezvous point-specific upper bound on TTL".
  checkTTL :: IO (Maybe Word64)
  checkTTL = case mTTL of
    Nothing -> pure (Just (rcDefaultTTL cfg))
    Just ttl
      | ttl < rcMinTTL cfg -> pure Nothing
      | ttl > rcMaxTTL cfg -> pure (Just (rcMaxTTL cfg))
      | otherwise -> pure (Just ttl)

{- | Insert (or replace) a registration, enforcing the per-peer limit
across all namespaces. Returns 'Nothing' when the limit is reached.
The version counter is bumped in the same transaction so concurrent
registrations get strictly distinct versions; it is the rendezvous
point's registration heartbeat and the source of discovery cookies.
-}
storeRegistration ::
  RendezvousPoint ->
  PeerId ->
  Text ->
  ByteString ->
  Word64 ->
  IO (Maybe ())
storeRegistration point peer ns record ttl = do
  now <- getCurrentTime
  accepted <- atomically $ do
    regs <- readTVar (rvRegs point)
    -- Re-registering into a namespace that already holds this peer's
    -- slot replaces it instead of consuming a new one (spec: a new
    -- REGISTER supersedes previous registrations).
    let replacesExisting =
          Map.member peer (Map.findWithDefault Map.empty ns regs)
        liveCount = countLiveByPeer peer now regs
        projected =
          if replacesExisting then liveCount else liveCount + 1
    if projected > rcMaxPerPeer cfg
      then pure False
      else do
        -- Bump first, assign after: version 0 is what the initial
        -- (never-registered) cookie encodes, so a registration's
        -- version must be strictly greater than any cookie older than
        -- itself.
        next <- readTVar (rvVersion point)
        writeTVar (rvVersion point) (next + 1)
        let reg =
              Registration
                { regRecord = record
                , regTTL = ttl
                , regExpires = addUTCTime (fromIntegral ttl) now
                , regVersion = next + 1
                }
            nsRegs = Map.findWithDefault Map.empty ns regs
        writeTVar
          (rvRegs point)
          (Map.insert ns (Map.insert peer reg nsRegs) regs)
        pure True
  pure (if accepted then Just () else Nothing)
 where
  cfg = rvConfig point

-- | Live registrations by one peer across all namespaces.
countLiveByPeer :: PeerId -> UTCTime -> Map Text (Map PeerId Registration) -> Int
countLiveByPeer peer now regs =
  sum
    [ 1
    | nsRegs <- Map.elems regs
    , reg <- maybeToList (Map.lookup peer nsRegs)
    , regExpires reg > now
    ]

{- | Answer a DISCOVER (server side).

The cookie is the rendezvous point's registration version counter:
reading the counter /before/ the registration snapshot guarantees the
returned cookie covers every registration that already existed, so a
client polling with it never misses a registration — anything
registered afterwards gets a strictly larger version and shows up in
the next poll. Registrations are returned in version order, so
cookie pagination is stable.
-}
handleDiscover ::
  RendezvousPoint ->
  Maybe Text ->
  DiscoverLimit ->
  ByteString ->
  IO RendezvousMessage
handleDiscover point ns limit cookie = do
  now <- getCurrentTime
  case cookieVersion cookie of
    Nothing -> pure (discoverResponse StatusInvalidCookie)
    Just since -> do
      (counter, selected) <- atomically $ do
        counter <- readTVar (rvVersion point)
        liveRegs <- readTVar (rvRegs point)
        let live =
              Map.map (Map.filter (\r -> regExpires r > now)) liveRegs
            taggedAll =
              [ (name, reg)
              | (name, nsRegs) <- Map.toList live
              , reg <- Map.elems nsRegs
              ]
            tagged = case ns of
              -- A named scope returns only that namespace; an absent or
              -- empty namespace asks for all registrations.
              Just name ->
                (name,)
                  <$> Map.elems (Map.findWithDefault Map.empty name live)
              Nothing -> taggedAll
            fresh = case since of
              Just v -> keepSince v tagged
              Nothing -> tagged
            keepSince v rs = [(name, reg) | (name, reg) <- rs, regVersion reg > v]
            ordered = sortBy (comparing (regVersion . snd)) fresh
        pure (counter, take maxResults ordered)
      pure $
        RMDiscoverResponse
          [ RegistrationInfo
              { riNamespace = name
              , riPeerRecord = regRecord reg
              , riTTL = regTTL reg
              }
          | (name, reg) <- selected
          ]
          (encodeCookieVersion counter)
          StatusOK
          (Just "OK")
 where
  cfg = rvConfig point
  maxResults = case limit of
    LimitDefault -> rcMaxResults cfg
    -- An explicit limit above the rendezvous point's ceiling is
    -- capped, per the spec's 1000-per-query recommendation; compute
    -- the cap in Word64 so an absurd limit cannot overflow Int.
    LimitExact n ->
      fromIntegral (min n (fromIntegral (rcMaxResults cfg) :: Word64))

-- | Shell for an error DISCOVER_RESPONSE.
discoverResponse :: ResponseStatus -> RendezvousMessage
discoverResponse status =
  RMDiscoverResponse [] BS.empty status (Just (statusText status))

-- | Short human-readable text for a status; goes into statusText.
statusText :: ResponseStatus -> Text
statusText status = case status of
  StatusOK -> "OK"
  StatusInvalidNamespace -> "invalid namespace"
  StatusInvalidSignedPeerRecord -> "invalid signed peer record"
  StatusInvalidTTL -> "invalid ttl"
  StatusInvalidCookie -> "invalid cookie"
  StatusNotAuthorized -> "not authorized"
  StatusInternalError -> "internal error"
  StatusUnavailable -> "unavailable"
  StatusUnknown c -> T.pack ("unknown status " <> show c)

{- | Decode a discovery cookie. Empty means "first query" ('Nothing'
inside); exactly 8 bytes decode to the registration version any
other length is invalid ('Nothing' outside).
-}
cookieVersion :: ByteString -> Maybe (Maybe Word64)
cookieVersion bs
  | BS.null bs = Just Nothing
  | BS.length bs == 8 =
      Just (Just (BS.foldl' (\acc b -> acc * 256 + fromIntegral b) 0 bs))
  | otherwise = Nothing

{- | Encode a discovery cookie: the registration version counter as
8 big-endian bytes.
-}
encodeCookieVersion :: Word64 -> ByteString
encodeCookieVersion = BS.pack . go 8
 where
  go :: Int -> Word64 -> [Word8]
  go 0 _ = []
  go n v = go (n - 1) (v `div` 256) ++ [fromIntegral (v `mod` 256)]

--------------------------------------------------------------------------------
-- Client
--------------------------------------------------------------------------------

{- | Run one client interaction over a fresh stream to the rendezvous
point: open, negotiate, run the body, close on every exit path, all
bounded by 'rendezvousTimeoutMicros'.
-}
withRendezvousStream ::
  Switch ->
  Connection ->
  (StreamIO -> IO (Either RendezvousError a)) ->
  IO (Either RendezvousError a)
withRendezvousStream sw conn body = do
  opened <- newStream sw conn
  case opened of
    Left err ->
      pure (Left (RendezvousTransport ("stream reservation failed: " ++ show err)))
    Right stream -> do
      outcome <-
        timeout
          rendezvousTimeoutMicros
          (bracket (pure stream) closeQuietly negotiateThen)
      pure $ case outcome of
        Nothing -> Left RendezvousTimeout
        Just r -> r
 where
  negotiateThen st = do
    negotiated <- negotiateInitiator st [rendezvousProtocolId]
    case negotiated of
      NoProtocol ->
        pure (Left (RendezvousTransport "remote does not support rendezvous"))
      Accepted _ -> body st

-- | Send one request and read exactly one framed reply.
exchange ::
  StreamIO ->
  RendezvousMessage ->
  (RendezvousMessage -> Either RendezvousError a) ->
  IO (Either RendezvousError a)
exchange stream request check = do
  writeOutcome <- try (streamWrite stream (encodeFramedMessage request))
  case writeOutcome :: Either SomeException () of
    Left e -> pure (Left (RendezvousTransport ("write failed: " ++ show e)))
    Right () -> do
      reply <- try (readFramedMessage stream maxRendezvousMessageSize)
      case reply :: Either SomeException (Either String RendezvousMessage) of
        Left e -> pure (Left (RendezvousTransport ("read failed: " ++ show e)))
        Right (Left err) -> pure (Left (RendezvousDecode err))
        Right (Right msg) -> pure (check msg)

{- | Build the local signed peer record (RFC 0003 envelope) over our
current listen addresses, the payload a registration carries. The
record always builds; sealing cannot fail with our own identity key,
so the Either only reports the impossible.
-}
buildLocalPeerRecord :: Switch -> IO (Either String ByteString)
buildLocalPeerRecord sw = do
  listeners <- readTVarIO (swListeners sw)
  seqNo <- timestampSeq
  let record =
        PeerRecord
          { prPeerId = peerIdBytes (swLocalPeerId sw)
          , prSeq = seqNo
          , prAddresses =
              map (\(Multiaddr ps) -> encodeProtocols ps) (map alAddress listeners)
          }
  pure
    ( either
        (Left . ("seal local peer record failed: " ++))
        (Right . encodeSignedEnvelope)
        (sealPeerRecord (swIdentityKey sw) record)
    )

{- | Register ourselves in a namespace (client side of REGISTER). A
signed peer record over our current listen addresses is built here;
the granted TTL is returned so the application knows when to
refresh.
-}
registerSelf ::
  Switch ->
  Connection ->
  Text ->
  Maybe Word64 ->
  IO (Either RendezvousError Word64)
registerSelf sw conn ns mTTL = do
  recordE <- buildLocalPeerRecord sw
  case recordE of
    Left err -> pure (Left (RendezvousTransport err))
    Right record ->
      withRendezvousStream sw conn $ \stream ->
        exchange stream (RMRegister ns record mTTL) $ \reply -> case reply of
          RMRegisterResponse StatusOK _ (Just ttl) -> Right ttl
          RMRegisterResponse StatusOK _ Nothing ->
            Left (RendezvousDecode "ok registration response without ttl")
          RMRegisterResponse status text _ -> Left (RendezvousRejected status text)
          _ -> Left (RendezvousDecode "unexpected response to REGISTER")

{- | Cancel our registration in a namespace (client side of
UNREGISTER). No reply is sent by the rendezvous point; the write
succeeding is the outcome.
-}
unregisterSelf :: Switch -> Connection -> Text -> IO (Either RendezvousError ())
unregisterSelf sw conn ns =
  withRendezvousStream sw conn $ \stream -> do
    outcome <- try (streamWrite stream (encodeFramedMessage (RMUnregister ns)))
    pure $ case outcome :: Either SomeException () of
      Right () -> Right ()
      Left e -> Left (RendezvousTransport ("write failed: " ++ show e))

{- | Discover registrations (client side of DISCOVER). Pass 'Nothing'
for the namespace to query every namespace; pass the cookie from a
previous response to list only registrations made since (progressive
refresh, specs/rendezvous §The Protocol). Returns the registrations
and the cookie for the next poll.
-}
discover ::
  Switch ->
  Connection ->
  Maybe Text ->
  DiscoverLimit ->
  ByteString ->
  IO (Either RendezvousError ([RegistrationInfo], ByteString))
discover sw conn ns limit cookie =
  withRendezvousStream sw conn $ \stream ->
    exchange stream (RMDiscover ns limit cookie) $ \reply -> case reply of
      RMDiscoverResponse regs nextCookie StatusOK _ -> Right (regs, nextCookie)
      RMDiscoverResponse _ _ status text -> Left (RendezvousRejected status text)
      _ -> Left (RendezvousDecode "unexpected response to DISCOVER")

{- | Validate a received registration's signed peer record envelope and
extract the peer identity and dialable addresses it advertises.
-}
inspectRegistration ::
  RegistrationInfo -> Either String DiscoveryEvent
inspectRegistration ri = do
  (_, rec) <- openPeerRecordEnvelope (riPeerRecord ri)
  let addrs = mapMaybe (either (const Nothing) Just . fromBytes) (prAddresses rec)
  pure (DiscoveryEvent (PeerId (prPeerId rec)) addrs)

{- | Push decoded discovery events for registrations onto a queue;
registrations whose record does not verify are dropped rather than
poisoning the feed.
-}
pushDiscoverEvents :: TQueue DiscoveryEvent -> [RegistrationInfo] -> IO ()
pushDiscoverEvents queue regs =
  forM_ regs $ \ri -> case inspectRegistration ri of
    Right ev -> atomically (writeTQueue queue ev)
    Left _ -> pure ()

--------------------------------------------------------------------------------
-- Wire framing
--------------------------------------------------------------------------------

{- | Encode a message with its uvarint length prefix, as written on the
wire: uvarint(len) ++ protobuf.
-}
encodeFramedMessage :: RendezvousMessage -> ByteString
encodeFramedMessage msg =
  let payload = encodeRendezvousMessage msg
   in encodeUvarint (fromIntegral (BS.length payload)) <> payload

{- | Read one varint-length-prefixed message from a stream.

Reads the uvarint length prefix, then exactly that many payload
bytes, and decodes the protobuf. Rejects messages larger than
maxSize before reading the payload.
-}
readFramedMessage :: StreamIO -> Int -> IO (Either String RendezvousMessage)
readFramedMessage stream maxSize = do
  varintBytes <- readVarintBytes stream
  case decodeUvarint varintBytes of
    Left err -> pure (Left ("rendezvous length prefix decode error: " ++ err))
    Right (len, _) -> do
      let msgLen = fromIntegral len :: Int
      if msgLen > maxSize
        then
          pure
            ( Left
                ( "rendezvous message too large: "
                    ++ show msgLen
                    ++ " > "
                    ++ show maxSize
                )
            )
        else do
          payloadOrErr <- readExactBounded stream maxSize msgLen
          case payloadOrErr of
            Left err -> pure (Left ("rendezvous read error: " ++ err))
            Right payload -> case decodeRendezvousMessage payload of
              Left parseErr ->
                pure (Left ("rendezvous protobuf decode error: " ++ show parseErr))
              Right msg -> pure (Right msg)

{- | Read the bytes of one unsigned varint from a stream (up to 10
bytes).
-}
readVarintBytes :: StreamIO -> IO ByteString
readVarintBytes stream = go [] (0 :: Int)
 where
  go acc n
    | n >= 10 = pure (BS.pack (reverse acc))
    | otherwise = do
        b <- streamReadByte stream
        if b < 0x80
          then pure (BS.pack (reverse (b : acc)))
          else go (b : acc) (n + 1)
