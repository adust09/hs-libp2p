-- | mDNS local peer discovery (specs/discovery/mdns.md), the
-- zero-configuration discovery mechanism for peers on one link.
--
-- Peers multicast DNS messages to the @224.0.0.251:5353@ (IPv4) /
-- @ff02::fb:5353@ (IPv6) groups under the DNS-SD service name
-- @_p2p._udp.local@:
--
--   * a peer starting up queries @_p2p._udp.local PTR@; every peer
--     (itself included — it hears its own query via multicast
--     loopback) answers with a @PTR@ record naming its instance and,
--     as additional records, @TXT@ records carrying its dialable
--     addresses as @dnsaddr=...@ strings;
--   * queries coming from the mDNS port are answered on the multicast
--     group; legacy-unicast queries (other source ports, RFC 6762
--     §6.7) are answered unicast, with their transaction id kept;
--   * peers also announce unsolicited responses at start-up and
--     periodically, so a peer that only listens still hears its
--     neighbours;
--   * on shutdown a @goodbye@ (records with TTL 0) is sent.
--
-- Service name, port and announcement cadence are on 'MDNSConfig';
-- the defaults track the spec, while tests pin a different service
-- name and port to stay independent of any real mDNS responder on
-- the machine.
--
-- The DNS wire format (header, questions, records, name compression)
-- is implemented in "LibP2P.Discovery.MDNS.Message". Discovered peers
-- are delivered as 'DiscoveryEvent' on the service's STM queue, the
-- same shape the Rendezvous module uses (see
-- \"LibP2P.Discovery.Rendezvous\").
--
-- Platform note: multicast group membership and the multicast socket
-- options live in "Network.Socket.Options" as @CustomSockOpt@s on
-- network >= 3.2 (the named constants were removed upstream); the
-- option numbers used here are the Linux ones.
module LibP2P.Discovery.MDNS
  ( -- * Configuration
    MDNSConfig (..)
  , defaultMDNSConfig
    -- * Service
  , MDNSService (..)
  , newMDNSService
  , stopMDNSService
    -- * Well-known mDNS constants
  , mdnsIPv4Group
  , mdnsIPv6Group
  , mdnsPort
    -- * Discovery events (shared with the Rendezvous module)
  , DiscoveryEvent (..)
  , newDiscoveryQueue
  , tryReadDiscoveryQueue
  , drainDiscoveryQueue
  ) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.Async (Async, async, cancel)
import Control.Concurrent.STM (TQueue, atomically, readTVarIO, writeTQueue)
import Control.Exception (IOException, SomeException, try)
import Control.Monad (forever, forM_, replicateM_, unless, void, when)
import Data.Bits ((.&.), shiftR)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Data.Foldable (traverse_)
import Data.Maybe (catMaybes, mapMaybe)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Text.Encoding (decodeUtf8With, encodeUtf8)
import Data.Text.Encoding.Error (lenientDecode)
import Data.Time.Clock.POSIX (getPOSIXTime)
import Data.Word (Word16, Word32, Word8)
import Foreign.C.Types (CInt)
import Foreign.Ptr (Ptr)
import Foreign.Storable (Storable (alignment, peek, peekByteOff, poke, pokeByteOff, sizeOf))
import LibP2P.Crypto.PeerId (peerIdBytes)
import LibP2P.Discovery.MDNS.Message
  ( DnsPacket (..)
  , DnsQuestion (..)
  , DnsRData (..)
  , DnsRecord (..)
  , classIN
  , decodeDnsPacket
  , encodeDnsPacket
  , typePTR
  , typeTXT
  )
import LibP2P.Discovery.Types
  ( DiscoveryEvent (..)
  , drainDiscoveryQueue
  , newDiscoveryQueue
  , tryReadDiscoveryQueue
  )
import LibP2P.Multiaddr (Multiaddr (..), fromText, isRelayedAddr, splitP2P, toText)
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.Switch.Types
  ( ActiveListener (..)
  , Switch (..)
  )
import Network.Socket
  ( Family (AF_INET, AF_INET6)
  , SockAddr (..)
  , Socket
  , SocketOption (IPv6Only, ReuseAddr, ReusePort)
  , SocketType (Datagram)
  , bind
  , close
  , defaultProtocol
  , setSocketOption
  , socket
  , tupleToHostAddress
  , tupleToHostAddress6
  )
import Network.Socket.ByteString (recvFrom, sendTo)
import Network.Socket (SocketOption (SockOpt), setSockOpt)
import System.IO (IOMode (ReadMode), withBinaryFile)

--------------------------------------------------------------------------------
-- Well-known constants
--------------------------------------------------------------------------------

-- | @224.0.0.251@ — the IPv4 mDNS group (RFC 6762 §4).
mdnsIPv4Group :: ByteString
mdnsIPv4Group = BS.pack [0xE0, 0x00, 0x00, 0xFB]

-- | @ff02::fb@ — the IPv6 (link-local) mDNS group (RFC 6762 §4).
mdnsIPv6Group :: ByteString
mdnsIPv6Group = BS.pack ([0xFF, 0x02] ++ replicate 14 0 ++ [0xFB])

-- | 5353 — the mDNS UDP port (RFC 6762 §6).
mdnsPort :: Word16
mdnsPort = 5353

-- | The DNS-SD meta-query for discovering all services on the link
-- (specs/discovery/mdns.md §Meta Query). Answering it advertises the
-- service name itself.
metaQueryName :: Text
metaQueryName = "_services._dns-sd._udp.local"

-- | mDNS response flags: QR = 1 (response), AA = 1 (authoritative).
responseFlags :: Word16
responseFlags = 0x8400

-- | Linux socket-option numbers. network >= 3.2 removed the named
-- multicast constants; they are settable via the raw 'SockOpt'
-- constructor ('SockOpt level option-name', both from
-- "Network.Socket").
ipprotoIP, ipMulticastTTL, ipMulticastLoop, ipAddMembership :: Int
ipprotoIP = 0
ipMulticastTTL = 33
ipMulticastLoop = 34
ipAddMembership = 35

ipprotoIPv6, ipv6MulticastHops, ipv6MulticastLoop, ipv6AddMembership :: Int
ipprotoIPv6 = 41
ipv6MulticastHops = 18
ipv6MulticastLoop = 19
ipv6AddMembership = 20

--------------------------------------------------------------------------------
-- Configuration
--------------------------------------------------------------------------------

-- | mDNS service settings; 'defaultMDNSConfig' tracks the spec
-- (service @_p2p._udp.local@, port 5353, both address families).
data MDNSConfig = MDNSConfig
  { mcServiceName :: !Text
  -- ^ DNS-SD service name; the default is @_p2p._udp.local@. A
  -- private network (pnet) would use @_p2p-<fingerprint>._udp.local@.
  , mcPort :: !Word16
  -- ^ UDP port; the default is 5353.
  , mcAnnounceTTL :: !Word32
  -- ^ TTL carried by this service's records, in seconds. Records are
  -- re-announced, so this only bounds how long peers remember us if
  -- we vanish unannounced; the default (4500s) matches RFC 6762 §17.
  , mcAdvertiseInterval :: !Int
  -- ^ Seconds between periodic re-announcements; 0 disables them.
  , mcAnnounceCount :: !Int
  -- ^ How many times the start-up announcement is repeated, spaced by
  -- 'mcAnnounceSpacingMs' (multicast is lossy).
  , mcAnnounceSpacingMs :: !Int
  , mcMulticastLoopback :: !Bool
  -- ^ Whether our own multicasts loop back to us. On, peers sharing
  -- the host (and every test) discover each other; our own query
  -- coming back is answered by ourselves, which 'processResponse'
  -- filters out.
  , mcBindIPv6 :: !Bool
  -- ^ Whether to open the IPv6 (ff02::fb) socket in addition to the
  -- IPv4 one. Failing one stack does not fail the service.
  } deriving (Show, Eq)

defaultMDNSConfig :: MDNSConfig
defaultMDNSConfig =
  MDNSConfig
    { mcServiceName = "_p2p._udp.local"
    , mcPort = mdnsPort
    , mcAnnounceTTL = 4500
    , mcAdvertiseInterval = 600 -- 10 minutes
    , mcAnnounceCount = 3
    , mcAnnounceSpacingMs = 120
    , mcMulticastLoopback = True
    , mcBindIPv6 = True
    }

--------------------------------------------------------------------------------
-- Service
--------------------------------------------------------------------------------

-- | A running mDNS discovery service.
data MDNSService = MDNSService
  { msConfig :: !MDNSConfig
  , msSwitch :: !Switch
  -- ^ Listen addresses are advertised live from this switch; the
  -- local peer id filters our own announcements.
  , msPeerName :: !Text
  -- ^ Random lower-case identifier of this instance
  -- (specs/discovery/mdns.md: at least 32 lowercase alphanumeric
  -- characters, not the peer id, which may exceed the DNS label
  -- limit).
  , msEvents :: !(TQueue DiscoveryEvent)
  -- ^ Discovered peers, drained by the application.
  , msThreads :: [Async ()]
  , msSockets :: [MdnsSocket]
  }

-- | A socket joined to its mDNS group. 'skGroup' carries the family
-- and the group address so sends and replies stay on the socket's own
-- stack.
data MdnsSocket = MdnsSocket
  { skSock :: !Socket
  , skGroup :: !SockAddr
  }

-- | Start the mDNS service: open the multicast sockets (IPv4, and
-- IPv6 if configured and possible), join the groups, and start the
-- responder threads. Returns 'Left' only when /no/ socket could be
-- opened at all; failing one stack (an IPv4-only host, for example)
-- degrades the service to the other.
newMDNSService :: Switch -> MDNSConfig -> IO (Either String MDNSService)
newMDNSService sw cfg = do
  opened <- openSockets cfg
  case opened of
    [] -> pure (Left "mdns: could not open any multicast socket")
    _ -> do
      peerName <- randomPeerName
      events <- newDiscoveryQueue
      readers <- mapM (async . readerThread sw cfg peerName events) opened
      announcer <- async (announceThread sw cfg peerName opened)
      pure
        ( Right
            MDNSService
              { msConfig = cfg
              , msSwitch = sw
              , msPeerName = peerName
              , msEvents = events
              , msThreads = readers ++ [announcer]
              , msSockets = opened
              }
        )

-- | Stop the service: send the goodbye (records with TTL 0), cancel
-- the threads, close the sockets.
stopMDNSService :: MDNSService -> IO ()
stopMDNSService svc = do
  addrs <- advertisedAddrs (msSwitch svc)
  let bye = encodeDnsPacket (fullAnnouncement (msConfig svc) 0 (msPeerName svc) addrs)
  -- The goodbye matters less than tearing down: a dead socket must
  -- not stop the rest of the shutdown.
  forM_ (msSockets svc) $ \sk ->
    bestEffort (sendTo (skSock sk) bye (skGroup sk))
  traverse_ cancel (msThreads svc)
  traverse_ (close . skSock) (msSockets svc)

--------------------------------------------------------------------------------
-- Multicast sockets
--------------------------------------------------------------------------------

-- | Open every configured multicast socket, bound to the mDNS port
-- and joined to its group. Sockets that fail are dropped silently, so
-- an IPv4-only host still gets @ip4@ only.
openSockets :: MDNSConfig -> IO [MdnsSocket]
openSockets cfg = do
  v4 <- tagged (ipv4GroupAddr cfg) (openIPv4Socket cfg)
  v6 <-
    if mcBindIPv6 cfg
      then tagged (ipv6GroupAddr cfg) (openIPv6Socket cfg)
      else pure Nothing
  pure (catMaybes [v4, v6])
  where
    tagged :: SockAddr -> IO Socket -> IO (Maybe MdnsSocket)
    tagged group io = do
      opened <- try io
      pure $ case opened :: Either IOException Socket of
        Left _ -> Nothing -- this stack is unavailable: skip it
        Right sock -> Just (MdnsSocket sock group)

ipv4GroupAddr :: MDNSConfig -> SockAddr
ipv4GroupAddr cfg =
  SockAddrInet
    (fromIntegral (mcPort cfg))
    (tupleToHostAddress (0xE0, 0x00, 0x00, 0xFB))

ipv6GroupAddr :: MDNSConfig -> SockAddr
ipv6GroupAddr cfg =
  SockAddrInet6
    (fromIntegral (mcPort cfg))
    0
    (tupleToHostAddress6 (0xFF02, 0, 0, 0, 0, 0, 0, 0x00FB))
    0

-- | IPv4: a datagram socket bound to @0.0.0.0:<port>@ with
-- @SO_REUSEADDR@/@SO_REUSEPORT@ — every responder on the host binds
-- the same port — with multicast TTL 255 (RFC 6762 §11 mandates 255),
-- loopback per config, and the group joined on the default interface
-- (INADDR_ANY).
openIPv4Socket :: MDNSConfig -> IO Socket
openIPv4Socket cfg = do
  sock <- socket AF_INET Datagram defaultProtocol
  setSocketOption sock ReuseAddr 1
  setSocketOption sock ReusePort 1
  setSockOpt sock (SockOpt (ci ipprotoIP) (ci ipMulticastTTL)) (255 :: CInt)
  setSockOpt
    sock
    (SockOpt (ci ipprotoIP) (ci ipMulticastLoop))
    (fromIntegral (fromEnum (mcMulticastLoopback cfg)) :: CInt)
  bind sock (SockAddrInet (fromIntegral (mcPort cfg)) 0)
  setSockOpt
    sock
    (SockOpt (ci ipprotoIP) (ci ipAddMembership))
    (IpMreq (mdnsIPv4Group <> BS.pack [0, 0, 0, 0]))
  pure sock

-- | IPv6: a datagram socket bound to @[::]:<port>@ (IPv6-only), hop
-- limit 255 (RFC 6762 §11), loopback per config, group joined on the
-- default interface (index 0).
openIPv6Socket :: MDNSConfig -> IO Socket
openIPv6Socket cfg = do
  sock <- socket AF_INET6 Datagram defaultProtocol
  setSocketOption sock ReuseAddr 1
  setSocketOption sock ReusePort 1
  setSocketOption sock IPv6Only 1
  setSockOpt sock (SockOpt (ci ipprotoIPv6) (ci ipv6MulticastHops)) (255 :: CInt)
  setSockOpt
    sock
    (SockOpt (ci ipprotoIPv6) (ci ipv6MulticastLoop))
    (fromIntegral (fromEnum (mcMulticastLoopback cfg)) :: CInt)
  bind
    sock
    (SockAddrInet6 (fromIntegral (mcPort cfg)) 0 (tupleToHostAddress6 (0, 0, 0, 0, 0, 0, 0, 0)) 0)
  setSockOpt
    sock
    (SockOpt (ci ipprotoIPv6) (ci ipv6AddMembership))
    (IPv6Mreq (mdnsIPv6Group <> BS.pack [0, 0, 0, 0]))
  pure sock

ci :: Int -> CInt
ci = fromIntegral

-- | @ip_mreq@: 4 bytes group address + 4 bytes interface address, in
-- network byte order — the option struct the kernel reads
-- byte-for-byte.
newtype IpMreq = IpMreq ByteString

-- | @ipv6_mreq@: 16 bytes group address + 4 bytes interface index.
newtype IPv6Mreq = IPv6Mreq ByteString

instance Storable IpMreq where
  sizeOf _ = 8
  alignment _ = 4
  peek p = IpMreq <$> peekBytes p 8
  poke p (IpMreq bs) = pokeBytes p 8 bs

instance Storable IPv6Mreq where
  sizeOf _ = 20
  alignment _ = 4
  peek p = IPv6Mreq <$> peekBytes p 20
  poke p (IPv6Mreq bs) = pokeBytes p 20 bs

peekBytes :: Ptr a -> Int -> IO ByteString
peekBytes p n = BS.pack <$> mapM (peekByteOff p) [0 .. n - 1]

pokeBytes :: Ptr a -> Int -> ByteString -> IO ()
pokeBytes p n bs =
  mapM_
    (\(i, b) -> pokeByteOff p i b)
    (zip [0 ..] (BS.unpack (BS.take n (bs <> BS.replicate n 0))))

--------------------------------------------------------------------------------
-- Best-effort I/O
--------------------------------------------------------------------------------

-- | Run an I/O action, discarding failures (a dead socket, a stack
-- without a route to the group) so the remainder of the service keeps
-- working.
bestEffort :: IO a -> IO ()
bestEffort action = do
  outcome <- try (void action)
  pure $ case outcome :: Either SomeException () of
    _ -> ()

--------------------------------------------------------------------------------
-- Threads
--------------------------------------------------------------------------------

-- | Reader thread for one socket: receive, parse, and dispatch (a
-- query is answered, a response is consumed). Exits quietly when the
-- socket dies — 'stopMDNSService' shuts it down from the outside.
readerThread
  :: Switch -> MDNSConfig -> Text -> TQueue DiscoveryEvent -> MdnsSocket -> IO ()
readerThread sw cfg peerName events sk = loop
  where
    loop = do
      received <- try (recvFrom (skSock sk) 65536)
      case received :: Either SomeException (ByteString, SockAddr) of
        Left _ -> pure () -- socket gone: end the thread
        Right (payload, src) -> do
          handlePacket sw cfg peerName events sk src payload
          loop

handlePacket
  :: Switch
  -> MDNSConfig
  -> Text
  -> TQueue DiscoveryEvent
  -> MdnsSocket
  -> SockAddr
  -> ByteString
  -> IO ()
handlePacket sw cfg peerName events sk src payload =
  case decodeDnsPacket payload of
    Left _ -> pure () -- unauthenticated multicast: ignore the malformed
    Right pk
      | isQuery pk -> answerQuery sw cfg peerName sk src pk
      | otherwise -> processResponse sw peerName (mcServiceName cfg) events pk
  where
    isQuery pkt = pkFlags pkt .&. 0x8000 == 0

-- | Answer a query: for each question addressed to our service
-- (find-all-peers), the DNS-SD meta-query, or our instance's TXT
-- name, produce the records and send them on the query's own channel.
answerQuery
  :: Switch -> MDNSConfig -> Text -> MdnsSocket -> SockAddr -> DnsPacket -> IO ()
answerQuery sw cfg peerName sk src pk = do
  addrs <- advertisedAddrs sw
  let ttl = mcAnnounceTTL cfg
      (answered, additional) =
        unzip (map (questionRecords cfg peerName ttl addrs) (pkQuestion pk))
      reply =
        DnsPacket
          { pkID = pkID pk -- legacy unicast responses keep the id
          , pkFlags = responseFlags
          , pkQuestion = []
          , pkAnswer = dedupeRecords (concat answered)
          , pkAdditional = dedupeRecords (concat additional)
          }
  case pkAnswer reply ++ pkAdditional reply of
    [] -> pure () -- not a name we serve: stay silent (RFC 6762 §6.7)
    _ -> do
      dst <- replyDestination cfg sk src
      bestEffort (sendTo (skSock sk) (encodeDnsPacket reply) dst)

-- | Where a response to a query goes: genuine mDNS queries come from
-- the mDNS port and are answered on the multicast group;
-- legacy-unicast queries are answered unicast at their source.
replyDestination :: MDNSConfig -> MdnsSocket -> SockAddr -> IO SockAddr
replyDestination cfg sk src = case src of
  SockAddrInet p _ | p == toPort (mcPort cfg) -> pure (skGroup sk)
  SockAddrInet6 p _ _ _ | p == toPort (mcPort cfg) -> pure (skGroup sk)
  _ -> pure src
  where
    toPort = fromIntegral

-- | The records answering one question, as (answer, additional).
questionRecords
  :: MDNSConfig -> Text -> Word32 -> [Text] -> DnsQuestion
  -> ([DnsRecord], [DnsRecord])
questionRecords cfg peerName ttl addrs q
  -- Find all peers on this service: a PTR naming our instance, with
  -- our TXT address records as additional records.
  | qName q == service && qType q == typePTR =
      ([ptrRecord service ttl instanceName], [txtRecord instanceName ttl addrs])
  -- The DNS-SD meta-query: advertise the service name itself.
  | qName q == metaQueryName && qType q == typePTR =
      ([ptrRecord metaQueryName ttl service], [])
  -- A peer asking directly for our instance's TXT (specs/discovery/
  -- mdns.md §Gotchas: many tools query the additional records
  -- separately).
  | qName q == instanceName && qType q == typeTXT =
      ([txtRecord instanceName ttl addrs], [])
  | otherwise = ([], [])
  where
    service = mcServiceName cfg
    instanceName = peerName <> "." <> service

ptrRecord :: Text -> Word32 -> Text -> DnsRecord
ptrRecord name ttl instanceName =
  DnsRecord name typePTR classIN ttl (RdPtr instanceName)

txtRecord :: Text -> Word32 -> [Text] -> DnsRecord
txtRecord name ttl addrs =
  DnsRecord name typeTXT classIN ttl (RdTxt (map dnsaddrBytes addrs))
  where
    dnsaddrBytes addr = encodeUtf8 ("dnsaddr=" <> addr)

-- | Deduplicate records across questions by (name, type): two
-- identical questions must not double the answers, but a PTR answer
-- and a TXT record sharing an instance name must coexist.
dedupeRecords :: [DnsRecord] -> [DnsRecord]
dedupeRecords = Map.elems . Map.fromList . map (\r -> ((rName r, rType r), r))

-- | Unsolicited announcement: an authoritative response advertising
-- this instance. 'fullAnnouncement' with TTL 0 is the goodbye.
fullAnnouncement :: MDNSConfig -> Word32 -> Text -> [Text] -> DnsPacket
fullAnnouncement cfg ttl peerName addrs =
  DnsPacket
    { pkID = 0
    , pkFlags = responseFlags
    , pkQuestion = []
    , pkAnswer = [ptrRecord service ttl instanceName]
    , pkAdditional = [txtRecord instanceName ttl addrs | not (null addrs)]
    }
  where
    service = mcServiceName cfg
    instanceName = peerName <> "." <> service

-- | The find-all-peers question this service asks at start-up.
queryPacket :: Text -> DnsPacket
queryPacket service =
  DnsPacket
    { pkID = 0
    , pkFlags = 0
    , pkQuestion = [DnsQuestion service typePTR classIN]
    , pkAnswer = []
    , pkAdditional = []
    }

-- | Announcer: announce and query at start-up ('mcAnnounceCount'
-- times), then re-announce every 'mcAdvertiseInterval' seconds.
announceThread :: Switch -> MDNSConfig -> Text -> [MdnsSocket] -> IO ()
announceThread sw cfg peerName sockets = do
  replicateM_ (max 1 (mcAnnounceCount cfg)) $ do
    announceOnce
    when (mcAnnounceSpacingMs cfg > 0) $ threadDelay (mcAnnounceSpacingMs cfg * 1000)
  unless (mcAdvertiseInterval cfg <= 0) $
    forever $ do
      threadDelay (mcAdvertiseInterval cfg * 1000000)
      announceOnce
  where
    announceOnce = do
      packets <- do
        addrs <- advertisedAddrs sw
        pure
          ( encodeDnsPacket (queryPacket (mcServiceName cfg))
          , encodeDnsPacket (fullAnnouncement cfg (mcAnnounceTTL cfg) peerName addrs)
          )
      forM_ sockets $ \sk ->
        forM_ packets $ \bs ->
          bestEffort (sendTo (skSock sk) bs (skGroup sk))

--------------------------------------------------------------------------------
-- Discovery of remote peers
--------------------------------------------------------------------------------

-- | Extract peers from a response. TXT records describing an instance
-- carry @dnsaddr=...@ strings; each instance becomes one
-- 'DiscoveryEvent' with the peer id taken from the address
-- @/p2p/@ component and the dialable addresses (relayed circuit
-- addresses dropped: on one link a circuit address is unhelpful).
--
-- Our own announcements loop back to us and are filtered by instance
-- name; a peer advertising no address with a peer id at all is
-- skipped (nothing to dial, nothing to keep).
processResponse
  :: Switch -> Text -> Text -> TQueue DiscoveryEvent -> DnsPacket -> IO ()
processResponse sw peerName service events pk =
  forM_ (Map.toList byInstance) emit
  where
    ownInstance = peerName <> "." <> service

    byInstance =
      Map.fromListWith (++)
        [ (rName r, txtMultiaddrs (rData r))
        | r <- pkAnswer pk ++ pkAdditional pk
        , rType r == typeTXT
        ]
    txtMultiaddrs (RdTxt strings) = mapMaybe dnsaddrMultiaddr strings
    txtMultiaddrs _ = []
    dnsaddrMultiaddr s =
      maybe
        Nothing
        (either (const Nothing) Just . fromText)
        (T.stripPrefix "dnsaddr=" (decodeUtf8With lenientDecode s))

    emit (instanceName, mas)
      | instanceName == ownInstance = pure ()
      | otherwise = case [(addr, pid) | ma <- mas, Just (addr, pid) <- [splitP2P ma]] of
          [] -> pure () -- no address carried a peer id
          pairs@((_, pid) : _) ->
            -- All of a record's addresses describe one peer; if a
            -- malformed record mixes peer ids, the first wins and the
            -- rest are dropped.
            let dialable = dedupe [addr | (addr, _) <- pairs, not (isRelayedAddr addr)]
            in unless (pid == swLocalPeerId sw) $
                 unless (null dialable) $
                   atomically (writeTQueue events (DiscoveryEvent pid dialable))

    dedupe = Map.elems . Map.fromList . map (\a -> (toText a, a))

--------------------------------------------------------------------------------
-- Address preparation
--------------------------------------------------------------------------------

-- | The addresses this service currently advertised, as
-- @dnsaddr=...@ text: every listener address, with this node's
-- @\/p2p\/\<peer id\>@ component appended (a @dnsaddr@ must identify
-- the peer answering, specs/discovery/mdns.md §Response). Relayed
-- (circuit) addresses are dropped; loopback addresses are kept, so
-- peers sharing a host (and the tests) still discover one another.
advertisedAddrs :: Switch -> IO [Text]
advertisedAddrs sw = do
  listeners <- readTVarIO (swListeners sw)
  let pidBs = peerIdBytes (swLocalPeerId sw)
      withP2P (Multiaddr ps) = Multiaddr (ps ++ [P2P pidBs])
      keep addr = not (isRelayedAddr addr)
  pure [toText (withP2P addr) | al <- listeners, let addr = alAddress al, keep addr]

--------------------------------------------------------------------------------
-- Peer name
--------------------------------------------------------------------------------

-- | A random instance name: 32 lowercase hex characters (the spec's
-- recommendation: "a random, lower-case alphanumeric string of at
-- least 32 characters"). Entropy comes from /dev/urandom, with the
-- clock as a fallback.
randomPeerName :: IO Text
randomPeerName = T.take 32 . toHexLower <$> randomBytes24
  where
    randomBytes24 = do
      randomOrFallback <-
        try (withBinaryFile "/dev/urandom" ReadMode (\h -> BS.hGet h 24))
      fallback <- clockBytes
      pure $ case randomOrFallback :: Either SomeException ByteString of
        Right bs | BS.length bs == 24 -> bs
        _ -> fallback
    clockBytes = do
      nanos <- floor . (* 1e9) . toRational <$> getPOSIXTime :: IO Integer
      pure
        ( BS.pack
            (map (fromIntegral . (.&. 0xFF)) [nanos `shiftR` (8 * i) | i <- [0 .. 23 :: Int]])
        )

-- | Bytes as lowercase hex.
toHexLower :: ByteString -> Text
toHexLower = T.concat . map hexByte . BS.unpack
  where
    hexByte :: Word8 -> Text
    hexByte b = T.pack [hexDigit (b `shiftR` 4), hexDigit (b .&. 0xF)]
    hexDigit n
      | n < 10 = toEnum (fromEnum '0' + fromIntegral n)
      | otherwise = toEnum (fromEnum 'a' + fromIntegral n - 10)
