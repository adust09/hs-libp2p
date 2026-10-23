-- | TCP transport implementation.
--
-- Provides dial/listen for /ip4/.../tcp/... and /ip6/.../tcp/... multiaddrs.
-- Uses the network library for socket operations.
module LibP2P.Transport.TCP
  ( newTCPTransport
  , multiaddrToHostPort
  , socketToStreamIO
  ) where

import Control.Exception (onException)
import Data.Bits (shiftL, shiftR, (.&.), (.|.))
import qualified Data.ByteString as BS
import Data.IP (IPv6, fromHostAddress6, toHostAddress6)
import Data.Word (Word16, Word32, Word8)
import LibP2P.Multiaddr (Multiaddr (..))
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.MultistreamSelect.Negotiation (StreamIO (..))
import LibP2P.Transport
  ( ConnectionEndpoint (..)
  , Listener (..)
  , RawConnection (..)
  , Transport (..)
  )
import qualified Network.Socket as NS
import qualified Network.Socket.ByteString as NSB

-- | Create a new TCP transport.
newTCPTransport :: IO Transport
newTCPTransport = pure $ Transport
  { transportDial = tcpDialFrom Nothing
  , transportDialFrom = tcpDialFrom
  , transportListen = tcpListen
  , transportCanDial = canDialTCP
  }

-- | Drop a trailing /p2p/<peer-id> component if present. Identify- and
-- DHT-learned addresses carry the peer ID suffix; the TCP transport
-- connects to the transport portion only.
stripP2P :: Multiaddr -> Multiaddr
stripP2P (Multiaddr ps) = case reverse ps of
  (P2P _ : rest) -> Multiaddr (reverse rest)
  _ -> Multiaddr ps

-- | Check if a multiaddr is a TCP address (/ip4/.../tcp/... or
-- /ip6/.../tcp/...), optionally with a trailing /p2p/<peer-id> component.
canDialTCP :: Multiaddr -> Bool
canDialTCP addr = case stripP2P addr of
  Multiaddr [IP4 _, TCP _] -> True
  Multiaddr [IP6 _, TCP _] -> True
  _ -> False

-- | Extract (HostName, ServiceName) from a TCP multiaddr.
-- A trailing /p2p/<peer-id> component is ignored.
multiaddrToHostPort :: Multiaddr -> Either String (String, String)
multiaddrToHostPort addr = case stripP2P addr of
  Multiaddr [IP4 w, TCP port] -> Right (renderIPv4 w, show port)
  Multiaddr [IP6 bs, TCP port] -> Right (renderIPv6 bs, show port)
  _ -> Left "multiaddrToHostPort: expected /ip4/.../tcp/... or /ip6/.../tcp/..."

-- | Dial a TCP address by directly constructing a SockAddr from the Multiaddr.
-- A trailing /p2p/<peer-id> component is stripped before connecting; the
-- original (unstripped) multiaddr is kept as the connection's remote address.
--
-- When a local bind address is supplied the outgoing socket is bound to
-- that address (with SO_REUSEADDR/SO_REUSEPORT) so a hole-punch SYN
-- leaves from the listen port. Ordinary dials pass 'Nothing' and get an
-- ephemeral source port.
tcpDialFrom :: Maybe Multiaddr -> Multiaddr -> IO RawConnection
tcpDialFrom mLocal addr = case stripP2P addr of
  Multiaddr [IP4 w, TCP port] ->
    connectFrom mLocal addr NS.AF_INET (ipv4SockAddr w port)
  Multiaddr [IP6 bs, TCP port] ->
    connectFrom mLocal addr NS.AF_INET6 (ipv6SockAddr bs port)
  _ -> fail "tcpDial: unsupported multiaddr"

-- | Create, optionally bind, and connect a TCP socket.
connectFrom :: Maybe Multiaddr -> Multiaddr -> NS.Family -> NS.SockAddr -> IO RawConnection
connectFrom mLocal remoteAddr family sockAddr = do
  sock <- NS.socket family NS.Stream NS.defaultProtocol
  (do
      enableAddrReuse sock
      mapM_ (bindLocal sock) mLocal
      NS.connect sock sockAddr
      mkRawConnection sock remoteAddr
    ) `onException` NS.close sock

-- | Bind a dial socket to a TCP listen address so the SYN uses that port.
bindLocal :: NS.Socket -> Multiaddr -> IO ()
bindLocal sock local = case stripP2P local of
  Multiaddr [IP4 w, TCP port] -> NS.bind sock (ipv4SockAddr w port)
  Multiaddr [IP6 bs, TCP port] -> NS.bind sock (ipv6SockAddr bs port)
  _ -> fail "tcpDialFrom: local bind address is not TCP"

-- | SO_REUSEADDR + SO_REUSEPORT so a listen socket and a hole-punch
-- dial socket can share the same local port.
enableAddrReuse :: NS.Socket -> IO ()
enableAddrReuse sock = do
  NS.setSocketOption sock NS.ReuseAddr 1
  NS.setSocketOption sock NS.ReusePort 1

ipv4SockAddr :: Word32 -> Word16 -> NS.SockAddr
ipv4SockAddr w port =
  NS.SockAddrInet (fromIntegral port)
    (NS.tupleToHostAddress (octet 3 w, octet 2 w, octet 1 w, octet 0 w))

ipv6SockAddr :: BS.ByteString -> Word16 -> NS.SockAddr
ipv6SockAddr bs port =
  NS.SockAddrInet6 (fromIntegral port) 0 (toHostAddress6 (bytesToIPv6 bs)) 0

-- | Create a RawConnection from a connected socket.
--
-- TCP_NODELAY is set on every connection (dialed and accepted), matching
-- go-libp2p and rust-libp2p. libp2p traffic is already coalesced into
-- frames by the muxer, and the many small write-write-read exchanges of
-- the upgrade pipeline (multistream-select, Noise, per-stream
-- negotiation) otherwise stall on Nagle/delayed-ACK interaction —
-- observed as ~270ms per ping open/close cycle in the soak tier.
mkRawConnection :: NS.Socket -> Multiaddr -> IO RawConnection
mkRawConnection sock remoteAddr = do
  NS.setSocketOption sock NS.NoDelay 1
  localSockAddr <- NS.getSocketName sock
  localAddr <- sockAddrToMultiaddr localSockAddr
  pure RawConnection
    { rcEndpoint = ByteStreamEndpoint (socketToStreamIO sock)
    , rcLocalAddr = localAddr
    , rcRemoteAddr = remoteAddr
    , rcClose = NS.close sock
    , rcRelayLimit = Nothing
    }

-- | Listen on a TCP address.
tcpListen :: Multiaddr -> IO Listener
tcpListen (Multiaddr [IP4 w, TCP port]) = do
  let hostAddr = NS.tupleToHostAddress (octet 3 w, octet 2 w, octet 1 w, octet 0 w)
      sockAddr = NS.SockAddrInet (fromIntegral port) hostAddr
  sock <- NS.socket NS.AF_INET NS.Stream NS.defaultProtocol
  enableAddrReuse sock
  NS.bind sock sockAddr
  NS.listen sock 256
  boundSockAddr <- NS.getSocketName sock
  boundAddr <- sockAddrToMultiaddr boundSockAddr
  pure Listener
    { listenerAccept = do
        (clientSock, clientSockAddr) <- NS.accept sock
        clientAddr <- sockAddrToMultiaddr clientSockAddr
        mkRawConnection clientSock clientAddr
    , listenerClose = NS.close sock
    , listenerAddr = boundAddr
    }
tcpListen (Multiaddr [IP6 bs, TCP port]) = do
  let ipv6 = bytesToIPv6 bs
      hostAddr6 = toHostAddress6 ipv6
      sockAddr = NS.SockAddrInet6 (fromIntegral port) 0 hostAddr6 0
  sock <- NS.socket NS.AF_INET6 NS.Stream NS.defaultProtocol
  enableAddrReuse sock
  NS.bind sock sockAddr
  NS.listen sock 256
  boundSockAddr <- NS.getSocketName sock
  boundAddr <- sockAddrToMultiaddr boundSockAddr
  pure Listener
    { listenerAccept = do
        (clientSock, clientSockAddr) <- NS.accept sock
        clientAddr <- sockAddrToMultiaddr clientSockAddr
        mkRawConnection clientSock clientAddr
    , listenerClose = NS.close sock
    , listenerAddr = boundAddr
    }
tcpListen _ = fail "tcpListen: unsupported multiaddr"

-- | Convert a Socket to StreamIO.
socketToStreamIO :: NS.Socket -> StreamIO
socketToStreamIO sock = StreamIO
  { streamWrite = NSB.sendAll sock
  , streamReadByte = BS.head <$> recvChunk 1
  , streamReadChunk = recvChunk
  , streamClose = NS.close sock
  }
  where
    recvChunk n = do
      bs <- NSB.recv sock n
      if BS.null bs
        then fail "socketToStreamIO: connection closed"
        else pure bs

-- | Convert a SockAddr to a Multiaddr.
sockAddrToMultiaddr :: NS.SockAddr -> IO Multiaddr
sockAddrToMultiaddr (NS.SockAddrInet port host) = do
  let (a, b, c, d) = NS.hostAddressToTuple host
      w =
        (fromIntegral a `shiftL` 24)
          .|. (fromIntegral b `shiftL` 16)
          .|. (fromIntegral c `shiftL` 8)
          .|. fromIntegral d
      p = fromIntegral port :: Word16
  pure $ Multiaddr [IP4 w, TCP p]
sockAddrToMultiaddr (NS.SockAddrInet6 port _ host6 _) = do
  let p = fromIntegral port :: Word16
      ipv6 = fromHostAddress6 host6
      bs = ipv6ToBytes ipv6
  pure $ Multiaddr [IP6 bs, TCP p]
sockAddrToMultiaddr other =
  fail $ "sockAddrToMultiaddr: unsupported address type: " <> show other

-- | Extract the nth octet from a Word32 (0 = least significant).
octet :: Int -> Word32 -> Word8
octet n w = fromIntegral ((w `shiftR` (n * 8)) .&. 0xff)

-- | Render an IPv4 Word32 to dotted-decimal string.
renderIPv4 :: Word32 -> String
renderIPv4 w =
  show (octet 3 w) <> "." <> show (octet 2 w)
    <> "." <> show (octet 1 w) <> "." <> show (octet 0 w)

-- | Render a 16-byte IPv6 ByteString to text string.
renderIPv6 :: BS.ByteString -> String
renderIPv6 bs = show (bytesToIPv6 bs)

-- | Convert 16-byte ByteString to IPv6 address.
bytesToIPv6 :: BS.ByteString -> IPv6
bytesToIPv6 bs =
  let readW32 off =
        (fromIntegral (BS.index bs off) `shiftL` 24)
          .|. (fromIntegral (BS.index bs (off + 1)) `shiftL` 16)
          .|. (fromIntegral (BS.index bs (off + 2)) `shiftL` 8)
          .|. fromIntegral (BS.index bs (off + 3))
  in fromHostAddress6 (readW32 0, readW32 4, readW32 8, readW32 12)

-- | Convert IPv6 address to 16-byte ByteString.
ipv6ToBytes :: IPv6 -> BS.ByteString
ipv6ToBytes ipv6 =
  let (w0, w1, w2, w3) = toHostAddress6 ipv6
      word32ToBytes w =
        [ fromIntegral (w `shiftR` 24)
        , fromIntegral (w `shiftR` 16)
        , fromIntegral (w `shiftR` 8)
        , fromIntegral w
        ]
  in BS.pack $ word32ToBytes w0 <> word32ToBytes w1 <> word32ToBytes w2 <> word32ToBytes w3

