-- | QUIC v1 transport with libp2p mutual TLS authentication.
module LibP2P.Transport.QUIC
  ( newQUICTransport
  , canDialQUIC
  ) where

import Control.Concurrent.Async (Async, async, cancel, race, waitCatch)
import Control.Concurrent.STM
  ( TMVar
  , TQueue
  , atomically
  , newEmptyTMVarIO
  , newTQueueIO
  , putTMVar
  , readTQueue
  , readTMVar
  , tryPutTMVar
  , writeTQueue
  )
import Control.Exception (SomeException, displayException, onException, try)
import Control.Monad (void)
import Data.Bits (shiftL, shiftR, (.&.), (.|.))
import qualified Data.ByteString as BS
import Data.IP (IPv6, fromHostAddress6, toHostAddress6)
import Data.Word (Word32, Word8)
import Data.X509 (CertificateChain)
import Data.X509.Validation (FailedReason (..), SignatureFailure (..))
import LibP2P.Crypto.Key (KeyPair)
import LibP2P.Crypto.PeerId (PeerId)
import LibP2P.Multiaddr (Multiaddr (..))
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.MultistreamSelect.Negotiation (StreamIO (..))
import LibP2P.Transport
  ( ConnectionEndpoint (..)
  , Listener (..)
  , NativeMuxer (..)
  , RawConnection (..)
  , Transport (..)
  )
import LibP2P.Security.TLS.Certificate
  ( newIdentityCredential
  , verifyIdentityCertificate
  )
import qualified Network.QUIC as QUIC
import qualified Network.QUIC.Client as Client
import Network.QUIC.Internal
  ( ClientConfig (..)
  , Hooks (..)
  , ServerConfig (..)
  , Version (..)
  , defaultClientConfig
  , defaultHooks
  , defaultServerConfig
  )
import qualified Network.QUIC.Server as Server
import qualified Network.Socket as NS
import Network.TLS
  ( CertificateRejectReason (..)
  , CertificateUsage (..)
  , Credential
  , ClientHooks (..)
  , Credentials (..)
  , ServerHooks (..)
  )

libp2pALPN :: BS.ByteString
libp2pALPN = "libp2p"

-- | Construct a QUIC transport using the node's long-term identity key.
newQUICTransport :: KeyPair -> IO Transport
newQUICTransport identity = do
  credential <- newIdentityCredential identity
  pure Transport
    { transportDial = dialQUIC credential
    , transportDialFrom = \local remote -> case local of
        Nothing -> dialQUIC credential remote
        Just _ -> fail "QUIC transport does not support binding an existing listen address"
    , transportListen = listenQUIC credential
    , transportCanDial = canDialQUIC
    }

-- | Match RFC 9000 QUIC multiaddrs, with an optional trailing peer ID.
canDialQUIC :: Multiaddr -> Bool
canDialQUIC address = case stripP2P address of
  Multiaddr [IP4 _, UDP _, QuicV1] -> True
  Multiaddr [IP6 bytes, UDP _, QuicV1] -> BS.length bytes == 16
  _ -> False

stripP2P :: Multiaddr -> Multiaddr
stripP2P (Multiaddr protocols) = case reverse protocols of
  P2P _ : rest -> Multiaddr (reverse rest)
  _ -> Multiaddr protocols

dialQUIC :: Credential -> Multiaddr -> IO RawConnection
dialQUIC credential remoteAddress = do
  (host, port) <- either fail pure (multiaddrToHostPort remoteAddress)
  authenticated <- newEmptyTMVarIO
  established <- newEmptyTMVarIO
  closed <- newEmptyTMVarIO
  let config = clientConfig credential host port authenticated
  worker <- async $ runClient config remoteAddress authenticated established closed
  result <- atomically $ readTMVar established
  case result of
    Left message -> waitCatch worker >> fail message
    Right connection -> pure connection

runClient
  :: ClientConfig
  -> Multiaddr
  -> TMVar (Either String PeerId)
  -> TMVar (Either String RawConnection)
  -> TMVar ()
  -> IO ()
runClient config remoteAddress authenticated established closed = do
  outcome <- try $ Client.run config $ \connection -> do
    peerResult <- atomically $ readTMVar authenticated
    peerId <- either fail pure peerResult
    info <- QUIC.getConnectionInfo connection
    localAddress <- sockAddrToMultiaddr (QUIC.localSockAddr info)
    raw <- makeQUICConnection connection peerId localAddress remoteAddress closed
    atomically $ putTMVar established (Right raw)
    atomically $ readTMVar closed
  case outcome of
    Left (err :: SomeException) -> atomically $ void $
      tryPutTMVar established (Left (displayException err))
    Right () -> pure ()

clientConfig
  :: Credential
  -> String
  -> String
  -> TMVar (Either String PeerId)
  -> ClientConfig
clientConfig credential host port authenticated =
  defaultClientConfig
    { ccVersion = Version 1
    , ccVersions = [Version 1]
    , ccServerName = host
    , ccPortName = port
    , ccALPN = const (pure (Just [libp2pALPN]))
    , ccValidate = False
    , ccUseServerNameIndication = False
    , ccOnServerCertificate = validateServerCertificate authenticated
    , ccTlsHooks =
        (ccTlsHooks defaultClientConfig)
          { onCertificateRequest = const (pure (Just credential))
          }
    }

validateServerCertificate
  :: TMVar (Either String PeerId)
  -> certificateStore
  -> validationCache
  -> serviceId
  -> CertificateChain
  -> IO [FailedReason]
validateServerCertificate authenticated _ _ _ chain = do
  result <- verifyIdentityCertificate chain
  atomically $ void (tryPutTMVar authenticated result)
  pure $ case result of
    Right _ -> []
    Left _ -> [InvalidSignature SignatureInvalid]

listenQUIC :: Credential -> Multiaddr -> IO Listener
listenQUIC credential requestedAddress = do
  socketAddress <- either fail pure (multiaddrToSockAddr requestedAddress)
  socket <- openServerSocket socketAddress
  boundAddress <- NS.getSocketName socket >>= sockAddrToMultiaddr
  accepted <- newTQueueIO
  ready <- newEmptyTMVarIO
  let config = serverConfig credential ready
  worker <- async (Server.runWithSockets [socket] config (acceptQUIC accepted))
  waitForServer worker ready `onException` closeServer worker socket
  pure Listener
    { listenerAccept = atomically (readTQueue accepted)
    , listenerClose = closeServer worker socket
    , listenerAddr = boundAddress
    }

serverConfig :: Credential -> TMVar () -> ServerConfig
serverConfig credential ready = defaultServerConfig
  { scVersions = [Version 1]
  , scCredentials = Credentials [credential]
  , scRequireClientCert = True
  , scALPN = Just selectALPN
  , scHooks = defaultHooks {onServerReady = atomically (putTMVar ready ())}
  , scTlsHooks =
      (scTlsHooks defaultServerConfig)
        { onClientCertificate = authenticateClientCertificate
        , onUnverifiedClientCert = pure True
        }
  }

selectALPN :: Version -> [BS.ByteString] -> IO BS.ByteString
selectALPN _ protocols
  | libp2pALPN `elem` protocols = pure libp2pALPN
  | otherwise = pure BS.empty

authenticateClientCertificate :: CertificateChain -> IO CertificateUsage
authenticateClientCertificate chain = do
  result <- verifyIdentityCertificate chain
  pure $ case result of
    Right _ -> CertificateUsageAccept
    Left _ -> CertificateUsageReject
      (CertificateRejectOther "libp2p identity certificate rejected")

acceptQUIC :: TQueue RawConnection -> QUIC.Connection -> IO ()
acceptQUIC accepted connection = do
  maybeChain <- Server.clientCertificateChain connection
  chain <- maybe (fail "QUIC client did not provide a certificate") pure maybeChain
  peerId <- verifyIdentityCertificate chain >>= either fail pure
  info <- QUIC.getConnectionInfo connection
  localAddress <- sockAddrToMultiaddr (QUIC.localSockAddr info)
  remoteAddress <- sockAddrToMultiaddr (QUIC.remoteSockAddr info)
  closed <- newEmptyTMVarIO
  raw <- makeQUICConnection connection peerId localAddress remoteAddress closed
  atomically $ writeTQueue accepted raw
  atomically $ readTMVar closed

makeQUICConnection
  :: QUIC.Connection
  -> PeerId
  -> Multiaddr
  -> Multiaddr
  -> TMVar ()
  -> IO RawConnection
makeQUICConnection connection peerId localAddress remoteAddress closed = do
  let close = atomically $ void (tryPutTMVar closed ())
      native = NativeMuxer
        { nativePeerId = peerId
        , nativeSecurity = "/tls/1.0.0"
        , nativeMuxerProtocol = "/quic-v1"
        , nativeOpenStream = QUIC.stream connection >>= streamToStreamIO
        , nativeAcceptStream = QUIC.acceptStream connection >>= streamToStreamIO
        , nativeClose = close
        }
  pure RawConnection
    { rcEndpoint = NativeMuxerEndpoint native
    , rcLocalAddr = localAddress
    , rcRemoteAddr = remoteAddress
    , rcClose = close
    , rcRelayLimit = Nothing
    }

streamToStreamIO :: QUIC.Stream -> IO StreamIO
streamToStreamIO stream = pure StreamIO
  { streamWrite = QUIC.sendStream stream
  , streamReadByte = BS.head <$> receive 1
  , streamReadChunk = receive
  , streamClose = QUIC.closeStream stream
  }
  where
    receive size = do
      bytes <- QUIC.recvStream stream size
      if BS.null bytes
        then fail "QUIC stream closed"
        else pure bytes

waitForServer :: Async () -> TMVar () -> IO ()
waitForServer worker ready = do
  result <- race (waitCatch worker) (atomically $ readTMVar ready)
  case result of
    Right () -> pure ()
    Left (Left err) -> fail $ "QUIC listener failed: " <> displayException err
    Left (Right ()) -> fail "QUIC listener stopped before becoming ready"

closeServer :: Async () -> NS.Socket -> IO ()
closeServer worker socket = do
  cancel worker
  NS.close socket

openServerSocket :: NS.SockAddr -> IO NS.Socket
openServerSocket address = do
  socket <- NS.socket (socketFamily address) NS.Datagram NS.defaultProtocol
  (do
      NS.setSocketOption socket NS.ReuseAddr 1
      NS.withFdSocket socket NS.setCloseOnExecIfNeeded
      NS.bind socket address
      pure socket
    ) `onException` NS.close socket

multiaddrToHostPort :: Multiaddr -> Either String (String, String)
multiaddrToHostPort address = case stripP2P address of
  Multiaddr [IP4 word, UDP port, QuicV1] -> Right (renderIPv4 word, show port)
  Multiaddr [IP6 bytes, UDP port, QuicV1]
    | BS.length bytes == 16 -> Right (show (bytesToIPv6 bytes), show port)
  _ -> Left "expected /ip4|ip6/.../udp/.../quic-v1"

multiaddrToSockAddr :: Multiaddr -> Either String NS.SockAddr
multiaddrToSockAddr address = case stripP2P address of
  Multiaddr [IP4 word, UDP port, QuicV1] -> Right $
    NS.SockAddrInet (fromIntegral port)
      (NS.tupleToHostAddress (octet 3 word, octet 2 word, octet 1 word, octet 0 word))
  Multiaddr [IP6 bytes, UDP port, QuicV1]
    | BS.length bytes == 16 -> Right $
        NS.SockAddrInet6 (fromIntegral port) 0 (toHostAddress6 (bytesToIPv6 bytes)) 0
  _ -> Left "expected /ip4|ip6/.../udp/.../quic-v1"

sockAddrToMultiaddr :: NS.SockAddr -> IO Multiaddr
sockAddrToMultiaddr (NS.SockAddrInet port host) = do
  let (a, b, c, d) = NS.hostAddressToTuple host
      word =
        (fromIntegral a `shiftL` 24)
          .|. (fromIntegral b `shiftL` 16)
          .|. (fromIntegral c `shiftL` 8)
          .|. fromIntegral d
  pure $ Multiaddr [IP4 word, UDP (fromIntegral port), QuicV1]
sockAddrToMultiaddr (NS.SockAddrInet6 port _ host _) =
  pure $ Multiaddr [IP6 (ipv6ToBytes (fromHostAddress6 host)), UDP (fromIntegral port), QuicV1]
sockAddrToMultiaddr _ = fail "QUIC transport only supports IPv4 and IPv6 sockets"

socketFamily :: NS.SockAddr -> NS.Family
socketFamily NS.SockAddrInet {} = NS.AF_INET
socketFamily NS.SockAddrInet6 {} = NS.AF_INET6
socketFamily _ = NS.AF_UNSPEC

octet :: Int -> Word32 -> Word8
octet index word = fromIntegral ((word `shiftR` (index * 8)) .&. 0xff)

renderIPv4 :: Word32 -> String
renderIPv4 word =
  show (octet 3 word) <> "." <> show (octet 2 word)
    <> "." <> show (octet 1 word) <> "." <> show (octet 0 word)

bytesToIPv6 :: BS.ByteString -> IPv6
bytesToIPv6 bytes = fromHostAddress6
  ( readWord32 0
  , readWord32 4
  , readWord32 8
  , readWord32 12
  )
  where
    readWord32 offset =
      (fromIntegral (BS.index bytes offset) `shiftL` 24)
        .|. (fromIntegral (BS.index bytes (offset + 1)) `shiftL` 16)
        .|. (fromIntegral (BS.index bytes (offset + 2)) `shiftL` 8)
        .|. fromIntegral (BS.index bytes (offset + 3))

ipv6ToBytes :: IPv6 -> BS.ByteString
ipv6ToBytes ipv6 = BS.pack (concatMap word32Bytes words32)
  where
    (a, b, c, d) = toHostAddress6 ipv6
    words32 = [a, b, c, d]
    word32Bytes word =
      [ fromIntegral (word `shiftR` 24)
      , fromIntegral (word `shiftR` 16)
      , fromIntegral (word `shiftR` 8)
      , fromIntegral word
      ]
