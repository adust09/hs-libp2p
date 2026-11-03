{-# LANGUAGE OverloadedStrings #-}

{- | libp2p WebTransport over HTTP/3 and QUIC v1.

The first WebTransport stream performs a Noise XX handshake to authenticate
peer identities and bind the advertised TLS certificate hashes. Subsequent
WebTransport streams are exposed directly as the native libp2p muxer.
-}
module LibP2P.Transport.WebTransport (
  newWebTransportTransport,
  canDialWebTransport,
) where

import Control.Applicative ((<|>))
import Control.Concurrent (modifyMVar_, newMVar)
import Control.Concurrent.Async (Async, async, cancel, race, waitCatch)
import Control.Concurrent.STM (
  TMVar,
  TQueue,
  atomically,
  newEmptyTMVarIO,
  newTQueueIO,
  putTMVar,
  readTMVar,
  readTQueue,
  tryPutTMVar,
  writeTQueue,
 )
import Control.Exception (SomeException, displayException, finally, onException, try)
import Control.Monad (unless, void, when)
import Data.Bits (shiftL, shiftR, (.&.), (.|.))
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.IP (IPv6, fromHostAddress6, toHostAddress6)
import Data.Maybe (listToMaybe, mapMaybe)
import Data.Text qualified as Text
import Data.Word (Word16, Word32, Word8)
import Data.X509 (CertificateChain)
import Data.X509.Validation (FailedReason (..), SignatureFailure (..))
import LibP2P.Crypto.Key (KeyPair)
import LibP2P.Crypto.PeerId (PeerId (..))
import LibP2P.Multiaddr (Multiaddr (..))
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.MultistreamSelect.Negotiation (StreamIO (..))
import LibP2P.Noise.Handshake (HandshakeResult (..))
import LibP2P.Noise.WebTransport (
  performWebTransportInitiator,
  performWebTransportResponder,
 )
import LibP2P.Transport (
  ConnectionEndpoint (..),
  Listener (..),
  NativeMuxer (..),
  RawConnection (..),
  Transport (..),
 )
import LibP2P.Transport.WebTransport.Certificate (
  newWebTransportCredential,
  verifyWebTransportCertificate,
 )
import LibP2P.Transport.WebTransport.HTTP3 (
  WebTransportSession,
  acceptWebTransport,
  acceptWebTransportStream,
  closeWebTransportSession,
  connectWebTransport,
  openWebTransportStream,
 )
import Network.QUIC qualified as QUIC
import Network.QUIC.Client qualified as Client
import Network.QUIC.Internal (
  ClientConfig (..),
  Hooks (..),
  ServerConfig (..),
  Version (..),
  defaultClientConfig,
  defaultHooks,
  defaultServerConfig,
 )
import Network.QUIC.Server qualified as Server
import Network.Socket qualified as Socket
import Network.TLS (Credential, Credentials (..))

webTransportALPN :: ByteString
webTransportALPN = "h3"

webTransportMaxDatagramFrameSize :: Int
webTransportMaxDatagramFrameSize = 65535

{- | Construct a WebTransport transport with one short-lived self-signed TLS
certificate. The listener address includes its SHA-256 @/certhash@.
-}
newWebTransportTransport :: KeyPair -> IO Transport
newWebTransportTransport identity = do
  (credential, certificateHash) <- newWebTransportCredential
  pure
    Transport
      { transportDial = dialWebTransport identity
      , transportDialFrom = \local remote -> case local of
          Nothing -> dialWebTransport identity remote
          Just _ -> fail "WebTransport does not support binding an existing listen address"
      , transportListen = listenWebTransport identity credential certificateHash
      , transportCanDial = canDialWebTransport
      }

{- | Match dialable WebTransport multiaddrs containing at least one certificate
hash. A trailing peer ID is optional.
-}
canDialWebTransport :: Multiaddr -> Bool
canDialWebTransport address = case parseWebTransportAddress address of
  Right _ -> True
  Left _ -> False

data ParsedAddress = ParsedAddress
  { parsedHost :: !String
  , parsedPort :: !String
  , parsedAuthority :: !ByteString
  , parsedResolutionFamily :: !(Maybe Socket.Family)
  , parsedCertificateHashes :: ![ByteString]
  , parsedExpectedPeer :: !(Maybe PeerId)
  }

dialWebTransport :: KeyPair -> Multiaddr -> IO RawConnection
dialWebTransport identity remoteAddress = do
  parsedAddress <- either fail pure (parseWebTransportAddress remoteAddress)
  when (null (parsedCertificateHashes parsedAddress)) $
    fail "WebTransport address requires at least one /certhash"
  parsed <- resolveDialHost parsedAddress
  validation <- newEmptyTMVarIO
  established <- newEmptyTMVarIO
  let config = clientConfig parsed validation
  worker <-
    async $
      runClient identity parsed config remoteAddress validation established
  outcome <- atomically $ readTMVar established
  case outcome of
    Left message -> waitCatch worker >> fail message
    Right connection -> pure connection

runClient ::
  KeyPair ->
  ParsedAddress ->
  ClientConfig ->
  Multiaddr ->
  TMVar (Either String ()) ->
  TMVar (Either String RawConnection) ->
  IO ()
runClient identity parsed config remoteAddress validation established = do
  outcome <- try $ Client.run config $ \connection -> do
    certificateResult <- atomically $ readTMVar validation
    either fail pure certificateResult
    session <- connectWebTransport connection (parsedAuthority parsed)
    noiseStream <- openWebTransportStream session >>= streamToStreamIO
    (handshake, boundHashes) <-
      performWebTransportInitiator identity noiseStream `finally` streamClose noiseStream
    verifyBoundHashes (parsedCertificateHashes parsed) boundHashes
    verifyExpectedPeer (parsedExpectedPeer parsed) (hrRemotePeerId handshake)
    info <- QUIC.getConnectionInfo connection
    localAddress <- socketAddressToWebTransport (QUIC.localSockAddr info)
    closed <- newEmptyTMVarIO
    raw <- makeRawConnection session handshake localAddress remoteAddress closed
    atomically $ putTMVar established (Right raw)
    atomically $ readTMVar closed
  case outcome of
    Left (err :: SomeException) ->
      atomically $
        void $
          tryPutTMVar established (Left (displayException err))
    Right () -> pure ()

clientConfig ::
  ParsedAddress -> TMVar (Either String ()) -> ClientConfig
clientConfig parsed validation =
  defaultClientConfig
    { ccVersion = Version 1
    , ccVersions = [Version 1]
    , ccServerName = parsedHost parsed
    , ccPortName = parsedPort parsed
    , ccALPN = const (pure (Just [webTransportALPN]))
    , ccValidate = False
    , ccUseServerNameIndication = True
    , ccOnServerCertificate = validateCertificate validation hashes
    , ccMaxDatagramFrameSize = webTransportMaxDatagramFrameSize
    }
 where
  hashes = parsedCertificateHashes parsed

validateCertificate ::
  TMVar (Either String ()) ->
  [ByteString] ->
  certificateStore ->
  validationCache ->
  serviceId ->
  CertificateChain ->
  IO [FailedReason]
validateCertificate result expected _ _ _ chain = do
  verified <- verifyWebTransportCertificate expected chain
  atomically $ void (tryPutTMVar result verified)
  pure $ case verified of
    Right () -> []
    Left _ -> [InvalidSignature SignatureInvalid]

verifyBoundHashes :: [ByteString] -> [ByteString] -> IO ()
verifyBoundHashes expected received =
  unless (all (`elem` received) expected) $
    fail "Noise payload did not bind every dialed WebTransport certhash"

verifyExpectedPeer :: Maybe PeerId -> PeerId -> IO ()
verifyExpectedPeer Nothing _ = pure ()
verifyExpectedPeer (Just expected) actual =
  unless (expected == actual) $
    fail "WebTransport Noise peer ID does not match the /p2p address"

listenWebTransport ::
  KeyPair -> Credential -> ByteString -> Multiaddr -> IO Listener
listenWebTransport identity credential certificateHash requestedAddress = do
  socketAddress <- either fail pure (listenSocketAddress requestedAddress)
  socket <- openServerSocket socketAddress
  boundBase <- Socket.getSocketName socket >>= socketAddressToWebTransport
  let advertised = appendCerthash boundBase certificateHash
  accepted <- newTQueueIO
  ready <- newEmptyTMVarIO
  worker <-
    async $
      Server.runWithSockets
        [socket]
        (serverConfig credential ready)
        (acceptConnection identity certificateHash advertised accepted)
  waitForServer worker ready `onException` closeServer worker socket
  pure
    Listener
      { listenerAccept = atomically (readTQueue accepted)
      , listenerClose = closeServer worker socket
      , listenerAddr = advertised
      }

serverConfig :: Credential -> TMVar () -> ServerConfig
serverConfig credential ready =
  defaultServerConfig
    { scVersions = [Version 1]
    , scCredentials = Credentials [credential]
    , scRequireClientCert = False
    , scMaxDatagramFrameSize = webTransportMaxDatagramFrameSize
    , scALPN = Just selectALPN
    , scHooks = defaultHooks{onServerReady = atomically (putTMVar ready ())}
    }

selectALPN :: Version -> [ByteString] -> IO ByteString
selectALPN _ protocols
  | webTransportALPN `elem` protocols = pure webTransportALPN
  | otherwise = pure BS.empty

acceptConnection ::
  KeyPair ->
  ByteString ->
  Multiaddr ->
  TQueue RawConnection ->
  QUIC.Connection ->
  IO ()
acceptConnection identity certificateHash localAddress accepted connection = do
  session <- acceptWebTransport connection
  noiseStream <- acceptWebTransportStream session >>= streamToStreamIO
  handshake <-
    performWebTransportResponder identity [certificateHash] noiseStream
      `finally` streamClose noiseStream
  info <- QUIC.getConnectionInfo connection
  remoteAddress <- socketAddressToWebTransport (QUIC.remoteSockAddr info)
  closed <- newEmptyTMVarIO
  raw <- makeRawConnection session handshake localAddress remoteAddress closed
  atomically $ writeTQueue accepted raw
  atomically $ readTMVar closed

makeRawConnection ::
  WebTransportSession ->
  HandshakeResult ->
  Multiaddr ->
  Multiaddr ->
  TMVar () ->
  IO RawConnection
makeRawConnection session handshake localAddress remoteAddress closed = do
  close <- closeOnce $ do
    closeWebTransportSession session
    atomically $ void (tryPutTMVar closed ())
  let native =
        NativeMuxer
          { nativePeerId = hrRemotePeerId handshake
          , nativeSecurity = "/noise"
          , nativeMuxerProtocol = "/webtransport"
          , nativeOpenStream = openWebTransportStream session >>= streamToStreamIO
          , nativeAcceptStream = acceptWebTransportStream session >>= streamToStreamIO
          , nativeClose = close
          }
  pure
    RawConnection
      { rcEndpoint = NativeMuxerEndpoint native
      , rcLocalAddr = localAddress
      , rcRemoteAddr = remoteAddress
      , rcClose = close
      , rcRelayLimit = Nothing
      }

closeOnce :: IO () -> IO (IO ())
closeOnce action = do
  closed <- newMVar False
  pure $ modifyMVar_ closed $ \alreadyClosed ->
    if alreadyClosed
      then pure True
      else action >> pure True

streamToStreamIO :: QUIC.Stream -> IO StreamIO
streamToStreamIO stream =
  pure
    StreamIO
      { streamWrite = QUIC.sendStream stream
      , streamReadByte = BS.head <$> receive 1
      , streamReadChunk = receive
      , streamClose = QUIC.closeStream stream
      }
 where
  receive size = do
    bytes <- QUIC.recvStream stream size
    if BS.null bytes
      then fail "WebTransport stream closed"
      else pure bytes

parseWebTransportAddress :: Multiaddr -> Either String ParsedAddress
parseWebTransportAddress address = do
  let (withoutPeer, expectedPeer) = stripP2P address
  (host, port, authority, rest) <- parseHostPort withoutPeer
  hashes <- parseSuffix rest
  pure
    ParsedAddress
      { parsedHost = host
      , parsedPort = port
      , parsedAuthority = authority
      , parsedResolutionFamily = addressResolutionFamily withoutPeer
      , parsedCertificateHashes = hashes
      , parsedExpectedPeer = expectedPeer
      }

parseHostPort ::
  Multiaddr -> Either String (String, String, ByteString, [Protocol])
parseHostPort (Multiaddr protocols) = case protocols of
  IP4 word : UDP port : QuicV1 : WebTransport : rest ->
    endpoint (renderIPv4 word) port rest
  IP6 bytes : UDP port : QuicV1 : WebTransport : rest
    | BS.length bytes == 16 ->
        let host = show (bytesToIPv6 bytes)
         in Right (host, show port, bracketAuthority host port, rest)
  DNS name : UDP port : QuicV1 : WebTransport : rest ->
    endpoint (Text.unpack name) port rest
  DNS4 name : UDP port : QuicV1 : WebTransport : rest ->
    endpoint (Text.unpack name) port rest
  DNS6 name : UDP port : QuicV1 : WebTransport : rest ->
    endpoint (Text.unpack name) port rest
  _ -> Left "expected /ip4|ip6|dns|dns4|dns6/.../udp/.../quic-v1/webtransport"
 where
  endpoint host port rest =
    Right (host, show port, plainAuthority host port, rest)

addressResolutionFamily :: Multiaddr -> Maybe Socket.Family
addressResolutionFamily (Multiaddr (DNS _ : _)) = Just Socket.AF_UNSPEC
addressResolutionFamily (Multiaddr (DNS4 _ : _)) = Just Socket.AF_INET
addressResolutionFamily (Multiaddr (DNS6 _ : _)) = Just Socket.AF_INET6
addressResolutionFamily _ = Nothing

resolveDialHost :: ParsedAddress -> IO ParsedAddress
resolveDialHost parsed = case parsedResolutionFamily parsed of
  Nothing -> pure parsed
  Just family -> do
    let hints =
          Socket.defaultHints
            { Socket.addrFamily = family
            , Socket.addrSocketType = Socket.Datagram
            }
    addresses <-
      Socket.getAddrInfo
        (Just hints)
        (Just (parsedHost parsed))
        (Just (parsedPort parsed))
    host <-
      maybe (fail "WebTransport DNS lookup returned no usable address") pure $
        preferredHost (mapMaybe (numericHost . Socket.addrAddress) addresses)
    pure parsed{parsedHost = host, parsedResolutionFamily = Nothing}

numericHost :: Socket.SockAddr -> Maybe (Socket.Family, String)
numericHost (Socket.SockAddrInet _ host) =
  Just (Socket.AF_INET, renderIPv4 (hostAddressToWord host))
numericHost (Socket.SockAddrInet6 _ _ host _) =
  Just (Socket.AF_INET6, show (fromHostAddress6 host))
numericHost _ = Nothing

preferredHost :: [(Socket.Family, String)] -> Maybe String
preferredHost hosts = snd <$> (findIPv4 hosts <|> listToMaybe hosts)
 where
  findIPv4 = listToMaybe . filter ((== Socket.AF_INET) . fst)

parseSuffix :: [Protocol] -> Either String [ByteString]
parseSuffix [] = Right []
parseSuffix (Certhash hashBytes : rest) =
  (hashBytes :) <$> parseSuffix rest
parseSuffix _ = Left "only /certhash components may follow /webtransport"

stripP2P :: Multiaddr -> (Multiaddr, Maybe PeerId)
stripP2P (Multiaddr protocols) = case reverse protocols of
  P2P bytes : rest -> (Multiaddr (reverse rest), Just (PeerId bytes))
  _ -> (Multiaddr protocols, Nothing)

listenSocketAddress :: Multiaddr -> Either String Socket.SockAddr
listenSocketAddress address = case fst (stripP2P address) of
  Multiaddr [IP4 word, UDP port, QuicV1, WebTransport] ->
    Right $ Socket.SockAddrInet (fromIntegral port) (wordToHostAddress word)
  Multiaddr [IP6 bytes, UDP port, QuicV1, WebTransport]
    | BS.length bytes == 16 ->
        Right $
          Socket.SockAddrInet6
            (fromIntegral port)
            0
            (toHostAddress6 (bytesToIPv6 bytes))
            0
  _ -> Left "expected listen address /ip4|ip6/.../udp/.../quic-v1/webtransport"

socketAddressToWebTransport :: Socket.SockAddr -> IO Multiaddr
socketAddressToWebTransport (Socket.SockAddrInet port host) =
  pure $
    Multiaddr
      [ IP4 (hostAddressToWord host)
      , UDP (fromIntegral port)
      , QuicV1
      , WebTransport
      ]
socketAddressToWebTransport (Socket.SockAddrInet6 port _ host _) =
  pure $
    Multiaddr
      [ IP6 (ipv6ToBytes (fromHostAddress6 host))
      , UDP (fromIntegral port)
      , QuicV1
      , WebTransport
      ]
socketAddressToWebTransport _ =
  fail "WebTransport only supports IPv4 and IPv6 sockets"

appendCerthash :: Multiaddr -> ByteString -> Multiaddr
appendCerthash (Multiaddr protocols) hashBytes =
  Multiaddr (protocols <> [Certhash hashBytes])

waitForServer :: Async () -> TMVar () -> IO ()
waitForServer worker ready = do
  result <- race (waitCatch worker) (atomically $ readTMVar ready)
  case result of
    Right () -> pure ()
    Left (Left err) -> fail $ "WebTransport listener failed: " <> displayException err
    Left (Right ()) -> fail "WebTransport listener stopped before becoming ready"

closeServer :: Async () -> Socket.Socket -> IO ()
closeServer worker socket = do
  cancel worker
  Socket.close socket

openServerSocket :: Socket.SockAddr -> IO Socket.Socket
openServerSocket address = do
  socket <- Socket.socket (socketFamily address) Socket.Datagram Socket.defaultProtocol
  ( do
      Socket.setSocketOption socket Socket.ReuseAddr 1
      Socket.withFdSocket socket Socket.setCloseOnExecIfNeeded
      Socket.bind socket address
      pure socket
    )
    `onException` Socket.close socket

socketFamily :: Socket.SockAddr -> Socket.Family
socketFamily Socket.SockAddrInet{} = Socket.AF_INET
socketFamily Socket.SockAddrInet6{} = Socket.AF_INET6
socketFamily _ = Socket.AF_UNSPEC

wordToHostAddress :: Word32 -> Socket.HostAddress
wordToHostAddress word =
  Socket.tupleToHostAddress
    ( octet 3 word
    , octet 2 word
    , octet 1 word
    , octet 0 word
    )

hostAddressToWord :: Socket.HostAddress -> Word32
hostAddressToWord host =
  let (a, b, c, d) = Socket.hostAddressToTuple host
   in (fromIntegral a `shiftL` 24)
        .|. (fromIntegral b `shiftL` 16)
        .|. (fromIntegral c `shiftL` 8)
        .|. fromIntegral d

octet :: Int -> Word32 -> Word8
octet index word = fromIntegral ((word `shiftR` (index * 8)) .&. 0xff)

renderIPv4 :: Word32 -> String
renderIPv4 word =
  show (octet 3 word)
    <> "."
    <> show (octet 2 word)
    <> "."
    <> show (octet 1 word)
    <> "."
    <> show (octet 0 word)

plainAuthority :: String -> Word16 -> ByteString
plainAuthority host port =
  BS.pack (map (fromIntegral . fromEnum) (host <> ":" <> show port))

bracketAuthority :: String -> Word16 -> ByteString
bracketAuthority host port = plainAuthority ("[" <> host <> "]") port

bytesToIPv6 :: ByteString -> IPv6
bytesToIPv6 bytes =
  fromHostAddress6
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

ipv6ToBytes :: IPv6 -> ByteString
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
