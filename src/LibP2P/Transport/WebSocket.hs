-- | WebSocket transport over TCP and TLS.
--
-- Each WebSocket connection exposes an ordered byte stream to the standard
-- libp2p security and muxer upgrade pipeline. Only binary WebSocket messages
-- are accepted; message boundaries are hidden from stream consumers.
module LibP2P.Transport.WebSocket
  ( WebSocketConfig (..)
  , defaultWebSocketConfig
  , webSocketServerParams
  , newWebSocketTransport
  , newWebSocketTransportWithConfig
  , canDialWebSocket
  ) where

import Control.Concurrent.MVar
  ( MVar
  , modifyMVar
  , modifyMVar_
  , newMVar
  , withMVar
  )
import Control.Exception
  ( IOException
  , SomeException
  , catch
  , displayException
  , onException
  , try
  )
import Control.Monad (unless)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Data.Maybe (isJust)
import qualified Data.Text as Text
import Data.Word (Word16)
import LibP2P.Multiaddr (Multiaddr (..))
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.MultistreamSelect.Negotiation (StreamIO (..))
import LibP2P.Transport
  ( ConnectionEndpoint (..)
  , Listener (..)
  , RawConnection (..)
  , Transport (..)
  )
import LibP2P.Transport.TCP
  ( multiaddrToHostPort
  , newTCPTransport
  , sockAddrToMultiaddr
  )
import qualified Network.Socket as Socket
import Network.TLS
  ( Backend (..)
  , ClientParams (..)
  , Context
  , Credential
  , Credentials (..)
  , ServerParams (..)
  , Shared (..)
  , bye
  , contextNew
  , defaultParamsClient
  , defaultParamsServer
  , handshake
  , recvData
  , sendData
  )
import qualified Network.WebSockets as WebSocket
import qualified Network.WebSockets.Stream as WebSocketStream
import System.X509 (getSystemCertificateStore)

-- | Outer TLS settings for secure WebSockets.
--
-- The default client parameters use the system CA store and normal hostname
-- verification. A WSS listener is disabled until server parameters containing
-- a certificate are supplied explicitly.
data WebSocketConfig = WebSocketConfig
  { webSocketClientTLSParams :: !(String -> ClientParams)
  , webSocketServerTLSParams :: !(Maybe ServerParams)
  }

-- | Secure defaults for WebSocket dialing. WSS listening remains disabled
-- until 'webSocketServerTLSParams' is configured.
defaultWebSocketConfig :: IO WebSocketConfig
defaultWebSocketConfig = do
  certificateStore <- getSystemCertificateStore
  pure WebSocketConfig
    { webSocketClientTLSParams = \host ->
        let base = defaultParamsClient host BS.empty
        in base
          { clientShared = (clientShared base)
              { sharedCAStore = certificateStore
              }
          }
    , webSocketServerTLSParams = Nothing
    }

-- | Build ordinary Web-PKI server parameters from a configured credential.
webSocketServerParams :: Credential -> ServerParams
webSocketServerParams credential = base
  { serverShared = (serverShared base)
      { sharedCredentials = Credentials [credential]
      }
  }
  where
    base = defaultParamsServer

-- | Create a WebSocket transport with secure client defaults.
newWebSocketTransport :: IO Transport
newWebSocketTransport = defaultWebSocketConfig >>= newWebSocketTransportWithConfig

-- | Create a WebSocket transport using explicit outer TLS settings.
newWebSocketTransportWithConfig :: WebSocketConfig -> IO Transport
newWebSocketTransportWithConfig config = do
  tcp <- newTCPTransport
  pure Transport
    { transportDial = dialWebSocket tcp config
    , transportDialFrom = \local remote -> case local of
        Nothing -> dialWebSocket tcp config remote
        Just _ -> fail "WebSocket transport does not support binding a dial to a listener address"
    , transportListen = listenWebSocket tcp config
    , transportCanDial = canDialWebSocket
    }

-- | Recognize IP or DNS TCP addresses ending in /ws or /wss, with an optional
-- trailing /p2p component.
canDialWebSocket :: Multiaddr -> Bool
canDialWebSocket address = case parseWebSocketAddress address of
  Right _ -> True
  Left _ -> False

data WebSocketAddress = WebSocketAddress
  { websocketHost :: !String
  , websocketPort :: !Word16
  , websocketSecure :: !Bool
  , websocketFamily :: !Socket.Family
  , websocketTCPAddress :: !(Maybe Multiaddr)
  }

parseWebSocketAddress :: Multiaddr -> Either String WebSocketAddress
parseWebSocketAddress address = case stripP2P address of
  Multiaddr [IP4 word, TCP port, protocol] -> do
    secure <- parseWebSocketProtocol protocol
    (host, _) <- multiaddrToHostPort (Multiaddr [IP4 word, TCP port])
    pure (WebSocketAddress host port secure Socket.AF_INET (Just (Multiaddr [IP4 word, TCP port])))
  Multiaddr [IP6 bytes, TCP port, protocol]
    | BS.length bytes == 16 -> do
        secure <- parseWebSocketProtocol protocol
        (host, _) <- multiaddrToHostPort (Multiaddr [IP6 bytes, TCP port])
        pure (WebSocketAddress host port secure Socket.AF_INET6 (Just (Multiaddr [IP6 bytes, TCP port])))
  Multiaddr [DNS host, TCP port, protocol] ->
    dnsAddress Socket.AF_UNSPEC host port protocol
  Multiaddr [DNS4 host, TCP port, protocol] ->
    dnsAddress Socket.AF_INET host port protocol
  Multiaddr [DNS6 host, TCP port, protocol] ->
    dnsAddress Socket.AF_INET6 host port protocol
  _ -> Left "expected /ip4|ip6|dns|dns4|dns6/.../tcp/.../ws|wss"

dnsAddress
  :: Socket.Family -> Text.Text -> Word16 -> Protocol -> Either String WebSocketAddress
dnsAddress family host port protocol = do
  secure <- parseWebSocketProtocol protocol
  pure WebSocketAddress
    { websocketHost = Text.unpack host
    , websocketPort = port
    , websocketSecure = secure
    , websocketFamily = family
    , websocketTCPAddress = Nothing
    }

parseWebSocketProtocol :: Protocol -> Either String Bool
parseWebSocketProtocol WS = Right False
parseWebSocketProtocol WSS = Right True
parseWebSocketProtocol _ = Left "address does not end in /ws or /wss"

stripP2P :: Multiaddr -> Multiaddr
stripP2P (Multiaddr protocols) = case reverse protocols of
  P2P _ : rest -> Multiaddr (reverse rest)
  _ -> Multiaddr protocols

dialWebSocket :: Transport -> WebSocketConfig -> Multiaddr -> IO RawConnection
dialWebSocket tcp config remoteAddress = do
  parsed <- either fail pure (parseWebSocketAddress remoteAddress)
  rawTCP <- connectTCP tcp parsed
  buildClientConnection config parsed rawTCP remoteAddress
    `onException` rcClose rawTCP

connectTCP :: Transport -> WebSocketAddress -> IO RawConnection
connectTCP tcp parsed = case websocketTCPAddress parsed of
  Just address -> transportDial tcp address
  Nothing -> do
    addresses <- resolveTCPAddresses parsed
    tryAddresses addresses []
  where
    tryAddresses [] errors =
      fail $ "WebSocket DNS dial failed: " <> unwords (reverse errors)
    tryAddresses (address : rest) errors = do
      result <- try (transportDial tcp address) :: IO (Either IOException RawConnection)
      case result of
        Right connection -> pure connection
        Left err -> tryAddresses rest (displayException err : errors)

resolveTCPAddresses :: WebSocketAddress -> IO [Multiaddr]
resolveTCPAddresses parsed = do
  let hints = Socket.defaultHints
        { Socket.addrFamily = websocketFamily parsed
        , Socket.addrSocketType = Socket.Stream
        }
  infos <- Socket.getAddrInfo
    (Just hints)
    (Just (websocketHost parsed))
    (Just (show (websocketPort parsed)))
  mapM (sockAddrToMultiaddr . Socket.addrAddress) infos

buildClientConnection
  :: WebSocketConfig -> WebSocketAddress -> RawConnection -> Multiaddr -> IO RawConnection
buildClientConnection config parsed rawTCP remoteAddress = do
  rawStream <- expectByteStream rawTCP
  (networkStream, closeTLS) <- prepareClientStream config parsed rawStream
  socketStream <- streamIOToWebSocketStream networkStream
  connection <- WebSocket.newClientConnection
    socketStream
    (webSocketAuthority parsed)
    "/"
    WebSocket.defaultConnectionOptions
    []
  wrapConnection parsed rawTCP remoteAddress closeTLS connection

prepareClientStream
  :: WebSocketConfig -> WebSocketAddress -> StreamIO -> IO (StreamIO, IO ())
prepareClientStream config parsed rawStream
  | not (websocketSecure parsed) = pure (rawStream, pure ())
  | otherwise = do
      context <- contextNew (streamBackend rawStream) $
        webSocketClientTLSParams config (websocketHost parsed)
      handshake context
      stream <- tlsContextToStreamIO context
      pure (stream, closeTLSContext context)

webSocketAuthority :: WebSocketAddress -> String
webSocketAuthority parsed
  | websocketPort parsed == defaultPort = formatHost (websocketHost parsed)
  | otherwise = formatHost (websocketHost parsed) <> ":" <> show (websocketPort parsed)
  where
    defaultPort = if websocketSecure parsed then 443 else 80
    formatHost host
      | ':' `elem` host = "[" <> host <> "]"
      | otherwise = host

listenWebSocket :: Transport -> WebSocketConfig -> Multiaddr -> IO Listener
listenWebSocket tcp config requestedAddress = do
  parsed <- either fail pure (parseWebSocketAddress requestedAddress)
  tcpAddress <- maybe
    (fail "WebSocket listeners require an IP4 or IP6 multiaddr")
    pure
    (websocketTCPAddress parsed)
  unless (not (websocketSecure parsed) || hasServerTLS config) $
    fail "WSS listener requires webSocketServerTLSParams"
  tcpListener <- transportListen tcp tcpAddress
  pure Listener
    { listenerAccept = acceptWebSocket config parsed tcpListener
    , listenerClose = listenerClose tcpListener
    , listenerAddr = appendWebSocketProtocol parsed (listenerAddr tcpListener)
    }

hasServerTLS :: WebSocketConfig -> Bool
hasServerTLS = isJust . webSocketServerTLSParams

acceptWebSocket
  :: WebSocketConfig -> WebSocketAddress -> Listener -> IO RawConnection
acceptWebSocket config parsed tcpListener = do
  rawTCP <- listenerAccept tcpListener
  buildServerConnection config parsed rawTCP `onException` rcClose rawTCP

buildServerConnection
  :: WebSocketConfig -> WebSocketAddress -> RawConnection -> IO RawConnection
buildServerConnection config parsed rawTCP = do
  rawStream <- expectByteStream rawTCP
  (networkStream, closeTLS) <- prepareServerStream config parsed rawStream
  socketStream <- streamIOToWebSocketStream networkStream
  pending <- WebSocket.makePendingConnectionFromStream
    socketStream
    WebSocket.defaultConnectionOptions
  if WebSocket.requestPath (WebSocket.pendingRequest pending) /= "/"
    then WebSocket.rejectRequest pending "websocket path must be /" >> fail "invalid websocket path"
    else do
      connection <- WebSocket.acceptRequest pending
      let remoteAddress = appendWebSocketProtocol parsed (rcRemoteAddr rawTCP)
      wrapConnection parsed rawTCP remoteAddress closeTLS connection

prepareServerStream
  :: WebSocketConfig -> WebSocketAddress -> StreamIO -> IO (StreamIO, IO ())
prepareServerStream config parsed rawStream
  | not (websocketSecure parsed) = pure (rawStream, pure ())
  | otherwise = do
      params <- maybe
        (fail "WSS listener requires webSocketServerTLSParams")
        pure
        (webSocketServerTLSParams config)
      context <- contextNew (streamBackend rawStream) params
      handshake context
      stream <- tlsContextToStreamIO context
      pure (stream, closeTLSContext context)

wrapConnection
  :: WebSocketAddress
  -> RawConnection
  -> Multiaddr
  -> IO ()
  -> WebSocket.Connection
  -> IO RawConnection
wrapConnection parsed rawTCP remoteAddress closeTLS connection = do
  close <- closeOnce $ do
    WebSocket.sendClose connection (BS.empty :: BS.ByteString)
      `catch` \(_ :: SomeException) -> pure ()
    closeTLS
    rcClose rawTCP
  stream <- webSocketToStreamIO connection close
  pure RawConnection
    { rcEndpoint = ByteStreamEndpoint stream
    , rcLocalAddr = appendWebSocketProtocol parsed (rcLocalAddr rawTCP)
    , rcRemoteAddr = remoteAddress
    , rcClose = close
    , rcRelayLimit = Nothing
    }

appendWebSocketProtocol :: WebSocketAddress -> Multiaddr -> Multiaddr
appendWebSocketProtocol parsed (Multiaddr protocols) =
  Multiaddr (protocols <> [if websocketSecure parsed then WSS else WS])

expectByteStream :: RawConnection -> IO StreamIO
expectByteStream raw = case rcEndpoint raw of
  ByteStreamEndpoint stream -> pure stream
  NativeMuxerEndpoint _ -> fail "WebSocket requires a byte-stream TCP endpoint"

streamIOToWebSocketStream :: StreamIO -> IO WebSocketStream.Stream
streamIOToWebSocketStream stream = WebSocketStream.makeStream receive send
  where
    receive =
      (Just <$> streamReadChunk stream 8192)
        `catch` \(_ :: IOException) -> pure Nothing
    send Nothing = pure ()
    send (Just bytes) = mapM_ (streamWrite stream) (LBS.toChunks bytes)

webSocketToStreamIO :: WebSocket.Connection -> IO () -> IO StreamIO
webSocketToStreamIO connection close = do
  readBuffer <- newMVar BS.empty
  writeLock <- newMVar ()
  pure StreamIO
    { streamWrite = \bytes -> unless (BS.null bytes) $
        withMVar writeLock (\_ -> WebSocket.sendBinaryData connection bytes)
    , streamReadByte = BS.head <$> readWebSocketChunk connection readBuffer 1
    , streamReadChunk = readWebSocketChunk connection readBuffer
    , streamClose = close
    }

readWebSocketChunk
  :: WebSocket.Connection -> MVar BS.ByteString -> Int -> IO BS.ByteString
readWebSocketChunk _ _ requested | requested <= 0 = pure BS.empty
readWebSocketChunk connection readBuffer requested =
  modifyMVar readBuffer $ \buffer -> do
    available <- if BS.null buffer then receiveBinary connection else pure buffer
    let (front, rest) = BS.splitAt requested available
    pure (rest, front)

receiveBinary :: WebSocket.Connection -> IO BS.ByteString
receiveBinary connection = do
  message <- WebSocket.receiveDataMessage connection
  case message of
    WebSocket.Binary bytes
      | LBS.null bytes -> receiveBinary connection
      | otherwise -> pure (LBS.toStrict bytes)
    WebSocket.Text _ _ -> fail "WebSocket transport received a text message"

streamBackend :: StreamIO -> Backend
streamBackend stream = Backend
  { backendFlush = pure ()
  , backendClose = pure ()
  , backendSend = streamWrite stream
  , backendRecv = recvExact stream
  }

recvExact :: StreamIO -> Int -> IO BS.ByteString
recvExact stream requested
  | requested <= 0 = pure BS.empty
  | otherwise = collect [] requested
  where
    collect chunks remaining = do
      bytes <- streamReadChunk stream remaining
        `catch` \(_ :: IOException) -> pure BS.empty
      if BS.null bytes
        then pure (BS.concat (reverse chunks))
        else do
          let unread = remaining - BS.length bytes
          if unread <= 0
            then pure (BS.concat (reverse (bytes : chunks)))
            else collect (bytes : chunks) unread

tlsContextToStreamIO :: Context -> IO StreamIO
tlsContextToStreamIO context = do
  readBuffer <- newMVar BS.empty
  pure StreamIO
    { streamWrite = sendData context . LBS.fromStrict
    , streamReadByte = BS.head <$> readTLSChunk context readBuffer 1
    , streamReadChunk = readTLSChunk context readBuffer
    , streamClose = closeTLSContext context
    }

readTLSChunk :: Context -> MVar BS.ByteString -> Int -> IO BS.ByteString
readTLSChunk _ _ requested | requested <= 0 = pure BS.empty
readTLSChunk context readBuffer requested =
  modifyMVar readBuffer $ \buffer -> do
    available <- if BS.null buffer then recvData context else pure buffer
    if BS.null available
      then fail "WSS TLS connection closed"
      else do
        let (front, rest) = BS.splitAt requested available
        pure (rest, front)

closeTLSContext :: Context -> IO ()
closeTLSContext context = bye context `catch` \(_ :: SomeException) -> pure ()

closeOnce :: IO () -> IO (IO ())
closeOnce action = do
  closed <- newMVar False
  let close = modifyMVar_ closed $ \alreadyClosed ->
        if alreadyClosed
          then pure True
          else action >> pure True
  pure close
