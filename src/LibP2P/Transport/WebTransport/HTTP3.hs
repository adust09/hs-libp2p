{-# LANGUAGE OverloadedStrings #-}

{- | Minimal HTTP/3 WebTransport session layer for libp2p.

This implements only the protocol surface required by the libp2p
WebTransport specification: HTTP/3 SETTINGS, one Extended CONNECT request,
and bidirectional WebTransport streams. QPACK is restricted to a zero-sized
dynamic table, keeping all header blocks self-contained.
-}
module LibP2P.Transport.WebTransport.HTTP3 (
  WebTransportSession,
  connectWebTransport,
  acceptWebTransport,
  openWebTransportStream,
  acceptWebTransportStream,
  closeWebTransportSession,
) where

import Control.Concurrent.Async (Async, async, cancel)
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
import Control.Exception (SomeException, displayException, try)
import Control.Monad (forever, unless, void, when)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Int (Int64)
import Data.List (find)
import Network.QPACK (
  Header,
  QDecoderS,
  QEncoderS,
  dcBlockedSterams,
  dcMaxTableCapacity,
  defaultQDecoderConfig,
  defaultQEncoderConfig,
  ecMaxTableCapacity,
  mk,
  newQDecoderS,
  newQEncoderS,
  original,
 )
import Network.QUIC qualified as QUIC
import Network.QUIC.Internal (encodeInt)

webTransportPath :: ByteString
webTransportPath = "/.well-known/libp2p-webtransport?type=noise"

controlStreamType, qpackEncoderStreamType, qpackDecoderStreamType :: Int64
controlStreamType = 0x00
qpackEncoderStreamType = 0x02
qpackDecoderStreamType = 0x03

headersFrameType, settingsFrameType, webTransportFrameType :: Int64
headersFrameType = 0x01
settingsFrameType = 0x04
webTransportFrameType = 0x41

settingsEnableConnect, settingsH3Datagram, settingsWebTransport :: Int64
settingsEnableConnect = 0x08
settingsH3Datagram = 0x33
settingsWebTransport = 0x2b603742

maximumFrameSize :: Int
maximumFrameSize = 64 * 1024

data Role = ClientRole | ServerRole
  deriving (Eq)

data PeerSettings = PeerSettings
  { peerExtendedConnect :: !Bool
  , peerH3Datagram :: !Bool
  , peerWebTransport :: !Bool
  }

data SessionBase = SessionBase
  { baseConnection :: !QUIC.Connection
  , baseSettings :: !(TMVar (Either String PeerSettings))
  , baseRequest :: !(TMVar (Either String QUIC.Stream))
  , baseSessionId :: !(TMVar QUIC.StreamId)
  , baseIncoming :: !(TQueue (Either String QUIC.Stream))
  , baseEncoder :: !QEncoderS
  , baseDecoder :: !QDecoderS
  , baseDispatcher :: !(Async ())
  , baseLocalStreams :: ![QUIC.Stream]
  }

data WebTransportSession = WebTransportSession
  { sessionBase :: !SessionBase
  , sessionConnectStream :: !QUIC.Stream
  }

{- | Establish a client WebTransport session over an authenticated QUIC
connection using the standardized libp2p endpoint.
-}
connectWebTransport ::
  QUIC.Connection -> ByteString -> IO WebTransportSession
connectWebTransport connection authority = do
  base <- initializeSession ClientRole connection
  settings <- awaitPeerSettings base
  validatePeerSettings ClientRole settings
  connectStream <- QUIC.stream connection
  let sessionId = QUIC.streamId connectStream
  atomically $ putTMVar (baseSessionId base) sessionId
  sendConnectRequest base connectStream authority
  receiveConnectResponse base connectStream
  pure
    WebTransportSession
      { sessionBase = base
      , sessionConnectStream = connectStream
      }

{- | Accept the single libp2p WebTransport Extended CONNECT request on a QUIC
connection and send a successful response.
-}
acceptWebTransport :: QUIC.Connection -> IO WebTransportSession
acceptWebTransport connection = do
  base <- initializeSession ServerRole connection
  settings <- awaitPeerSettings base
  validatePeerSettings ServerRole settings
  connectStream <- awaitConnectRequest base
  validateConnectRequest base connectStream
  let sessionId = QUIC.streamId connectStream
  atomically $ putTMVar (baseSessionId base) sessionId
  sendConnectResponse base connectStream
  pure
    WebTransportSession
      { sessionBase = base
      , sessionConnectStream = connectStream
      }

-- | Open a bidirectional stream in this WebTransport session.
openWebTransportStream :: WebTransportSession -> IO QUIC.Stream
openWebTransportStream session = do
  let base = sessionBase session
  stream <- QUIC.stream (baseConnection base)
  sessionId <- atomically $ readTMVar (baseSessionId base)
  QUIC.sendStream stream $
    encodeInt webTransportFrameType <> encodeInt (fromIntegral sessionId)
  pure stream

-- | Accept the next bidirectional stream belonging to this session.
acceptWebTransportStream :: WebTransportSession -> IO QUIC.Stream
acceptWebTransportStream session = do
  result <- atomically $ readTQueue (baseIncoming (sessionBase session))
  either fail pure result

-- | Close the HTTP/3 control request and stop dispatching streams.
closeWebTransportSession :: WebTransportSession -> IO ()
closeWebTransportSession session =
  cancel (baseDispatcher (sessionBase session))

initializeSession :: Role -> QUIC.Connection -> IO SessionBase
initializeSession role connection = do
  settings <- newEmptyTMVarIO
  request <- newEmptyTMVarIO
  sessionId <- newEmptyTMVarIO
  incoming <- newTQueueIO
  encoder <- makeEncoder
  decoder <- makeDecoder
  localStreams <- openLocalControlStreams connection
  let create dispatcher =
        SessionBase
          { baseConnection = connection
          , baseSettings = settings
          , baseRequest = request
          , baseSessionId = sessionId
          , baseIncoming = incoming
          , baseEncoder = encoder
          , baseDecoder = decoder
          , baseDispatcher = dispatcher
          , baseLocalStreams = localStreams
          }
  dispatcher <- async $ dispatchIncoming role connection settings request sessionId incoming
  pure (create dispatcher)

makeEncoder :: IO QEncoderS
makeEncoder =
  newQEncoderS
    defaultQEncoderConfig{ecMaxTableCapacity = 0}
    rejectDynamicInstruction
    0
    True
    False
 where
  rejectDynamicInstruction bytes =
    unless (BS.null bytes) $ fail "unexpected QPACK encoder instruction"

makeDecoder :: IO QDecoderS
makeDecoder = fst <$> newQDecoderS config (const (pure ())) False
 where
  config =
    defaultQDecoderConfig
      { dcMaxTableCapacity = 0
      , dcBlockedSterams = 0
      }

openLocalControlStreams :: QUIC.Connection -> IO [QUIC.Stream]
openLocalControlStreams connection = do
  control <- QUIC.unidirectionalStream connection
  encoder <- QUIC.unidirectionalStream connection
  decoder <- QUIC.unidirectionalStream connection
  QUIC.sendStream control $ encodeInt controlStreamType <> encodeSettingsFrame
  QUIC.sendStream encoder (encodeInt qpackEncoderStreamType)
  QUIC.sendStream decoder (encodeInt qpackDecoderStreamType)
  pure [control, encoder, decoder]

encodeSettingsFrame :: ByteString
encodeSettingsFrame = encodeFrame settingsFrameType payload
 where
  payload =
    BS.concat
      [ setting settingsEnableConnect
      , setting settingsH3Datagram
      , setting settingsWebTransport
      ]
  setting key = encodeInt key <> encodeInt 1

dispatchIncoming ::
  Role ->
  QUIC.Connection ->
  TMVar (Either String PeerSettings) ->
  TMVar (Either String QUIC.Stream) ->
  TMVar QUIC.StreamId ->
  TQueue (Either String QUIC.Stream) ->
  IO ()
dispatchIncoming role connection settings request sessionId incoming = do
  outcome <- try $ forever $ do
    stream <- QUIC.acceptStream connection
    if isUnidirectional (QUIC.streamId stream)
      then handleUnidirectional stream settings
      else handleBidirectional role stream request sessionId incoming
  case outcome of
    Left (err :: SomeException) ->
      publishDispatchError (displayException err) settings request incoming
    Right () -> pure ()

isUnidirectional :: QUIC.StreamId -> Bool
isUnidirectional streamId = streamId `mod` 4 >= 2

handleUnidirectional ::
  QUIC.Stream -> TMVar (Either String PeerSettings) -> IO ()
handleUnidirectional stream settings = do
  streamType <- readVarint stream
  case streamType of
    0x00 -> readSettings stream >>= atomically . void . tryPutTMVar settings . Right
    0x02 -> pure ()
    0x03 -> pure ()
    _ -> QUIC.closeStream stream

handleBidirectional ::
  Role ->
  QUIC.Stream ->
  TMVar (Either String QUIC.Stream) ->
  TMVar QUIC.StreamId ->
  TQueue (Either String QUIC.Stream) ->
  IO ()
handleBidirectional role stream request sessionId incoming = do
  firstType <- readVarint stream
  case firstType of
    0x01
      | role == ServerRole ->
          atomically $ void (tryPutTMVar request (Right stream))
    0x41 -> do
      receivedId <- readVarint stream
      expectedId <- atomically $ readTMVar sessionId
      if receivedId == fromIntegral expectedId
        then atomically $ writeTQueue incoming (Right stream)
        else QUIC.closeStream stream
    _ -> fail $ "unexpected HTTP/3 bidirectional stream type " <> show firstType

publishDispatchError ::
  String ->
  TMVar (Either String PeerSettings) ->
  TMVar (Either String QUIC.Stream) ->
  TQueue (Either String QUIC.Stream) ->
  IO ()
publishDispatchError message settings request incoming = atomically $ do
  void $ tryPutTMVar settings (Left message)
  void $ tryPutTMVar request (Left message)
  writeTQueue incoming (Left message)

readSettings :: QUIC.Stream -> IO PeerSettings
readSettings stream = do
  frameType <- readVarint stream
  when (frameType /= settingsFrameType) $
    fail "HTTP/3 control stream did not begin with SETTINGS"
  payload <- readFramePayload stream
  pairs <- either fail pure (decodeSettings payload)
  pure
    PeerSettings
      { peerExtendedConnect = enabled settingsEnableConnect pairs
      , peerH3Datagram = enabled settingsH3Datagram pairs
      , peerWebTransport = enabled settingsWebTransport pairs
      }
 where
  enabled key pairs = lookup key pairs == Just 1

decodeSettings :: ByteString -> Either String [(Int64, Int64)]
decodeSettings bytes
  | BS.null bytes = Right []
  | otherwise = do
      (key, rest1) <- decodeVarint bytes
      (value, rest2) <- decodeVarint rest1
      remaining <- decodeSettings rest2
      if any ((== key) . fst) remaining
        then Left $ "duplicate HTTP/3 setting " <> show key
        else Right ((key, value) : remaining)

awaitPeerSettings :: SessionBase -> IO PeerSettings
awaitPeerSettings base =
  atomically (readTMVar (baseSettings base)) >>= either fail pure

validatePeerSettings :: Role -> PeerSettings -> IO ()
validatePeerSettings role settings = do
  when (role == ClientRole && not (peerExtendedConnect settings)) $
    fail "server did not enable HTTP/3 Extended CONNECT"
  unless (peerH3Datagram settings) $
    fail "peer did not enable HTTP/3 datagrams"
  when (role == ClientRole && not (peerWebTransport settings)) $
    fail "server did not enable WebTransport"

awaitConnectRequest :: SessionBase -> IO QUIC.Stream
awaitConnectRequest base =
  atomically (readTMVar (baseRequest base)) >>= either fail pure

sendConnectRequest :: SessionBase -> QUIC.Stream -> ByteString -> IO ()
sendConnectRequest base stream authority = do
  payload <-
    baseEncoder
      base
      (QUIC.streamId stream)
      [ header ":method" "CONNECT"
      , header ":scheme" "https"
      , header ":authority" authority
      , header ":path" webTransportPath
      , header ":protocol" "webtransport"
      ]
  QUIC.sendStream stream (encodeFrame headersFrameType payload)

validateConnectRequest :: SessionBase -> QUIC.Stream -> IO ()
validateConnectRequest base stream = do
  headers <- receiveHeaders base stream headersFrameType
  requireHeader headers ":method" "CONNECT"
  requireHeader headers ":scheme" "https"
  requireHeader headers ":protocol" "webtransport"
  requireHeader headers ":path" webTransportPath

sendConnectResponse :: SessionBase -> QUIC.Stream -> IO ()
sendConnectResponse base stream = do
  payload <- baseEncoder base (QUIC.streamId stream) [header ":status" "200"]
  QUIC.sendStream stream (encodeFrame headersFrameType payload)

receiveConnectResponse :: SessionBase -> QUIC.Stream -> IO ()
receiveConnectResponse base stream = do
  frameType <- readVarint stream
  headers <- receiveHeaders base stream frameType
  requireHeader headers ":status" "200"

receiveHeaders :: SessionBase -> QUIC.Stream -> Int64 -> IO [Header]
receiveHeaders base stream frameType = do
  when (frameType /= headersFrameType) $
    fail $
      "expected HTTP/3 HEADERS frame, got " <> show frameType
  payload <- readFramePayload stream
  decoded <- baseDecoder base (QUIC.streamId stream) payload
  maybe (fail "failed to decode QPACK header block") pure decoded

header :: ByteString -> ByteString -> Header
header name value = (mk name, value)

requireHeader :: [Header] -> ByteString -> ByteString -> IO ()
requireHeader headers name expected =
  case find ((== name) . original . fst) headers of
    Just (_, actual) | actual == expected -> pure ()
    _ -> fail $ "invalid or missing HTTP/3 header " <> show name

encodeFrame :: Int64 -> ByteString -> ByteString
encodeFrame frameType payload =
  encodeInt frameType <> encodeInt (fromIntegral (BS.length payload)) <> payload

readFramePayload :: QUIC.Stream -> IO ByteString
readFramePayload stream = do
  size <- readVarint stream
  when (size < 0 || size > fromIntegral maximumFrameSize) $
    fail $
      "HTTP/3 frame too large: " <> show size
  readExact stream (fromIntegral size)

readVarint :: QUIC.Stream -> IO Int64
readVarint stream = do
  first <- readExact stream 1
  let byte = BS.head first
      trailingLength = case byte `div` 64 of
        0 -> 0
        1 -> 1
        2 -> 3
        _ -> 7
      initial = fromIntegral (byte `mod` 64)
  trailing <- readExact stream trailingLength
  pure $ BS.foldl' (\value next -> value * 256 + fromIntegral next) initial trailing

decodeVarint :: ByteString -> Either String (Int64, ByteString)
decodeVarint bytes
  | BS.null bytes = Left "truncated QUIC varint"
  | BS.length bytes < totalLength = Left "truncated QUIC varint"
  | otherwise = Right (value, BS.drop totalLength bytes)
 where
  first = BS.head bytes
  trailingLength = case first `div` 64 of
    0 -> 0
    1 -> 1
    2 -> 3
    _ -> 7
  totalLength = trailingLength + 1
  initial = fromIntegral (first `mod` 64)
  value =
    BS.foldl'
      (\acc next -> acc * 256 + fromIntegral next)
      initial
      (BS.take trailingLength (BS.tail bytes))

readExact :: QUIC.Stream -> Int -> IO ByteString
readExact _ 0 = pure BS.empty
readExact stream wanted = go BS.empty wanted
 where
  go acc 0 = pure acc
  go acc remaining = do
    chunk <- QUIC.recvStream stream remaining
    if BS.null chunk
      then fail "HTTP/3 stream closed unexpectedly"
      else go (acc <> chunk) (remaining - BS.length chunk)
