{-# LANGUAGE OverloadedStrings #-}

{- | libp2p WebRTC Direct transport.

WebRTC provides DTLS-authenticated SCTP data channels over UDP. A negotiated
channel with ID 0 carries the Noise XX identity handshake; every subsequent
data channel is exposed as one native libp2p stream.
-}
module LibP2P.Transport.WebRTC (
  newWebRTCTransport,
  canDialWebRTC,
  buildWebRTCNoisePrologue,
) where

import Control.Concurrent (MVar, modifyMVar, modifyMVar_, newMVar)
import Control.Exception (SomeException, catch, finally, onException)
import Control.Monad (unless)
import Data.Bits (shiftL, shiftR, (.&.), (.|.))
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.IP (
  IPv4,
  IPv6,
  fromHostAddress6,
  toHostAddress,
  toHostAddress6,
 )
import Data.Word (Word16, Word32, Word64)
import Foreign.Ptr (Ptr)
import LibP2P.Core.Multihash qualified as Multihash
import LibP2P.Core.Varint (decodeUvarint, encodeUvarint)
import LibP2P.Crypto.Key (KeyPair)
import LibP2P.Crypto.PeerId (PeerId (..))
import LibP2P.Multiaddr (Multiaddr (..))
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.MultistreamSelect.Negotiation (StreamIO (..))
import LibP2P.Noise.Handshake (HandshakeResult (..))
import LibP2P.Switch.Types (Direction (..))
import LibP2P.Switch.Upgrade (performStreamHandshakeWithPrologue)
import LibP2P.Transport (
  ConnectionEndpoint (..),
  Listener (..),
  NativeMuxer (..),
  RawConnection (..),
  Transport (..),
 )
import LibP2P.Transport.WebRTC.FFI qualified as FFI
import Network.Socket qualified as Socket
import Text.Read (readMaybe)

{- | Construct a WebRTC Direct transport. Each listener creates one DTLS
certificate and advertises its SHA-256 multihash as @/certhash@.
-}
newWebRTCTransport :: KeyPair -> IO Transport
newWebRTCTransport identity =
  pure
    Transport
      { transportDial = dialWebRTC identity
      , transportDialFrom = \local remote -> case local of
          Nothing -> dialWebRTC identity remote
          Just _ -> fail "WebRTC Direct does not support binding an existing listen address"
      , transportListen = listenWebRTC identity
      , transportCanDial = canDialWebRTC
      }

{- | Match WebRTC Direct dial addresses containing exactly one SHA-256
certificate hash. A trailing peer ID is optional.
-}
canDialWebRTC :: Multiaddr -> Bool
canDialWebRTC address =
  either (const False) (const True) (parseDialAddress address)
    || either (const False) (const True) (parseListenAddress address)

data ParsedAddress = ParsedAddress
  { parsedIP :: !String
  , parsedPort :: !Word16
  , parsedFingerprint :: !ByteString
  , parsedExpectedPeer :: !(Maybe PeerId)
  }

dialWebRTC :: KeyPair -> Multiaddr -> IO RawConnection
dialWebRTC identity remoteAddress = do
  parsed <- either fail pure (parseDialAddress remoteAddress)
  connection <- dialWithFallback parsed
  establishConnection
    identity
    Outbound
    connection
    Nothing
    remoteAddress
    (parsedExpectedPeer parsed)
    `onException` FFI.connectionClose connection

-- v2 is the current protocol. Retry with v1 for deployed legacy peers.
dialWithFallback :: ParsedAddress -> IO (Ptr FFI.CWebRTCConnection)
dialWithFallback parsed =
  FFI.dial (parsedIP parsed) (parsedPort parsed) (parsedFingerprint parsed) 2
    `catch` \(_ :: SomeException) ->
      FFI.dial (parsedIP parsed) (parsedPort parsed) (parsedFingerprint parsed) 1

listenWebRTC :: KeyPair -> Multiaddr -> IO Listener
listenWebRTC identity requestedAddress = do
  (ip, port, makeAddress) <- either fail pure (parseListenAddress requestedAddress)
  listener <- FFI.listenerNew ip port
  actualPort <- FFI.listenerPort listener
  fingerprint <- FFI.listenerFingerprint listener
  certificateHash <-
    either fail pure $
      Multihash.encodeMultihashDigest Multihash.SHA256 fingerprint
  let advertised = appendCerthash (makeAddress actualPort) certificateHash
  close <- closeOnce (FFI.listenerClose listener)
  pure
    Listener
      { listenerAccept = acceptConnection identity listener advertised
      , listenerClose = close
      , listenerAddr = advertised
      }

acceptConnection :: KeyPair -> Ptr FFI.CWebRTCListener -> Multiaddr -> IO RawConnection
acceptConnection identity listener localAddress = do
  connection <- FFI.listenerAccept listener
  remoteAddress <- connectionAddress connection True
  establishConnection identity Inbound connection (Just localAddress) remoteAddress Nothing
    `onException` FFI.connectionClose connection

establishConnection ::
  KeyPair ->
  Direction ->
  Ptr FFI.CWebRTCConnection ->
  Maybe Multiaddr ->
  Multiaddr ->
  Maybe PeerId ->
  IO RawConnection
establishConnection identity direction connection advertisedLocal remoteAddress expectedPeer = do
  noiseChannel <- FFI.connectionNoiseChannel connection
  noiseStream <- channelToStreamIO noiseChannel
  prologue <- webRTCNoisePrologue direction connection
  let noiseDirection = case direction of
        Outbound -> Inbound
        Inbound -> Outbound
  (_, handshake) <-
    performStreamHandshakeWithPrologue identity noiseDirection prologue noiseStream
      `finally` streamClose noiseStream
  verifyExpectedPeer expectedPeer (hrRemotePeerId handshake)
  localAddress <- maybe (connectionAddress connection False) pure advertisedLocal
  close <- closeOnce (FFI.connectionClose connection)
  let native =
        NativeMuxer
          { nativePeerId = hrRemotePeerId handshake
          , nativeSecurity = "/noise"
          , nativeMuxerProtocol = "/webrtc-direct"
          , nativeOpenStream =
              FFI.connectionOpenChannel connection >>= channelToStreamIO
          , nativeAcceptStream =
              FFI.connectionAcceptChannel connection >>= channelToStreamIO
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

data ChannelReadState = ChannelReadState
  { channelBuffered :: !ByteString
  , channelWireBuffered :: !ByteString
  , channelFinished :: !Bool
  }

channelToStreamIO :: Ptr FFI.CWebRTCChannel -> IO StreamIO
channelToStreamIO channel = do
  state <- newMVar (ChannelReadState BS.empty BS.empty False)
  close <- closeOnce $ do
    FFI.channelSend channel (encodeFlagFrame 0)
      `catch` \(_ :: SomeException) -> pure ()
    FFI.channelClose channel
  pure
    StreamIO
      { streamWrite = mapM_ (FFI.channelSend channel . encodeDataFrame) . chunksOf 1200
      , streamReadByte = BS.head <$> readChannel state channel 1
      , streamReadChunk = readChannel state channel
      , streamClose = close
      }

readChannel ::
  MVar ChannelReadState -> Ptr FFI.CWebRTCChannel -> Int -> IO ByteString
readChannel stateVar channel requested
  | requested <= 0 = pure BS.empty
  | otherwise = modifyMVar stateVar $ \state -> do
      filled <- fillReadBuffer channel state
      if BS.null (channelBuffered filled)
        then fail "WebRTC data channel closed"
        else do
          let (result, remaining) = BS.splitAt requested (channelBuffered filled)
          pure (filled{channelBuffered = remaining}, result)

fillReadBuffer ::
  Ptr FFI.CWebRTCChannel -> ChannelReadState -> IO ChannelReadState
fillReadBuffer _ state
  | not (BS.null (channelBuffered state)) || channelFinished state = pure state
fillReadBuffer channel state = do
  received <- receiveFrame channel (channelWireBuffered state)
  case received of
    Nothing -> pure state{channelFinished = True}
    Just (framed, remaining) -> case decodeMessage framed Nothing Nothing of
      Left message -> fail message
      Right (Just payload, _) ->
        pure state{channelBuffered = payload, channelWireBuffered = remaining}
      Right (Nothing, Just 0) -> do
        FFI.channelSend channel (encodeFlagFrame 3)
        pure state{channelWireBuffered = remaining, channelFinished = True}
      Right _ -> fillReadBuffer channel state{channelWireBuffered = remaining}

receiveFrame ::
  Ptr FFI.CWebRTCChannel -> ByteString -> IO (Maybe (ByteString, ByteString))
receiveFrame channel buffered = case extractFrame buffered of
  Left message -> fail message
  Right (Just result) -> pure (Just result)
  Right Nothing -> do
    received <- FFI.channelReceive channel
    case received of
      Nothing
        | BS.null buffered -> pure Nothing
        | otherwise -> fail "WebRTC stream frame is truncated"
      Just bytes -> receiveFrame channel (buffered <> bytes)

encodeDataFrame :: ByteString -> ByteString
encodeDataFrame payload = frame message
 where
  message =
    BS.singleton 0x12
      <> encodeUvarint (fromIntegral (BS.length payload))
      <> payload

encodeFlagFrame :: Word64 -> ByteString
encodeFlagFrame flag = frame (BS.singleton 0x08 <> encodeUvarint flag)

frame :: ByteString -> ByteString
frame message = encodeUvarint (fromIntegral (BS.length message)) <> message

extractFrame :: ByteString -> Either String (Maybe (ByteString, ByteString))
extractFrame input = case decodeFrameLength input of
  Nothing -> Right Nothing
  Just (Left message) -> Left message
  Just (Right (frameLength, prefixLength)) -> do
    let totalLength = frameLength + fromIntegral prefixLength
    unless (totalLength <= 16384) $
      Left "WebRTC stream frame exceeds 16 KiB"
    let byteCount = fromIntegral frameLength
        frameEnd = prefixLength + byteCount
    if BS.length input < frameEnd
      then Right Nothing
      else
        let framed = BS.take byteCount (BS.drop prefixLength input)
            remaining = BS.drop frameEnd input
         in Right (Just (framed, remaining))

decodeFrameLength :: ByteString -> Maybe (Either String (Word64, Int))
decodeFrameLength = go 0 0 0 . BS.unpack
 where
  go _ _ _ [] = Nothing
  go value shift count (byte : rest)
    | count >= 9 && byte > 1 = Just (Left "WebRTC stream frame length overflows")
    | byte .&. 0x80 == 0 =
        Just (Right (value .|. (fromIntegral byte `shiftL` shift), count + 1))
    | count >= 9 = Just (Left "WebRTC stream frame length is too long")
    | otherwise =
        go (value .|. (fromIntegral (byte .&. 0x7f) `shiftL` shift)) (shift + 7) (count + 1) rest

decodeMessage ::
  ByteString ->
  Maybe ByteString ->
  Maybe Word64 ->
  Either String (Maybe ByteString, Maybe Word64)
decodeMessage input payload flag
  | BS.null input = Right (payload, flag)
  | otherwise = do
      (tag, rest) <- decodeUvarint input
      case (tag `shiftR` 3, tag .&. 0x7) of
        (1, 0) -> do
          (value, remaining) <- decodeUvarint rest
          decodeMessage remaining payload (Just value)
        (2, 2) -> do
          (size, bytes) <- decodeUvarint rest
          unless (size <= fromIntegral (BS.length bytes)) $
            Left "WebRTC stream message is truncated"
          let byteCount = fromIntegral size
              (value, remaining) = BS.splitAt byteCount bytes
          decodeMessage remaining (Just value) flag
        (_, wireType) -> do
          remaining <- skipProtobufField wireType rest
          decodeMessage remaining payload flag

skipProtobufField :: Word64 -> ByteString -> Either String ByteString
skipProtobufField 0 input = snd <$> decodeUvarint input
skipProtobufField 1 input = skipFixed 8 input
skipProtobufField 2 input = do
  (size, bytes) <- decodeUvarint input
  if size > fromIntegral (BS.length bytes)
    then Left "WebRTC stream message is truncated"
    else skipFixed (fromIntegral size) bytes
skipProtobufField 5 input = skipFixed 4 input
skipProtobufField _ _ = Left "WebRTC stream message uses an unsupported wire type"

skipFixed :: Int -> ByteString -> Either String ByteString
skipFixed size input
  | BS.length input < size = Left "WebRTC stream message is truncated"
  | otherwise = Right (BS.drop size input)

chunksOf :: Int -> ByteString -> [ByteString]
chunksOf size bytes
  | BS.null bytes = []
  | otherwise =
      let (chunk, rest) = BS.splitAt size bytes
       in chunk : chunksOf size rest

webRTCNoisePrologue ::
  Direction -> Ptr FFI.CWebRTCConnection -> IO ByteString
webRTCNoisePrologue direction connection = do
  local <- FFI.connectionLocalFingerprint connection
  remote <- FFI.connectionRemoteFingerprint connection
  let (clientFingerprint, serverFingerprint) = case direction of
        Outbound -> (local, remote)
        Inbound -> (remote, local)
  either fail pure $
    buildWebRTCNoisePrologue clientFingerprint serverFingerprint

-- | Build the WebRTC Noise prologue from raw SHA-256 DTLS fingerprints.
buildWebRTCNoisePrologue :: ByteString -> ByteString -> Either String ByteString
buildWebRTCNoisePrologue clientFingerprint serverFingerprint = do
  client <- Multihash.encodeMultihashDigest Multihash.SHA256 clientFingerprint
  server <- Multihash.encodeMultihashDigest Multihash.SHA256 serverFingerprint
  pure $ "libp2p-webrtc-noise:" <> client <> server

connectionAddress :: Ptr FFI.CWebRTCConnection -> Bool -> IO Multiaddr
connectionAddress connection remote = do
  ip <- FFI.connectionIP connection remote
  port <- FFI.connectionPort connection remote
  socketIPToMultiaddr ip port

socketIPToMultiaddr :: String -> Word16 -> IO Multiaddr
socketIPToMultiaddr ip port = case (readMaybe ip :: Maybe IPv4, readMaybe ip :: Maybe IPv6) of
  (Just address, _) ->
    pure $ Multiaddr [IP4 (hostAddressToWord (toHostAddress address)), UDP port, WebRTCDirect]
  (_, Just address) ->
    pure $ Multiaddr [IP6 (ipv6ToBytes address), UDP port, WebRTCDirect]
  _ -> fail "WebRTC connection returned an invalid IP address"

parseDialAddress :: Multiaddr -> Either String ParsedAddress
parseDialAddress address = do
  let (withoutPeer, expectedPeer) = stripP2P address
  (ip, port, suffix) <- parseEndpoint withoutPeer
  certificateHash <- case suffix of
    [Certhash value] -> Right value
    _ -> Left "WebRTC Direct address requires exactly one /certhash"
  fingerprint <- decodeSHA256 certificateHash
  pure
    ParsedAddress
      { parsedIP = ip
      , parsedPort = port
      , parsedFingerprint = fingerprint
      , parsedExpectedPeer = expectedPeer
      }

parseListenAddress ::
  Multiaddr -> Either String (String, Word16, Word16 -> Multiaddr)
parseListenAddress (Multiaddr protocols) = case protocols of
  [IP4 word, UDP port, WebRTCDirect] ->
    Right (renderIPv4 word, port, \actual -> Multiaddr [IP4 word, UDP actual, WebRTCDirect])
  [IP6 bytes, UDP port, WebRTCDirect]
    | BS.length bytes == 16 ->
        Right
          ( show (bytesToIPv6 bytes)
          , port
          , \actual -> Multiaddr [IP6 bytes, UDP actual, WebRTCDirect]
          )
  _ -> Left "WebRTC Direct listen address must be /ip4|ip6/.../udp/.../webrtc-direct"

parseEndpoint :: Multiaddr -> Either String (String, Word16, [Protocol])
parseEndpoint (Multiaddr protocols) = case protocols of
  IP4 word : UDP port : WebRTCDirect : rest ->
    Right (renderIPv4 word, port, rest)
  IP6 bytes : UDP port : WebRTCDirect : rest
    | BS.length bytes == 16 -> Right (show (bytesToIPv6 bytes), port, rest)
  _ -> Left "WebRTC Direct address must be /ip4|ip6/.../udp/.../webrtc-direct"

decodeSHA256 :: ByteString -> Either String ByteString
decodeSHA256 multihash = do
  (algorithm, digest) <- Multihash.validateMultihash multihash
  unless (algorithm == Multihash.SHA256) $
    Left "WebRTC Direct certhash must use SHA-256"
  unless (BS.length digest == 32) $
    Left "WebRTC Direct SHA-256 certhash must contain 32 bytes"
  pure digest

verifyExpectedPeer :: Maybe PeerId -> PeerId -> IO ()
verifyExpectedPeer Nothing _ = pure ()
verifyExpectedPeer (Just expected) actual =
  unless (expected == actual) $
    fail "WebRTC Direct Noise peer ID does not match the /p2p address"

stripP2P :: Multiaddr -> (Multiaddr, Maybe PeerId)
stripP2P (Multiaddr protocols) = case reverse protocols of
  P2P bytes : rest -> (Multiaddr (reverse rest), Just (PeerId bytes))
  _ -> (Multiaddr protocols, Nothing)

appendCerthash :: Multiaddr -> ByteString -> Multiaddr
appendCerthash (Multiaddr protocols) hashBytes =
  Multiaddr (protocols <> [Certhash hashBytes])

closeOnce :: IO () -> IO (IO ())
closeOnce action = do
  closed <- newMVar False
  pure $ modifyMVar_ closed $ \alreadyClosed ->
    if alreadyClosed then pure True else action >> pure True

hostAddressToWord :: Socket.HostAddress -> Word32
hostAddressToWord host =
  let (a, b, c, d) = Socket.hostAddressToTuple host
   in (fromIntegral a `shiftL` 24)
        .|. (fromIntegral b `shiftL` 16)
        .|. (fromIntegral c `shiftL` 8)
        .|. fromIntegral d

renderIPv4 :: Word32 -> String
renderIPv4 word =
  show ((word `shiftR` 24) .&. 0xff)
    <> "."
    <> show ((word `shiftR` 16) .&. 0xff)
    <> "."
    <> show ((word `shiftR` 8) .&. 0xff)
    <> "."
    <> show (word .&. 0xff)

bytesToIPv6 :: ByteString -> IPv6
bytesToIPv6 bytes = fromHostAddress6 (word 0, word 4, word 8, word 12)
 where
  word offset =
    (fromIntegral (BS.index bytes offset) `shiftL` 24)
      .|. (fromIntegral (BS.index bytes (offset + 1)) `shiftL` 16)
      .|. (fromIntegral (BS.index bytes (offset + 2)) `shiftL` 8)
      .|. fromIntegral (BS.index bytes (offset + 3))

ipv6ToBytes :: IPv6 -> ByteString
ipv6ToBytes address = BS.pack (concatMap wordBytes words32)
 where
  (a, b, c, d) = toHostAddress6 address
  words32 = [a, b, c, d]
  wordBytes word =
    [ fromIntegral (word `shiftR` 24)
    , fromIntegral (word `shiftR` 16)
    , fromIntegral (word `shiftR` 8)
    , fromIntegral word
    ]
