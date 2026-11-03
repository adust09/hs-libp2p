{-# LANGUAGE OverloadedStrings #-}

-- | libp2p WebRTC Direct transport.
module LibP2P.Transport.WebRTC.Direct (
  webRTCDirectTransport,
  canDialWebRTCDirect,
  buildWebRTCNoisePrologue,
) where

import Control.Exception (SomeException, catch, finally, onException)
import Control.Monad (unless)
import Data.Bits (shiftL, shiftR, (.&.), (.|.))
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.IP (IPv4, IPv6, fromHostAddress6, toHostAddress, toHostAddress6)
import Data.Word (Word16, Word32)
import Foreign.Ptr (Ptr)
import LibP2P.Core.Multihash qualified as Multihash
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
import LibP2P.Transport.WebRTC.Stream (channelToStreamIO, closeOnce)
import Network.Socket qualified as Socket
import Text.Read (readMaybe)

-- | Construct an ICE-lite WebRTC Direct transport.
webRTCDirectTransport :: KeyPair -> IO Transport
webRTCDirectTransport identity = pure Transport
  { transportDial = dialWebRTC identity
  , transportDialFrom = \local remote -> case local of
      Nothing -> dialWebRTC identity remote
      Just _ -> fail "WebRTC Direct does not support binding an existing listen address"
  , transportListen = listenWebRTC identity
  , transportCanDial = canDialWebRTCDirect
  }

-- | Match WebRTC Direct dial or listen addresses.
canDialWebRTCDirect :: Multiaddr -> Bool
canDialWebRTCDirect address =
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
  establishConnection identity Outbound connection Nothing remoteAddress
    (parsedExpectedPeer parsed)
    `onException` FFI.connectionClose connection

-- v2 is current; retry v1 for deployed legacy peers.
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
  certificateHash <- either fail pure $
    Multihash.encodeMultihashDigest Multihash.SHA256 fingerprint
  let advertised = appendCerthash (makeAddress actualPort) certificateHash
  close <- closeOnce (FFI.listenerClose listener)
  pure Listener
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
  KeyPair -> Direction -> Ptr FFI.CWebRTCConnection -> Maybe Multiaddr ->
  Multiaddr -> Maybe PeerId -> IO RawConnection
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
  let native = NativeMuxer
        { nativePeerId = hrRemotePeerId handshake
        , nativeSecurity = "/noise"
        , nativeMuxerProtocol = "/webrtc-direct"
        , nativeOpenStream = FFI.connectionOpenChannel connection >>= channelToStreamIO
        , nativeAcceptStream = FFI.connectionAcceptChannel connection >>= channelToStreamIO
        , nativeClose = close
        }
  pure RawConnection
    { rcEndpoint = NativeMuxerEndpoint native
    , rcLocalAddr = localAddress
    , rcRemoteAddr = remoteAddress
    , rcClose = close
    , rcRelayLimit = Nothing
    }

webRTCNoisePrologue :: Direction -> Ptr FFI.CWebRTCConnection -> IO ByteString
webRTCNoisePrologue direction connection = do
  local <- FFI.connectionLocalFingerprint connection
  remote <- FFI.connectionRemoteFingerprint connection
  let (clientFingerprint, serverFingerprint) = case direction of
        Outbound -> (local, remote)
        Inbound -> (remote, local)
  either fail pure $ buildWebRTCNoisePrologue clientFingerprint serverFingerprint

-- | Build the Noise prologue from raw SHA-256 DTLS fingerprints.
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
  pure ParsedAddress
    { parsedIP = ip
    , parsedPort = port
    , parsedFingerprint = fingerprint
    , parsedExpectedPeer = expectedPeer
    }

parseListenAddress :: Multiaddr -> Either String (String, Word16, Word16 -> Multiaddr)
parseListenAddress (Multiaddr protocols) = case protocols of
  [IP4 word, UDP port, WebRTCDirect] ->
    Right (renderIPv4 word, port, \actual -> Multiaddr [IP4 word, UDP actual, WebRTCDirect])
  [IP6 bytes, UDP port, WebRTCDirect]
    | BS.length bytes == 16 -> Right
        ( show (bytesToIPv6 bytes)
        , port
        , \actual -> Multiaddr [IP6 bytes, UDP actual, WebRTCDirect]
        )
  _ -> Left "WebRTC Direct listen address must be /ip4|ip6/.../udp/.../webrtc-direct"

parseEndpoint :: Multiaddr -> Either String (String, Word16, [Protocol])
parseEndpoint (Multiaddr protocols) = case protocols of
  IP4 word : UDP port : WebRTCDirect : rest -> Right (renderIPv4 word, port, rest)
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
verifyExpectedPeer (Just expected) actual = unless (expected == actual) $
  fail "WebRTC Direct Noise peer ID does not match the /p2p address"

stripP2P :: Multiaddr -> (Multiaddr, Maybe PeerId)
stripP2P (Multiaddr protocols) = case reverse protocols of
  P2P bytes : rest -> (Multiaddr (reverse rest), Just (PeerId bytes))
  _ -> (Multiaddr protocols, Nothing)

appendCerthash :: Multiaddr -> ByteString -> Multiaddr
appendCerthash (Multiaddr protocols) hashBytes =
  Multiaddr (protocols <> [Certhash hashBytes])

hostAddressToWord :: Socket.HostAddress -> Word32
hostAddressToWord host =
  let (a, b, c, d) = Socket.hostAddressToTuple host
   in (fromIntegral a `shiftL` 24)
        .|. (fromIntegral b `shiftL` 16)
        .|. (fromIntegral c `shiftL` 8)
        .|. fromIntegral d

renderIPv4 :: Word32 -> String
renderIPv4 word =
  show ((word `shiftR` 24) .&. 0xff) <> "."
    <> show ((word `shiftR` 16) .&. 0xff) <> "."
    <> show ((word `shiftR` 8) .&. 0xff) <> "."
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
ipv6ToBytes address = BS.pack (concatMap wordBytes [a, b, c, d])
 where
  (a, b, c, d) = toHostAddress6 address
  wordBytes word =
    [ fromIntegral (word `shiftR` 24)
    , fromIntegral (word `shiftR` 16)
    , fromIntegral (word `shiftR` 8)
    , fromIntegral word
    ]
