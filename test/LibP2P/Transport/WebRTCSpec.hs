{-# LANGUAGE CPP #-}

module LibP2P.Transport.WebRTCSpec (spec) where

#ifdef WITH_WEBRTC
import Control.Concurrent (threadDelay)
import Control.Concurrent.Async (concurrently)
import Control.Exception (bracket)
import Control.Monad (replicateM)
import Data.ByteArray.Encoding (Base (Base16), convertFromBase)
import Data.ByteString qualified as BS
import Data.ByteString.Char8 qualified as C8
import Data.Maybe (listToMaybe)
import Data.Text (Text)
import LibP2P.Core.Multihash qualified as Multihash
import LibP2P.Crypto.Ed25519 (generateKeyPair)
import LibP2P.Crypto.Key (KeyPair, publicKey)
import LibP2P.Crypto.PeerId (PeerId, fromPublicKey, peerIdBytes)
import LibP2P.Multiaddr (Multiaddr (..), fromText)
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.MultistreamSelect.Negotiation (StreamIO (..), mkMemoryStreamPair)
import LibP2P.NAT (defaultNATConfig, registerNATHandlers)
import LibP2P.Protocol.Ping (PingResult (..), registerPingHandler, sendPing)
import LibP2P.Switch (addTransport, newSwitch, switchClose)
import LibP2P.Switch.Dial (dial)
import LibP2P.Switch.Listen (defaultConnectionGater, switchListen)
import LibP2P.Switch.Types (Connection (..), Switch)
import LibP2P.Transport (
  ConnectionEndpoint (..),
  Listener (..),
  NativeMuxer (..),
  RawConnection (..),
  Transport (..),
 )
import LibP2P.Transport.TCP (newTCPTransport)
import LibP2P.Transport.WebRTC (
  buildWebRTCNoisePrologue,
  canDialWebRTC,
  canDialWebRTCDirect,
  defaultWebRTCConfig,
  webRTCDirectTransport,
  webRTCTransport,
 )
import LibP2P.Transport.WebRTC.Signaling (
  SignalingMessage (..),
  decodeSignalingMessage,
  encodeSignalingMessage,
  readSignalingMessage,
  writeSignalingMessage,
 )
import System.Timeout (timeout)
import Test.Hspec

spec :: Spec
spec = do
  describe "canDialWebRTCDirect" $ do
    it "accepts IPv4 and IPv6 WebRTC Direct addresses with SHA-256 certhashes" $ do
      canDialWebRTCDirect (parseAddr sampleIPv4Address) `shouldBe` True
      canDialWebRTCDirect (parseAddr sampleIPv6Address) `shouldBe` True

    it "accepts listen addresses and rejects malformed transport stacks" $ do
      canDialWebRTCDirect (parseAddr listenAddress) `shouldBe` True
      canDialWebRTCDirect (parseAddr "/ip4/127.0.0.1/tcp/443/ws") `shouldBe` False

    it "rejects non-SHA-256 certhashes" $ do
      let identityHash = Multihash.encodeMultihash Multihash.Identity "certificate"
          address = Multiaddr [IP4 0x7f000001, UDP 443, WebRTCDirect, Certhash identityHash]
      canDialWebRTCDirect address `shouldBe` False

  describe "canDialWebRTC" $ do
    it "accepts relay-signaled listen and dial addresses" $ do
      let relay = BS.pack [0x00, 0x01]
          target = BS.pack [0x00, 0x02]
          prefix = [IP4 0x7f000001, TCP 4001, P2P relay, P2PCircuit, WebRTC]
      canDialWebRTC (Multiaddr prefix) `shouldBe` True
      canDialWebRTC (Multiaddr (prefix <> [P2P target])) `shouldBe` True

    it "rejects WebRTC Direct and malformed relay stacks" $ do
      canDialWebRTC (parseAddr listenAddress) `shouldBe` False
      canDialWebRTC (Multiaddr [P2PCircuit, WebRTC]) `shouldBe` False

  describe "WebRTC signaling messages" $ do
    it "encodes the protobuf type and UTF-8 payload" $ do
      encodeSignalingMessage (SDPAnswer "answer")
        `shouldBe` BS.pack [0x08, 0x01, 0x12, 0x06, 0x61, 0x6e, 0x73, 0x77, 0x65, 0x72]

    it "round-trips offer, answer, and ICE candidate messages" $ do
      let messages = [SDPOffer "offer", SDPAnswer "answer", ICECandidate "{\"candidate\":\"x\"}"]
      map (decodeSignalingMessage . encodeSignalingMessage) messages
        `shouldBe` map Right messages

    it "reads and writes length-delimited messages over a stream" $ do
      (writer, reader) <- mkMemoryStreamPair
      writeSignalingMessage writer (ICECandidate "candidate")
      readSignalingMessage reader `shouldReturn` Right (ICECandidate "candidate")

  describe "buildWebRTCNoisePrologue" $ do
    it "matches the specification vector and fingerprint order" $ do
      let client = unhex "3e79af40d6059617a0d83b83a52ce73b0c1f37a72c6043ad2969e2351bdca870"
          server = unhex "30fc9f469c207419dfdd0aab5f27a86c973c94e40548db9375cca2e915973b99"
          expected =
            unhex $
              "6c69627032702d7765627274632d6e6f6973653a1220"
                <> "3e79af40d6059617a0d83b83a52ce73b0c1f37a72c6043ad2969e2351bdca870"
                <> "122030fc9f469c207419dfdd0aab5f27a86c973c94e40548db9375cca2e915973b99"
      buildWebRTCNoisePrologue client server `shouldBe` Right expected

  describe "WebRTC Direct loopback" $ do
    it "binds Noise to DTLS fingerprints and exchanges framed native stream data" $
      withWebRTCPair $ \(clientPeer, serverPeer, clientRaw, serverRaw) -> do
        clientMuxer <- expectNative clientRaw
        serverMuxer <- expectNative serverRaw
        nativePeerId clientMuxer `shouldBe` serverPeer
        nativePeerId serverMuxer `shouldBe` clientPeer
        nativeSecurity clientMuxer `shouldBe` "/noise"
        nativeMuxerProtocol clientMuxer `shouldBe` "/webrtc-direct"
        exchangePayload clientMuxer serverMuxer

    it "advertises exactly one SHA-256 certificate hash" $ do
      (_, serverKey) <- generateIdentity
      transport <- webRTCDirectTransport serverKey
      bracket
        (transportListen transport (parseAddr listenAddress))
        listenerClose
        (\listener -> certificateHashes (listenerAddr listener) `shouldSatisfy` validHashes)

  describe "Switch integration" $ do
    it "runs Ping over authenticated WebRTC data channels" $ do
      (clientPeer, clientKey) <- generateIdentity
      (serverPeer, serverKey) <- generateIdentity
      bracket (newSwitch clientPeer clientKey) switchClose $ \clientSwitch ->
        bracket (newSwitch serverPeer serverKey) switchClose $ \serverSwitch -> do
          webRTCDirectTransport clientKey >>= addTransport clientSwitch
          webRTCDirectTransport serverKey >>= addTransport serverSwitch
          registerPingHandler serverSwitch
          addresses <-
            switchListen serverSwitch defaultConnectionGater [parseAddr listenAddress]
          connectionResult <- timeout 10000000 $ dial clientSwitch serverPeer addresses
          connection <- case connectionResult of
            Nothing -> fail "WebRTC Direct Switch dial timed out"
            Just (Left err) -> fail $ "WebRTC Direct Switch dial failed: " <> show err
            Just (Right established) -> pure established
          connSecurity connection `shouldBe` "/noise"
          connMuxer connection `shouldBe` "/webrtc-direct"
          pingResult <- timeout 5000000 $ sendPing clientSwitch connection
          case pingResult of
            Just (Right (PingResult rtt)) -> rtt `shouldSatisfy` (> 0)
            other -> expectationFailure $ "WebRTC Direct Ping failed: " <> show other

    it "runs Ping over Circuit Relay signaling and direct WebRTC" $
      withRelayWebRTC $ \clientSwitch serverPeer address -> do
        connectionResult <- timeout 20000000 $ dial clientSwitch serverPeer [address]
        connection <- case connectionResult of
          Nothing -> fail "relay-signaled WebRTC dial timed out"
          Just (Left err) -> fail $ "relay-signaled WebRTC dial failed: " <> show err
          Just (Right established) -> pure established
        connSecurity connection `shouldBe` "/webrtc"
        connMuxer connection `shouldBe` "/webrtc"
        pingResult <- timeout 5000000 $ sendPing clientSwitch connection
        case pingResult of
          Just (Right (PingResult rtt)) -> rtt `shouldSatisfy` (> 0)
          other -> expectationFailure $ "relay-signaled WebRTC Ping failed: " <> show other

withRelayWebRTC :: (Switch -> PeerId -> Multiaddr -> IO a) -> IO a
withRelayWebRTC action = do
  (relayPeer, relayKey) <- generateIdentity
  bracket (newSwitch relayPeer relayKey) switchClose $ \relaySwitch -> do
    addTransport relaySwitch =<< newTCPTransport
    _ <- registerNATHandlers relaySwitch defaultNATConfig
    relayAddresses <- switchListen relaySwitch defaultConnectionGater [parseAddr "/ip4/127.0.0.1/tcp/0"]
    relayAddress <- maybe (fail "relay did not bind") pure (listToMaybe relayAddresses)
    (serverPeer, serverKey) <- generateIdentity
    bracket (newSwitch serverPeer serverKey) switchClose $ \serverSwitch -> do
      addTransport serverSwitch =<< newTCPTransport
      _ <- registerNATHandlers serverSwitch defaultNATConfig
      webRTCTransport serverSwitch defaultWebRTCConfig >>= addTransport serverSwitch
      registerPingHandler serverSwitch
      let listenAddress' = appendProtocols relayAddress
            [P2P (peerIdBytes relayPeer), P2PCircuit, WebRTC]
      serverAddresses <- switchListen serverSwitch defaultConnectionGater [listenAddress']
      serverAddress <- maybe (fail "WebRTC listener did not bind") pure (listToMaybe serverAddresses)
      (clientPeer, clientKey) <- generateIdentity
      bracket (newSwitch clientPeer clientKey) switchClose $ \clientSwitch -> do
        addTransport clientSwitch =<< newTCPTransport
        _ <- registerNATHandlers clientSwitch defaultNATConfig
        webRTCTransport clientSwitch defaultWebRTCConfig >>= addTransport clientSwitch
        threadDelay 300000
        action clientSwitch serverPeer $
          appendProtocols serverAddress [P2P (peerIdBytes serverPeer)]

appendProtocols :: Multiaddr -> [Protocol] -> Multiaddr
appendProtocols (Multiaddr protocols) suffix = Multiaddr (protocols <> suffix)

withWebRTCPair ::
  ((PeerId, PeerId, RawConnection, RawConnection) -> IO a) -> IO a
withWebRTCPair action = do
  (clientPeer, clientKey) <- generateIdentity
  (serverPeer, serverKey) <- generateIdentity
  clientTransport <- webRTCDirectTransport clientKey
  serverTransport <- webRTCDirectTransport serverKey
  bracket
    (transportListen serverTransport (parseAddr listenAddress))
    listenerClose
    ( \listener -> do
        connected <-
          timeout 10000000 $
            concurrently
              (transportDial clientTransport (listenerAddr listener))
              (listenerAccept listener)
        pair <- maybe (fail "WebRTC Direct loopback timed out") pure connected
        bracket
          (pure pair)
          (\(clientRaw, serverRaw) -> rcClose clientRaw >> rcClose serverRaw)
          ( \(clientRaw, serverRaw) ->
              action (clientPeer, serverPeer, clientRaw, serverRaw)
          )
    )

exchangePayload :: NativeMuxer -> NativeMuxer -> IO ()
exchangePayload clientMuxer serverMuxer = do
  clientStream <- nativeOpenStream clientMuxer
  streamWrite clientStream (BS.replicate 4096 0x5a)
  serverStream <- nativeAcceptStream serverMuxer
  request <- readExactly serverStream 4096
  request `shouldBe` BS.replicate 4096 0x5a
  streamWrite serverStream "native WebRTC stream"
  response <- readExactly clientStream 20
  response `shouldBe` "native WebRTC stream"
  streamClose clientStream
  streamClose serverStream

expectNative :: RawConnection -> IO NativeMuxer
expectNative raw = case rcEndpoint raw of
  NativeMuxerEndpoint native -> pure native
  ByteStreamEndpoint _ -> fail "expected a native WebRTC endpoint"

certificateHashes :: Multiaddr -> [BS.ByteString]
certificateHashes (Multiaddr protocols) =
  [hashBytes | Certhash hashBytes <- protocols]

validHashes :: [BS.ByteString] -> Bool
validHashes [multihash] = case Multihash.validateMultihash multihash of
  Right (Multihash.SHA256, digest) -> BS.length digest == 32
  _ -> False
validHashes _ = False

readExactly :: StreamIO -> Int -> IO BS.ByteString
readExactly stream size = BS.pack <$> replicateM size (streamReadByte stream)

generateIdentity :: IO (PeerId, KeyPair)
generateIdentity = do
  result <- generateKeyPair
  keyPair <- either fail pure result
  pure (fromPublicKey (publicKey keyPair), keyPair)

parseAddr :: Text -> Multiaddr
parseAddr text = case fromText text of
  Left err -> error $ "invalid test multiaddr: " <> show err
  Right address -> address

listenAddress :: Text
listenAddress = "/ip4/127.0.0.1/udp/0/webrtc-direct"

sampleHash :: Text
sampleHash = "uEiDDq4_xNyDorZBH3TlGazyJdOWSwvo4PUo5YHFMrvDE8g"

sampleIPv4Address :: Text
sampleIPv4Address =
  "/ip4/127.0.0.1/udp/443/webrtc-direct/certhash/" <> sampleHash

sampleIPv6Address :: Text
sampleIPv6Address =
  "/ip6/::1/udp/443/webrtc-direct/certhash/" <> sampleHash

unhex :: String -> BS.ByteString
unhex value = case convertFromBase Base16 (C8.pack value) of
  Left err -> error $ "invalid hex fixture: " <> err
  Right bytes -> bytes
#else
import Test.Hspec (Spec)

spec :: Spec
spec = pure ()
#endif
