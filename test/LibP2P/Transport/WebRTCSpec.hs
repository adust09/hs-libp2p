{-# LANGUAGE CPP #-}

module LibP2P.Transport.WebRTCSpec (spec) where

#ifdef WITH_WEBRTC
import Control.Concurrent.Async (concurrently)
import Control.Exception (bracket)
import Control.Monad (replicateM)
import Data.ByteArray.Encoding (Base (Base16), convertFromBase)
import Data.ByteString qualified as BS
import Data.ByteString.Char8 qualified as C8
import Data.Text (Text)
import LibP2P.Core.Multihash qualified as Multihash
import LibP2P.Crypto.Ed25519 (generateKeyPair)
import LibP2P.Crypto.Key (KeyPair, publicKey)
import LibP2P.Crypto.PeerId (PeerId, fromPublicKey)
import LibP2P.Multiaddr (Multiaddr (..), fromText)
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.MultistreamSelect.Negotiation (StreamIO (..))
import LibP2P.Protocol.Ping (PingResult (..), registerPingHandler, sendPing)
import LibP2P.Switch (addTransport, newSwitch, switchClose)
import LibP2P.Switch.Dial (dial)
import LibP2P.Switch.Listen (defaultConnectionGater, switchListen)
import LibP2P.Switch.Types (Connection (..))
import LibP2P.Transport (
  ConnectionEndpoint (..),
  Listener (..),
  NativeMuxer (..),
  RawConnection (..),
  Transport (..),
 )
import LibP2P.Transport.WebRTC (
  buildWebRTCNoisePrologue,
  canDialWebRTC,
  newWebRTCTransport,
 )
import System.Timeout (timeout)
import Test.Hspec

spec :: Spec
spec = do
  describe "canDialWebRTC" $ do
    it "accepts IPv4 and IPv6 WebRTC Direct addresses with SHA-256 certhashes" $ do
      canDialWebRTC (parseAddr sampleIPv4Address) `shouldBe` True
      canDialWebRTC (parseAddr sampleIPv6Address) `shouldBe` True

    it "accepts listen addresses and rejects malformed transport stacks" $ do
      canDialWebRTC (parseAddr listenAddress) `shouldBe` True
      canDialWebRTC (parseAddr "/ip4/127.0.0.1/tcp/443/ws") `shouldBe` False

    it "rejects non-SHA-256 certhashes" $ do
      let identityHash = Multihash.encodeMultihash Multihash.Identity "certificate"
          address = Multiaddr [IP4 0x7f000001, UDP 443, WebRTCDirect, Certhash identityHash]
      canDialWebRTC address `shouldBe` False

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
      transport <- newWebRTCTransport serverKey
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
          newWebRTCTransport clientKey >>= addTransport clientSwitch
          newWebRTCTransport serverKey >>= addTransport serverSwitch
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

withWebRTCPair ::
  ((PeerId, PeerId, RawConnection, RawConnection) -> IO a) -> IO a
withWebRTCPair action = do
  (clientPeer, clientKey) <- generateIdentity
  (serverPeer, serverKey) <- generateIdentity
  clientTransport <- newWebRTCTransport clientKey
  serverTransport <- newWebRTCTransport serverKey
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
