module LibP2P.Transport.WebTransportSpec (spec) where

import Control.Concurrent.Async (concurrently)
import Control.Exception (bracket, try)
import Control.Monad (replicateM)
import Data.ByteString qualified as BS
import Data.Text (Text)
import LibP2P.Crypto.Ed25519 (generateKeyPair)
import LibP2P.Crypto.Key (KeyPair, publicKey)
import LibP2P.Crypto.PeerId (PeerId, fromPublicKey, peerIdBytes)
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
import LibP2P.Transport.WebTransport (
  canDialWebTransport,
  newWebTransportTransport,
 )
import System.Timeout (timeout)
import Test.Hspec

spec :: Spec
spec = do
  describe "canDialWebTransport" $ do
    it "accepts IP and DNS WebTransport addresses with certhashes" $ do
      canDialWebTransport (parseAddr sampleIPv4Address) `shouldBe` True
      canDialWebTransport (parseAddr sampleIPv6Address) `shouldBe` True
      canDialWebTransport (parseAddr sampleDNSAddress) `shouldBe` True

    it "accepts listen shapes without certhashes and rejects malformed stacks" $ do
      canDialWebTransport
        (parseAddr "/ip4/127.0.0.1/udp/443/quic-v1/webtransport")
        `shouldBe` True
      canDialWebTransport
        (parseAddr "/ip4/127.0.0.1/tcp/443/ws")
        `shouldBe` False

  describe "WebTransport loopback" $ do
    it "authenticates both peers and exchanges native stream data" $
      withWebTransportPair $ \(clientPeer, serverPeer, clientRaw, serverRaw) -> do
        clientMuxer <- expectNative clientRaw
        serverMuxer <- expectNative serverRaw
        nativePeerId clientMuxer `shouldBe` serverPeer
        nativePeerId serverMuxer `shouldBe` clientPeer
        nativeSecurity clientMuxer `shouldBe` "/noise"
        nativeMuxerProtocol clientMuxer `shouldBe` "/webtransport"
        exchangePayload clientMuxer serverMuxer

    it "advertises and verifies a certificate hash" $ do
      (_, serverKey) <- generateIdentity
      transport <- newWebTransportTransport serverKey
      bracket
        (transportListen transport (parseAddr listenAddress))
        listenerClose
        ( \listener -> do
            listenerAddr listener `shouldSatisfy` hasCerthash
            let tampered = replaceCerthash (listenerAddr listener) (BS.replicate 34 0)
            (_, clientKey) <- generateIdentity
            client <- newWebTransportTransport clientKey
            result <-
              timeout 5000000 $
                try (transportDial client tampered) ::
                IO (Maybe (Either IOError RawConnection))
            case result of
              Just (Left _) -> pure ()
              Just (Right raw) -> rcClose raw >> expectationFailure "accepted wrong certhash"
              Nothing -> expectationFailure "wrong-certhash dial timed out"
        )

    it "rejects a mismatched trailing peer ID" $ do
      (_, serverKey) <- generateIdentity
      transport <- newWebTransportTransport serverKey
      bracket
        (transportListen transport (parseAddr listenAddress))
        listenerClose
        ( \listener -> do
            (wrongPeer, clientKey) <- generateIdentity
            client <- newWebTransportTransport clientKey
            let targeted = appendPeer (listenerAddr listener) wrongPeer
            result <-
              timeout 5000000 $
                try (transportDial client targeted) ::
                IO (Maybe (Either IOError RawConnection))
            case result of
              Just (Left _) -> pure ()
              Just (Right raw) -> rcClose raw >> expectationFailure "accepted wrong peer ID"
              Nothing -> expectationFailure "wrong-peer dial timed out"
        )

    it "resolves DNS4 addresses" $ do
      (_, clientKey) <- generateIdentity
      (_, serverKey) <- generateIdentity
      client <- newWebTransportTransport clientKey
      server <- newWebTransportTransport serverKey
      bracket
        (transportListen server (parseAddr listenAddress))
        listenerClose
        ( \listener -> do
            let dnsAddress = replaceHostWithDNS (listenerAddr listener)
            dialed <- timeout 10000000 (transportDial client dnsAddress)
            clientRaw <- maybe (fail "DNS WebTransport dial timed out") pure dialed
            serverRaw <- listenerAccept listener
            rcClose clientRaw
            rcClose serverRaw
        )

  describe "Switch integration" $ do
    it "runs Ping over authenticated native WebTransport streams" $ do
      (clientPeer, clientKey) <- generateIdentity
      (serverPeer, serverKey) <- generateIdentity
      bracket (newSwitch clientPeer clientKey) switchClose $ \clientSwitch ->
        bracket (newSwitch serverPeer serverKey) switchClose $ \serverSwitch -> do
          newWebTransportTransport clientKey >>= addTransport clientSwitch
          newWebTransportTransport serverKey >>= addTransport serverSwitch
          registerPingHandler serverSwitch
          addresses <-
            switchListen
              serverSwitch
              defaultConnectionGater
              [parseAddr listenAddress]
          connectionResult <-
            timeout 10000000 $
              dial clientSwitch serverPeer addresses
          connection <- case connectionResult of
            Nothing -> fail "WebTransport Switch dial timed out"
            Just (Left err) -> fail $ "WebTransport Switch dial failed: " <> show err
            Just (Right established) -> pure established
          connSecurity connection `shouldBe` "/noise"
          connMuxer connection `shouldBe` "/webtransport"
          pingResult <- timeout 5000000 $ sendPing clientSwitch connection
          case pingResult of
            Just (Right (PingResult rtt)) -> rtt `shouldSatisfy` (> 0)
            other -> expectationFailure $ "WebTransport Ping failed: " <> show other

withWebTransportPair ::
  ((PeerId, PeerId, RawConnection, RawConnection) -> IO a) ->
  IO a
withWebTransportPair action = do
  (clientPeer, clientKey) <- generateIdentity
  (serverPeer, serverKey) <- generateIdentity
  clientTransport <- newWebTransportTransport clientKey
  serverTransport <- newWebTransportTransport serverKey
  bracket
    (transportListen serverTransport (parseAddr listenAddress))
    listenerClose
    ( \listener -> do
        connected <-
          timeout 10000000 $
            concurrently
              (transportDial clientTransport (listenerAddr listener))
              (listenerAccept listener)
        pair <- maybe (fail "WebTransport loopback connection timed out") pure connected
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
  streamWrite clientStream "hello over WebTransport"
  serverStream <- nativeAcceptStream serverMuxer
  request <- readExactly serverStream 23
  request `shouldBe` "hello over WebTransport"
  streamWrite serverStream "native stream"
  response <- readExactly clientStream 13
  response `shouldBe` "native stream"
  streamClose clientStream
  streamClose serverStream

expectNative :: RawConnection -> IO NativeMuxer
expectNative raw = case rcEndpoint raw of
  NativeMuxerEndpoint native -> pure native
  ByteStreamEndpoint _ -> fail "expected a native WebTransport endpoint"

hasCerthash :: Multiaddr -> Bool
hasCerthash (Multiaddr protocols) = any isCerthash protocols
 where
  isCerthash Certhash{} = True
  isCerthash _ = False

replaceCerthash :: Multiaddr -> BS.ByteString -> Multiaddr
replaceCerthash (Multiaddr protocols) replacement =
  Multiaddr (map replace protocols)
 where
  replace Certhash{} = Certhash replacement
  replace protocol = protocol

replaceHostWithDNS :: Multiaddr -> Multiaddr
replaceHostWithDNS (Multiaddr (IP4 _ : rest)) = Multiaddr (DNS4 "localhost" : rest)
replaceHostWithDNS address = address

appendPeer :: Multiaddr -> PeerId -> Multiaddr
appendPeer (Multiaddr protocols) peer =
  Multiaddr (protocols <> [P2P (peerIdBytes peer)])

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
listenAddress = "/ip4/127.0.0.1/udp/0/quic-v1/webtransport"

sampleHash :: Text
sampleHash = "uEiDDq4_xNyDorZBH3TlGazyJdOWSwvo4PUo5YHFMrvDE8g"

sampleIPv4Address :: Text
sampleIPv4Address =
  "/ip4/127.0.0.1/udp/443/quic-v1/webtransport/certhash/" <> sampleHash

sampleIPv6Address :: Text
sampleIPv6Address =
  "/ip6/::1/udp/443/quic-v1/webtransport/certhash/" <> sampleHash

sampleDNSAddress :: Text
sampleDNSAddress =
  "/dns4/localhost/udp/443/quic-v1/webtransport/certhash/" <> sampleHash
