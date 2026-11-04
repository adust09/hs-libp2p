module LibP2P.Transport.WebTransportSpec (spec) where

import Control.Concurrent.Async (concurrently)
import Control.Exception (bracket, try)
import Control.Monad (replicateM)
import Crypto.Error qualified as Crypto
import Crypto.PubKey.Ed25519 qualified as Ed25519
import Crypto.PubKey.RSA.Types qualified as RSA
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Hourglass
  ( DateTime
  , Duration (..)
  , Hours (..)
  , Minutes (..)
  , NanoSeconds (..)
  , Seconds (..)
  , timeAdd
  , timeConvert
  )
import Data.Text (Text)
import Data.X509
  ( Certificate (..)
  , CertificateChain (..)
  , DistinguishedName (..)
  , Extensions (..)
  , PubKey (..)
  , PubKeyALG (..)
  , SignatureALG (..)
  , SignedCertificate
  , encodeSignedObject
  , objectToSignedExact
  )
import LibP2P.Core.Multihash qualified as Multihash
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
  verifyBoundHashes,
 )
import LibP2P.Transport.WebTransport.Certificate
  ( verifyWebTransportCertificate
  )
import System.Timeout (timeout)
import Test.Hspec
import Time.System (timeCurrent)

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

  describe "WebTransport certificate verification" $ do
    it "rejects a well-formed SHA-256 multihash for a different certificate" $ do
      fixture <- validCertificateFixture
      let wrongHash = sha256Multihash "different certificate"
      verifyWebTransportCertificate [wrongHash] (fixtureChain fixture)
        `shouldReturn` Left "WebTransport certificate hash mismatch"

    it "keeps malformed hashes distinct from digest mismatches" $ do
      fixture <- validCertificateFixture
      verifyWebTransportCertificate [BS.replicate 34 0] (fixtureChain fixture)
        `shouldReturn` Left "validateMultihash: 32 trailing bytes"

    it "accepts any matching expected hash and rejects when none match" $ do
      fixture <- validCertificateFixture
      let wrongA = sha256Multihash "wrong-a"
          wrongB = sha256Multihash "wrong-b"
          chain = fixtureChain fixture
          actual = fixtureHash fixture
      verifyWebTransportCertificate [wrongA, actual] chain `shouldReturn` Right ()
      verifyWebTransportCertificate [wrongA, wrongB] chain
        `shouldReturn` Left "WebTransport certificate hash mismatch"

    it "enforces validity duration, key type, and chain cardinality" $ do
      now <- timeConvert <$> timeCurrent
      valid <- certificateFixture now (-1) 1 Ed25519Fixture
      expired <- certificateFixture now (-2) (-1) Ed25519Fixture
      future <- certificateFixture now 1 2 Ed25519Fixture
      tooLong <- certificateFixture now (-1) (14 * 24 + 1) Ed25519Fixture
      rsa <- certificateFixture now (-1) 1 RSAFixture
      verifyFixture valid `shouldReturn` Right ()
      verifyFixture expired `shouldReturn` Left "WebTransport certificate has expired"
      verifyFixture future `shouldReturn` Left "WebTransport certificate is not yet valid"
      verifyFixture tooLong
        `shouldReturn` Left "WebTransport certificate is valid for longer than 14 days"
      verifyFixture rsa `shouldReturn` Left "WebTransport certificate must not use RSA"
      verifyWebTransportCertificate [fixtureHash valid] (CertificateChain [])
        `shouldReturn` Left "WebTransport TLS chain must contain exactly one certificate"
      verifyWebTransportCertificate
        [fixtureHash valid]
        (CertificateChain [fixtureCertificate valid, fixtureCertificate valid])
        `shouldReturn` Left "WebTransport TLS chain must contain exactly one certificate"

    it "requires Noise to bind hashes even after TLS certificate validation" $ do
      fixture <- validCertificateFixture
      verifyFixture fixture `shouldReturn` Right ()
      result <- try (verifyBoundHashes [fixtureHash fixture] [])
        :: IO (Either IOError ())
      result `shouldSatisfy` isLeft

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
            let tampered = replaceCerthash
                  (listenerAddr listener)
                  (sha256Multihash "different certificate")
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

data FixtureKey = Ed25519Fixture | RSAFixture

data CertificateFixture = CertificateFixture
  { fixtureCertificate :: !SignedCertificate
  , fixtureHash :: !ByteString
  }

fixtureChain :: CertificateFixture -> CertificateChain
fixtureChain fixture = CertificateChain [fixtureCertificate fixture]

validCertificateFixture :: IO CertificateFixture
validCertificateFixture = do
  now <- timeConvert <$> timeCurrent
  certificateFixture now (-1) 1 Ed25519Fixture

certificateFixture :: DateTime -> Int -> Int -> FixtureKey -> IO CertificateFixture
certificateFixture now startHour endHour fixtureKey = do
  secret <- fixedSecret
  let signingPublic = Ed25519.toPublic secret
      subjectPublic = case fixtureKey of
        Ed25519Fixture -> PubKeyEd25519 signingPublic
        RSAFixture -> PubKeyRSA (RSA.PublicKey 256 3 65537)
      certificate = Certificate
        { certVersion = 2
        , certSerial = 7
        , certSignatureAlg = signatureAlgorithm
        , certIssuerDN = DistinguishedName []
        , certValidity =
            (timeAdd now (hoursDuration startHour), timeAdd now (hoursDuration endHour))
        , certSubjectDN = DistinguishedName []
        , certPubKey = subjectPublic
        , certExtensions = Extensions Nothing
        }
      signCertificate bytes =
        (convert (Ed25519.sign secret signingPublic bytes), signatureAlgorithm, ())
      (signedCertificate, ()) = objectToSignedExact signCertificate certificate
  pure CertificateFixture
    { fixtureCertificate = signedCertificate
    , fixtureHash = sha256Multihash (encodeSignedObject signedCertificate)
    }

fixedSecret :: IO Ed25519.SecretKey
fixedSecret = case Crypto.eitherCryptoError (Ed25519.secretKey (BS.replicate 32 7)) of
  Left err -> fail $ "fixed Ed25519 fixture key: " <> show err
  Right secret -> pure secret

verifyFixture :: CertificateFixture -> IO (Either String ())
verifyFixture fixture =
  verifyWebTransportCertificate [fixtureHash fixture] (fixtureChain fixture)

sha256Multihash :: ByteString -> ByteString
sha256Multihash = Multihash.encodeMultihash Multihash.SHA256

signatureAlgorithm :: SignatureALG
signatureAlgorithm = SignatureALG_IntrinsicHash PubKeyALG_Ed25519

hoursDuration :: Int -> Duration
hoursDuration hours =
  Duration (Hours (fromIntegral hours)) (Minutes 0) (Seconds 0) (NanoSeconds 0)

isLeft :: Either a b -> Bool
isLeft Left{} = True
isLeft Right{} = False

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
