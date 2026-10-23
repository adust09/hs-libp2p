module LibP2P.Transport.WebSocketSpec (spec) where

import Control.Concurrent.Async (concurrently)
import Control.Exception (SomeException, bracket, try)
import Control.Monad (replicateM)
import qualified Data.ByteString as BS
import Data.Text (Text)
import LibP2P.Crypto.Ed25519 (generateKeyPair)
import LibP2P.Crypto.Key (KeyPair, publicKey)
import LibP2P.Crypto.PeerId (PeerId, fromPublicKey)
import LibP2P.Multiaddr (Multiaddr (..), fromText)
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.MultistreamSelect.Negotiation (StreamIO (..))
import LibP2P.Protocol.Ping (PingResult (..), registerPingHandler, sendPing)
import LibP2P.Security.TLS.Certificate (newIdentityCredential)
import LibP2P.Switch (addTransport, newSwitch, switchClose)
import LibP2P.Switch.Dial (dial)
import LibP2P.Switch.Listen (defaultConnectionGater, switchListen)
import LibP2P.Switch.Types (Connection (..))
import LibP2P.Transport
  ( ConnectionEndpoint (..)
  , Listener (..)
  , RawConnection (..)
  , Transport (..)
  )
import LibP2P.Transport.WebSocket
  ( WebSocketConfig (..)
  , canDialWebSocket
  , newWebSocketTransport
  , newWebSocketTransportWithConfig
  , webSocketServerParams
  )
import Network.TLS
  ( ClientHooks (..)
  , ClientParams (..)
  , defaultParamsClient
  )
import System.Timeout (timeout)
import Test.Hspec

spec :: Spec
spec = do
  describe "canDialWebSocket" $ do
    it "accepts IP and DNS websocket multiaddrs" $ do
      canDialWebSocket (parseAddr "/ip4/127.0.0.1/tcp/80/ws") `shouldBe` True
      canDialWebSocket (parseAddr "/ip6/::1/tcp/443/wss") `shouldBe` True
      canDialWebSocket (parseAddr "/dns4/example.com/tcp/443/wss") `shouldBe` True
      canDialWebSocket (parseAddr "/dns6/example.com/tcp/80/ws") `shouldBe` True

    it "accepts a trailing peer ID and rejects bare TCP" $ do
      let peerSuffix = "/p2p/12D3KooWEtEnzvAaVkULx9kqyfRsU7Dw5Z7fuCBNhdEPCAuF1uAC"
      canDialWebSocket (parseAddr ("/ip4/127.0.0.1/tcp/80/ws" <> peerSuffix))
        `shouldBe` True
      canDialWebSocket (parseAddr "/ip4/127.0.0.1/tcp/80") `shouldBe` False

  describe "WebSocket loopback" $ do
    it "exchanges a byte stream over /ws" $ do
      transport <- newWebSocketTransport
      withWebSocketPair transport (parseAddr "/ip4/127.0.0.1/tcp/0/ws") exchangePayload

    it "dials /ws through a DNS multiaddr" $ do
      transport <- newWebSocketTransport
      bracket
        (transportListen transport (parseAddr "/ip4/127.0.0.1/tcp/0/ws"))
        listenerClose
        (\listener -> do
          let dnsAddress = localhostAddress (listenerAddr listener)
          connected <- timeout 10000000 $ concurrently
            (transportDial transport dnsAddress)
            (listenerAccept listener)
          (clientRaw, serverRaw) <- maybe (fail "DNS websocket dial timed out") pure connected
          bracket
            (pure (clientRaw, serverRaw))
            (\(client, server) -> rcClose client >> rcClose server)
            exchangePayload)

    it "requires explicit server TLS parameters for /wss listeners" $ do
      transport <- newWebSocketTransport
      result <- try (transportListen transport (parseAddr "/ip4/127.0.0.1/tcp/0/wss"))
        :: IO (Either SomeException Listener)
      case result of
        Left _ -> pure ()
        Right listener -> listenerClose listener >> expectationFailure "wss listener unexpectedly started"

    it "rejects an untrusted /wss server with the default client configuration" $ do
      (_, serverKey) <- generateIdentity
      serverConfig <- localWSSConfig serverKey
      serverTransport <- newWebSocketTransportWithConfig serverConfig
      clientTransport <- newWebSocketTransport
      bracket
        (transportListen serverTransport (parseAddr "/ip4/127.0.0.1/tcp/0/wss"))
        listenerClose
        (\listener -> do
          result <- timeout 10000000 $ concurrently
            (try (transportDial clientTransport (listenerAddr listener)) :: IO (Either SomeException RawConnection))
            (try (listenerAccept listener) :: IO (Either SomeException RawConnection))
          case result of
            Nothing -> expectationFailure "untrusted wss handshake timed out"
            Just (Right client, _) -> rcClose client >> expectationFailure "untrusted wss dial succeeded"
            Just (Left _, _) -> pure ())

    it "exchanges a byte stream over /wss with explicit TLS parameters" $ do
      (_, serverKey) <- generateIdentity
      config <- localWSSConfig serverKey
      transport <- newWebSocketTransportWithConfig config
      withWebSocketPair transport (parseAddr "/ip4/127.0.0.1/tcp/0/wss") exchangePayload

  describe "Switch integration" $ do
    it "runs Noise, Yamux, and Ping over /ws" $
      verifySwitchPing
        newWebSocketTransport
        newWebSocketTransport
        (parseAddr "/ip4/127.0.0.1/tcp/0/ws")

    it "runs Noise, Yamux, and Ping over /wss" $ do
      (_, outerTLSKey) <- generateIdentity
      config <- localWSSConfig outerTLSKey
      verifySwitchPing
        (newWebSocketTransportWithConfig config)
        (newWebSocketTransportWithConfig config)
        (parseAddr "/ip4/127.0.0.1/tcp/0/wss")

verifySwitchPing :: IO Transport -> IO Transport -> Multiaddr -> IO ()
verifySwitchPing clientTransport serverTransport listenAddress = do
  (clientPeer, clientKey) <- generateIdentity
  (serverPeer, serverKey) <- generateIdentity
  bracket (newSwitch clientPeer clientKey) switchClose $ \clientSwitch ->
    bracket (newSwitch serverPeer serverKey) switchClose $ \serverSwitch -> do
      clientTransport >>= addTransport clientSwitch
      serverTransport >>= addTransport serverSwitch
      registerPingHandler serverSwitch
      addresses <- switchListen serverSwitch defaultConnectionGater [listenAddress]
      connectionResult <- timeout 10000000 $ dial clientSwitch serverPeer addresses
      connection <- case connectionResult of
        Nothing -> fail "WebSocket Switch dial timed out"
        Just (Left err) -> fail $ "WebSocket Switch dial failed: " <> show err
        Just (Right established) -> pure established
      connSecurity connection `shouldBe` "/noise"
      connMuxer connection `shouldBe` "/yamux/1.0.0"
      pingResult <- timeout 5000000 $ sendPing clientSwitch connection
      case pingResult of
        Just (Right (PingResult rtt)) -> rtt `shouldSatisfy` (> 0)
        other -> expectationFailure $ "WebSocket Ping failed: " <> show other

withWebSocketPair
  :: Transport
  -> Multiaddr
  -> ((RawConnection, RawConnection) -> IO a)
  -> IO a
withWebSocketPair transport listenAddress action =
  bracket
    (transportListen transport listenAddress)
    listenerClose
    (\listener -> do
      connected <- timeout 10000000 $ concurrently
        (transportDial transport (listenerAddr listener))
        (listenerAccept listener)
      pair <- maybe (fail "websocket loopback connection timed out") pure connected
      bracket
        (pure pair)
        (\(clientRaw, serverRaw) -> rcClose clientRaw >> rcClose serverRaw)
        action)

exchangePayload :: (RawConnection, RawConnection) -> IO ()
exchangePayload (clientRaw, serverRaw) = do
  clientStream <- expectByteStream clientRaw
  serverStream <- expectByteStream serverRaw
  streamWrite clientStream "hello over websocket"
  request <- readExactly serverStream 20
  request `shouldBe` "hello over websocket"
  streamWrite serverStream "framed byte stream"
  response <- readExactly clientStream 18
  response `shouldBe` "framed byte stream"

expectByteStream :: RawConnection -> IO StreamIO
expectByteStream raw = case rcEndpoint raw of
  ByteStreamEndpoint stream -> pure stream
  NativeMuxerEndpoint _ -> fail "expected websocket byte-stream endpoint"

readExactly :: StreamIO -> Int -> IO BS.ByteString
readExactly stream size = BS.pack <$> replicateM size (streamReadByte stream)

localWSSConfig :: KeyPair -> IO WebSocketConfig
localWSSConfig serverKey = do
  credential <- newIdentityCredential serverKey
  pure WebSocketConfig
    { webSocketClientTLSParams = acceptingClientParams
    , webSocketServerTLSParams = Just (webSocketServerParams credential)
    }

acceptingClientParams :: String -> ClientParams
acceptingClientParams host = base
  { clientUseServerNameIndication = False
  , clientHooks = (clientHooks base)
      { onServerCertificate = \_ _ _ _ -> pure []
      }
  }
  where
    base = defaultParamsClient host BS.empty

localhostAddress :: Multiaddr -> Multiaddr
localhostAddress (Multiaddr [IP4 _, TCP port, WS]) =
  Multiaddr [DNS4 "localhost", TCP port, WS]
localhostAddress address = error $ "unexpected websocket listener address: " <> show address

generateIdentity :: IO (PeerId, KeyPair)
generateIdentity = do
  result <- generateKeyPair
  keyPair <- either fail pure result
  pure (fromPublicKey (publicKey keyPair), keyPair)

parseAddr :: Text -> Multiaddr
parseAddr text = case fromText text of
  Left err -> error $ "invalid test multiaddr: " <> show err
  Right address -> address
