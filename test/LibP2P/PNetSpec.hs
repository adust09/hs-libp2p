{-# LANGUAGE LambdaCase #-}

module LibP2P.PNetSpec (spec) where

import Control.Concurrent.Async (concurrently)
import Control.Exception (bracket)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteArray.Encoding (Base (..), convertFromBase, convertToBase)
import Data.Either (isLeft)
import LibP2P.Crypto.Ed25519 (generateKeyPair)
import LibP2P.Crypto.Key (KeyPair, publicKey)
import LibP2P.Crypto.PeerId (PeerId, fromPublicKey)
import LibP2P.Multiaddr (Multiaddr (..))
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.MultistreamSelect.Negotiation (StreamIO (..), mkMemoryStreamPair)
import LibP2P.PNet
import LibP2P.Protocol.Ping (PingResult (..), registerPingHandler, sendPing)
import LibP2P.Switch (addTransport, newSwitchWithConfig, switchClose)
import LibP2P.Switch.Dial (dial)
import LibP2P.Switch.Listen (defaultConnectionGater, switchListen)
import LibP2P.Switch.Types (SwitchConfig (..), defaultSwitchConfig)
import LibP2P.Transport (Transport)
import LibP2P.Transport.QUIC (newQUICTransport)
import LibP2P.Transport.TCP (newTCPTransport)
import System.Timeout (timeout)
import Test.Hspec

spec :: Spec
spec = do
  describe "swarm.key decoding" $ do
    let keyBytes = BS.pack [0 .. 31]
        hexKey = convertToBase Base16 keyBytes :: ByteString
    it "decodes /base16/" $
      decodeSwarmKey ("/key/swarm/psk/1.0.0/\n/base16/\n" <> hexKey <> "\n")
        `shouldBe` pskFromBytes keyBytes
    it "decodes /base64/ with CRLF line endings" $
      decodeSwarmKey "/key/swarm/psk/1.0.0/\r\n/base64/\r\nAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\r\n"
        `shouldBe` pskFromBytes keyBytes
    it "decodes /bin/" $
      decodeSwarmKey ("/key/swarm/psk/1.0.0/\n/bin/\n" <> keyBytes)
        `shouldBe` pskFromBytes keyBytes
    it "rejects an unknown codec" $
      decodeSwarmKey ("/key/swarm/psk/2.0.0/\n/base16/\n" <> hexKey) `shouldSatisfy` isLeft
    it "rejects an unknown encoding" $
      decodeSwarmKey ("/key/swarm/psk/1.0.0/\n/base58/\n" <> hexKey) `shouldSatisfy` isLeft
    it "rejects a short key" $
      decodeSwarmKey ("/key/swarm/psk/1.0.0/\n/base16/\n" <> BS.take 62 hexKey) `shouldSatisfy` isLeft
    it "rejects a raw key that is not 32 bytes" $
      pskFromBytes (BS.replicate 31 0) `shouldSatisfy` isLeft

  describe "protected stream" $ around_ within5s $ do
    it "sends the nonce, then XSalsa20 ciphertext matching golang.org/x/crypto/salsa20" $ do
      -- Vector from golang.org/x/crypto v0.59.0 salsa20.XORKeyStream with a
      -- 24-byte nonce (XSalsa20), which go-libp2p's pnet uses.
      let nonce = BS.pack [0x80 .. 0x97]
          expected = either error id (convertFromBase Base16 ("c165a537579030c6f7191fa03f44b5cfbae2f4" :: ByteString)) :: ByteString
      (near, far) <- mkMemoryStreamPair
      protected <- protectStreamWithNonce key0 nonce near
      streamWrite protected "/multistream/1.0.0\n"
      readExactly far 24 `shouldReturn` nonce
      readExactly far (BS.length expected) `shouldReturn` expected

    it "round-trips both directions between peers sharing a key" $ do
      (a, b) <- protectedPair key0 key0
      _ <- concurrently (streamWrite a "hello from a") (streamWrite b "hello from b")
      (fromB, fromA) <- concurrently (readExactly a 12) (readExactly b 12)
      fromA `shouldBe` "hello from a"
      fromB `shouldBe` "hello from b"

    it "writes without waiting for the peer's nonce" $ do
      -- go-libp2p sends its nonce only on its first write, so a dialer
      -- that waited for it before writing would deadlock.
      (near, far) <- mkMemoryStreamPair
      firstWrite <- timeout 1000000 $ do
        a <- protectStream key0 near
        streamWrite a "first"
      firstWrite `shouldBe` Just ()
      b <- protectStream key0 far
      timeout 1000000 (readExactly b 5) `shouldReturn` Just "first"

    it "scrambles data between peers with different keys" $ do
      (a, b) <- protectedPair key0 key1
      streamWrite a "/multistream/1.0.0\n"
      received <- readExactly b 19
      received `shouldNotBe` "/multistream/1.0.0\n"

  describe "Switch with a private network" $ do
    it "connects and pings when both peers share the key" $
      dialResult (Just key0) (Just key0) tcp >>= \case
        Just (Right (PingResult rtt)) -> rtt `shouldSatisfy` (> 0)
        other -> expectationFailure ("expected a ping, got " <> show other)

    it "fails to connect when the keys differ" $
      dialResult (Just key0) (Just key1) tcp >>= (`shouldSatisfy` failedToConnect)

    it "fails to connect to a node outside the private network" $
      dialResult (Just key0) Nothing tcp >>= (`shouldSatisfy` failedToConnect)

    it "refuses a transport without a raw byte stream" $
      dialResult (Just key0) (Just key0) quic >>= (`shouldSatisfy` failedToConnect)

tcp, quic :: (KeyPair -> IO Transport, Multiaddr)
tcp = (const newTCPTransport, Multiaddr [IP4 0x7f000001, TCP 0])
quic = (newQUICTransport, Multiaddr [IP4 0x7f000001, UDP 0, QuicV1])

-- | Fail rather than hang when a stream blocks, e.g. on a nonce that never comes.
within5s :: IO () -> IO ()
within5s action =
  timeout 5000000 action >>= maybe (expectationFailure "timed out after 5s") pure

key0, key1 :: PSK
key0 = either error id (pskFromBytes (BS.pack [0 .. 31]))
key1 = either error id (pskFromBytes (BS.replicate 32 7))

protectedPair :: PSK -> PSK -> IO (StreamIO, StreamIO)
protectedPair keyA keyB = do
  (near, far) <- mkMemoryStreamPair
  (,) <$> protectStream keyA near <*> protectStream keyB far

readExactly :: StreamIO -> Int -> IO ByteString
readExactly stream n
  | n <= 0 = pure BS.empty
  | otherwise = do
      chunk <- streamReadChunk stream n
      (chunk <>) <$> readExactly stream (n - BS.length chunk)

failedToConnect :: Maybe (Either String PingResult) -> Bool
failedToConnect (Just (Right _)) = False
failedToConnect _ = True

-- | Dial a listener on a fresh transport and ping it. 'Left' means the dial
-- failed; 'Nothing' means it timed out.
dialResult ::
  Maybe PSK ->
  Maybe PSK ->
  (KeyPair -> IO Transport, Multiaddr) ->
  IO (Maybe (Either String PingResult))
dialResult clientKey serverKey (mkTransport, listenAddress) = do
  (clientPeer, clientIdentity) <- identity
  (serverPeer, serverIdentity) <- identity
  let config key = defaultSwitchConfig{scPrivateNetwork = key}
  bracket (newSwitchWithConfig (config clientKey) clientPeer clientIdentity) switchClose $ \client ->
    bracket (newSwitchWithConfig (config serverKey) serverPeer serverIdentity) switchClose $ \server -> do
      mkTransport clientIdentity >>= addTransport client
      mkTransport serverIdentity >>= addTransport server
      registerPingHandler server
      addresses <- switchListen server defaultConnectionGater [listenAddress]
      timeout 10000000 $
        dial client serverPeer addresses >>= \case
          Left err -> pure (Left (show err))
          Right connection -> either (Left . show) Right <$> sendPing client connection

identity :: IO (PeerId, KeyPair)
identity = do
  Right keyPair <- generateKeyPair
  pure (fromPublicKey (publicKey keyPair), keyPair)
