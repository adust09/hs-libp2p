module LibP2P.Switch.UpgradeSpec (spec) where

import Control.Concurrent.Async (concurrently)
import qualified Data.ByteString as BS
import Data.IORef (newIORef)
import LibP2P.Crypto.Ed25519 (generateKeyPair)
import LibP2P.Crypto.Key (KeyPair, publicKey)
import LibP2P.Crypto.PeerId (PeerId, fromPublicKey)
import LibP2P.Multiaddr (Multiaddr (..))
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.MultistreamSelect.Negotiation (StreamIO (..), mkMemoryStreamPair)
import LibP2P.Noise.Framing (maxNoisePlaintextSize)
import LibP2P.Noise.Handshake (HandshakeResult (..))
import LibP2P.Security.TLS (tlsProtocolId)
import LibP2P.Switch.ResourceManager
  ( DefaultLimits (..)
  , newResourceManager
  , noLimits
  , unlimitedMemoryAccount
  )
import LibP2P.Switch.Types (Connection (..), Direction (..), MuxerSession (..))
import LibP2P.Switch.Upgrade hiding (upgradeInbound, upgradeOutbound)
import qualified LibP2P.Switch.Upgrade as Upgrade
import LibP2P.Transport (ConnectionEndpoint (..), RawConnection (..), RelayCircuitLimit (..))
import Test.Hspec

-- | Generate a test identity (PeerId, KeyPair).
mkTestIdentity :: IO (PeerId, KeyPair)
mkTestIdentity = do
  Right kp <- generateKeyPair
  let pid = fromPublicKey (publicKey kp)
  pure (pid, kp)

upgradeOutbound :: KeyPair -> RawConnection -> IO Connection
upgradeOutbound kp raw = do
  rm <- newResourceManager (DefaultLimits noLimits noLimits noLimits noLimits)
  Upgrade.upgradeOutbound rm kp raw

upgradeInbound :: KeyPair -> RawConnection -> IO Connection
upgradeInbound kp raw = do
  rm <- newResourceManager (DefaultLimits noLimits noLimits noLimits noLimits)
  Upgrade.upgradeInbound rm kp raw

upgradeWithTLS :: Direction -> KeyPair -> RawConnection -> IO Connection
upgradeWithTLS direction kp raw = do
  rm <- newResourceManager (DefaultLimits noLimits noLimits noLimits noLimits)
  Upgrade.upgradeAsWithSecurityProtocols rm [tlsProtocolId] direction kp raw

openMuxStream :: Connection -> IO StreamIO
openMuxStream conn = muxOpenStream (connSession conn) unlimitedMemoryAccount

-- | Create a mock RawConnection from a StreamIO and addresses.
mkMockRawConn :: StreamIO -> Multiaddr -> Multiaddr -> IO RawConnection
mkMockRawConn sio local remote = pure RawConnection
  { rcEndpoint   = ByteStreamEndpoint sio
  , rcLocalAddr  = local
  , rcRemoteAddr = remote
  , rcClose      = pure ()
  , rcRelayLimit = Nothing
  }

localAddr :: Multiaddr
localAddr = Multiaddr [IP4 0x7f000001, TCP 12345]

remoteAddr :: Multiaddr
remoteAddr = Multiaddr [IP4 0x7f000001, TCP 54321]

spec :: Spec
spec = do
  describe "Framed message I/O" $ do
    it "writeFramedMessage + readFramedMessage round-trips" $ do
      (streamA, streamB) <- mkMemoryStreamPair
      writeFramedMessage streamA "hello noise"
      received <- readFramedMessage streamB
      received `shouldBe` "hello noise"

    it "readFramedMessage handles empty payload" $ do
      (streamA, streamB) <- mkMemoryStreamPair
      writeFramedMessage streamA BS.empty
      received <- readFramedMessage streamB
      received `shouldBe` BS.empty

    it "writeFramedMessage rejects a message larger than 65535 bytes" $ do
      (streamA, _streamB) <- mkMemoryStreamPair
      writeFramedMessage streamA (BS.replicate 65536 0x42) `shouldThrow` anyIOException

  describe "performStreamHandshake" $ do
    it "initiator and responder complete handshake and return correct PeerIds" $ do
      (pidA, kpA) <- mkTestIdentity
      (pidB, kpB) <- mkTestIdentity
      (streamA, streamB) <- mkMemoryStreamPair
      ((_sessA, resultA), (_sessB, resultB)) <-
        concurrently
          (performStreamHandshake kpA Outbound streamA)
          (performStreamHandshake kpB Inbound streamB)
      -- A sees B's PeerId, B sees A's PeerId
      hrRemotePeerId resultA `shouldBe` pidB
      hrRemotePeerId resultB `shouldBe` pidA

  describe "noiseSessionToStreamIO" $ do
    it "encrypted write on one side is decrypted read on other side" $ do
      (_pidA, kpA) <- mkTestIdentity
      (_pidB, kpB) <- mkTestIdentity
      (rawA, rawB) <- mkMemoryStreamPair
      -- Perform handshake to get sessions
      ((sessA, _), (sessB, _)) <-
        concurrently
          (performStreamHandshake kpA Outbound rawA)
          (performStreamHandshake kpB Inbound rawB)
      -- Create encrypted StreamIOs
      sendRefA <- newIORef sessA
      recvRefA <- newIORef sessA
      bufRefA  <- newIORef BS.empty
      sendRefB <- newIORef sessB
      recvRefB <- newIORef sessB
      bufRefB  <- newIORef BS.empty
      let encA = noiseSessionToStreamIO sendRefA recvRefA bufRefA rawA
          encB = noiseSessionToStreamIO sendRefB recvRefB bufRefB rawB
      -- A writes "hello", B reads
      streamWrite encA "hello"
      received <- readExact encB 5
      received `shouldBe` "hello"
      -- B writes "world", A reads
      streamWrite encB "world"
      received2 <- readExact encA 5
      received2 `shouldBe` "world"

    it "round-trips a payload larger than 65535 bytes without corruption" $ do
      (_pidA, kpA) <- mkTestIdentity
      (_pidB, kpB) <- mkTestIdentity
      (rawA, rawB) <- mkMemoryStreamPair
      ((sessA, _), (sessB, _)) <-
        concurrently
          (performStreamHandshake kpA Outbound rawA)
          (performStreamHandshake kpB Inbound rawB)
      sendRefA <- newIORef sessA
      recvRefA <- newIORef sessA
      bufRefA  <- newIORef BS.empty
      sendRefB <- newIORef sessB
      recvRefB <- newIORef sessB
      bufRefB  <- newIORef BS.empty
      let encA = noiseSessionToStreamIO sendRefA recvRefA bufRefA rawA
          encB = noiseSessionToStreamIO sendRefB recvRefB bufRefB rawB
          -- Larger than the 65535-byte Noise message cap: must be chunked
          -- into multiple frames, never truncated.
          bigPayload = BS.pack (take 70000 (cycle [0 .. 255]))
      streamWrite encA bigPayload
      received <- readExact encB 70000
      received `shouldBe` bigPayload
      -- The connection must remain usable after the large write
      streamWrite encA "still alive"
      received2 <- readExact encB 11
      received2 `shouldBe` "still alive"
      -- And the reverse direction too
      streamWrite encB bigPayload
      received3 <- readExact encA 70000
      received3 `shouldBe` bigPayload

    it "round-trips payloads at the exact single-frame boundary (65519 and 65520 bytes)" $ do
      (_pidA, kpA) <- mkTestIdentity
      (_pidB, kpB) <- mkTestIdentity
      (rawA, rawB) <- mkMemoryStreamPair
      ((sessA, _), (sessB, _)) <-
        concurrently
          (performStreamHandshake kpA Outbound rawA)
          (performStreamHandshake kpB Inbound rawB)
      sendRefA <- newIORef sessA
      recvRefA <- newIORef sessA
      bufRefA  <- newIORef BS.empty
      sendRefB <- newIORef sessB
      recvRefB <- newIORef sessB
      bufRefB  <- newIORef BS.empty
      let encA = noiseSessionToStreamIO sendRefA recvRefA bufRefA rawA
          encB = noiseSessionToStreamIO sendRefB recvRefB bufRefB rawB
          -- 65519 bytes: the largest plaintext that fits a single Noise
          -- frame (65535-byte message minus the 16-byte AEAD tag).
          atLimit = BS.pack (take maxNoisePlaintextSize (cycle [0 .. 255]))
          -- 65520 bytes: the first size that MUST be split into two
          -- frames — before chunking existed, this single write corrupted
          -- the connection (declared length wrapped to 0).
          overLimit = BS.pack (take (maxNoisePlaintextSize + 1) (cycle [255, 254 .. 0]))
      streamWrite encA atLimit
      received <- readExact encB maxNoisePlaintextSize
      received `shouldBe` atLimit
      streamWrite encA overLimit
      received2 <- readExact encB (maxNoisePlaintextSize + 1)
      received2 `shouldBe` overLimit
      -- The channel must stay usable in both directions afterwards.
      streamWrite encB "still alive"
      received3 <- readExact encA 11
      received3 `shouldBe` "still alive"

    it "streamReadChunk hands back a whole decrypted frame at once (#276)" $ do
      (_pidA, kpA) <- mkTestIdentity
      (_pidB, kpB) <- mkTestIdentity
      (rawA, rawB) <- mkMemoryStreamPair
      ((sessA, _), (sessB, _)) <-
        concurrently
          (performStreamHandshake kpA Outbound rawA)
          (performStreamHandshake kpB Inbound rawB)
      sendRefA <- newIORef sessA
      recvRefA <- newIORef sessA
      bufRefA  <- newIORef BS.empty
      sendRefB <- newIORef sessB
      recvRefB <- newIORef sessB
      bufRefB  <- newIORef BS.empty
      let encA = noiseSessionToStreamIO sendRefA recvRefA bufRefA rawA
          encB = noiseSessionToStreamIO sendRefB recvRefB bufRefB rawB
      -- A single write fits one Noise frame; the decrypted plaintext
      -- must come back as one chunk, not byte-at-a-time.
      streamWrite encA "hello world"
      chunk <- streamReadChunk encB 1024
      chunk `shouldBe` "hello world"
      -- Byte- and chunk-level reads share the buffer without loss.
      streamWrite encA "abcdef"
      b <- streamReadByte encB
      b `shouldBe` 0x61
      front <- streamReadChunk encB 2
      front `shouldBe` "bc"
      rest <- streamReadChunk encB 1024
      rest `shouldBe` "def"

  describe "Full upgrade pipeline" $ do
    it "upgradeOutbound + upgradeInbound exchange data on muxed stream" $ do
      (_pidA, kpA) <- mkTestIdentity
      (_pidB, kpB) <- mkTestIdentity
      (rawA, rawB) <- mkMemoryStreamPair
      rawConnA <- mkMockRawConn rawA localAddr remoteAddr
      rawConnB <- mkMockRawConn rawB remoteAddr localAddr
      (connA, connB) <-
        concurrently
          (upgradeOutbound kpA rawConnA)
          (upgradeInbound kpB rawConnB)
      -- Open stream from A (client), accept on B (server)
      (streamA, streamB) <-
        concurrently
          (openMuxStream connA)
          (muxAcceptStream (connSession connB))
      -- Exchange data
      streamWrite streamA "ping"
      received <- readExact streamB 4
      received `shouldBe` "ping"
      streamWrite streamB "pong"
      received2 <- readExact streamA 4
      received2 `shouldBe` "pong"
      -- Cleanup
      muxClose (connSession connA)
      muxClose (connSession connB)

    it "falls back from Noise to TLS 1.3 with ALPN-inlined Yamux" $ do
      (pidA, kpA) <- mkTestIdentity
      (pidB, kpB) <- mkTestIdentity
      (rawA, rawB) <- mkMemoryStreamPair
      rawConnA <- mkMockRawConn rawA localAddr remoteAddr
      rawConnB <- mkMockRawConn rawB remoteAddr localAddr
      (connA, connB) <- concurrently
        (upgradeOutbound kpA rawConnA)
        (upgradeWithTLS Inbound kpB rawConnB)
      connPeerId connA `shouldBe` pidB
      connPeerId connB `shouldBe` pidA
      connSecurity connA `shouldBe` tlsProtocolId
      connSecurity connB `shouldBe` tlsProtocolId
      connMuxer connA `shouldBe` "/yamux/1.0.0"
      connMuxer connB `shouldBe` "/yamux/1.0.0"
      (streamA, streamB) <- concurrently
        (openMuxStream connA)
        (muxAcceptStream (connSession connB))
      streamWrite streamA "tls ping"
      readExact streamB 8 `shouldReturn` "tls ping"
      muxClose (connSession connA)
      muxClose (connSession connB)

    it "keeps accounting active for a response after the requester half-closes" $ do
      (_pidA, kpA) <- mkTestIdentity
      (_pidB, kpB) <- mkTestIdentity
      (rawA, rawB) <- mkMemoryStreamPair
      rawConnA <- mkMockRawConn rawA localAddr remoteAddr
      rawConnB <- mkMockRawConn rawB remoteAddr localAddr
      (connA, connB) <- concurrently
        (upgradeOutbound kpA rawConnA)
        (upgradeInbound kpB rawConnB)
      (streamA, streamB) <- concurrently
        (openMuxStream connA)
        (muxAcceptStream (connSession connB))
      streamWrite streamA "request"
      streamClose streamA
      readExact streamB 7 `shouldReturn` "request"
      streamWrite streamB "response"
      readExact streamA 8 `shouldReturn` "response"
      streamClose streamB
      muxClose (connSession connA)
      muxClose (connSession connB)

    it "upgradeOutbound + upgradeInbound verify remote PeerIds" $ do
      (pidA, kpA) <- mkTestIdentity
      (pidB, kpB) <- mkTestIdentity
      (rawA, rawB) <- mkMemoryStreamPair
      rawConnA <- mkMockRawConn rawA localAddr remoteAddr
      rawConnB <- mkMockRawConn rawB remoteAddr localAddr
      (connA, connB) <-
        concurrently
          (upgradeOutbound kpA rawConnA)
          (upgradeInbound kpB rawConnB)
      -- A's connection should show B's PeerId and vice versa
      connPeerId connA `shouldBe` pidB
      connPeerId connB `shouldBe` pidA
      connSecurity connA `shouldBe` "/noise"
      connMuxer connA `shouldBe` "/yamux/1.0.0"
      connRelayLimit connA `shouldBe` Nothing
      connRelayLimit connB `shouldBe` Nothing
      muxClose (connSession connA)
      muxClose (connSession connB)

    it "retains a relay circuit budget through upgrade" $ do
      (_pidA, kpA) <- mkTestIdentity
      (_pidB, kpB) <- mkTestIdentity
      (rawA, rawB) <- mkMemoryStreamPair
      rawConnA <- mkMockRawConn rawA localAddr remoteAddr
      rawConnB <- mkMockRawConn rawB remoteAddr localAddr
      let budget = Just (RelayCircuitLimit (Just 120) (Just 131072))
          withBudget raw = raw { rcRelayLimit = budget }
      (connA, connB) <- concurrently
        (upgradeOutbound kpA (withBudget rawConnA))
        (upgradeInbound kpB (withBudget rawConnB))
      connRelayLimit connA `shouldBe` budget
      connRelayLimit connB `shouldBe` budget
      muxClose (connSession connA)
      muxClose (connSession connB)

    it "multiple streams on single upgraded connection" $ do
      (_pidA, kpA) <- mkTestIdentity
      (_pidB, kpB) <- mkTestIdentity
      (rawA, rawB) <- mkMemoryStreamPair
      rawConnA <- mkMockRawConn rawA localAddr remoteAddr
      rawConnB <- mkMockRawConn rawB remoteAddr localAddr
      (connA, connB) <-
        concurrently
          (upgradeOutbound kpA rawConnA)
          (upgradeInbound kpB rawConnB)
      -- Open two streams from A
      (stream1A, stream1B) <-
        concurrently
          (openMuxStream connA)
          (muxAcceptStream (connSession connB))
      (stream2A, stream2B) <-
        concurrently
          (openMuxStream connA)
          (muxAcceptStream (connSession connB))
      -- Exchange data on both streams independently
      streamWrite stream1A "stream-1"
      streamWrite stream2A "stream-2"
      recv1 <- readExact stream1B 8
      recv2 <- readExact stream2B 8
      recv1 `shouldBe` "stream-1"
      recv2 `shouldBe` "stream-2"
      muxClose (connSession connA)
      muxClose (connSession connB)

    it "drains a bulk payload through streamReadChunk on a muxed stream (#276)" $ do
      (_pidA, kpA) <- mkTestIdentity
      (_pidB, kpB) <- mkTestIdentity
      (rawA, rawB) <- mkMemoryStreamPair
      rawConnA <- mkMockRawConn rawA localAddr remoteAddr
      rawConnB <- mkMockRawConn rawB remoteAddr localAddr
      (connA, connB) <-
        concurrently
          (upgradeOutbound kpA rawConnA)
          (upgradeInbound kpB rawConnB)
      (streamA, streamB) <-
        concurrently
          (openMuxStream connA)
          (muxAcceptStream (connSession connB))
      -- Larger than the yamux flow-control window, so the writer only
      -- makes progress while the reader drains — the perf download
      -- path in miniature.
      let total = 300000 :: Int
          payload = BS.pack (take total (cycle [0 .. 255]))
          drain acc
            | BS.length acc >= total = pure acc
            | otherwise = do
                chunk <- streamReadChunk streamB 65536
                drain (acc <> chunk)
      (received, ()) <-
        concurrently (drain BS.empty) (streamWrite streamA payload)
      received `shouldBe` payload
      muxClose (connSession connA)
      muxClose (connSession connB)
