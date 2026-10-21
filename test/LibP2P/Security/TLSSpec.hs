module LibP2P.Security.TLSSpec (spec) where

import Control.Concurrent.Async (concurrently)
import Control.Exception (finally)
import Data.ByteString qualified as BS
import LibP2P.Crypto.Ed25519 (generateKeyPair)
import LibP2P.Crypto.Key (KeyPair, publicKey)
import LibP2P.Crypto.PeerId (PeerId, fromPublicKey)
import LibP2P.Multiaddr (fromText)
import LibP2P.MultistreamSelect.Negotiation (StreamIO (..), mkMemoryStreamPair)
import LibP2P.Security.TLS (
  TLSHandshakeResult (..),
  TLSRole (..),
  performTLSHandshake,
  performTLSHandshakeWithMuxers,
  tlsProtocolId,
  yamuxProtocolId,
 )
import LibP2P.Switch.Types (defaultSwitchConfig, scSecurityProtocols)
import LibP2P.Switch.Upgrade (readExact)
import LibP2P.Transport (ConnectionEndpoint (..), RawConnection (..))
import LibP2P.Transport.TCP (newTCPTransport)
import LibP2P.Transport qualified as Transport
import Test.Hspec

spec :: Spec
spec = describe "libp2p TLS 1.3 secure channel" $ do
  it "mutually authenticates both Peer IDs and negotiates Yamux with ALPN" $ do
    (pidA, identityA) <- generateIdentity
    (pidB, identityB) <- generateIdentity
    (rawA, rawB) <- mkMemoryStreamPair
    (channelA, channelB) <-
      concurrently
        (performTLSHandshake identityA TLSClient rawA)
        (performTLSHandshake identityB TLSServer rawB)
    tlsRemotePeerId channelA `shouldBe` pidB
    tlsRemotePeerId channelB `shouldBe` pidA
    tlsNegotiatedALPN channelA `shouldBe` Just "/yamux/1.0.0"
    tlsNegotiatedALPN channelB `shouldBe` Just "/yamux/1.0.0"
    concurrently (tlsClose channelA) (tlsClose channelB) `shouldReturn` ((), ())

  it "negotiates the libp2p fallback when the server cannot inline a muxer" $ do
    (_pidA, identityA) <- generateIdentity
    (_pidB, identityB) <- generateIdentity
    (rawA, rawB) <- mkMemoryStreamPair
    (channelA, channelB) <-
      concurrently
        (performTLSHandshakeWithMuxers [yamuxProtocolId] identityA TLSClient rawA)
        (performTLSHandshakeWithMuxers [] identityB TLSServer rawB)
    tlsNegotiatedALPN channelA `shouldBe` Just "libp2p"
    tlsNegotiatedALPN channelB `shouldBe` Just "libp2p"
    concurrently (tlsClose channelA) (tlsClose channelB) `shouldReturn` ((), ())

  it "encrypts data in both directions after the handshake" $ do
    (_pidA, identityA) <- generateIdentity
    (_pidB, identityB) <- generateIdentity
    (rawA, rawB) <- mkMemoryStreamPair
    (channelA, channelB) <-
      concurrently
        (performTLSHandshake identityA TLSClient rawA)
        (performTLSHandshake identityB TLSServer rawB)
    let streamA = tlsStream channelA
        streamB = tlsStream channelB
        payload = BS.pack (take 70000 (cycle [0 .. 255]))
    (received, ()) <-
      concurrently
        (readExact streamB (BS.length payload))
        (streamWrite streamA payload)
    received `shouldBe` payload
    streamWrite streamB "still alive"
    readExact streamA 11 `shouldReturn` "still alive"
    concurrently (tlsClose channelA) (tlsClose channelB) `shouldReturn` ((), ())

  it "reassembles TLS records when each transport read returns one byte" $ do
    (_pidA, identityA) <- generateIdentity
    (_pidB, identityB) <- generateIdentity
    (rawA, rawB) <- mkMemoryStreamPair
    (channelA, channelB) <-
      concurrently
        (performTLSHandshake identityA TLSClient (oneByteReads rawA))
        (performTLSHandshake identityB TLSServer (oneByteReads rawB))
    let streamA = tlsStream channelA
        streamB = tlsStream channelB
        payload = BS.pack (take 70000 (cycle [0 .. 255]))
    (received, ()) <-
      concurrently
        (readExact streamB (BS.length payload))
        (streamWrite streamA payload)
    received `shouldBe` payload
    streamWrite streamB payload
    readExact streamA (BS.length payload) `shouldReturn` payload
    concurrently (tlsClose channelA) (tlsClose channelB) `shouldReturn` ((), ())

  it "exchanges a large payload over a real TCP connection" $ do
    (_pidA, identityA) <- generateIdentity
    (_pidB, identityB) <- generateIdentity
    transport <- newTCPTransport
    listenAddr <- either fail pure (fromText "/ip4/127.0.0.1/tcp/0")
    listener <- Transport.transportListen transport listenAddr
    flip finally (Transport.listenerClose listener) $ do
      (accepted, dialed) <-
        concurrently
          (Transport.listenerAccept listener)
          (Transport.transportDial transport (Transport.listenerAddr listener))
      flip finally (rcClose accepted >> rcClose dialed) $ do
        serverIO <- expectByteStream accepted
        clientIO <- expectByteStream dialed
        (channelA, channelB) <-
          concurrently
            (performTLSHandshake identityA TLSClient clientIO)
            (performTLSHandshake identityB TLSServer serverIO)
        let payload = BS.replicate (256 * 1024) 0x5a
            streamA = tlsStream channelA
            streamB = tlsStream channelB
        (received, ()) <-
          concurrently
            (readExact streamB (BS.length payload))
            (streamWrite streamA payload)
        received `shouldBe` payload
        concurrently (tlsClose channelA) (tlsClose channelB)
          `shouldReturn` ((), ())

  it "offers TLS under the handshake protocol id by default" $
    scSecurityProtocols defaultSwitchConfig `shouldContain` [tlsProtocolId]

oneByteReads :: StreamIO -> StreamIO
oneByteReads stream =
  stream {streamReadChunk = \requested -> streamReadChunk stream (min 1 requested)}

expectByteStream :: RawConnection -> IO StreamIO
expectByteStream raw = case rcEndpoint raw of
  ByteStreamEndpoint stream -> pure stream
  NativeMuxerEndpoint _ -> fail "expected a TCP byte stream"

generateIdentity :: IO (PeerId, KeyPair)
generateIdentity = do
  generated <- generateKeyPair
  identity <- either fail pure generated
  pure (fromPublicKey (publicKey identity), identity)
