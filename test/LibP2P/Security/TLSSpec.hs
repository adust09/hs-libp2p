module LibP2P.Security.TLSSpec (spec) where

import Control.Concurrent.Async (concurrently)
import Data.ByteString qualified as BS
import LibP2P.Crypto.Ed25519 (generateKeyPair)
import LibP2P.Crypto.Key (KeyPair, publicKey)
import LibP2P.Crypto.PeerId (PeerId, fromPublicKey)
import LibP2P.MultistreamSelect.Negotiation (StreamIO (..), mkMemoryStreamPair)
import LibP2P.Security.TLS (
  TLSHandshakeResult (..),
  TLSRole (..),
  performTLSHandshake,
  performTLSHandshakeWithMuxers,
  yamuxProtocolId,
 )
import LibP2P.Switch.Upgrade (readExact)
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

generateIdentity :: IO (PeerId, KeyPair)
generateIdentity = do
  generated <- generateKeyPair
  identity <- either fail pure generated
  pure (fromPublicKey (publicKey identity), identity)
