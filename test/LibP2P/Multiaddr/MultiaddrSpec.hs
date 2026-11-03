module LibP2P.Multiaddr.MultiaddrSpec (spec) where

import Data.ByteArray.Encoding (Base (Base32), convertToBase)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base58 as B58
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Word (Word64)
import LibP2P.Core.Varint (encodeUvarint)
import LibP2P.Crypto.PeerId (PeerId (..), toCIDv1)
import LibP2P.Multiaddr.Codec
import LibP2P.Multiaddr
import LibP2P.Multiaddr.Protocol
import Test.Hspec
import Test.QuickCheck

spec :: Spec
spec = do
  describe "Binary encoding" $ do
    it "encodes /ip4/127.0.0.1/tcp/4001 to correct bytes" $ do
      let ps = [IP4 0x7f000001, TCP 4001]
      -- 04 7f000001 06 0fa1
      encodeProtocols ps `shouldBe` BS.pack [0x04, 0x7f, 0x00, 0x00, 0x01, 0x06, 0x0f, 0xa1]

    it "encodes /ip4/198.51.100.0/udp/9090/quic-v1 to correct bytes" $ do
      let ps = [IP4 0xc6336400, UDP 9090, QuicV1]
      -- 04 c6336400 9102 2382 cd03 (quic-v1 = 461 = varint cd 03)
      encodeProtocols ps
        `shouldBe` BS.pack [0x04, 0xc6, 0x33, 0x64, 0x00, 0x91, 0x02, 0x23, 0x82, 0xcd, 0x03]

    it "encodes quic-v1 as protocol code 461, not legacy quic 460" $
      encodeProtocols [QuicV1] `shouldBe` encodeUvarint 461

    it "encodes each zero-address protocol to exactly its varint code" $ do
      encodeProtocols [QuicV1] `shouldBe` BS.pack [0xcd, 0x03]
      encodeProtocols [WS] `shouldBe` BS.pack [0xdd, 0x03]
      encodeProtocols [WSS] `shouldBe` BS.pack [0xde, 0x03]
      encodeProtocols [P2PCircuit] `shouldBe` BS.pack [0xa2, 0x02]
      encodeProtocols [WebRTCDirect] `shouldBe` BS.pack [0x98, 0x02]
      encodeProtocols [WebTransport] `shouldBe` BS.pack [0xd1, 0x03]
      encodeProtocols [NoiseProto] `shouldBe` BS.pack [0xc6, 0x03]

  describe "Binary decoding" $ do
    it "decodes /ip4/127.0.0.1/tcp/4001 from bytes" $ do
      let bytes = BS.pack [0x04, 0x7f, 0x00, 0x00, 0x01, 0x06, 0x0f, 0xa1]
      decodeProtocols bytes `shouldBe` Right [IP4 0x7f000001, TCP 4001]

    it "decodes /ip4/198.51.100.0/udp/9090/quic-v1 from bytes" $ do
      let bytes = BS.pack [0x04, 0xc6, 0x33, 0x64, 0x00, 0x91, 0x02, 0x23, 0x82, 0xcd, 0x03]
      decodeProtocols bytes `shouldBe` Right [IP4 0xc6336400, UDP 9090, QuicV1]

    it "does not decode legacy quic code 460 as quic-v1" $
      decodeProtocols (encodeUvarint 460) `shouldNotBe` Right [QuicV1]

    it "rejects unassigned code 467 (formerly used for yamux)" $
      decodeProtocols (encodeUvarint 467) `shouldSatisfy` isLeft

    it "decodes empty input as the empty protocol list" $
      decodeProtocols BS.empty `shouldBe` Right []

    it "rejects a varint-prefixed component with an absurd declared length" $ do
      -- dns (53) claiming a 2^63-1 byte address must not decode as DNS ""
      let bytes = encodeUvarint 53 <> encodeUvarint (2 ^ (63 :: Int) - 1)
      decodeProtocols bytes `shouldSatisfy` isLeft

    it "fails on unknown protocol code" $ do
      -- 0xff 0x7f = varint 16383, unknown protocol
      let bytes = BS.pack [0xff, 0x7f]
      decodeProtocols bytes `shouldSatisfy` isLeft

  describe "Binary round-trip" $ do
    it "decode(encode(ps)) == ps for /ip4/tcp" $ do
      let ps = [IP4 0x0a000001, TCP 8080]
      decodeProtocols (encodeProtocols ps) `shouldBe` Right ps

    it "decode(encode(ps)) == ps for /ip4/udp/quic-v1" $ do
      let ps = [IP4 0xc0a80001, UDP 443, QuicV1]
      decodeProtocols (encodeProtocols ps) `shouldBe` Right ps

    it "decode(encode(ps)) == ps for p2p with multihash" $ do
      let peerIdBytes = BS.pack $ [0x00, 0x24, 0x08, 0x01, 0x12, 0x20] <> replicate 32 0xAB
      let ps = [IP4 0x7f000001, TCP 4001, P2P peerIdBytes]
      decodeProtocols (encodeProtocols ps) `shouldBe` Right ps

    it "decode(encode(ps)) == ps for WebRTC Direct certhash" $ do
      let certificateHash = BS.pack ([0x12, 0x20] <> replicate 32 0xAB)
          ps = [IP4 0x7f000001, UDP 443, WebRTCDirect, Certhash certificateHash]
      decodeProtocols (encodeProtocols ps) `shouldBe` Right ps

    it "decode(encode(ps)) == ps for WebTransport certhash" $ do
      let certificateHash = BS.pack ([0x12, 0x20] <> replicate 32 0xCD)
          ps = [IP4 0x7f000001, UDP 443, QuicV1, WebTransport, Certhash certificateHash]
      decodeProtocols (encodeProtocols ps) `shouldBe` Right ps

  describe "Text encoding" $ do
    it "renders /ip4/127.0.0.1/tcp/4001" $ do
      let ps = [IP4 0x7f000001, TCP 4001]
      protocolsToText ps `shouldBe` ("/ip4/127.0.0.1/tcp/4001" :: Text)

    it "renders /ip4/198.51.100.0/udp/9090/quic-v1" $ do
      let ps = [IP4 0xc6336400, UDP 9090, QuicV1]
      protocolsToText ps `shouldBe` ("/ip4/198.51.100.0/udp/9090/quic-v1" :: Text)

    it "renders dns4 protocols" $ do
      let ps = [DNS4 "example.com", TCP 443, WSS]
      protocolsToText ps `shouldBe` ("/dns4/example.com/tcp/443/wss" :: Text)

    it "renders WebRTC Direct addresses" $ do
      let certificateHash = BS.pack ([0x12, 0x20] <> replicate 32 0xAB)
          rendered = protocolsToText [IP4 0x7f000001, UDP 443, WebRTCDirect, Certhash certificateHash]
      rendered `shouldSatisfy` T.isPrefixOf "/ip4/127.0.0.1/udp/443/webrtc-direct/certhash/u"

    it "round-trips certhash text using multibase base64url" $ do
      let certificateHash = BS.pack ([0x12, 0x20] <> replicate 32 0xCD)
          rendered = protocolsToText [Certhash certificateHash]
      rendered `shouldSatisfy` T.isPrefixOf "/certhash/u"
      textToProtocols rendered `shouldBe` Right [Certhash certificateHash]

  describe "Text parsing" $ do
    it "parses /ip4/127.0.0.1/tcp/4001" $ do
      textToProtocols "/ip4/127.0.0.1/tcp/4001"
        `shouldBe` Right [IP4 0x7f000001, TCP 4001]

    it "parses /ip4/198.51.100.0/udp/9090/quic-v1" $ do
      textToProtocols "/ip4/198.51.100.0/udp/9090/quic-v1"
        `shouldBe` Right [IP4 0xc6336400, UDP 9090, QuicV1]

    it "parses /dns4/example.com/tcp/443/wss" $ do
      textToProtocols "/dns4/example.com/tcp/443/wss"
        `shouldBe` Right [DNS4 "example.com", TCP 443, WSS]

    it "parses /webrtc-direct as a no-address protocol" $ do
      textToProtocols "/ip4/127.0.0.1/udp/443/webrtc-direct"
        `shouldBe` Right [IP4 0x7f000001, UDP 443, WebRTCDirect]

    it "parses /webrtc as a no-address protocol" $ do
      textToProtocols "/p2p-circuit/webrtc"
        `shouldBe` Right [P2PCircuit, WebRTC]

    it "parses /ipfs/<peer-id> as the legacy alias of /p2p/<peer-id>" $ do
      let mh = BS.pack $ [0x12, 0x20] <> replicate 32 0xAB
      let b58 = TE.decodeUtf8 (B58.encode mh)
      textToProtocols ("/ipfs/" <> b58) `shouldBe` Right [P2P mh]
      textToProtocols ("/ipfs/" <> b58) `shouldBe` textToProtocols ("/p2p/" <> b58)

    it "renders /ipfs input back as /p2p" $ do
      let mh = BS.pack $ [0x12, 0x20] <> replicate 32 0xAB
      let b58 = TE.decodeUtf8 (B58.encode mh)
      case textToProtocols ("/ipfs/" <> b58) of
        Right ps -> protocolsToText ps `shouldBe` ("/p2p/" <> b58)
        Left err -> expectationFailure err

    it "fails on /yamux (not a registered multiaddr protocol)" $
      textToProtocols "/yamux" `shouldSatisfy` isLeft

    it "fails on invalid protocol name" $
      textToProtocols "/invalid/foo" `shouldSatisfy` isLeft

    it "fails on missing address for ip4" $
      textToProtocols "/ip4" `shouldSatisfy` isLeft

  describe "UTF-8 multibyte DNS names" $ do
    it "binary round-trip for multibyte UTF-8 DNS name" $ do
      -- Japanese domain: テスト.jp (3-byte UTF-8 chars)
      let ps = [DNS4 "\12486\12473\12488.jp", TCP 443]
      decodeProtocols (encodeProtocols ps) `shouldBe` Right ps

    it "binary round-trip for emoji DNS name" $ do
      -- Emoji domain (4-byte UTF-8 char)
      let ps = [DNS "\128640.example.com", TCP 80]
      decodeProtocols (encodeProtocols ps) `shouldBe` Right ps

    it "text round-trip for multibyte UTF-8 DNS name" $ do
      let ps = [DNS4 "\12486\12473\12488.jp", TCP 443]
      textToProtocols (protocolsToText ps) `shouldBe` Right ps

  describe "IPv6 rendering and parsing" $ do
    it "renders /ip6/::1 correctly" $ do
      -- ::1 = 15 zero bytes followed by 0x01
      let loopback = BS.pack (replicate 15 0x00 <> [0x01])
      protocolsToText [IP6 loopback] `shouldBe` "/ip6/::1"

    it "renders /ip6/fe80::1 correctly" $ do
      -- fe80::1 = fe80 0000 0000 0000 0000 0000 0000 0001
      let linkLocal = BS.pack [0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                               , 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
      protocolsToText [IP6 linkLocal] `shouldBe` "/ip6/fe80::1"

    it "renders /ip6/2001:db8::1 correctly" $ do
      let addr = BS.pack [0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00
                          , 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
      protocolsToText [IP6 addr] `shouldBe` "/ip6/2001:db8::1"

    it "parses /ip6/::1 correctly" $ do
      let expected = BS.pack (replicate 15 0x00 <> [0x01])
      textToProtocols "/ip6/::1" `shouldBe` Right [IP6 expected]

    it "parses /ip6/fe80::1 correctly" $ do
      let expected = BS.pack [0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                              , 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
      textToProtocols "/ip6/fe80::1" `shouldBe` Right [IP6 expected]

    it "IPv6 text round-trip" $ do
      let addr = BS.pack [0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00
                          , 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
      let ps = [IP6 addr, TCP 4001]
      textToProtocols (protocolsToText ps) `shouldBe` Right ps

  describe "Text round-trip" $ do
    it "textToProtocols(protocolsToText(ps)) == ps" $ do
      let ps = [IP4 0x0a000001, TCP 8080]
      textToProtocols (protocolsToText ps) `shouldBe` Right ps

  describe "Multiaddr operations" $ do
    it "encapsulate combines two multiaddrs" $ do
      let ma1 = Multiaddr [IP4 0x7f000001, TCP 4001]
      let ma2 = Multiaddr [WS]
      protocols (encapsulate ma1 ma2) `shouldBe` [IP4 0x7f000001, TCP 4001, WS]

    it "fromText and toText round-trip" $ do
      let input = "/ip4/127.0.0.1/tcp/4001" :: Text
      case fromText input of
        Right ma -> toText ma `shouldBe` input
        Left err -> expectationFailure err

  describe "splitP2P" $ do
    it "splits /ip4/.../tcp/.../p2p/<id> into transport addr and PeerId" $ do
      let peerIdMH = BS.pack $ [0x00, 0x24, 0x08, 0x01, 0x12, 0x20] <> replicate 32 0xAB
      let ma = Multiaddr [IP4 0x7f000001, TCP 4001, P2P peerIdMH]
      case splitP2P ma of
        Nothing -> expectationFailure "splitP2P returned Nothing"
        Just (transport, pid) -> do
          transport `shouldBe` Multiaddr [IP4 0x7f000001, TCP 4001]
          pid `shouldBe` PeerId peerIdMH

    it "returns Nothing when multiaddr has no /p2p/ suffix" $ do
      let ma = Multiaddr [IP4 0x7f000001, TCP 4001]
      splitP2P ma `shouldBe` Nothing

    it "returns Nothing for empty multiaddr" $ do
      let ma = Multiaddr []
      splitP2P ma `shouldBe` Nothing

    it "roundtrips: encapsulate transport (Multiaddr [P2P id]) == original" $ do
      let peerIdMH = BS.pack $ [0x00, 0x24, 0x08, 0x01, 0x12, 0x20] <> replicate 32 0xCC
      let original = Multiaddr [IP4 0xc0a80001, TCP 9090, P2P peerIdMH]
      case splitP2P original of
        Nothing -> expectationFailure "splitP2P returned Nothing"
        Just (transport, PeerId mhBytes) ->
          encapsulate transport (Multiaddr [P2P mhBytes]) `shouldBe` original

  describe "P2P validation" $ do
    it "text /p2p/INVALID rejects non-base58 input" $ do
      textToProtocols "/p2p/INVALID!!!" `shouldSatisfy` isLeft

    it "text /p2p/ with invalid multihash rejects" $ do
      -- base58-encode bytes that aren't a valid multihash
      textToProtocols "/p2p/1111" `shouldSatisfy` isLeft

    it "binary P2P with invalid multihash rejects" $ do
      -- Protocol code 421 = P2P, followed by invalid multihash bytes
      let invalidMh = BS.pack [0xDE, 0xAD]  -- unknown hash code 0xDE
      let encoded = encodeUvarint 421 <> encodeUvarint (fromIntegral (BS.length invalidMh)) <> invalidMh
      decodeProtocols encoded `shouldSatisfy` isLeft

  describe "Text parsing strictness" $ do
    it "rejects the empty string" $
      textToProtocols "" `shouldSatisfy` isLeft

    it "rejects a bare slash" $
      textToProtocols "/" `shouldSatisfy` isLeft

    it "rejects a multiaddr without a leading slash" $
      textToProtocols "ip4/127.0.0.1/tcp/4001" `shouldSatisfy` isLeft

    it "rejects doubled slashes" $
      textToProtocols "//ip4/127.0.0.1/tcp/4001" `shouldSatisfy` isLeft

    it "rejects a trailing slash" $
      textToProtocols "/ip4/127.0.0.1/tcp/4001/" `shouldSatisfy` isLeft

    it "rejects an IPv4 octet above 255" $
      textToProtocols "/ip4/256.0.0.1/tcp/4001" `shouldSatisfy` isLeft

    it "rejects a negative IPv4 octet" $
      textToProtocols "/ip4/-1.0.0.1/tcp/4001" `shouldSatisfy` isLeft

    it "rejects an IPv4 octet with leading zeros" $
      textToProtocols "/ip4/010.0.0.1/tcp/4001" `shouldSatisfy` isLeft

    it "rejects a hexadecimal IPv4 octet" $
      textToProtocols "/ip4/0xff.0.0.1/tcp/4001" `shouldSatisfy` isLeft

    it "rejects an IPv4 address with fewer than four octets" $
      textToProtocols "/ip4/1.2.3/tcp/4001" `shouldSatisfy` isLeft

    it "rejects an IPv4 address with more than four octets" $
      textToProtocols "/ip4/1.2.3.4.5/tcp/4001" `shouldSatisfy` isLeft

    it "accepts 0.0.0.0 and 255.255.255.255" $ do
      textToProtocols "/ip4/0.0.0.0/tcp/4001"
        `shouldBe` Right [IP4 0x00000000, TCP 4001]
      textToProtocols "/ip4/255.255.255.255/tcp/4001"
        `shouldBe` Right [IP4 0xffffffff, TCP 4001]

    it "rejects a TCP port above 65535" $
      textToProtocols "/ip4/127.0.0.1/tcp/65536" `shouldSatisfy` isLeft

    it "rejects a negative TCP port" $
      textToProtocols "/ip4/127.0.0.1/tcp/-1" `shouldSatisfy` isLeft

    it "rejects a hexadecimal TCP port" $
      textToProtocols "/ip4/127.0.0.1/tcp/0x50" `shouldSatisfy` isLeft

    it "rejects a non-numeric TCP port" $
      textToProtocols "/ip4/127.0.0.1/tcp/port" `shouldSatisfy` isLeft

    it "accepts ports 0 and 65535" $ do
      textToProtocols "/ip4/127.0.0.1/tcp/0" `shouldBe` Right [IP4 0x7f000001, TCP 0]
      textToProtocols "/ip4/127.0.0.1/tcp/65535" `shouldBe` Right [IP4 0x7f000001, TCP 65535]

    it "accepts a port with leading zeros (go-multiaddr compatible)" $
      textToProtocols "/ip4/127.0.0.1/tcp/0080" `shouldBe` Right [IP4 0x7f000001, TCP 80]

    it "rejects a malformed IPv6 literal" $ do
      textToProtocols "/ip6/zzzz" `shouldSatisfy` isLeft
      textToProtocols "/ip6/1:2:3" `shouldSatisfy` isLeft

  describe "Binary decoding strictness" $ do
    it "rejects trailing garbage after a valid component" $ do
      let bytes = BS.pack [0x04, 0x7f, 0x00, 0x00, 0x01, 0x06, 0x0f, 0xa1, 0x00]
      decodeProtocols bytes `shouldSatisfy` isLeft
      fromBytes bytes `shouldSatisfy` isLeft

    it "rejects truncated ip4 address bytes" $
      decodeProtocols (BS.pack [0x04, 0x7f, 0x00]) `shouldSatisfy` isLeft

    it "rejects truncated tcp port bytes" $
      decodeProtocols (BS.pack [0x06, 0x0f]) `shouldSatisfy` isLeft

    it "rejects a varint-prefixed component shorter than its declared length" $ do
      let bytes = encodeUvarint 53 <> encodeUvarint 5 <> "ab"
      decodeProtocols bytes `shouldSatisfy` isLeft

    it "rejects invalid UTF-8 in a dns component" $ do
      let bytes = encodeUvarint 53 <> encodeUvarint 2 <> BS.pack [0xff, 0xfe]
      decodeProtocols bytes `shouldSatisfy` isLeft

  describe "P2P multihash forms" $ do
    let idMH = BS.pack $ [0x00, 0x24, 0x08, 0x01, 0x12, 0x20] <> replicate 32 0xAB
        idB58 = TE.decodeUtf8 (B58.encode idMH)

    it "parses /p2p/<CIDv1> and /p2p/<base58btc> to the same component" $ do
      let cid = toCIDv1 (PeerId idMH)
      textToProtocols ("/p2p/" <> cid) `shouldBe` Right [P2P idMH]
      textToProtocols ("/p2p/" <> cid) `shouldBe` textToProtocols ("/p2p/" <> idB58)

    it "renders an identity-hash peer id back as base58btc, even when parsed from CIDv1" $ do
      let cid = toCIDv1 (PeerId idMH)
      case textToProtocols ("/p2p/" <> cid) of
        Right ps -> protocolsToText ps `shouldBe` ("/p2p/" <> idB58)
        Left err -> expectationFailure err

    it "rejects a CIDv1 with a non-libp2p-key codec" $ do
      -- codec 0x55 (raw) instead of 0x72 (libp2p-key)
      textToProtocols ("/p2p/" <> mkCIDText 1 0x55 idMH) `shouldSatisfy` isLeft

    it "rejects a CIDv1 wrapping an invalid multihash" $
      textToProtocols ("/p2p/" <> mkCIDText 1 0x72 (BS.pack [0xDE, 0xAD]))
        `shouldSatisfy` isLeft

    it "binary round-trips a p2p component with an identity multihash at the 42-byte boundary" $ do
      let mh = BS.pack $ [0x00, 0x2A] <> replicate 42 0x42
      decodeProtocols (encodeProtocols [P2P mh]) `shouldBe` Right [P2P mh]

    it "binary rejects a p2p component with an identity digest above 42 bytes" $ do
      let mh = BS.pack $ [0x00, 0x2B] <> replicate 43 0x42
          bytes = encodeUvarint 421 <> encodeUvarint (fromIntegral (BS.length mh)) <> mh
      decodeProtocols bytes `shouldSatisfy` isLeft

    it "binary round-trips a p2p component with a SHA-256 multihash" $ do
      let mh = BS.pack $ [0x12, 0x20] <> replicate 32 0xCD
      decodeProtocols (encodeProtocols [P2P mh]) `shouldBe` Right [P2P mh]

  describe "decapsulate" $ do
    let relayed =
          Multiaddr
            [ IP4 0x7f000001
            , TCP 4001
            , P2PCircuit
            , P2P (BS.pack ([0x12, 0x20] <> replicate 32 0x01))
            ]

    it "removes the suffix and everything after it" $
      decapsulate relayed (Multiaddr [P2PCircuit])
        `shouldBe` Multiaddr [IP4 0x7f000001, TCP 4001]

    it "removes from the last occurrence of the suffix" $ do
      let ma = Multiaddr [WS, TCP 1, WS, TCP 2]
      decapsulate ma (Multiaddr [WS]) `shouldBe` Multiaddr [WS, TCP 1]

    it "returns the original when the suffix is absent" $ do
      let ma = Multiaddr [IP4 0x7f000001, TCP 4001]
      decapsulate ma (Multiaddr [WS]) `shouldBe` ma

    it "decapsulating by the empty multiaddr is a no-op" $
      decapsulate relayed (Multiaddr []) `shouldBe` relayed

    it "splits a relayed address on /p2p-circuit" $ do
      let relayTransport = decapsulate relayed (Multiaddr [P2PCircuit])
      encapsulate relayTransport (Multiaddr [P2PCircuit]) `shouldBe`
        Multiaddr [IP4 0x7f000001, TCP 4001, P2PCircuit]

    it "is a left inverse of encapsulate (property)" $
      property $
        forAll ((,) <$> listOf genProtocol <*> listOf1 genProtocol) $ \(a, b) ->
          decapsulate (encapsulate (Multiaddr a) (Multiaddr b)) (Multiaddr b)
            === Multiaddr a

  describe "Property: binary round-trip" $ do
    it "decode(encode(ps)) == ps for arbitrary protocol stacks" $
      property $
        forAll (listOf genProtocol) $ \ps ->
          decodeProtocols (encodeProtocols ps) === Right ps

    it "fromBytes(toBytes(ma)) == ma for arbitrary multiaddrs" $
      property $
        forAll (listOf genProtocol) $ \ps ->
          fromBytes (toBytes (Multiaddr ps)) === Right (Multiaddr ps)

-- | Generate a protocol component whose binary form is canonical
-- (valid multihash for p2p, valid UTF-8 dns names).
genProtocol :: Gen Protocol
genProtocol =
  oneof
    [ IP4 <$> arbitrary
    , IP6 . BS.pack <$> vector 16
    , TCP <$> arbitrary
    , UDP <$> arbitrary
    , P2P <$> genIdentityMultihash
    , Certhash <$> genIdentityMultihash
    , DNS <$> genDnsName
    , DNS4 <$> genDnsName
    , DNS6 <$> genDnsName
    , DNSAddr <$> genDnsName
    , pure QuicV1
    , pure WS
    , pure WSS
    , pure P2PCircuit
    , pure WebRTCDirect
    , pure WebTransport
    , pure NoiseProto
    ]
  where
    genIdentityMultihash = do
      n <- chooseInt (0, 42)
      bytes <- vector n
      pure (BS.pack (0x00 : fromIntegral n : bytes))
    genDnsName =
      T.pack <$> listOf1 (elements (['a' .. 'z'] ++ ['0' .. '9'] ++ "-."))

-- | Build a CIDv1 text form ('b' + base32lower, no padding) with an
-- arbitrary version, codec and multihash payload.
mkCIDText :: Word64 -> Word64 -> BS.ByteString -> Text
mkCIDText version codec mh =
  let bytes = encodeUvarint version <> encodeUvarint codec <> mh
      b32 = convertToBase Base32 bytes :: BS.ByteString
      noPad = BS.filter (/= 0x3D) b32
      lower = BS.map (\w -> if w >= 0x41 && w <= 0x5A then w + 32 else w) noPad
   in "b" <> TE.decodeUtf8 lower

isLeft :: Either a b -> Bool
isLeft (Left _) = True
isLeft _ = False
