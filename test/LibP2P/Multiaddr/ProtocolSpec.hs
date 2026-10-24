-- | Pins the multiaddr protocol table against the canonical multiformats
-- registry. Every assertion here is an absolute value transcribed from
-- https://github.com/multiformats/multiaddr/blob/master/protocols.csv —
-- round-trip tests cannot substitute for these, because a wrong constant
-- that the encoder and decoder share stays green under round-tripping
-- (the root cause of issue #158).
module LibP2P.Multiaddr.ProtocolSpec (spec) where

import Control.Monad (forM_)
import qualified Data.ByteString as BS
import Data.Maybe (isJust, isNothing)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Word (Word64)
import LibP2P.Core.Varint (encodeUvarint)
import LibP2P.Multiaddr.Protocol
import Test.Hspec

-- | One representative value per constructor. The compiler enforces
-- completeness via 'constructorTag': a new constructor that is not added
-- here will trigger an incomplete-pattern warning there.
allProtocols :: [Protocol]
allProtocols =
  [ IP4 0x7f000001
  , IP6 (BS.replicate 16 0x00)
  , TCP 4001
  , UDP 9090
  , P2P (BS.pack ([0x12, 0x20] <> replicate 32 0xAB))
  , Certhash (BS.pack ([0x12, 0x20] <> replicate 32 0xCD))
  , QuicV1
  , WS
  , WSS
  , DNS "example.com"
  , DNS4 "example.com"
  , DNS6 "example.com"
  , DNSAddr "example.com"
  , P2PCircuit
  , WebRTCDirect
  , WebTransport
  , NoiseProto
  ]

-- | Wildcard-free match over every constructor. Adding a constructor to
-- 'Protocol' without extending 'allProtocols' makes this function emit an
-- incomplete-pattern warning under -Wall, flagging the spec as stale.
constructorTag :: Protocol -> Text
constructorTag p = case p of
  IP4 _ -> "IP4"
  IP6 _ -> "IP6"
  TCP _ -> "TCP"
  UDP _ -> "UDP"
  P2P _ -> "P2P"
  Certhash _ -> "Certhash"
  QuicV1 -> "QuicV1"
  WS -> "WS"
  WSS -> "WSS"
  DNS _ -> "DNS"
  DNS4 _ -> "DNS4"
  DNS6 _ -> "DNS6"
  DNSAddr _ -> "DNSAddr"
  P2PCircuit -> "P2PCircuit"
  WebRTCDirect -> "WebRTCDirect"
  WebTransport -> "WebTransport"
  NoiseProto -> "NoiseProto"

-- | Canonical rows from protocols.csv: (sample, code, name).
canonicalTable :: [(Protocol, Word64, Text)]
canonicalTable =
  [ (IP4 0, 4, "ip4")
  , (TCP 0, 6, "tcp")
  , (IP6 (BS.replicate 16 0), 41, "ip6")
  , (DNS "", 53, "dns")
  , (DNS4 "", 54, "dns4")
  , (DNS6 "", 55, "dns6")
  , (DNSAddr "", 56, "dnsaddr")
  , (UDP 0, 273, "udp")
  , (WebRTCDirect, 280, "webrtc-direct")
  , (P2PCircuit, 290, "p2p-circuit")
  , (P2P BS.empty, 421, "p2p")
  , (NoiseProto, 454, "noise")
  , (QuicV1, 461, "quic-v1")
  , (WebTransport, 465, "webtransport")
  , (Certhash BS.empty, 466, "certhash")
  , (WS, 477, "ws")
  , (WSS, 478, "wss")
  ]

spec :: Spec
spec = do
  describe "protocolCode (canonical multiformats table)" $ do
    it "assigns ip4 code 4" $ protocolCode (IP4 0) `shouldBe` 4
    it "assigns tcp code 6" $ protocolCode (TCP 0) `shouldBe` 6
    it "assigns ip6 code 41" $
      protocolCode (IP6 (BS.replicate 16 0)) `shouldBe` 41
    it "assigns dns 53, dns4 54, dns6 55, dnsaddr 56" $ do
      protocolCode (DNS "") `shouldBe` 53
      protocolCode (DNS4 "") `shouldBe` 54
      protocolCode (DNS6 "") `shouldBe` 55
      protocolCode (DNSAddr "") `shouldBe` 56
    it "assigns udp code 273" $ protocolCode (UDP 0) `shouldBe` 273
    it "assigns webrtc-direct code 280" $ protocolCode WebRTCDirect `shouldBe` 280
    it "assigns p2p-circuit code 290" $ protocolCode P2PCircuit `shouldBe` 290
    it "assigns p2p code 421" $ protocolCode (P2P BS.empty) `shouldBe` 421
    it "assigns noise code 454" $ protocolCode NoiseProto `shouldBe` 454
    it "assigns quic-v1 code 461, not 460 (460 is quic draft-29)" $ do
      protocolCode QuicV1 `shouldBe` 461
      protocolCode QuicV1 `shouldNotBe` 460
    it "assigns webtransport code 465" $ protocolCode WebTransport `shouldBe` 465
    it "assigns certhash code 466" $ protocolCode (Certhash BS.empty) `shouldBe` 466
    it "assigns ws 477, wss 478" $ do
      protocolCode WS `shouldBe` 477
      protocolCode WSS `shouldBe` 478

  describe "protocolCode varint wire encoding" $ do
    it "encodes single-byte codes as one byte" $ do
      encodeUvarint (protocolCode (IP4 0)) `shouldBe` BS.pack [0x04]
      encodeUvarint (protocolCode (TCP 0)) `shouldBe` BS.pack [0x06]
      encodeUvarint (protocolCode (IP6 (BS.replicate 16 0))) `shouldBe` BS.pack [0x29]
      encodeUvarint (protocolCode (DNS "")) `shouldBe` BS.pack [0x35]
      encodeUvarint (protocolCode (DNS4 "")) `shouldBe` BS.pack [0x36]
      encodeUvarint (protocolCode (DNS6 "")) `shouldBe` BS.pack [0x37]
      encodeUvarint (protocolCode (DNSAddr "")) `shouldBe` BS.pack [0x38]
    it "encodes udp (273) as 0x91 0x02" $
      encodeUvarint (protocolCode (UDP 0)) `shouldBe` BS.pack [0x91, 0x02]
    it "encodes webrtc-direct (280) as 0x98 0x02" $
      encodeUvarint (protocolCode WebRTCDirect) `shouldBe` BS.pack [0x98, 0x02]
    it "encodes p2p-circuit (290) as 0xa2 0x02" $
      encodeUvarint (protocolCode P2PCircuit) `shouldBe` BS.pack [0xa2, 0x02]
    it "encodes p2p (421) as 0xa5 0x03" $
      encodeUvarint (protocolCode (P2P BS.empty)) `shouldBe` BS.pack [0xa5, 0x03]
    it "encodes noise (454) as 0xc6 0x03" $
      encodeUvarint (protocolCode NoiseProto) `shouldBe` BS.pack [0xc6, 0x03]
    it "encodes quic-v1 (461) as 0xcd 0x03" $
      encodeUvarint (protocolCode QuicV1) `shouldBe` BS.pack [0xcd, 0x03]
    it "encodes webtransport (465) as 0xd1 0x03" $
      encodeUvarint (protocolCode WebTransport) `shouldBe` BS.pack [0xd1, 0x03]
    it "encodes certhash (466) as 0xd2 0x03" $
      encodeUvarint (protocolCode (Certhash BS.empty)) `shouldBe` BS.pack [0xd2, 0x03]
    it "encodes ws (477) as 0xdd 0x03" $
      encodeUvarint (protocolCode WS) `shouldBe` BS.pack [0xdd, 0x03]
    it "encodes wss (478) as 0xde 0x03" $
      encodeUvarint (protocolCode WSS) `shouldBe` BS.pack [0xde, 0x03]

  describe "protocolName (canonical multiformats table)" $
    it "matches the canonical name for every constructor" $
      forM_ canonicalTable $ \(p, _, name) ->
        protocolName p `shouldBe` name

  describe "protocolAddressSize" $ do
    it "assigns ip4 Fixed 4" $ protocolAddressSize 4 `shouldBe` Just (Fixed 4)
    it "assigns ip6 Fixed 16" $ protocolAddressSize 41 `shouldBe` Just (Fixed 16)
    it "assigns tcp and udp Fixed 2" $ do
      protocolAddressSize 6 `shouldBe` Just (Fixed 2)
      protocolAddressSize 273 `shouldBe` Just (Fixed 2)
    it "assigns p2p, certhash, and dns variants VarIntPrefixed" $ do
      protocolAddressSize 421 `shouldBe` Just VarIntPrefixed
      protocolAddressSize 466 `shouldBe` Just VarIntPrefixed
      protocolAddressSize 53 `shouldBe` Just VarIntPrefixed
      protocolAddressSize 54 `shouldBe` Just VarIntPrefixed
      protocolAddressSize 55 `shouldBe` Just VarIntPrefixed
      protocolAddressSize 56 `shouldBe` Just VarIntPrefixed
    it "assigns NoAddress to all zero-address protocols" $
      forM_ [280, 290, 454, 461, 465, 477, 478 :: Word64] $ \code ->
        protocolAddressSize code `shouldBe` Just NoAddress
    it "is defined for the code of every constructor (totality)" $
      forM_ allProtocols $ \p ->
        protocolAddressSize (protocolCode p) `shouldSatisfy` isJust
    it "is undefined for unsupported and unassigned codes" $ do
      protocolAddressSize 460 `shouldSatisfy` isNothing -- quic draft-29 (unsupported)
      protocolAddressSize 467 `shouldSatisfy` isNothing -- unassigned (former yamux bug)
      protocolAddressSize 0 `shouldSatisfy` isNothing

  describe "codeToProtocolName" $ do
    it "inverts protocolCode for every constructor" $
      forM_ allProtocols $ \p ->
        codeToProtocolName (protocolCode p) `shouldBe` Just (protocolName p)
    it "returns Nothing for unsupported and unassigned codes" $ do
      codeToProtocolName 460 `shouldSatisfy` isNothing
      codeToProtocolName 467 `shouldSatisfy` isNothing
      codeToProtocolName 0 `shouldSatisfy` isNothing

  describe "table consistency" $ do
    it "covers every constructor exactly once in this spec's tables" $ do
      map constructorTag allProtocols `shouldBe`
        [ "IP4", "IP6", "TCP", "UDP", "P2P", "Certhash", "QuicV1", "WS", "WSS"
        , "DNS", "DNS4", "DNS6", "DNSAddr", "P2PCircuit", "WebRTCDirect", "WebTransport"
        , "NoiseProto"
        ]
      length canonicalTable `shouldBe` length allProtocols
    it "assigns a unique code to every constructor" $ do
      let codes = map protocolCode allProtocols
      length codes `shouldBe` length (foldr (\c acc -> if c `elem` acc then acc else c : acc) [] codes)
    it "assigns a unique, non-empty name to every constructor" $ do
      let names = map protocolName allProtocols
      forM_ names $ \n -> n `shouldNotBe` T.empty
      length names `shouldBe` length (foldr (\n acc -> if n `elem` acc then acc else n : acc) [] names)
    it "matches the canonical code for every table row" $
      forM_ canonicalTable $ \(p, code, name) ->
        (name, protocolCode p) `shouldBe` (name, code)
