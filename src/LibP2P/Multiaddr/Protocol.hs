-- | Protocol definitions for multiaddr.
--
-- Each protocol has a numeric code and an address format.
-- See: https://github.com/multiformats/multiaddr/blob/master/protocols.csv
module LibP2P.Multiaddr.Protocol
  ( Protocol (..)
  , protocolCode
  , protocolName
  , AddressSize (..)
  , protocolAddressSize
  , codeToProtocolName
  ) where

import Data.ByteString (ByteString)
import Data.Text (Text)
import Data.Word (Word16, Word32, Word64)

-- | A single protocol component within a multiaddr.
data Protocol
  = IP4 !Word32        -- ^ IPv4 address (4 bytes big-endian)
  | IP6 !ByteString    -- ^ IPv6 address (16 bytes)
  | TCP !Word16        -- ^ TCP port
  | UDP !Word16        -- ^ UDP port
  | P2P !ByteString    -- ^ Peer ID as multihash bytes
  | Certhash !ByteString -- ^ TLS certificate fingerprint as multihash bytes
  | QuicV1             -- ^ QUIC v1 (no address)
  | WS                 -- ^ WebSocket (no address)
  | WSS                -- ^ WebSocket Secure (no address)
  | DNS !Text          -- ^ DNS hostname
  | DNS4 !Text         -- ^ DNS4 hostname
  | DNS6 !Text         -- ^ DNS6 hostname
  | DNSAddr !Text      -- ^ DNSAddr hostname
  | P2PCircuit         -- ^ Circuit relay marker (no address)
  | WebRTCDirect       -- ^ ICE-lite WebRTC Direct (no address)
  | WebTransport       -- ^ WebTransport (no address)
  | NoiseProto         -- ^ Noise protocol marker (no address)
  deriving (Show, Eq)

-- | Address size specification for a protocol.
data AddressSize
  = Fixed !Int       -- ^ Fixed number of bytes
  | VarIntPrefixed   -- ^ Varint-length-prefixed bytes
  | NoAddress        -- ^ No address bytes
  deriving (Show, Eq)

-- | Get the multicodec code for a protocol.
protocolCode :: Protocol -> Word64
protocolCode (IP4 _) = 4
protocolCode (IP6 _) = 41
protocolCode (TCP _) = 6
protocolCode (UDP _) = 273
protocolCode (P2P _) = 421
protocolCode (Certhash _) = 466
protocolCode QuicV1 = 461
protocolCode WS = 477
protocolCode WSS = 478
protocolCode (DNS _) = 53
protocolCode (DNS4 _) = 54
protocolCode (DNS6 _) = 55
protocolCode (DNSAddr _) = 56
protocolCode P2PCircuit = 290
protocolCode WebRTCDirect = 280
protocolCode WebTransport = 465
protocolCode NoiseProto = 454

-- | Get the human-readable name for a protocol.
protocolName :: Protocol -> Text
protocolName (IP4 _) = "ip4"
protocolName (IP6 _) = "ip6"
protocolName (TCP _) = "tcp"
protocolName (UDP _) = "udp"
protocolName (P2P _) = "p2p"
protocolName (Certhash _) = "certhash"
protocolName QuicV1 = "quic-v1"
protocolName WS = "ws"
protocolName WSS = "wss"
protocolName (DNS _) = "dns"
protocolName (DNS4 _) = "dns4"
protocolName (DNS6 _) = "dns6"
protocolName (DNSAddr _) = "dnsaddr"
protocolName P2PCircuit = "p2p-circuit"
protocolName WebRTCDirect = "webrtc-direct"
protocolName WebTransport = "webtransport"
protocolName NoiseProto = "noise"

-- | Get the address size specification for a protocol code.
protocolAddressSize :: Word64 -> Maybe AddressSize
protocolAddressSize 4 = Just (Fixed 4)        -- ip4
protocolAddressSize 41 = Just (Fixed 16)      -- ip6
protocolAddressSize 6 = Just (Fixed 2)        -- tcp
protocolAddressSize 273 = Just (Fixed 2)      -- udp
protocolAddressSize 421 = Just VarIntPrefixed -- p2p
protocolAddressSize 466 = Just VarIntPrefixed -- certhash
protocolAddressSize 461 = Just NoAddress      -- quic-v1
protocolAddressSize 477 = Just NoAddress      -- ws
protocolAddressSize 478 = Just NoAddress      -- wss
protocolAddressSize 53 = Just VarIntPrefixed  -- dns
protocolAddressSize 54 = Just VarIntPrefixed  -- dns4
protocolAddressSize 55 = Just VarIntPrefixed  -- dns6
protocolAddressSize 56 = Just VarIntPrefixed  -- dnsaddr
protocolAddressSize 290 = Just NoAddress      -- p2p-circuit
protocolAddressSize 280 = Just NoAddress      -- webrtc-direct
protocolAddressSize 465 = Just NoAddress      -- webtransport
protocolAddressSize 454 = Just NoAddress      -- noise
protocolAddressSize _ = Nothing

-- | Map protocol code to name (for text parsing).
codeToProtocolName :: Word64 -> Maybe Text
codeToProtocolName 4 = Just "ip4"
codeToProtocolName 41 = Just "ip6"
codeToProtocolName 6 = Just "tcp"
codeToProtocolName 273 = Just "udp"
codeToProtocolName 421 = Just "p2p"
codeToProtocolName 466 = Just "certhash"
codeToProtocolName 461 = Just "quic-v1"
codeToProtocolName 477 = Just "ws"
codeToProtocolName 478 = Just "wss"
codeToProtocolName 53 = Just "dns"
codeToProtocolName 54 = Just "dns4"
codeToProtocolName 55 = Just "dns6"
codeToProtocolName 56 = Just "dnsaddr"
codeToProtocolName 290 = Just "p2p-circuit"
codeToProtocolName 280 = Just "webrtc-direct"
codeToProtocolName 465 = Just "webtransport"
codeToProtocolName 454 = Just "noise"
codeToProtocolName _ = Nothing
