-- | Transport abstraction for libp2p.
--
-- Defines the record-of-functions pattern for transport-agnostic
-- connection management. Stream transports produce a byte stream for the
-- standard security/muxer upgrade; native multiplexed transports such as QUIC
-- provide an already authenticated stream multiplexer.
module LibP2P.Transport
  ( ConnectionEndpoint (..)
  , NativeMuxer (..)
  , RelayCircuitLimit (..)
  , relayCircuitIsLimited
  , RawConnection (..)
  , Listener (..)
  , Transport (..)
  ) where

import Data.Word (Word32, Word64)
import LibP2P.Crypto.PeerId (PeerId)
import LibP2P.Multiaddr (Multiaddr)
import LibP2P.MultistreamSelect.Negotiation (ProtocolId, StreamIO)

-- | Budget a relay advertised for one relayed circuit (specs/relay/circuit-v2).
--
-- A component of 0, or an absent component, means that component is
-- unlimited. 'Nothing' on a connection means it is not a relay circuit.
data RelayCircuitLimit = RelayCircuitLimit
  { rclDurationSeconds :: !(Maybe Word32)
  , rclDataBytes       :: !(Maybe Word64)
  } deriving (Show, Eq)

-- | True when the relay imposed a non-zero duration or a non-zero
-- per-direction data cap. A zero or omitted component does not count.
relayCircuitIsLimited :: Maybe RelayCircuitLimit -> Bool
relayCircuitIsLimited = maybe False active
  where
    active lim = positive (rclDurationSeconds lim) || positive (rclDataBytes lim)
    positive (Just n) = n > 0
    positive Nothing = False

-- | A transport-native authenticated stream multiplexer.
data NativeMuxer = NativeMuxer
  { nativePeerId :: !PeerId
  , nativeSecurity :: !ProtocolId
  , nativeMuxerProtocol :: !ProtocolId
  , nativeOpenStream :: !(IO StreamIO)
  , nativeAcceptStream :: !(IO StreamIO)
  , nativeClose :: !(IO ())
  }

-- | The I/O endpoint established by a transport.
data ConnectionEndpoint
  = ByteStreamEndpoint !StreamIO
  | NativeMuxerEndpoint !NativeMuxer

-- | A connection established by a transport.
--
-- TCP and relayed connections carry an unencrypted byte stream. QUIC carries
-- a TLS-authenticated native multiplexer and therefore bypasses Noise/Yamux.
data RawConnection = RawConnection
  { rcEndpoint :: !ConnectionEndpoint
  , rcLocalAddr :: !Multiaddr
  , rcRemoteAddr :: !Multiaddr
  , rcClose :: !(IO ())
  , rcRelayLimit :: !(Maybe RelayCircuitLimit)
  }

-- | A listener that accepts inbound connections.
data Listener = Listener
  { listenerAccept :: !(IO RawConnection)
  , listenerClose :: !(IO ())
  , listenerAddr :: !Multiaddr
  }

-- | Transport provides dial/listen capabilities for a specific protocol.
data Transport = Transport
  { transportDial :: !(Multiaddr -> IO RawConnection)
  , transportDialFrom :: !(Maybe Multiaddr -> Multiaddr -> IO RawConnection)
  , transportListen :: !(Multiaddr -> IO Listener)
  , transportCanDial :: !(Multiaddr -> Bool)
  }
