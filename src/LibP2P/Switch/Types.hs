-- | Core types for the libp2p Switch (central coordinator).
--
-- Defines connection states, direction, muxer session abstraction,
-- connection records, switch events, and the Switch itself.
--
module LibP2P.Switch.Types
  ( ConnState (..)
  , Direction (..)
  , MuxerSession (..)
  , Connection (..)
  , SwitchEvent (..)
  , StreamHandler
  , Switch (..)
  , SwitchConfig (..)
  , defaultSwitchConfig
  , DialError (..)
  , BackoffEntry (..)
  , ResourceError (..)
  , ActiveListener (..)
  ) where

import Control.Concurrent.Async (Async)
import Control.Concurrent.STM (TChan, TMVar, TVar)
import Data.Map.Strict (Map)
import Data.Time.Clock (UTCTime)
import LibP2P.Crypto.Key (KeyPair)
import LibP2P.Switch.CertifiedRecords (CertifiedRecord)
import LibP2P.Crypto.PeerId (PeerId)
import LibP2P.Multiaddr (Multiaddr)
import LibP2P.MultistreamSelect.Negotiation (ProtocolId, StreamIO)
import LibP2P.Protocol.Identify.Message (IdentifyInfo)
import LibP2P.Switch.ResourceManager (Direction (..), ResourceError (..), ResourceManager)
import LibP2P.Yamux.Types (YamuxConfig, defaultYamuxConfig)
import LibP2P.Transport (Listener, Transport)

-- | Connection state machine.
--
-- Connecting → ConnOpen → Closing → Closed
data ConnState
  = Connecting  -- ^ Raw transport established, upgrade in progress
  | ConnOpen    -- ^ Fully upgraded, streams can be opened/accepted
  | Closing     -- ^ Go Away sent/received, draining existing streams
  | ConnClosed  -- ^ Transport connection closed, resources freed
  deriving (Show, Eq)

-- | Abstract muxer session interface.
--
-- Decouples Switch from a specific muxer (Yamux, mplex, etc.).
-- Each muxer implementation provides a MuxerSession adapter.
data MuxerSession = MuxerSession
  { muxOpenStream   :: !(IO StreamIO)   -- ^ Open a new outbound stream
  , muxAcceptStream :: !(IO StreamIO)   -- ^ Accept an inbound stream (blocks)
  , muxClose        :: !(IO ())         -- ^ Close the muxer session
  }

-- | An upgraded (secure + multiplexed) connection to a remote peer.
data Connection = Connection
  { connPeerId     :: !PeerId          -- ^ Remote peer identity
  , connDirection  :: !Direction        -- ^ Inbound or outbound
  , connLocalAddr  :: !Multiaddr       -- ^ Local multiaddr
  , connRemoteAddr :: !Multiaddr       -- ^ Remote multiaddr
  , connSecurity   :: !ProtocolId      -- ^ Negotiated security protocol (e.g. "/noise")
  , connMuxer      :: !ProtocolId      -- ^ Negotiated muxer protocol (e.g. "/yamux/1.0.0")
  , connSession    :: !MuxerSession    -- ^ Muxer session for opening/accepting streams
  , connState      :: !(TVar ConnState) -- ^ Mutable connection state
  }

-- | A protocol stream handler.
--
-- Receives the connection the stream runs over and the stream I/O.
-- The connection exposes the remote peer identity ('connPeerId') and
-- addresses ('connRemoteAddr', 'connLocalAddr'), which protocols like
-- Identify (observedAddr) and the NAT stack need.
--
-- The handler owns the stream, matching go-libp2p: it must close or
-- reset on every exit path. Dispatch does not close on return, because
-- some handlers (Circuit Relay STOP) hand the stream off as a connection.
-- One-shot protocols (Identify, AutoNAT) close after the single exchange;
-- long-lived protocols (DHT, Ping, GossipSub) close when the remote
-- half-closes or the session ends.
type StreamHandler = Connection -> StreamIO -> IO ()

-- | Events emitted by the Switch for observability.
data SwitchEvent
  = Connected    !PeerId !Direction !Multiaddr  -- ^ Connection fully upgraded
  | Disconnected !PeerId !Direction !Multiaddr  -- ^ Connection closed
  deriving (Show, Eq)

-- | Errors that can occur during a dial operation.
data DialError
  = DialBackoff               -- ^ Peer is in backoff period (recently failed)
  | DialNoAddresses           -- ^ No addresses provided for dialing
  | DialNoTransport !Multiaddr -- ^ No registered transport can handle this address
  | DialAllFailed ![String]   -- ^ All dial attempts failed
  | DialUpgradeFailed !String -- ^ Connection upgrade pipeline failed
  | DialSwitchClosed          -- ^ Switch has been shut down
  | DialResourceLimit !ResourceError  -- ^ Resource limit exceeded
  | DialPeerIdMismatch !PeerId !PeerId  -- ^ Expected vs actual remote PeerId
  deriving (Show, Eq)

-- | Per-peer dial backoff state.
--
-- After a failed dial, subsequent dials are rejected until the backoff
-- expires. Duration doubles on each consecutive failure up to 300s max.
data BackoffEntry = BackoffEntry
  { beExpiry   :: !UTCTime  -- ^ When the backoff period ends
  , beAttempts :: !Int      -- ^ Number of consecutive failures (for exponential calc)
  } deriving (Show, Eq)

-- | An active listener bound to an address with its accept loop thread.
data ActiveListener = ActiveListener
  { alListener   :: !Listener      -- ^ The transport listener (accept, close)
  , alAcceptLoop :: !(Async ())    -- ^ Background thread accepting connections
  , alAddress    :: !Multiaddr     -- ^ Actual bound address (port 0 resolved)
  }

-- | Switch-wide settings, fixed when the Switch is created.
data SwitchConfig = SwitchConfig
  { scYamuxConfig :: !YamuxConfig -- ^ Applied to every Yamux session the Switch upgrades
  }
  deriving (Show, Eq)

defaultSwitchConfig :: SwitchConfig
defaultSwitchConfig = SwitchConfig
  { scYamuxConfig = defaultYamuxConfig
  }

-- | The Switch: central coordinator of the libp2p networking stack.
--
-- Manages transports, connection pool, protocol handlers, and events.
-- All mutable state is STM-based for safe concurrent access.
data Switch = Switch
  { swLocalPeerId  :: !PeerId                                            -- ^ This node's peer identity
  , swIdentityKey  :: !KeyPair                                           -- ^ This node's key pair
  , swTransports   :: !(TVar [Transport])                                -- ^ Registered transports
  , swConnPool     :: !(TVar (Map PeerId [Connection]))                  -- ^ Active connections per peer
  , swProtocols    :: !(TVar (Map ProtocolId StreamHandler))             -- ^ Protocol registry
  , swEvents       :: !(TChan SwitchEvent)                               -- ^ Event broadcast channel
  , swClosed       :: !(TVar Bool)                                       -- ^ Whether the switch is shut down
  , swDialBackoffs :: !(TVar (Map PeerId BackoffEntry))                  -- ^ Per-peer dial backoff state
  , swPendingDials :: !(TVar (Map PeerId (TMVar (Either DialError Connection)))) -- ^ In-flight dials for dedup
  , swResourceMgr  :: !ResourceManager                                   -- ^ Hierarchical resource manager
  , swPeerStore    :: !(TVar (Map PeerId IdentifyInfo))                  -- ^ Identify info per peer
  , swCertifiedRecords :: !(TVar (Map PeerId CertifiedRecord))           -- ^ Accepted RFC 0003 records per peer
  , swNotifiers    :: !(TVar [Connection -> IO ()])                      -- ^ Callbacks on new connection
  , swDisconnectNotifiers :: !(TVar [Connection -> IO ()])               -- ^ Callbacks on connection teardown
  , swListeners    :: !(TVar [ActiveListener])                           -- ^ Active listeners
  , swConfig       :: !SwitchConfig                                      -- ^ Settings given at creation
  }
