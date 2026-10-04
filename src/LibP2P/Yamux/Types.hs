-- | Shared types for Yamux session management.
--
-- Types follow the HashiCorp yamux spec.md.
-- SessionRole determines stream ID parity, StreamState tracks the
-- stream lifecycle state machine, and YamuxSession/YamuxStream hold
-- per-session/per-stream mutable state via STM.
module LibP2P.Yamux.Types
  ( SessionRole (..)
  , StreamState (..)
  , YamuxError (..)
  , YamuxStream (..)
  , YamuxSession (..)
  , PingWaiter
  , YamuxConfig (..)
  , defaultYamuxConfig
  ) where

import Control.Concurrent.STM (TBQueue, TMVar, TQueue, TVar)
import Data.ByteString (ByteString)
import qualified Data.Map.Strict as Map
import Data.Word (Word32)
import LibP2P.Yamux.Frame (GoAwayCode, YamuxHeader)

-- | Result delivered to a pending ping waiter: Right on a matching ACK,
-- Left when the session dies before the ACK arrives.
type PingWaiter = TMVar (Either YamuxError ())

-- | Session tunables that spec.md leaves to the implementation.
data YamuxConfig = YamuxConfig
  { ycEnableKeepAlive :: !Bool
  , ycKeepAliveIntervalMicros :: !Int -- ^ Time between keepalive pings
  , ycPingTimeoutMicros :: !Int -- ^ How long to wait for a Ping ACK before the session is considered dead
  }
  deriving (Show, Eq)

-- | go-yamux defaults: keepalive enabled, 30s interval, 10s ping timeout.
defaultYamuxConfig :: YamuxConfig
defaultYamuxConfig =
  YamuxConfig
    { ycEnableKeepAlive = True
    , ycKeepAliveIntervalMicros = 30000000
    , ycPingTimeoutMicros = 10000000
    }

-- | SessionRole determines stream ID parity (spec.md §Stream Identification).
-- Client uses odd IDs (1, 3, 5, ...), Server uses even IDs (2, 4, 6, ...).
data SessionRole = RoleClient | RoleServer
  deriving (Show, Eq)

-- | Stream state machine (spec.md §Stream Open/Close/Reset).
-- States map to the spec's lifecycle:
--   SYN sent/received -> Established -> FIN sent/received -> Closed
data StreamState
  = StreamSYNSent -- ^ SYN sent, awaiting ACK (initiator)
  | StreamSYNReceived -- ^ SYN received, awaiting local ACK (responder)
  | StreamEstablished -- ^ Both SYN/ACK exchanged, data flows
  | StreamLocalClose -- ^ Local FIN sent (half-closed)
  | StreamRemoteClose -- ^ Remote FIN received (half-closed)
  | StreamClosed -- ^ Both FIN'd
  | StreamReset -- ^ RST sent or received
  deriving (Show, Eq)

-- | Errors map to spec-defined conditions.
data YamuxError
  = YamuxProtocolError !String -- ^ Spec violation (e.g., invalid version, unknown frame type)
  | YamuxStreamClosed -- ^ Write/read on closed stream
  | YamuxStreamReset -- ^ RST received
  | YamuxSessionShutdown -- ^ GoAway received or session closed
  | YamuxGoAway !GoAwayCode -- ^ Remote sent GoAway with specific code
  deriving (Show, Eq)

-- | Per-stream state (spec.md §Flow Control: per-stream windows only).
data YamuxStream = YamuxStream
  { ysStreamId :: !Word32
  , ysState :: !(TVar StreamState)
  , ysSendWindow :: !(TVar Word32) -- ^ Starts at 262144 (256 KiB)
  , ysRecvWindow :: !(TVar Word32) -- ^ Starts at 262144 (256 KiB)
  , ysRecvBuf :: !(TQueue ByteString) -- ^ Incoming data frames
  , ysSendNotify :: !(TMVar ()) -- ^ Wakeup blocked writers on WindowUpdate
  , ysSession :: !YamuxSession -- ^ Back-reference for frame sending
  }

-- | Session state.
data YamuxSession = YamuxSession
  { ysessConfig :: !YamuxConfig
  , ysessRole :: !SessionRole
  , ysessNextStreamId :: !(TVar Word32) -- ^ Next ID to allocate
  , ysessStreams :: !(TVar (Map.Map Word32 YamuxStream)) -- ^ Active streams
  , ysessAcceptCh :: !(TBQueue YamuxStream) -- ^ Inbound streams, bounded to acceptBacklog (256); excess SYNs are reset
  , ysessSendCh :: !(TQueue (YamuxHeader, ByteString)) -- ^ Outbound frame queue
  , ysessShutdown :: !(TVar Bool) -- ^ Local GoAway sent
  , ysessRemoteGoAway :: !(TVar (Maybe GoAwayCode)) -- ^ Code of the remote GoAway, if one was received
  , ysessPings :: !(TVar (Map.Map Word32 PingWaiter)) -- ^ Pending ping responses
  , ysessNextPingId :: !(TVar Word32)
  , ysessWrite :: !(ByteString -> IO ()) -- ^ Underlying transport write
  , ysessRead :: !(Int -> IO ByteString) -- ^ Underlying transport read exact N bytes
  }
