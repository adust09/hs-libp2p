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
  , enqueueFrame
  , enqueueDataFrame
  , enqueueFrameNumbered
  , awaitFrameWritten
  ) where

import Control.Concurrent.STM (STM, TBQueue, TMVar, TQueue, TVar, check, readTVar, writeTQueue, writeTVar)
import Control.Monad (void)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Data.Word (Word32, Word64)
import LibP2P.Switch.ResourceManager
  ( MemoryAccount (..)
  , ResourceError
  )
import LibP2P.Yamux.Frame (GoAwayCode, YamuxHeader)

-- | Result delivered to a pending ping waiter: Right on a matching ACK,
-- Left when the session dies before the ACK arrives.
type PingWaiter = TMVar (Either YamuxError ())

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
  | YamuxResourceLimit !ResourceError -- ^ Stream buffer reservation failed
  deriving (Show, Eq)

-- | Per-stream state (spec.md §Flow Control: per-stream windows only).
data YamuxStream = YamuxStream
  { ysStreamId :: !Word32
  , ysState :: !(TVar StreamState)
  , ysSendWindow :: !(TVar Word32) -- ^ Starts at 262144 (256 KiB)
  , ysRecvWindow :: !(TVar Word32) -- ^ Starts at 262144 (256 KiB)
  , ysRecvBuf :: !(TQueue ByteString) -- ^ Incoming data frames
  , ysSendNotify :: !(TMVar ()) -- ^ Wakeup blocked writers on WindowUpdate
  , ysMemoryAccount :: !MemoryAccount -- ^ Buffer ownership for this stream
  , ysSession :: !YamuxSession -- ^ Back-reference for frame sending
  }

-- | Session state.
data YamuxSession = YamuxSession
  { ysessRole :: !SessionRole
  , ysessNextStreamId :: !(TVar Word32) -- ^ Next ID to allocate
  , ysessStreams :: !(TVar (Map.Map Word32 YamuxStream)) -- ^ Active streams
  , ysessAcceptCh :: !(TBQueue YamuxStream) -- ^ Inbound streams, bounded to acceptBacklog (256); excess SYNs are reset
  , ysessSendCh :: !(TQueue (YamuxHeader, ByteString, Maybe MemoryAccount)) -- ^ Outbound frame queue
  , ysessConnectionMemory :: !MemoryAccount -- ^ Memory used outside a known stream
  , ysessInboundMemory :: !(STM (Either ResourceError MemoryAccount)) -- ^ Account factory for inbound streams
  , ysessOutboundMemory :: !(STM (Either ResourceError MemoryAccount)) -- ^ Account factory for outbound streams
  , ysessShutdown :: !(TVar Bool) -- ^ Local GoAway sent
  , ysessRemoteGoAway :: !(TVar (Maybe GoAwayCode)) -- ^ Code of the remote GoAway, if one was received
  , ysessPings :: !(TVar (Map.Map Word32 PingWaiter)) -- ^ Pending ping responses
  , ysessNextPingId :: !(TVar Word32)
  , ysessQueuedCount :: !(TVar Word64) -- ^ Frames queued so far; the number of the latest queued frame
  , ysessSentCount :: !(TVar Word64) -- ^ Frames sendLoop has finished writing
  , ysessRecvCount :: !(TVar Word64) -- ^ Frame headers recvLoop has read
  , ysessWrite :: !(ByteString -> IO ()) -- ^ Underlying transport write
  , ysessRead :: !(Int -> IO ByteString) -- ^ Underlying transport read exact N bytes
  }

-- | Queue a frame for sendLoop to write. Every outbound frame goes
-- through here, so this is the one place that sees each frame as it
-- enters the send queue.
enqueueFrame :: YamuxSession -> YamuxHeader -> ByteString -> STM ()
enqueueFrame sess hdr payload = void (enqueueFrameNumbered sess hdr payload)

-- | Like 'enqueueFrame', returning the frame's number. Frames are
-- numbered from 1 in queue order, in the same transaction that queues
-- them, so the number also tells how many frames sendLoop must write
-- before this one is out (see 'awaitFrameWritten').
--
-- The counters are Word64, which cannot wrap in practice (about 58,000
-- years at 10M frames/s), so frame numbers are compared directly.
enqueueFrameNumbered :: YamuxSession -> YamuxHeader -> ByteString -> STM Word64
enqueueFrameNumbered sess hdr payload = do
  writeTQueue (ysessSendCh sess) (hdr, payload, Nothing)
  numberQueuedFrame sess

-- | Reserve a payload while it waits in the outbound queue.
enqueueDataFrame
  :: YamuxSession -> MemoryAccount -> YamuxHeader -> ByteString
  -> STM (Either ResourceError Word64)
enqueueDataFrame sess account hdr payload = do
  reserved <- maReserve account (BS.length payload)
  case reserved of
    Left err -> pure (Left err)
    Right () -> do
      writeTQueue (ysessSendCh sess) (hdr, payload, Just account)
      Right <$> numberQueuedFrame sess

numberQueuedFrame :: YamuxSession -> STM Word64
numberQueuedFrame sess = do
  n <- (+ 1) <$> readTVar (ysessQueuedCount sess)
  writeTVar (ysessQueuedCount sess) n
  pure n

-- | Block until sendLoop has finished writing the frame with the given
-- number to the transport.
awaitFrameWritten :: YamuxSession -> Word64 -> STM ()
awaitFrameWritten sess n = readTVar (ysessSentCount sess) >>= check . (>= n)
