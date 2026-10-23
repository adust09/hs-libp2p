-- | Ping protocol implementation (specs/ping).
--
-- Protocol ID: /ipfs/ping/1.0.0
--
-- Wire format: 32 bytes random → 32 bytes echo. No framing, no protobuf.
-- The responder runs an echo loop: reads 32 bytes, writes them back,
-- until the initiator closes the stream, then closes its own side.
--
-- The initiator keeps at most one outbound ping stream per peer
-- (ping.md: "The dialing peer MUST NOT keep more than one outbound
-- stream for the ping protocol per peer"). A 'PingSession' holds that
-- single stream and reuses it for successive pings (ping.md: the peer
-- "MAY send further payloads on the same stream"); the stream is closed
-- when the session ends or on the first failed ping. Streams are opened
-- through the Switch ('newStream'), so each session holds exactly one
-- stream reservation, released on close.
--
-- The listener accepts at most two concurrent ping streams per remote
-- peer (ping.md: "The listening peer SHOULD accept at most two streams
-- per peer since cross-stream behavior is non-linear and stream writes
-- occur asynchronously"). 'registerPingHandler' installs a
-- 'PingLimiter' that counts live inbound ping streams per peer and
-- resets the third and subsequent streams without serving them.
module LibP2P.Protocol.Ping
  ( -- * Protocol ID
    pingProtocolId
    -- * Types
  , PingError (..)
  , PingResult (..)
  , PingSession
    -- * Responder
  , handlePing
  , PingLimiter
  , newPingLimiter
  , handlePingLimited
    -- * Initiator
  , sendPing
  , openPingSession
  , ping
  , pingWithTimeout
  , closePingSession
  , withPingSession
    -- * Registration
  , registerPingHandler
    -- * Constants
  , pingSize
  , pingTimeoutMicros
  , maxPingStreamsPerPeer
  ) where

import Control.Concurrent.MVar (MVar, newMVar, withMVar)
import Control.Concurrent.STM
  ( TVar
  , atomically
  , modifyTVar'
  , newTVarIO
  , readTVar
  , writeTVar
  )
import Control.Exception (SomeException, catch, finally, try)
import Control.Monad (unless)
import Data.ByteString (ByteString)
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef)
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import Data.Time.Clock (NominalDiffTime, diffUTCTime, getCurrentTime)
import Crypto.Random (getRandomBytes)
import LibP2P.Crypto.PeerId (PeerId)
import LibP2P.MultistreamSelect.Negotiation
  ( StreamIO (..)
  , negotiateInitiator
  , NegotiationResult (..)
  , readExactBounded
  )
import LibP2P.Switch.Connection (newStreamAllowingLimited)
import LibP2P.Switch.Types
  ( Connection (..)
  , Switch (..)
  )
import System.Timeout (timeout)

-- | Ping protocol ID.
pingProtocolId :: Text
pingProtocolId = "/ipfs/ping/1.0.0"

-- | Ping payload size: 32 bytes.
pingSize :: Int
pingSize = 32

-- | Time to wait for an echo before giving up, in microseconds.
-- 10 seconds, mirroring go-libp2p's ping timeout.
pingTimeoutMicros :: Int
pingTimeoutMicros = 10000000

-- | Maximum concurrent inbound ping streams served per remote peer
-- (ping.md: "The listening peer SHOULD accept at most two streams per
-- peer since cross-stream behavior is non-linear and stream writes
-- occur asynchronously").
maxPingStreamsPerPeer :: Int
maxPingStreamsPerPeer = 2

-- | Ping error types.
data PingError
  = PingTimeout          -- ^ No echo within the timeout
  | PingMismatch         -- ^ Response doesn't match sent bytes
  | PingStreamError !String  -- ^ Stream open, negotiation, or I/O error
  deriving (Show, Eq)

-- | Successful ping result.
data PingResult = PingResult
  { pingRTT :: !NominalDiffTime  -- ^ Round-trip time
  } deriving (Show, Eq)

-- | Handle an inbound Ping request (responder / echo loop).
--
-- Reads 32 bytes, writes them back. Repeats until the initiator closes
-- its write side (EOF), then closes this side of the stream (ping.md:
-- the listening peer SHOULD exit the loop and close the stream).
handlePing :: StreamIO -> PeerId -> IO ()
handlePing stream _remotePeerId = echoLoop `finally` closeQuietly stream
  where
    echoLoop = do
      result <- readExactBounded stream pingSize pingSize `catch`
                (\(_ :: SomeException) -> pure (Left "stream closed"))
      case result of
        Left _ -> pure ()  -- Stream closed, exit loop
        Right payload -> do
          streamWrite stream payload
          echoLoop

-- | Per-peer accounting of live inbound ping streams, shared by every
-- invocation of the registered ping handler on one Switch.
newtype PingLimiter = PingLimiter (TVar (Map.Map PeerId Int))

-- | Create an empty inbound ping stream limiter.
newPingLimiter :: IO PingLimiter
newPingLimiter = PingLimiter <$> newTVarIO Map.empty

-- | Serve an inbound ping stream, enforcing the per-peer cap.
--
-- If the remote peer already has 'maxPingStreamsPerPeer' live ping
-- streams, the new stream is reset (closed without serving the echo
-- loop). Otherwise the stream occupies a slot for the duration of
-- 'handlePing'; the slot is released when the stream closes or errors.
handlePingLimited :: PingLimiter -> StreamIO -> PeerId -> IO ()
handlePingLimited (PingLimiter countsVar) stream peer = do
  accepted <- atomically $ do
    counts <- readTVar countsVar
    let live = Map.findWithDefault 0 peer counts
    if live >= maxPingStreamsPerPeer
      then pure False
      else do
        writeTVar countsVar (Map.insert peer (live + 1) counts)
        pure True
  if accepted
    then handlePing stream peer `finally` atomically (modifyTVar' countsVar releaseSlot)
    else closeQuietly stream
  where
    releaseSlot = Map.update (\n -> if n <= 1 then Nothing else Just (n - 1)) peer

-- | The single outbound ping stream to a peer, negotiated and ready.
--
-- Obtain with 'openPingSession' (or scoped via 'withPingSession'), send
-- pings with 'ping', and always release with 'closePingSession'. A
-- session whose ping failed (timeout, mismatch, I/O error) closes its
-- stream immediately and rejects further pings.
--
-- Concurrent 'ping' calls on one session are serialized on 'psLock':
-- exactly one write/echo exchange runs on the stream at a time, so
-- concurrent callers queue instead of interleaving their 32-byte
-- payloads on the wire.
data PingSession = PingSession
  { psStream :: !StreamIO
  , psClosed :: !(IORef Bool)
  , psLock   :: !(MVar ())  -- ^ Held for the duration of one ping exchange
  }

-- | Open a ping stream on the connection and negotiate the protocol.
--
-- The stream is opened through the Switch so it is counted against the
-- peer's stream limits; the reservation is released when the session is
-- closed. On any failure the stream (if opened) is closed before
-- returning.
openPingSession :: Switch -> Connection -> IO (Either PingError PingSession)
openPingSession sw conn = do
  -- A ping is a short probe; go-libp2p opens it with WithAllowLimitedConn.
  streamOrErr <- newStreamAllowingLimited sw conn
  case streamOrErr of
    Left err ->
      pure (Left (PingStreamError ("stream reservation failed: " ++ show err)))
    Right stream -> do
      negotiated <- try (negotiateInitiator stream [pingProtocolId])
      case negotiated of
        Right (Accepted _) -> do
          closedRef <- newIORef False
          lock <- newMVar ()
          pure (Right (PingSession stream closedRef lock))
        Right NoProtocol -> do
          closeQuietly stream
          pure (Left (PingStreamError "remote does not support ping"))
        Left (e :: SomeException) -> do
          closeQuietly stream
          pure (Left (PingStreamError ("ping negotiation failed: " ++ show e)))

-- | Send one ping on the session with the default timeout
-- ('pingTimeoutMicros'). The session's stream is reused across calls.
ping :: PingSession -> IO (Either PingError PingResult)
ping = pingWithTimeout pingTimeoutMicros

-- | Send one ping on the session, waiting at most the given number of
-- microseconds for the echo. On failure the session is closed: a stream
-- whose echo timed out or went wrong cannot be reused, because a late
-- echo would corrupt the next ping.
--
-- The whole exchange runs under the session lock, so concurrent callers
-- are queued one after another on the single stream. The closed check
-- happens under the lock too: a caller queued behind a failed ping sees
-- the session as closed instead of writing into a poisoned stream.
pingWithTimeout :: Int -> PingSession -> IO (Either PingError PingResult)
pingWithTimeout timeoutUs sess = withMVar (psLock sess) $ \() -> do
  closed <- readIORef (psClosed sess)
  if closed
    then pure (Left (PingStreamError "ping session is closed"))
    else do
      result <- pingOnce timeoutUs (psStream sess)
      case result of
        Left err -> do
          closePingSession sess
          pure (Left err)
        ok -> pure ok

-- | One ping exchange on an already-negotiated stream.
pingOnce :: Int -> StreamIO -> IO (Either PingError PingResult)
pingOnce timeoutUs stream = do
  payload <- getRandomBytes pingSize :: IO ByteString
  t0 <- getCurrentTime
  -- try must wrap timeout (not the reverse): an inner try would catch
  -- the Timeout exception itself and misreport it as a stream error.
  outcome <- try $ timeout timeoutUs $ do
    streamWrite stream payload
    either fail pure =<< readExactBounded stream pingSize pingSize
  case outcome of
    Left (e :: SomeException) ->
      pure (Left (PingStreamError ("ping I/O failed: " ++ show e)))
    Right Nothing -> pure (Left PingTimeout)
    Right (Just echo)
      | echo /= payload -> pure (Left PingMismatch)
      | otherwise -> do
          t1 <- getCurrentTime
          pure (Right (PingResult (diffUTCTime t1 t0)))

-- | Close the session's stream (signalling EOF to the responder's echo
-- loop) and release its stream reservation. Idempotent.
closePingSession :: PingSession -> IO ()
closePingSession sess = do
  alreadyClosed <- atomicModifyIORef' (psClosed sess) (\c -> (True, c))
  unless alreadyClosed $ closeQuietly (psStream sess)

-- | Run an action with a ping session, closing it afterwards even if
-- the action throws. Returns Left if the session could not be opened.
withPingSession
  :: Switch
  -> Connection
  -> (PingSession -> IO a)
  -> IO (Either PingError a)
withPingSession sw conn action = do
  opened <- openPingSession sw conn
  case opened of
    Left err -> pure (Left err)
    Right sess -> (Right <$> action sess) `finally` closePingSession sess

-- | Send a single Ping to a remote peer (initiator side).
--
-- Convenience wrapper: opens a ping session, pings once, and closes the
-- stream. For repeated pings to the same peer, use 'withPingSession'
-- to reuse one stream instead of opening one per call.
sendPing :: Switch -> Connection -> IO (Either PingError PingResult)
sendPing sw conn = either Left id <$> withPingSession sw conn ping

-- | Register the Ping handler on the Switch.
--
-- The installed handler shares one 'PingLimiter', so concurrent inbound
-- ping streams are capped at 'maxPingStreamsPerPeer' per remote peer.
registerPingHandler :: Switch -> IO ()
registerPingHandler sw = do
  limiter <- newPingLimiter
  atomically $ do
    protos <- readTVar (swProtocols sw)
    let handler conn stream = handlePingLimited limiter stream (connPeerId conn)
    writeTVar (swProtocols sw) (Map.insert pingProtocolId handler protos)

-- | Close a stream, swallowing any exception (best-effort EOF signal).
closeQuietly :: StreamIO -> IO ()
closeQuietly stream = streamClose stream `catch` \(_ :: SomeException) -> pure ()
