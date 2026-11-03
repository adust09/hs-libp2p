-- | Client-side enforcement of a relay-advertised circuit budget.
--
-- specs/relay/circuit-v2: the relay counts bytes on the relayed
-- connection itself (the byte stream after the hop or stop handshake),
-- separately in each direction, and resets both sides when either
-- direction exceeds @data@ or the circuit has been open for @duration@.
-- A component of 0, or an absent component, is unlimited. An omitted
-- limit means the relay applies none.
--
-- This wrapper charges that same stream. A write that does not fit is
-- not sent. A read never consumes a byte past the cap. Once either
-- budget is exhausted the underlying stream is closed and every later
-- read or write throws 'RelayCircuitExhausted', rather than waiting for
-- the relay's reset to surface as an opaque transport failure.
module LibP2P.NAT.Relay.Limit
  ( RelayCircuitExhausted (..)
  , toRelayCircuitLimit
  , enforceRelayCircuitLimit
  ) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.Async (race)
import Control.Exception (Exception (..), onException, throwIO)
import Control.Monad (unless, when)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef)
import Data.Maybe (fromMaybe)
import Data.Time.Clock.POSIX (POSIXTime, getPOSIXTime)
import Data.Word (Word64, Word8)
import LibP2P.MultistreamSelect.Negotiation (StreamIO (..), closeQuietly)
import LibP2P.NAT.Relay.Message (RelayLimit (..))
import LibP2P.Transport (RelayCircuitLimit (..), relayCircuitIsLimited)

-- | Why a relayed circuit was closed locally.
data RelayCircuitExhausted
  = RelayCircuitDurationExhausted
  | RelayCircuitDataExhausted
  deriving (Eq, Show)

instance Exception RelayCircuitExhausted

data Charge = Charge
  { chRead   :: !Word64
  , chWrite  :: !Word64
  , chReason :: !(Maybe RelayCircuitExhausted)
  }

data ActiveLimit = ActiveLimit
  { alData     :: !(Maybe Word64)
  , alDeadline :: !(Maybe POSIXTime)
  }

-- | Copy a relay protobuf limit into the transport-level budget.
toRelayCircuitLimit :: RelayLimit -> RelayCircuitLimit
toRelayCircuitLimit lim = RelayCircuitLimit
  { rclDurationSeconds = rlDuration lim
  , rclDataBytes = rlData lim
  }

-- | Charge @stream@ against @mLimit@. A missing or inactive budget
-- (every component 0 or absent) is returned unchanged. The duration
-- clock starts when this returns, which is when the hop or stop
-- handshake has completed and the stream has become the circuit.
enforceRelayCircuitLimit :: Maybe RelayCircuitLimit -> StreamIO -> IO StreamIO
enforceRelayCircuitLimit mLimit stream = case mLimit of
  Just lim | relayCircuitIsLimited mLimit -> arm lim stream
  _ -> pure stream

arm :: RelayCircuitLimit -> StreamIO -> IO StreamIO
arm lim stream = do
  now <- getPOSIXTime
  ref <- newIORef Charge { chRead = 0, chWrite = 0, chReason = Nothing }
  pure (wrap ref (activeLimit lim now) stream)

activeLimit :: RelayCircuitLimit -> POSIXTime -> ActiveLimit
activeLimit lim now = ActiveLimit
  { alData = positive (rclDataBytes lim)
  , alDeadline = (now +) . fromIntegral <$> positive (rclDurationSeconds lim)
  }
  where
    positive (Just n) | n > 0 = Just n
    positive _ = Nothing

wrap :: IORef Charge -> ActiveLimit -> StreamIO -> StreamIO
wrap ref lim inner = StreamIO
  { streamWrite = writeLimited ref lim inner
  , streamReadByte = readByteLimited ref lim inner
  , streamReadChunk = readChunkLimited ref lim inner
  , streamClose = closeQuietly inner
  }

writeLimited :: IORef Charge -> ActiveLimit -> StreamIO -> ByteString -> IO ()
writeLimited ref lim inner bs = do
  ensureFresh ref lim inner
  unless (BS.null bs) $ do
    ok <- reserveWrite ref (alData lim) (BS.length bs)
    unless ok (trip ref inner RelayCircuitDataExhausted)
    runBounded ref lim inner (streamWrite inner bs)
      `onException` refundWrite ref (fromIntegral (BS.length bs))

readByteLimited :: IORef Charge -> ActiveLimit -> StreamIO -> IO Word8
readByteLimited ref lim inner = do
  ensureFresh ref lim inner
  claimed <- claimRead ref (alData lim) 1
  when (claimed <= 0) (trip ref inner RelayCircuitDataExhausted)
  runBounded ref lim inner (streamReadByte inner)
    `onException` refundRead ref 1

readChunkLimited :: IORef Charge -> ActiveLimit -> StreamIO -> Int -> IO ByteString
readChunkLimited ref lim inner n
  | n < 1 = pure BS.empty
  | otherwise = do
      ensureFresh ref lim inner
      claimed <- claimRead ref (alData lim) n
      when (claimed <= 0) (trip ref inner RelayCircuitDataExhausted)
      chunk <- runBounded ref lim inner (streamReadChunk inner claimed)
        `onException` refundRead ref (fromIntegral claimed)
      refundUnused claimed chunk
      pure (BS.take claimed chunk)
  where
    refundUnused claimed chunk =
      let extra = claimed - BS.length chunk
      in when (extra > 0) (refundRead ref (fromIntegral extra))

-- | Run an I/O action, failing with the duration error if the deadline
-- passes while it is blocked. @race@ cancels the loser, so a blocked
-- read does not surface later as a transport reset.
runBounded :: IORef Charge -> ActiveLimit -> StreamIO -> IO a -> IO a
runBounded ref lim inner action = case alDeadline lim of
  Nothing -> action
  Just deadline -> do
    result <- race (waitDeadline deadline) action
    case result of
      Left () -> trip ref inner RelayCircuitDurationExhausted
      Right a -> pure a

ensureFresh :: IORef Charge -> ActiveLimit -> StreamIO -> IO ()
ensureFresh ref lim inner = do
  reason <- chReason <$> readIORef ref
  case reason of
    Just stored -> throwIO stored
    Nothing -> case alDeadline lim of
      Just deadline -> do
        now <- getPOSIXTime
        when (now >= deadline) (trip ref inner RelayCircuitDurationExhausted)
      Nothing -> pure ()

trip :: IORef Charge -> StreamIO -> RelayCircuitExhausted -> IO a
trip ref inner reason = do
  stored <- atomicModifyIORef' ref $ \ch ->
    let reason' = fromMaybe reason (chReason ch)
    in (ch { chReason = Just reason' }, reason')
  closeQuietly inner
  throwIO stored

reserveWrite :: IORef Charge -> Maybe Word64 -> Int -> IO Bool
reserveWrite _ Nothing _ = pure True
reserveWrite ref (Just cap) n = atomicModifyIORef' ref $ \ch ->
  let need = fromIntegral n :: Word64
      used = chWrite ch
      fits = used < cap && need <= cap - used
      ch' = if fits then ch { chWrite = used + need } else ch
  in (ch', fits)

claimRead :: IORef Charge -> Maybe Word64 -> Int -> IO Int
claimRead _ Nothing n = pure n
claimRead ref (Just cap) n = atomicModifyIORef' ref $ \ch ->
  let room = if chRead ch >= cap then 0 else cap - chRead ch
      takeN = min (fromIntegral n) room
  in (ch { chRead = chRead ch + takeN }, fromIntegral takeN)

refundWrite :: IORef Charge -> Word64 -> IO ()
refundWrite ref n = atomicModifyIORef' ref $ \ch ->
  (ch { chWrite = chWrite ch - min n (chWrite ch) }, ())

refundRead :: IORef Charge -> Word64 -> IO ()
refundRead ref n = atomicModifyIORef' ref $ \ch ->
  (ch { chRead = chRead ch - min n (chRead ch) }, ())

-- | Block until @deadline@. A duration longer than one 'threadDelay'
-- step (possible on 32-bit 'Int') is waited out in pieces. Cancelled
-- when the I/O it races against finishes first.
waitDeadline :: POSIXTime -> IO ()
waitDeadline deadline = do
  now <- getPOSIXTime
  let remainUs = ceiling ((deadline - now) * 1000000) :: Integer
  when (remainUs > 0) $ do
    let step = min remainUs (toInteger (maxBound :: Int))
    threadDelay (fromInteger step)
    when (step < remainUs) (waitDeadline deadline)
