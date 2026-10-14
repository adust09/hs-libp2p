-- | Yamux stream operations: read, write, close, reset.
--
-- Implements per-stream data transfer with flow control
-- per HashiCorp yamux spec.md §Data/WindowUpdate/Stream Close.
module LibP2P.Yamux.Stream
  ( streamWrite
  , streamRead
  , streamReadRetained
  , streamClose
  , streamReset
  , releaseReceiveBuffer
  ) where

import Control.Concurrent.STM
import Control.Exception (mask_)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import LibP2P.Switch.ResourceManager (MemoryAccount (..))
import LibP2P.Yamux.Frame
import LibP2P.Yamux.Types

-- | Reclaim a dead stream's slot in the session map (STM so callers
-- can combine it with the terminal state transition atomically).
unregisterStream :: YamuxStream -> STM ()
unregisterStream stream =
  modifyTVar' (ysessStreams (ysSession stream)) (Map.delete (ysStreamId stream))

-- | Write data to a stream. Blocks when send window is 0.
-- Writable states: SYNSent (optimistic), Established, RemoteClose.
-- Returns YamuxStreamClosed on LocalClose/Closed.
-- Returns YamuxStreamReset on Reset.
streamWrite :: YamuxStream -> ByteString -> IO (Either YamuxError ())
streamWrite stream payload
  | BS.null payload = pure (Right ())
  | otherwise = do
      st <- readTVarIO (ysState stream)
      case st of
        StreamClosed -> pure (Left YamuxStreamClosed)
        StreamLocalClose -> pure (Left YamuxStreamClosed)
        StreamReset -> pure (Left YamuxStreamReset)
        _ -> writeChunked stream payload

-- | Write payload in chunks respecting the send window.
-- Uses STM retry to block when window is 0 — STM automatically watches
-- ysSendWindow and re-evaluates when handleWindowUpdate writes to it.
writeChunked :: YamuxStream -> ByteString -> IO (Either YamuxError ())
writeChunked stream payload
  | BS.null payload = pure (Right ())
  | otherwise = do
      -- Wait for available send window (blocks via STM retry if 0)
      result <- atomically $ do
        st <- readTVar (ysState stream)
        case st of
          StreamReset -> pure (Left YamuxStreamReset)
          StreamClosed -> pure (Left YamuxStreamClosed)
          _ -> do
            window <- readTVar (ysSendWindow stream)
            if window == 0
              then retry -- blocks until ysSendWindow changes
              else do
                let chunkSize = min (fromIntegral window) (BS.length payload)
                    chunk = BS.take chunkSize payload
                    hdr = YamuxHeader
                      { yhVersion = 0
                      , yhType = FrameData
                      , yhFlags = defaultFlags
                      , yhStreamId = ysStreamId stream
                      , yhLength = fromIntegral chunkSize
                      }
                queued <- enqueueDataFrame
                  (ysSession stream) (ysMemoryAccount stream) hdr chunk
                case queued of
                  Left err -> pure (Left (YamuxResourceLimit err))
                  Right _ -> do
                    writeTVar (ysSendWindow stream)
                      (window - fromIntegral chunkSize)
                    pure (Right chunk)
      case result of
        Left err -> pure (Left err)
        Right chunk ->
          writeChunked stream (BS.drop (BS.length chunk) payload)

-- | Read data and transfer ownership to the caller.
streamRead :: YamuxStream -> IO (Either YamuxError ByteString)
streamRead stream = mask_ $ do
  result <- streamReadRetained stream
  case result of
    Right payload -> do
      atomically $ maRelease (ysMemoryAccount stream) (BS.length payload)
      pure (Right payload)
    Left err -> pure (Left err)

-- | Read data while retaining its memory charge. The StreamIO adapter uses
-- this to keep partially-consumed chunks accounted until its buffer drains.
streamReadRetained :: YamuxStream -> IO (Either YamuxError ByteString)
streamReadRetained stream = mask_ $ do
  result <- atomically $ do
    mData <- tryReadTQueue (ysRecvBuf stream)
    case mData of
      Just payload -> pure (Right payload)
      Nothing -> do
        state <- readTVar (ysState stream)
        case state of
          StreamClosed -> pure (Left YamuxStreamClosed)
          StreamReset -> pure (Left YamuxStreamReset)
          StreamRemoteClose -> pure (Left YamuxStreamClosed)
          _ -> retry
  case result of
    Right payload -> replenishWindow stream payload >> pure (Right payload)
    Left err -> pure (Left err)

replenishWindow :: YamuxStream -> ByteString -> IO ()
replenishWindow stream payload = atomically $ do
  let consumed = fromIntegral (BS.length payload)
      hdr = YamuxHeader
        { yhVersion = 0
        , yhType = FrameWindowUpdate
        , yhFlags = defaultFlags
        , yhStreamId = ysStreamId stream
        , yhLength = consumed
        }
  enqueueFrame (ysSession stream) hdr BS.empty
  modifyTVar' (ysRecvWindow stream) (+ consumed)

-- | Half-close the stream by sending FIN flag.
-- Only valid in Established or RemoteClose states.
streamClose :: YamuxStream -> IO (Either YamuxError ())
streamClose stream = do
  result <- atomically $ do
    st <- readTVar (ysState stream)
    case st of
      StreamEstablished -> do
        writeTVar (ysState stream) StreamLocalClose
        pure (Right ())
      StreamRemoteClose -> do
        -- Both sides FIN'd: the stream is dead, reclaim its map slot
        writeTVar (ysState stream) StreamClosed
        unregisterStream stream
        maClose (ysMemoryAccount stream)
        pure (Right ())
      StreamSYNSent -> do
        writeTVar (ysState stream) StreamLocalClose
        pure (Right ())
      StreamSYNReceived -> do
        writeTVar (ysState stream) StreamLocalClose
        pure (Right ())
      StreamClosed -> pure (Left YamuxStreamClosed)
      StreamLocalClose -> pure (Left YamuxStreamClosed)
      StreamReset -> pure (Left YamuxStreamReset)
  case result of
    Right () -> do
      -- Send FIN frame
      let hdr =
            YamuxHeader
              { yhVersion = 0
              , yhType = FrameData
              , yhFlags = defaultFlags {flagFIN = True}
              , yhStreamId = ysStreamId stream
              , yhLength = 0
              }
      let sess = ysSession stream
      atomically $ enqueueFrame sess hdr BS.empty
      pure (Right ())
    Left err -> pure (Left err)

releaseReceiveBuffer :: YamuxStream -> STM ()
releaseReceiveBuffer stream = do
  payload <- tryReadTQueue (ysRecvBuf stream)
  case payload of
    Nothing -> pure ()
    Just bytes -> do
      maRelease (ysMemoryAccount stream) (BS.length bytes)
      releaseReceiveBuffer stream

-- | Reset the stream by sending RST flag.
streamReset :: YamuxStream -> IO ()
streamReset stream = do
  atomically $ do
    writeTVar (ysState stream) StreamReset
    unregisterStream stream
    releaseReceiveBuffer stream
    maClose (ysMemoryAccount stream)
  -- Send RST frame
  let hdr =
        YamuxHeader
          { yhVersion = 0
          , yhType = FrameData
          , yhFlags = defaultFlags {flagRST = True}
          , yhStreamId = ysStreamId stream
          , yhLength = 0
          }
  let sess = ysSession stream
  atomically $ enqueueFrame sess hdr BS.empty
