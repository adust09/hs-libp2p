{-# LANGUAGE OverloadedStrings #-}

-- | libp2p framing over an RTCDataChannel.
module LibP2P.Transport.WebRTC.Stream (
  ChannelIO (..),
  channelToStreamIO,
  closeOnce,
) where

import Control.Concurrent (MVar, modifyMVar, modifyMVar_, newMVar, withMVar)
import Control.Concurrent.Async (Async, async, wait, waitCatch, withAsync)
import Control.Concurrent.STM
import Control.Exception
  ( Exception
  , IOException
  , SomeException
  , catch
  , displayException
  , finally
  , fromException
  , mask
  , onException
  , throwIO
  )
import Control.Monad (unless, void, when)
import Data.Bits (shiftL, shiftR, (.&.), (.|.))
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Maybe (isNothing)
import Data.Sequence (Seq, ViewL (..), (<|), (|>))
import qualified Data.Sequence as Seq
import Data.Word (Word64)
import System.IO.Error (eofErrorType, ioeGetErrorString, mkIOError)
import LibP2P.Core.Varint (decodeUvarint, encodeUvarint)
import LibP2P.MultistreamSelect.Negotiation (StreamIO (..))
import System.Timeout (timeout)

-- | The adapter owns the channel. Shutdown must unblock I/O without freeing it.
-- Final close releases the handle after receives and sends have stopped.
data ChannelIO = ChannelIO
  { dcSend :: ByteString -> IO ()
  , dcReceive :: IO (Maybe ByteString)
  , dcShutdown :: IO ()
  , dcClose :: IO ()
  }

data WebRTCStreamError
  = WebRTCStreamReset
  | WebRTCStopSending
  | WebRTCWriteClosed
  | WebRTCChannelFailed
  | WebRTCFrameError String
  deriving (Eq, Show)

instance Exception WebRTCStreamError

streamErrorText :: WebRTCStreamError -> String
streamErrorText err = case err of
  WebRTCStreamReset -> "WebRTC stream reset"
  WebRTCStopSending -> "WebRTC peer stopped receiving"
  WebRTCWriteClosed -> "WebRTC write side closed"
  WebRTCChannelFailed -> "WebRTC channel failed"
  WebRTCFrameError message -> message

streamIOException :: WebRTCStreamError -> IOException
streamIOException err = userError (streamErrorText err)

-- Keep the diagnostic text of the original failure, whether it was an
-- IOException from the channel or a framing error raised here.
failureText :: SomeException -> String
failureText exception
  | Just ioException <- fromException exception :: Maybe IOException =
      ioeGetErrorString ioException
  | Just streamError <- fromException exception :: Maybe WebRTCStreamError =
      streamErrorText streamError
  | otherwise = displayException exception


data ReceiveState = Receiving | ReceivedFIN | ReceiveReset | ReceiveFailed WebRTCStreamError
  deriving (Eq)

data SendState = Sending | SentFIN | ReceivedFINAck | SendStopped
  deriving (Eq)

data ChannelState = ChannelState
  { channelReceiveState :: !ReceiveState
  , channelSendState :: !SendState
  , channelPhysicalClosed :: !Bool
  , channelBuffered :: !(Seq ByteString)
  , channelBufferedSize :: !Int
  }

data ChannelRuntime = ChannelRuntime
  { crChannel :: !ChannelIO
  , crState :: !(TVar ChannelState)
  , crWriteLock :: !(MVar ())
  , crLifetime :: !(MVar Bool)
  , crShutdownSent :: !(MVar Bool)
  }

-- | Close writes with FIN, waiting at most the given microseconds for FIN_ACK.
-- Reads remain usable until remote FIN; only the receive worker frees the handle.
channelToStreamIO :: Int -> ChannelIO -> IO StreamIO
channelToStreamIO closeTimeoutMicros channel = mask $ \restore -> do
  when (closeTimeoutMicros <= 0) $ fail "WebRTC close timeout must be positive"
  state <- newTVarIO (ChannelState Receiving Sending False Seq.empty 0)
  runtime <- ChannelRuntime channel state <$> newMVar () <*> newMVar True <*> newMVar False
  worker <- async $
    (restore (receiveLoop runtime BS.empty) `catch` recordFailure runtime)
      `finally` finishChannel runtime
  close <- closeOnce $ closeWrite runtime worker closeTimeoutMicros
  pure StreamIO
    { streamWrite = mapM_ (writeData runtime) . chunksOf 1200
    , streamReadByte = BS.head <$> readChannel state 1
    , streamReadChunk = readChannel state
    , streamClose = close
    }

readChannel :: TVar ChannelState -> Int -> IO ByteString
readChannel stateVar requested
  | requested <= 0 = pure BS.empty
  | otherwise = atomically $ do
      state <- readTVar stateVar
      case channelReceiveState state of
        ReceiveReset -> throwSTM (streamIOException WebRTCStreamReset)
        ReceiveFailed err -> throwSTM (streamIOException err)
        _ -> case Seq.viewl (channelBuffered state) of
          bytes :< rest -> do
            let (result, remaining) = BS.splitAt requested bytes
                buffered = if BS.null remaining then rest else remaining <| rest
            writeTVar stateVar state
              { channelBuffered = buffered
              , channelBufferedSize = channelBufferedSize state - BS.length result
              }
            pure result
          EmptyL
            | channelReceiveState state == Receiving && not (channelPhysicalClosed state) -> retry
            | otherwise -> throwSTM (mkIOError eofErrorType "WebRTC stream ended" Nothing Nothing)

writeData :: ChannelRuntime -> ByteString -> IO ()
writeData runtime bytes = withMVar (crWriteLock runtime) $ \_ -> do
  atomically $ do
    state <- readTVar (crState runtime)
    case channelSendState state of
      SendStopped -> throwSTM (streamIOException WebRTCStopSending)
      Sending | not (channelPhysicalClosed state) -> pure ()
      _ -> throwSTM (streamIOException WebRTCWriteClosed)
  dcSend (crChannel runtime) (encodeDataFrame bytes)
    `onException` shutdownChannel runtime

sendFIN :: ChannelRuntime -> IO ()
sendFIN runtime = withMVar (crWriteLock runtime) $ \_ -> do
  send <- atomically $ do
    state <- readTVar (crState runtime)
    if channelPhysicalClosed state || channelSendState state /= Sending
      then pure False
      else do
        writeTVar (crState runtime) state { channelSendState = SentFIN }
        pure True
  when send $ dcSend (crChannel runtime) (encodeFlagFrame 0)

-- Keep the deadline outside foreign send calls so it can shut them down before joining.
closeWrite :: ChannelRuntime -> Async () -> Int -> IO ()
closeWrite runtime worker closeTimeoutMicros =
  withAsync (sendFIN runtime >> awaitAcknowledgement) $ \closing -> do
    result <- timeout closeTimeoutMicros (wait closing)
      `onException` shutdownChannel runtime
    when (isNothing result) $ do
      shutdownChannel runtime
      void $ waitCatch worker
  where
    awaitAcknowledgement = atomically $ do
      state <- readTVar (crState runtime)
      check (channelPhysicalClosed state || channelSendState state /= SentFIN)

receiveLoop :: ChannelRuntime -> ByteString -> IO ()
receiveLoop runtime buffered = do
  closed <- channelPhysicalClosed <$> readTVarIO (crState runtime)
  unless closed $ do
    received <- receiveFrame (crChannel runtime) buffered
    case received of
      Nothing -> pure ()
      Just (framed, remaining) -> do
        decoded <- either (throwIO . WebRTCFrameError) pure (decodeMessage framed Nothing Nothing)
        accepted <- atomically $ applyMessage (crState runtime) decoded
        when (accepted && snd decoded == Just 0) $ acknowledgeFIN runtime
        state <- readTVarIO (crState runtime)
        unless (channelPhysicalClosed state || bothHalvesFinished state) $
          receiveLoop runtime remaining

-- Payload and FIN become visible in the same transaction: EOF cannot overtake data.
applyMessage :: TVar ChannelState -> (Maybe ByteString, Maybe Word64) -> STM Bool
applyMessage stateVar (payload, flag) = do
  state <- readTVar stateVar
  if channelPhysicalClosed state then pure False else do
    let updated = applyFlag flag state
        dataAllowed = channelReceiveState state == Receiving && flag /= Just 2
        bytes = if dataAllowed then maybe BS.empty id payload else BS.empty
        total = channelBufferedSize updated + BS.length bytes
    check (total <= 256 * 1024)
    writeTVar stateVar updated
      { channelBuffered = if BS.null bytes then channelBuffered updated else channelBuffered updated |> bytes
      , channelBufferedSize = total
      }
    pure True

applyFlag :: Maybe Word64 -> ChannelState -> ChannelState
applyFlag (Just 0) state
  | channelReceiveState state == Receiving = state { channelReceiveState = ReceivedFIN }
applyFlag (Just 1) state
  | channelSendState state `elem` [Sending, SentFIN] = state { channelSendState = SendStopped }
applyFlag (Just 2) state
  | channelReceiveState state == Receiving = state
      { channelReceiveState = ReceiveReset, channelBuffered = Seq.empty, channelBufferedSize = 0 }
applyFlag (Just 3) state
  | channelSendState state == SentFIN = state { channelSendState = ReceivedFINAck }
applyFlag _ state = state

acknowledgeFIN :: ChannelRuntime -> IO ()
acknowledgeFIN runtime = withMVar (crWriteLock runtime) $ \_ -> do
  closed <- channelPhysicalClosed <$> readTVarIO (crState runtime)
  unless closed $ dcSend (crChannel runtime) (encodeFlagFrame 3)

bothHalvesFinished :: ChannelState -> Bool
bothHalvesFinished state =
  channelReceiveState state /= Receiving
    && channelSendState state `elem` [ReceivedFINAck, SendStopped]

-- Shutdown may run alongside a blocked send or receive, but never after free.
shutdownChannel :: ChannelRuntime -> IO ()
shutdownChannel runtime = do
  first <- modifyMVar (crShutdownSent runtime) $ \sent -> pure (True, not sent)
  when first $ withMVar (crLifetime runtime) $ \alive -> when alive $ do
    shutdown <- atomically $ do
      state <- readTVar (crState runtime)
      writeTVar (crState runtime) (markClosed state)
      pure (not (channelPhysicalClosed state))
    when shutdown $ dcShutdown (crChannel runtime)

-- Only the receive worker calls this, after leaving its last raw receive.
finishChannel :: ChannelRuntime -> IO ()
finishChannel runtime = withMVar (crWriteLock runtime) $ \_ -> do
  alive <- modifyMVar (crLifetime runtime) $ \owned -> pure (False, owned)
  atomically $ modifyTVar' (crState runtime) markClosed
  when alive $ dcClose (crChannel runtime)

markClosed :: ChannelState -> ChannelState
markClosed state = state
  { channelPhysicalClosed = True
  , channelReceiveState = case channelReceiveState state of
      Receiving -> ReceivedFIN
      other -> other
  }

-- Preserve the underlying failure text; late failures after FIN stay silent.
recordFailure :: ChannelRuntime -> SomeException -> IO ()
recordFailure runtime exception = atomically $ modifyTVar' (crState runtime) $ \state ->
  if channelPhysicalClosed state || channelReceiveState state /= Receiving then state else state
    { channelReceiveState = ReceiveFailed (WebRTCFrameError (failureText exception)) }

receiveFrame :: ChannelIO -> ByteString -> IO (Maybe (ByteString, ByteString))
receiveFrame channel buffered = case extractFrame buffered of
  Left message -> throwIO (WebRTCFrameError message)
  Right (Just result) -> pure (Just result)
  Right Nothing -> do
    received <- dcReceive channel
    case received of
      Nothing
        | BS.null buffered -> pure Nothing
        | otherwise -> throwIO (WebRTCFrameError "WebRTC stream frame is truncated")
      Just bytes -> receiveFrame channel (buffered <> bytes)

encodeDataFrame :: ByteString -> ByteString
encodeDataFrame payload = frame $
  BS.singleton 0x12 <> encodeUvarint (fromIntegral (BS.length payload)) <> payload

encodeFlagFrame :: Word64 -> ByteString
encodeFlagFrame flag = frame (BS.singleton 0x08 <> encodeUvarint flag)

frame :: ByteString -> ByteString
frame message = encodeUvarint (fromIntegral (BS.length message)) <> message

extractFrame :: ByteString -> Either String (Maybe (ByteString, ByteString))
extractFrame input = case decodeFrameLength input of
  Nothing -> Right Nothing
  Just (Left message) -> Left message
  Just (Right (frameLength, prefixLength)) -> do
    unless (frameLength <= 16384 - fromIntegral prefixLength) $
      Left "WebRTC stream frame exceeds 16 KiB"
    let byteCount = fromIntegral frameLength
        frameEnd = prefixLength + byteCount
    if BS.length input < frameEnd
      then Right Nothing
      else Right $ Just
        ( BS.take byteCount (BS.drop prefixLength input)
        , BS.drop frameEnd input
        )

decodeFrameLength :: ByteString -> Maybe (Either String (Word64, Int))
decodeFrameLength = go 0 0 0 . BS.unpack
 where
  go _ _ _ [] = Nothing
  go value shift count (byte : rest)
    | count >= 9 && byte > 1 = Just (Left "WebRTC stream frame length overflows")
    | byte .&. 0x80 == 0 =
        Just (Right (value .|. (fromIntegral byte `shiftL` shift), count + 1))
    | count >= 9 = Just (Left "WebRTC stream frame length is too long")
    | otherwise =
        go (value .|. (fromIntegral (byte .&. 0x7f) `shiftL` shift)) (shift + 7) (count + 1) rest

decodeMessage :: ByteString -> Maybe ByteString -> Maybe Word64 -> Either String (Maybe ByteString, Maybe Word64)
decodeMessage input payload flag
  | BS.null input = Right (payload, flag)
  | otherwise = do
      (tag, rest) <- decodeUvarint input
      case (tag `shiftR` 3, tag .&. 0x7) of
        (1, 0) -> do
          (value, remaining) <- decodeUvarint rest
          decodeMessage remaining payload (Just value)
        (2, 2) -> do
          (size, bytes) <- decodeUvarint rest
          unless (size <= fromIntegral (BS.length bytes)) $
            Left "WebRTC stream message is truncated"
          let byteCount = fromIntegral size
              (value, remaining) = BS.splitAt byteCount bytes
          decodeMessage remaining (Just value) flag
        (_, wireType) -> skipProtobufField wireType rest >>= \remaining ->
          decodeMessage remaining payload flag

skipProtobufField :: Word64 -> ByteString -> Either String ByteString
skipProtobufField 0 input = snd <$> decodeUvarint input
skipProtobufField 1 input = skipFixed 8 input
skipProtobufField 2 input = do
  (size, bytes) <- decodeUvarint input
  if size > fromIntegral (BS.length bytes)
    then Left "WebRTC stream message is truncated"
    else skipFixed (fromIntegral size) bytes
skipProtobufField 5 input = skipFixed 4 input
skipProtobufField _ _ = Left "WebRTC stream message uses an unsupported wire type"

skipFixed :: Int -> ByteString -> Either String ByteString
skipFixed size input
  | BS.length input < size = Left "WebRTC stream message is truncated"
  | otherwise = Right (BS.drop size input)

chunksOf :: Int -> ByteString -> [ByteString]
chunksOf size bytes
  | BS.null bytes = []
  | otherwise = let (chunk, rest) = BS.splitAt size bytes in chunk : chunksOf size rest

closeOnce :: IO () -> IO (IO ())
closeOnce action = do
  closed <- newMVar False
  pure $ modifyMVar_ closed $ \alreadyClosed ->
    if alreadyClosed then pure True else action >> pure True
