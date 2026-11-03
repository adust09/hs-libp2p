{-# LANGUAGE OverloadedStrings #-}

-- | libp2p framing over an RTCDataChannel.
module LibP2P.Transport.WebRTC.Stream (
  channelToStreamIO,
  closeOnce,
) where

import Control.Concurrent (MVar, modifyMVar, modifyMVar_, newMVar)
import Control.Exception (SomeException, catch)
import Control.Monad (unless)
import Data.Bits (shiftL, shiftR, (.&.), (.|.))
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Word (Word64)
import Foreign.Ptr (Ptr)
import LibP2P.Core.Varint (decodeUvarint, encodeUvarint)
import LibP2P.MultistreamSelect.Negotiation (StreamIO (..))
import LibP2P.Transport.WebRTC.FFI qualified as FFI

data ChannelReadState = ChannelReadState
  { channelBuffered :: !ByteString
  , channelWireBuffered :: !ByteString
  , channelFinished :: !Bool
  }

channelToStreamIO :: Ptr FFI.CWebRTCChannel -> IO StreamIO
channelToStreamIO channel = do
  state <- newMVar (ChannelReadState BS.empty BS.empty False)
  close <- closeOnce $ do
    FFI.channelSend channel (encodeFlagFrame 0)
      `catch` \(_ :: SomeException) -> pure ()
    FFI.channelClose channel
  pure
    StreamIO
      { streamWrite = mapM_ (FFI.channelSend channel . encodeDataFrame) . chunksOf 1200
      , streamReadByte = BS.head <$> readChannel state channel 1
      , streamReadChunk = readChannel state channel
      , streamClose = close
      }

readChannel :: MVar ChannelReadState -> Ptr FFI.CWebRTCChannel -> Int -> IO ByteString
readChannel stateVar channel requested
  | requested <= 0 = pure BS.empty
  | otherwise = modifyMVar stateVar $ \state -> do
      filled <- fillReadBuffer channel state
      if BS.null (channelBuffered filled)
        then fail "WebRTC data channel closed"
        else do
          let (result, remaining) = BS.splitAt requested (channelBuffered filled)
          pure (filled{channelBuffered = remaining}, result)

fillReadBuffer :: Ptr FFI.CWebRTCChannel -> ChannelReadState -> IO ChannelReadState
fillReadBuffer _ state
  | not (BS.null (channelBuffered state)) || channelFinished state = pure state
fillReadBuffer channel state = do
  received <- receiveFrame channel (channelWireBuffered state)
  case received of
    Nothing -> pure state{channelFinished = True}
    Just (framed, remaining) -> case decodeMessage framed Nothing Nothing of
      Left message -> fail message
      Right (Just payload, _) ->
        pure state{channelBuffered = payload, channelWireBuffered = remaining}
      Right (Nothing, Just 0) -> do
        FFI.channelSend channel (encodeFlagFrame 3)
        pure state{channelWireBuffered = remaining, channelFinished = True}
      Right _ -> fillReadBuffer channel state{channelWireBuffered = remaining}

receiveFrame :: Ptr FFI.CWebRTCChannel -> ByteString -> IO (Maybe (ByteString, ByteString))
receiveFrame channel buffered = case extractFrame buffered of
  Left message -> fail message
  Right (Just result) -> pure (Just result)
  Right Nothing -> do
    received <- FFI.channelReceive channel
    case received of
      Nothing
        | BS.null buffered -> pure Nothing
        | otherwise -> fail "WebRTC stream frame is truncated"
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
    let totalLength = frameLength + fromIntegral prefixLength
    unless (totalLength <= 16384) $ Left "WebRTC stream frame exceeds 16 KiB"
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
