{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE InterruptibleFFI #-}

module LibP2P.Transport.WebRTC.FFI (
  CWebRTCListener,
  CWebRTCConnection,
  CWebRTCChannel,
  lastError,
  listenerNew,
  listenerPort,
  listenerFingerprint,
  listenerAccept,
  listenerClose,
  dial,
  connectionLocalFingerprint,
  connectionRemoteFingerprint,
  connectionIP,
  connectionPort,
  connectionNoiseChannel,
  connectionOpenChannel,
  connectionAcceptChannel,
  channelSend,
  channelReceive,
  channelClose,
  connectionClose,
) where

import Control.Concurrent (threadDelay)
import Control.Exception (bracket)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Unsafe qualified as BSU
import Data.Word (Word16, Word8)
import Foreign.C.String (CString, peekCString, withCString)
import Foreign.C.Types (CInt (..), CSize (..), CUChar (..), CUShort (..))
import Foreign.Marshal.Alloc (alloca, allocaBytes)
import Foreign.Marshal.Array (allocaArray, peekArray)
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.Storable (peek, poke)

data CWebRTCListener
data CWebRTCConnection
data CWebRTCChannel

foreign import ccall unsafe "hs_webrtc_last_error"
  cLastError :: IO CString

foreign import ccall safe "hs_webrtc_listener_new"
  cListenerNew :: CString -> CUShort -> IO (Ptr CWebRTCListener)

foreign import ccall unsafe "hs_webrtc_listener_port"
  cListenerPort :: Ptr CWebRTCListener -> IO CUShort

foreign import ccall unsafe "hs_webrtc_listener_fingerprint"
  cListenerFingerprint :: Ptr CWebRTCListener -> Ptr Word8 -> CSize -> IO CInt

foreign import ccall unsafe "hs_webrtc_listener_accept"
  cListenerAccept :: Ptr CWebRTCListener -> Ptr CInt -> IO (Ptr CWebRTCConnection)

foreign import ccall safe "hs_webrtc_listener_close"
  cListenerClose :: Ptr CWebRTCListener -> IO ()

foreign import ccall interruptible "hs_webrtc_dial"
  cDial :: CString -> CUShort -> Ptr Word8 -> CSize -> CUChar -> IO (Ptr CWebRTCConnection)

foreign import ccall unsafe "hs_webrtc_connection_local_fingerprint"
  cConnectionLocalFingerprint :: Ptr CWebRTCConnection -> Ptr Word8 -> CSize -> IO CInt

foreign import ccall unsafe "hs_webrtc_connection_remote_fingerprint"
  cConnectionRemoteFingerprint :: Ptr CWebRTCConnection -> Ptr Word8 -> CSize -> IO CInt

foreign import ccall unsafe "hs_webrtc_connection_ip"
  cConnectionIP :: Ptr CWebRTCConnection -> CInt -> CString -> CSize -> IO CInt

foreign import ccall unsafe "hs_webrtc_connection_port"
  cConnectionPort :: Ptr CWebRTCConnection -> CInt -> IO CUShort

foreign import ccall unsafe "hs_webrtc_connection_noise_channel"
  cConnectionNoiseChannel :: Ptr CWebRTCConnection -> IO (Ptr CWebRTCChannel)

foreign import ccall interruptible "hs_webrtc_connection_open_channel"
  cConnectionOpenChannel :: Ptr CWebRTCConnection -> IO (Ptr CWebRTCChannel)

foreign import ccall interruptible "hs_webrtc_connection_accept_channel"
  cConnectionAcceptChannel :: Ptr CWebRTCConnection -> IO (Ptr CWebRTCChannel)

foreign import ccall interruptible "hs_webrtc_channel_send"
  cChannelSend :: Ptr CWebRTCChannel -> Ptr Word8 -> CSize -> IO CInt

foreign import ccall interruptible "hs_webrtc_channel_recv"
  cChannelReceive :: Ptr CWebRTCChannel -> Ptr (Ptr Word8) -> Ptr CSize -> IO CInt

foreign import ccall unsafe "hs_webrtc_bytes_free"
  cBytesFree :: Ptr Word8 -> CSize -> IO ()

foreign import ccall safe "hs_webrtc_channel_close"
  cChannelClose :: Ptr CWebRTCChannel -> IO ()

foreign import ccall safe "hs_webrtc_connection_close"
  cConnectionClose :: Ptr CWebRTCConnection -> IO ()

lastError :: IO String
lastError = cLastError >>= peekCString

listenerNew :: String -> Word16 -> IO (Ptr CWebRTCListener)
listenerNew ip port = withCString ip $ \ipPtr ->
  requirePointer "create WebRTC listener" =<< cListenerNew ipPtr (fromIntegral port)

listenerPort :: Ptr CWebRTCListener -> IO Word16
listenerPort listener = fromIntegral <$> cListenerPort listener

listenerFingerprint :: Ptr CWebRTCListener -> IO ByteString
listenerFingerprint listener = readFingerprint (cListenerFingerprint listener)

-- Poll in Haskell so async cancellation can stop a listener accept loop.
listenerAccept :: Ptr CWebRTCListener -> IO (Ptr CWebRTCConnection)
listenerAccept listener = alloca $ \statusPtr -> do
  pointer <- cListenerAccept listener statusPtr
  status <- peek statusPtr
  case status of
    0 -> requirePointer "accept WebRTC connection" pointer
    1 -> threadDelay 2000 >> listenerAccept listener
    _ -> lastError >>= fail . ("accept WebRTC connection: " <>)

listenerClose :: Ptr CWebRTCListener -> IO ()
listenerClose = cListenerClose

dial :: String -> Word16 -> ByteString -> Word8 -> IO (Ptr CWebRTCConnection)
dial ip port fingerprint version = withCString ip $ \ipPtr ->
  BSU.unsafeUseAsCStringLen fingerprint $ \(fingerprintPtr, fingerprintLength) ->
    requirePointer "dial WebRTC connection"
      =<< cDial
        ipPtr
        (fromIntegral port)
        (castBytes fingerprintPtr)
        (fromIntegral fingerprintLength)
        (fromIntegral version)

connectionLocalFingerprint :: Ptr CWebRTCConnection -> IO ByteString
connectionLocalFingerprint connection =
  readFingerprint (cConnectionLocalFingerprint connection)

connectionRemoteFingerprint :: Ptr CWebRTCConnection -> IO ByteString
connectionRemoteFingerprint connection =
  readFingerprint (cConnectionRemoteFingerprint connection)

connectionIP :: Ptr CWebRTCConnection -> Bool -> IO String
connectionIP connection remote = allocaBytes 64 $ \output -> do
  result <- cConnectionIP connection (boolFlag remote) output 64
  requireSuccess "read WebRTC connection address" result
  peekCString output

connectionPort :: Ptr CWebRTCConnection -> Bool -> IO Word16
connectionPort connection remote =
  fromIntegral <$> cConnectionPort connection (boolFlag remote)

connectionNoiseChannel :: Ptr CWebRTCConnection -> IO (Ptr CWebRTCChannel)
connectionNoiseChannel connection =
  requirePointer "open WebRTC Noise channel" =<< cConnectionNoiseChannel connection

connectionOpenChannel :: Ptr CWebRTCConnection -> IO (Ptr CWebRTCChannel)
connectionOpenChannel connection =
  requirePointer "open WebRTC data channel" =<< cConnectionOpenChannel connection

connectionAcceptChannel :: Ptr CWebRTCConnection -> IO (Ptr CWebRTCChannel)
connectionAcceptChannel connection =
  requirePointer "accept WebRTC data channel" =<< cConnectionAcceptChannel connection

channelSend :: Ptr CWebRTCChannel -> ByteString -> IO ()
channelSend channel bytes =
  BSU.unsafeUseAsCStringLen bytes $ \(bytesPtr, byteCount) -> do
    result <- cChannelSend channel (castBytes bytesPtr) (fromIntegral byteCount)
    requireSuccess "send WebRTC data" result

channelReceive :: Ptr CWebRTCChannel -> IO (Maybe ByteString)
channelReceive channel = alloca $ \outputPtr -> alloca $ \lengthPtr -> do
  poke outputPtr nullPtr
  poke lengthPtr 0
  result <- cChannelReceive channel outputPtr lengthPtr
  case result of
    0 -> do
      output <- peek outputPtr
      byteCount <- peek lengthPtr
      Just
        <$> bracket
          (pure output)
          (\pointer -> cBytesFree pointer byteCount)
          (\pointer -> BS.pack <$> peekArray (fromIntegral byteCount) pointer)
    1 -> pure Nothing
    _ -> lastError >>= fail . ("receive WebRTC data: " <>)

channelClose :: Ptr CWebRTCChannel -> IO ()
channelClose = cChannelClose

connectionClose :: Ptr CWebRTCConnection -> IO ()
connectionClose = cConnectionClose

readFingerprint :: (Ptr Word8 -> CSize -> IO CInt) -> IO ByteString
readFingerprint action = allocaArray 32 $ \output -> do
  result <- action output 32
  requireSuccess "read WebRTC fingerprint" result
  BS.pack <$> peekArray (fromIntegral result) output

requirePointer :: String -> Ptr value -> IO (Ptr value)
requirePointer action pointer
  | pointer /= nullPtr = pure pointer
  | otherwise = lastError >>= fail . ((action <> ": ") <>)

boolFlag :: Bool -> CInt
boolFlag True = 1
boolFlag False = 0

requireSuccess :: String -> CInt -> IO ()
requireSuccess action result
  | result >= 0 = pure ()
  | otherwise = lastError >>= fail . ((action <> ": ") <>)

castBytes :: Ptr a -> Ptr Word8
castBytes = castPtr
