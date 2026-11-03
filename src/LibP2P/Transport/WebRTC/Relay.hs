{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Circuit Relay v2 signaling for standard libp2p WebRTC.
module LibP2P.Transport.WebRTC.Relay (
  STUNServer (..),
  WebRTCConfig (..),
  defaultWebRTCConfig,
  webRTCTransport,
  canDialWebRTC,
) where

import Control.Concurrent.Async (Async, async, cancel, race)
import Control.Concurrent.STM (
  TQueue,
  TVar,
  atomically,
  check,
  newTQueueIO,
  newTVarIO,
  orElse,
  readTQueue,
  readTVar,
  writeTQueue,
  writeTVar,
 )
import Control.Exception (SomeException, catch, onException, throwIO, try)
import Control.Monad (forever, unless, when)
import Data.List (find)
import Data.Map.Strict (Map)
import Data.Map.Strict qualified as Map
import Data.Text qualified as Text
import Data.Word (Word16)
import Foreign.Ptr (Ptr)
import LibP2P.Crypto.PeerId (PeerId (..), peerIdBytes)
import LibP2P.Multiaddr (Multiaddr (..))
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.MultistreamSelect.Negotiation (
  NegotiationResult (..),
  StreamIO (..),
  negotiateInitiator,
 )
import LibP2P.NAT.Relay.Transport (CircuitAddr (..), parseCircuitAddr)
import LibP2P.Switch (setStreamHandler)
import LibP2P.Switch.Connection (newStreamAllowingLimited)
import LibP2P.Switch.Dial (DialOpts (..), dialWith)
import LibP2P.Switch.Types (Connection (..), Switch (..))
import LibP2P.Transport (
  ConnectionEndpoint (..),
  Listener (..),
  NativeMuxer (..),
  RawConnection (..),
  Transport (..),
 )
import LibP2P.Transport.WebRTC.FFI qualified as FFI
import LibP2P.Transport.WebRTC.Signaling (
  SignalingMessage (..),
  readSignalingMessage,
  signalingProtocolId,
  writeSignalingMessage,
 )
import LibP2P.Transport.WebRTC.Stream (channelToStreamIO, closeOnce)

-- | A STUN server used to gather a server-reflexive ICE candidate.
data STUNServer = STUNServer
  { stunHost :: !String
  , stunPort :: !Word16
  }
  deriving (Show, Eq)

-- | Configuration for relay-signaled WebRTC.
data WebRTCConfig = WebRTCConfig
  { webRTCBindAddress :: !String
  , webRTCSTUNServers :: ![STUNServer]
  }
  deriving (Show, Eq)

-- | Host candidates only, bound to an automatically selected IPv4 address.
defaultWebRTCConfig :: WebRTCConfig
defaultWebRTCConfig = WebRTCConfig
  { webRTCBindAddress = "0.0.0.0"
  , webRTCSTUNServers = []
  }

data WebRTCListenerState = WebRTCListenerState
  { wlsQueue :: !(TQueue RawConnection)
  , wlsClosed :: !(TVar Bool)
  , wlsAddress :: !Multiaddr
  }

newtype WebRTCState = WebRTCState (TVar (Map PeerId WebRTCListenerState))

-- | Construct standard relay-signaled WebRTC transport.
webRTCTransport :: Switch -> WebRTCConfig -> IO Transport
webRTCTransport sw config = do
  validateConfig config
  state <- WebRTCState <$> newTVarIO Map.empty
  setStreamHandler sw signalingProtocolId (handleSignaling config state)
  pure
    Transport
      { transportDial = dialSignaled sw config
      , transportDialFrom = \_ -> dialSignaled sw config
      , transportListen = listenSignaled sw state
      , transportCanDial = canDialWebRTC
      }

-- | Match @.../p2p-circuit/webrtc[/p2p/<target>]@ addresses.
canDialWebRTC :: Multiaddr -> Bool
canDialWebRTC = either (const False) (const True) . parseSignaledAddress

data SignaledAddress = SignaledAddress
  { signaledCircuitListen :: !Multiaddr
  , signaledRelayId :: !PeerId
  , signaledTarget :: !(Maybe PeerId)
  }

dialSignaled :: Switch -> WebRTCConfig -> Multiaddr -> IO RawConnection
dialSignaled sw config remoteAddress = do
  parsed <- either fail pure (parseSignaledAddress remoteAddress)
  target <- maybe (fail "WebRTC address has no /p2p target") pure (signaledTarget parsed)
  relayConnection <- dialWith sw signalingDialOpts target [circuitDialAddress parsed target]
    >>= either (fail . ("WebRTC signaling relay dial failed: " <>) . show) pure
  signalingStream <- openSignalingStream sw relayConnection
  connection <- runOffer config signalingStream
    `onException` streamClose signalingStream
  closeQuietly signalingStream
  rawSignaledConnection connection target
    (logicalWebRTCAddress (swLocalPeerId sw)) remoteAddress

signalingDialOpts :: DialOpts
signalingDialOpts = DialOpts
  { doForceDirect = True
  , doUpgradeAsClient = True
  }

listenSignaled :: Switch -> WebRTCState -> Multiaddr -> IO Listener
listenSignaled sw state requested = do
  parsed <- either fail pure (parseSignaledAddress requested)
  when (signaledTarget parsed /= Nothing) $
    fail "WebRTC listen address must not include a target peer"
  circuitTransport <- findCircuitTransport sw (signaledCircuitListen parsed)
  circuitListener <- transportListen circuitTransport (signaledCircuitListen parsed)
  let advertised = appendWebRTC (listenerAddr circuitListener)
  listenerState <- registerWebRTCListener state (signaledRelayId parsed) advertised
  worker <- startCircuitPump circuitListener listenerState
  close <- closeOnce $ do
    unregisterWebRTCListener state (signaledRelayId parsed)
    cancel worker
    listenerClose circuitListener
  pure Listener
    { listenerAccept = acceptWebRTCConnection listenerState
    , listenerClose = close
    , listenerAddr = advertised
    }

startCircuitPump :: Listener -> WebRTCListenerState -> IO (Async ())
startCircuitPump listener listenerState = async $
  (forever $ listenerAccept listener >>= enqueueConnection listenerState)
    `catch` \(_ :: SomeException) -> atomically (writeTVar (wlsClosed listenerState) True)

findCircuitTransport :: Switch -> Multiaddr -> IO Transport
findCircuitTransport sw address = do
  transports <- atomically $ readTVar (swTransports sw)
  maybe (fail "WebRTC requires a registered Circuit Relay transport") pure $
    find (\transport -> transportCanDial transport address) transports

registerWebRTCListener :: WebRTCState -> PeerId -> Multiaddr -> IO WebRTCListenerState
registerWebRTCListener (WebRTCState listenersVar) relayId address = do
  listener <- WebRTCListenerState <$> newTQueueIO <*> newTVarIO False <*> pure address
  registered <- atomically $ do
    listeners <- readTVar listenersVar
    if Map.member relayId listeners
      then pure False
      else writeTVar listenersVar (Map.insert relayId listener listeners) >> pure True
  unless registered $ fail "WebRTC is already listening through this relay"
  pure listener

unregisterWebRTCListener :: WebRTCState -> PeerId -> IO ()
unregisterWebRTCListener (WebRTCState listenersVar) relayId = atomically $ do
  listeners <- readTVar listenersVar
  case Map.lookup relayId listeners of
    Nothing -> pure ()
    Just listener -> do
      writeTVar (wlsClosed listener) True
      writeTVar listenersVar (Map.delete relayId listeners)

acceptWebRTCConnection :: WebRTCListenerState -> IO RawConnection
acceptWebRTCConnection listener = do
  result <- atomically $
    (Just <$> readTQueue (wlsQueue listener))
      `orElse` do
        closed <- readTVar (wlsClosed listener)
        check closed
        pure Nothing
  maybe (fail "WebRTC listener is closed") pure result

enqueueConnection :: WebRTCListenerState -> RawConnection -> IO ()
enqueueConnection listener connection = do
  accepted <- atomically $ do
    closed <- readTVar (wlsClosed listener)
    if closed
      then pure False
      else writeTQueue (wlsQueue listener) connection >> pure True
  unless accepted (rcClose connection)

handleSignaling :: WebRTCConfig -> WebRTCState -> Connection -> StreamIO -> IO ()
handleSignaling config state relayConnection stream = do
  result <- try $ do
    listener <- findWebRTCListener state relayConnection
    connection <- runAnswer config stream
    raw <- rawSignaledConnection connection (connPeerId relayConnection)
      (wlsAddress listener) (logicalWebRTCAddress (connPeerId relayConnection))
    enqueueConnection listener raw
  closeQuietly stream
  case result of
    Left (_ :: SomeException) -> pure ()
    Right () -> pure ()

findWebRTCListener :: WebRTCState -> Connection -> IO WebRTCListenerState
findWebRTCListener (WebRTCState listenersVar) connection = do
  circuit <- either fail pure (parseCircuitAddr (connRemoteAddr connection))
  listeners <- atomically $ readTVar listenersVar
  maybe (fail "no WebRTC listener is registered for the signaling relay") pure $
    Map.lookup (caRelayId circuit) listeners

openSignalingStream :: Switch -> Connection -> IO StreamIO
openSignalingStream sw relayConnection = do
  stream <- newStreamAllowingLimited sw relayConnection
    >>= either (fail . ("WebRTC signaling stream failed: " <>) . show) pure
  negotiated <- negotiateInitiator stream [signalingProtocolId]
  case negotiated of
    Accepted _ -> pure stream
    NoProtocol -> streamClose stream >> fail "peer does not support WebRTC signaling"

runOffer :: WebRTCConfig -> StreamIO -> IO (Ptr FFI.CWebRTCConnection)
runOffer config stream = do
  setup <- createOfferSetup config
  offer <- withSetup setup (FFI.signalingSDP setup)
  withSetup setup $ writeSignalingMessage stream (SDPOffer (Text.pack offer))
  withSetup setup $ sendLocalCandidates setup stream
  answer <- withSetup setup (readUntilAnswer setup stream)
  withSetup setup (FFI.signalingAcceptAnswer setup answer)
  connection <- FFI.signalingStart setup
  awaitSignaledConnection connection stream `onException` FFI.connectionClose connection
  pure connection

runAnswer :: WebRTCConfig -> StreamIO -> IO (Ptr FFI.CWebRTCConnection)
runAnswer config stream = do
  offer <- readRequiredOffer stream
  setup <- createAnswerSetup config offer
  answer <- withSetup setup (FFI.signalingSDP setup)
  withSetup setup $ writeSignalingMessage stream (SDPAnswer (Text.pack answer))
  withSetup setup $ sendLocalCandidates setup stream
  connection <- FFI.signalingStart setup
  awaitSignaledConnection connection stream `onException` FFI.connectionClose connection
  pure connection

withSetup :: Ptr FFI.CWebRTCSignaling -> IO value -> IO value
withSetup setup action = action `onException` FFI.signalingClose setup

createOfferSetup :: WebRTCConfig -> IO (Ptr FFI.CWebRTCSignaling)
createOfferSetup config =
  FFI.signalingOfferNew (webRTCBindAddress config) (renderSTUNServers config)

createAnswerSetup :: WebRTCConfig -> String -> IO (Ptr FFI.CWebRTCSignaling)
createAnswerSetup config =
  FFI.signalingAnswerNew (webRTCBindAddress config) (renderSTUNServers config)

sendLocalCandidates :: Ptr FFI.CWebRTCSignaling -> StreamIO -> IO ()
sendLocalCandidates setup stream = FFI.signalingCandidates setup >>= mapM_ send
 where
  send = writeSignalingMessage stream . ICECandidate . Text.pack

readUntilAnswer :: Ptr FFI.CWebRTCSignaling -> StreamIO -> IO String
readUntilAnswer setup stream = readSignaling stream >>= \case
  SDPAnswer answer -> pure (Text.unpack answer)
  ICECandidate candidate -> do
    FFI.signalingAddCandidate setup (Text.unpack candidate)
    readUntilAnswer setup stream
  SDPOffer _ -> fail "received a second WebRTC SDP offer"

readRequiredOffer :: StreamIO -> IO String
readRequiredOffer stream = readSignaling stream >>= \case
  SDPOffer offer -> pure (Text.unpack offer)
  _ -> fail "first WebRTC signaling message must be an SDP offer"

awaitSignaledConnection :: Ptr FFI.CWebRTCConnection -> StreamIO -> IO ()
awaitSignaledConnection connection stream = do
  let readResult = try (readCandidates connection stream) :: IO (Either SomeException ())
  result <- race (FFI.connectionWaitReady connection) readResult
  case result of
    Left () -> pure ()
    Right (Right ()) -> FFI.connectionWaitReady connection
    Right (Left readError) ->
      FFI.connectionWaitReady connection
        `catch` \(_ :: SomeException) -> throwIO readError

readCandidates :: Ptr FFI.CWebRTCConnection -> StreamIO -> IO ()
readCandidates connection stream = forever $ readSignaling stream >>= \case
  ICECandidate candidate -> FFI.connectionAddCandidate connection (Text.unpack candidate)
  _ -> fail "expected a WebRTC ICE candidate"

readSignaling :: StreamIO -> IO SignalingMessage
readSignaling stream = readSignalingMessage stream >>= either fail pure

rawSignaledConnection :: Ptr FFI.CWebRTCConnection -> PeerId -> Multiaddr -> Multiaddr -> IO RawConnection
rawSignaledConnection connection remotePeer localAddress remoteAddress = do
  close <- closeOnce (FFI.connectionClose connection)
  let native = NativeMuxer
        { nativePeerId = remotePeer
        , nativeSecurity = "/webrtc"
        , nativeMuxerProtocol = "/webrtc"
        , nativeOpenStream = FFI.connectionOpenChannel connection >>= channelToStreamIO
        , nativeAcceptStream = FFI.connectionAcceptChannel connection >>= channelToStreamIO
        , nativeClose = close
        }
  pure RawConnection
    { rcEndpoint = NativeMuxerEndpoint native
    , rcLocalAddr = localAddress
    , rcRemoteAddr = remoteAddress
    , rcClose = close
    , rcRelayLimit = Nothing
    }

parseSignaledAddress :: Multiaddr -> Either String SignaledAddress
parseSignaledAddress (Multiaddr protocols) = case break (== WebRTC) protocols of
  (_, []) -> Left "WebRTC address has no /webrtc component"
  (before, _ : after) -> do
    circuit <- parseCircuitAddr (Multiaddr before)
    target <- case after of
      [] -> Right Nothing
      [P2P peer] -> Right (Just (PeerId peer))
      _ -> Left "WebRTC address must end with at most /p2p/<target>"
    pure SignaledAddress
      { signaledCircuitListen = Multiaddr before
      , signaledRelayId = caRelayId circuit
      , signaledTarget = target
      }

circuitDialAddress :: SignaledAddress -> PeerId -> Multiaddr
circuitDialAddress parsed target = case signaledCircuitListen parsed of
  Multiaddr protocols -> Multiaddr (protocols <> [P2P (peerIdBytes target)])

appendWebRTC :: Multiaddr -> Multiaddr
appendWebRTC (Multiaddr protocols) = Multiaddr (protocols <> [WebRTC])

logicalWebRTCAddress :: PeerId -> Multiaddr
logicalWebRTCAddress peer = Multiaddr [WebRTC, P2P (peerIdBytes peer)]

renderSTUNServers :: WebRTCConfig -> String
renderSTUNServers = unlines . map render . webRTCSTUNServers
 where
  render server = bracketIPv6 (stunHost server) <> ":" <> show (stunPort server)
  bracketIPv6 host@('[' : _) = host
  bracketIPv6 host
    | ':' `elem` host = "[" <> host <> "]"
    | otherwise = host

validateConfig :: WebRTCConfig -> IO ()
validateConfig config = do
  validateText "WebRTC bind address" (webRTCBindAddress config)
  mapM_ (validateText "STUN host" . stunHost) (webRTCSTUNServers config)
  when (any (null . stunHost) (webRTCSTUNServers config)) $
    fail "STUN host must not be empty"

validateText :: String -> String -> IO ()
validateText label value = when (any (`elem` ['\0', '\n', '\r']) value) $
  fail (label <> " contains an invalid control character")

closeQuietly :: StreamIO -> IO ()
closeQuietly stream = streamClose stream `catch` \(_ :: SomeException) -> pure ()
