-- | Yamux session management: create, openStream, acceptStream, ping, goaway.
--
-- Implements the session-level Yamux protocol per HashiCorp yamux spec.md.
-- The session manages a collection of multiplexed streams over a single
-- underlying transport connection.
--
-- Two background loops run per session:
--   recvLoop: reads 12-byte headers from transport, dispatches to streams
--   sendLoop: dequeues from ysessSendCh, writes to transport
module LibP2P.Yamux.Session
  ( newSession
  , newSessionWith
  , closeSession
  , openStream
  , acceptStream
  , ping
  , sendGoAway
  , recvLoop
  , sendLoop
  , acceptBacklog
  ) where

import Control.Concurrent.STM
import Control.Exception (finally)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Data.Word (Word32)
import LibP2P.Yamux.Frame
import LibP2P.Yamux.Types
import Numeric.Natural (Natural)

-- | Maximum number of inbound streams buffered while the application
-- is not accepting (go-yamux AcceptBacklog). The spec requires this
-- buffer to be bounded to mitigate DoS; excess SYNs are reset.
acceptBacklog :: Natural
acceptBacklog = 256

-- | Create a new Yamux session over a transport connection.
-- Client uses odd stream IDs starting at 1, server uses even starting at 2.
newSession :: SessionRole -> (ByteString -> IO ()) -> (Int -> IO ByteString) -> IO YamuxSession
newSession = newSessionWith defaultYamuxConfig

-- | Like 'newSession', with an explicit configuration.
newSessionWith :: YamuxConfig -> SessionRole -> (ByteString -> IO ()) -> (Int -> IO ByteString) -> IO YamuxSession
newSessionWith config role writeFn readFn = do
  let startId = case role of
        RoleClient -> 1
        RoleServer -> 2
  nextId <- newTVarIO startId
  streams <- newTVarIO Map.empty
  acceptCh <- newTBQueueIO acceptBacklog
  sendCh <- newTQueueIO
  shutdown <- newTVarIO False
  remoteGoAway <- newTVarIO Nothing
  pings <- newTVarIO Map.empty
  nextPingId <- newTVarIO 1
  pure
    YamuxSession
      { ysessConfig = config
      , ysessRole = role
      , ysessNextStreamId = nextId
      , ysessStreams = streams
      , ysessAcceptCh = acceptCh
      , ysessSendCh = sendCh
      , ysessShutdown = shutdown
      , ysessRemoteGoAway = remoteGoAway
      , ysessPings = pings
      , ysessNextPingId = nextPingId
      , ysessWrite = writeFn
      , ysessRead = readFn
      }

-- | Gracefully close the session by sending GoAway Normal.
closeSession :: YamuxSession -> IO ()
closeSession sess = sendGoAway sess GoAwayNormal

-- | Open a new outbound stream. Allocates the next stream ID and sends SYN.
-- Returns YamuxSessionShutdown after a local GoAway, or YamuxGoAway with
-- the received code after a remote GoAway.
openStream :: YamuxSession -> IO (Either YamuxError YamuxStream)
openStream sess = do
  -- Check shutdown state
  status <- atomically $ do
    shut <- readTVar (ysessShutdown sess)
    remote <- readTVar (ysessRemoteGoAway sess)
    pure $ case (shut, remote) of
      (True, _) -> Left YamuxSessionShutdown
      (False, Just code) -> Left (YamuxGoAway code)
      (False, Nothing) -> Right ()
  case status of
    Left err -> pure (Left err)
    Right () -> do
      -- Allocate stream ID (atomically increment by 2)
      sid <- atomically $ do
        nextId <- readTVar (ysessNextStreamId sess)
        writeTVar (ysessNextStreamId sess) (nextId + 2)
        pure nextId
      -- Create stream in SYNSent state
      stream <- newStream sess sid StreamSYNSent
      -- Register stream
      atomically $ modifyTVar' (ysessStreams sess) (Map.insert sid stream)
      -- Send SYN frame (Data frame with SYN flag, no payload)
      let hdr =
            YamuxHeader
              { yhVersion = 0
              , yhType = FrameData
              , yhFlags = defaultFlags {flagSYN = True}
              , yhStreamId = sid
              , yhLength = 0
              }
      atomically $ writeTQueue (ysessSendCh sess) (hdr, BS.empty)
      pure (Right stream)

-- | Accept an inbound stream. Blocks until a remote SYN arrives.
-- Returns YamuxSessionShutdown if the session is shut down.
acceptStream :: YamuxSession -> IO (Either YamuxError YamuxStream)
acceptStream sess = do
  stream <- atomically $ readTBQueue (ysessAcceptCh sess)
  -- Send ACK (WindowUpdate frame with ACK flag)
  let hdr =
        YamuxHeader
          { yhVersion = 0
          , yhType = FrameWindowUpdate
          , yhFlags = defaultFlags {flagACK = True}
          , yhStreamId = ysStreamId stream
          , yhLength = 0
          }
  atomically $ writeTQueue (ysessSendCh sess) (hdr, BS.empty)
  -- Transition to Established only from SYNReceived. The remote may have
  -- already half-closed (FIN) before we accepted; that state must survive.
  atomically $ do
    st <- readTVar (ysState stream)
    case st of
      StreamSYNReceived -> writeTVar (ysState stream) StreamEstablished
      _ -> pure ()
  pure (Right stream)

-- | Send a Ping and wait for the ACK response.
-- Ping uses StreamID 0 and the Length field carries an opaque value.
ping :: YamuxSession -> IO (Either YamuxError ())
ping sess = do
  (pingId, waiter) <- atomically $ do
    pid <- readTVar (ysessNextPingId sess)
    writeTVar (ysessNextPingId sess) (pid + 1)
    w <- newEmptyTMVar
    modifyTVar' (ysessPings sess) (Map.insert pid w)
    pure (pid, w)
  -- Send Ping SYN frame
  let hdr =
        YamuxHeader
          { yhVersion = 0
          , yhType = FramePing
          , yhFlags = defaultFlags {flagSYN = True}
          , yhStreamId = 0
          , yhLength = pingId
          }
  atomically $ writeTQueue (ysessSendCh sess) (hdr, BS.empty)
  -- Wait for ACK (or a session-failure notification)
  result <- atomically $ takeTMVar waiter
  -- Cleanup
  atomically $ modifyTVar' (ysessPings sess) (Map.delete pingId)
  pure result

-- | Send a GoAway frame with the specified error code.
-- Sets ysessShutdown to True so no new streams can be opened.
sendGoAway :: YamuxSession -> GoAwayCode -> IO ()
sendGoAway sess code = do
  atomically $ writeTVar (ysessShutdown sess) True
  let errCode = goAwayCodeToWord32 code
  let hdr =
        YamuxHeader
          { yhVersion = 0
          , yhType = FrameGoAway
          , yhFlags = defaultFlags
          , yhStreamId = 0
          , yhLength = errCode
          }
  atomically $ writeTQueue (ysessSendCh sess) (hdr, BS.empty)

-- | Receive loop: reads 12-byte headers from transport and dispatches frames.
-- This loop runs until the transport connection is closed or an error occurs.
--
-- Whenever the loop terminates -- transport EOF or error (ysessRead
-- throws), a fatal protocol error, or cancellation -- the session is
-- torn down via failSession so that no reader, writer or ping waiter
-- is left blocked forever on a session that can no longer make
-- progress.
recvLoop :: YamuxSession -> IO ()
recvLoop sess = go `finally` failSession sess
  where
    go = do
      -- Read 12-byte header
      headerBytes <- ysessRead sess headerSize
      case decodeHeader headerBytes of
        -- Malformed header (unknown frame type): tell the peer why we
        -- are leaving before terminating, as go-yamux does
        Left _err -> sendGoAway sess GoAwayProtocol
        Right hdr ->
          -- Verify version
          if yhVersion hdr /= 0
            then sendGoAway sess GoAwayProtocol
            else do
              continue <- dispatchFrame sess hdr
              when continue go

-- | Tear down the session once the receive loop can no longer make
-- progress (transport EOF mid-frame, transport error, or a fatal
-- protocol error). Mirrors go-yamux, which closes every stream with
-- the session error on exit: new streams are refused, every registered
-- stream is reset so blocked readers and writers observe an error
-- instead of hanging, and every pending ping fails with
-- YamuxSessionShutdown.
failSession :: YamuxSession -> IO ()
failSession sess = atomically $ do
  writeTVar (ysessShutdown sess) True
  streams <- readTVar (ysessStreams sess)
  mapM_ (\s -> writeTVar (ysState s) StreamReset) (Map.elems streams)
  writeTVar (ysessStreams sess) Map.empty
  pings <- readTVar (ysessPings sess)
  mapM_ (\w -> tryPutTMVar w (Left YamuxSessionShutdown)) (Map.elems pings)
  writeTVar (ysessPings sess) Map.empty

-- | Dispatch a decoded frame to the appropriate handler.
-- Returns False when a fatal protocol error occurred and the receive
-- loop must terminate (go-yamux treats these as session-fatal).
dispatchFrame :: YamuxSession -> YamuxHeader -> IO Bool
dispatchFrame sess hdr = case yhType hdr of
  FrameData -> handleDataFrame sess hdr
  FrameWindowUpdate -> handleWindowUpdate sess hdr
  FramePing -> handlePing sess hdr >> pure True
  FrameGoAway -> handleGoAway sess hdr >> pure True

-- | Handle a Data frame: validate declared length, read payload, manage
-- stream state, deliver data. Returns False on fatal protocol error.
handleDataFrame :: YamuxSession -> YamuxHeader -> IO Bool
handleDataFrame sess hdr = do
  let sid = yhStreamId hdr
      flags = yhFlags hdr
      declaredLen = yhLength hdr
  -- Handle SYN first so the flow-control check below sees the new stream
  synOk <-
    if flagSYN flags
      then acceptInboundSYN sess sid
      else pure True
  if not synOk
    then do
      sendGoAway sess GoAwayProtocol
      pure False
    else do
      -- Flow control: validate the declared length against the receive
      -- window BEFORE reading the payload off the transport. A frame that
      -- overruns the window is a protocol error and must not cause the
      -- session to buffer attacker-controlled amounts of memory.
      reserved <- reserveRecvWindow sess sid declaredLen
      if not reserved
        then do
          sendGoAway sess GoAwayProtocol
          pure False
        else do
          payload <-
            if declaredLen > 0
              then ysessRead sess (fromIntegral declaredLen)
              else pure BS.empty
          -- Handle ACK flag: transition SYNSent -> Established
          when (flagACK flags) $ handleAckFlag sess sid
          -- Deliver payload to stream buffer (window already reserved)
          when (BS.length payload > 0) $ do
            mStream <- lookupStream sess sid
            case mStream of
              Just stream -> atomically $ writeTQueue (ysRecvBuf stream) payload
              Nothing -> pure () -- unknown stream: discard
          -- Handle FIN flag
          when (flagFIN flags) $ applyRemoteFin sess sid
          -- Handle RST flag
          when (flagRST flags) $ applyRemoteRst sess sid
          pure True

-- | Handle a WindowUpdate frame: update send window, manage stream
-- lifecycle. Returns False on fatal protocol error.
handleWindowUpdate :: YamuxSession -> YamuxHeader -> IO Bool
handleWindowUpdate sess hdr = do
  let sid = yhStreamId hdr
      flags = yhFlags hdr
      delta = yhLength hdr
  -- Handle SYN flag: create new inbound stream (with parity + duplicate validation)
  synOk <-
    if flagSYN flags
      then acceptInboundSYN sess sid
      else pure True
  if not synOk
    then do
      sendGoAway sess GoAwayProtocol
      pure False
    else do
      -- Handle ACK flag
      when (flagACK flags) $ handleAckFlag sess sid
      -- Update send window
      when (delta > 0) $ do
        mStream <- lookupStream sess sid
        case mStream of
          Just stream -> atomically $ do
            w <- readTVar (ysSendWindow stream)
            writeTVar (ysSendWindow stream) (w + delta)
          Nothing -> pure ()
      -- Handle FIN flag
      when (flagFIN flags) $ applyRemoteFin sess sid
      -- Handle RST flag
      when (flagRST flags) $ applyRemoteRst sess sid
      pure True

-- | Look up a stream by ID.
lookupStream :: YamuxSession -> Word32 -> IO (Maybe YamuxStream)
lookupStream sess sid = Map.lookup sid <$> readTVarIO (ysessStreams sess)

-- | Validate and register an inbound SYN (parity + duplicate check).
-- Returns False on protocol error; the caller sends GoAway and stops.
-- When the accept backlog is full the SYN is rejected with RST instead
-- of being buffered (spec.md, ACK backlog: the buffer MUST be bounded);
-- that is not a protocol error, so the session stays alive.
acceptInboundSYN :: YamuxSession -> Word32 -> IO Bool
acceptInboundSYN sess sid = do
  valid <- atomically $ validateInboundSYN sess sid
  if not valid
    then pure False
    else do
      stream <- newStream sess sid StreamSYNReceived
      atomically $ do
        full <- isFullTBQueue (ysessAcceptCh sess)
        if full
          then writeTQueue (ysessSendCh sess) (rstHeader sid, BS.empty)
          else do
            modifyTVar' (ysessStreams sess) (Map.insert sid stream)
            writeTBQueue (ysessAcceptCh sess) stream
      pure True

-- | Data frame carrying only the RST flag for the given stream.
rstHeader :: Word32 -> YamuxHeader
rstHeader sid =
  YamuxHeader
    { yhVersion = 0
    , yhType = FrameData
    , yhFlags = defaultFlags {flagRST = True}
    , yhStreamId = sid
    , yhLength = 0
    }

-- | Reserve receive window for a declared Data-frame length before the
-- payload is read off the transport. Returns False on a flow-control
-- violation (declared length exceeds the stream's receive window or the
-- absolute maxStreamWindowSize bound); the session must then terminate.
reserveRecvWindow :: YamuxSession -> Word32 -> Word32 -> IO Bool
reserveRecvWindow sess sid len
  | len == 0 = pure True
  | len > maxStreamWindowSize = pure False
  | otherwise = atomically $ do
      streams <- readTVar (ysessStreams sess)
      case Map.lookup sid streams of
        -- Unknown stream: payload is read and discarded, bounded by the
        -- maxStreamWindowSize check above (defence in depth)
        Nothing -> pure True
        Just stream -> do
          w <- readTVar (ysRecvWindow stream)
          if len > w
            then pure False
            else do
              writeTVar (ysRecvWindow stream) (w - len)
              pure True

-- | ACK flag: transition SYNSent -> Established.
handleAckFlag :: YamuxSession -> Word32 -> IO ()
handleAckFlag sess sid = do
  mStream <- lookupStream sess sid
  case mStream of
    Just stream -> atomically $ do
      st <- readTVar (ysState stream)
      case st of
        StreamSYNSent -> writeTVar (ysState stream) StreamEstablished
        _ -> pure ()
    Nothing -> pure ()

-- | Shared FIN transition (spec.md, Closing a stream). The remote may
-- half-close from any pre-close state: nothing in the spec ties FIN to
-- the local ACK state, and go-libp2p pipelines SYN, data and FIN in one
-- burst, so SYNSent/SYNReceived must transition like Established.
applyRemoteFin :: YamuxSession -> Word32 -> IO ()
applyRemoteFin sess sid = do
  mStream <- lookupStream sess sid
  case mStream of
    Just stream -> atomically $ do
      st <- readTVar (ysState stream)
      case st of
        StreamSYNSent -> writeTVar (ysState stream) StreamRemoteClose
        StreamSYNReceived -> writeTVar (ysState stream) StreamRemoteClose
        StreamEstablished -> writeTVar (ysState stream) StreamRemoteClose
        StreamLocalClose -> do
          -- Both sides FIN'd: the stream is dead, reclaim its map slot
          writeTVar (ysState stream) StreamClosed
          modifyTVar' (ysessStreams sess) (Map.delete sid)
        _ -> pure ()
    Nothing -> pure ()

-- | Shared RST transition: any state -> Reset. A reset stream is dead,
-- so its map slot is reclaimed in the same transaction; the application
-- still holds the handle and observes StreamReset through it.
applyRemoteRst :: YamuxSession -> Word32 -> IO ()
applyRemoteRst sess sid = do
  mStream <- lookupStream sess sid
  case mStream of
    Just stream -> atomically $ do
      writeTVar (ysState stream) StreamReset
      modifyTVar' (ysessStreams sess) (Map.delete sid)
    Nothing -> pure ()

-- | Handle a Ping frame (StreamID must be 0).
-- SYN: echo back with ACK flag and same opaque value.
-- ACK: resolve the matching pending ping.
handlePing :: YamuxSession -> YamuxHeader -> IO ()
handlePing sess hdr
  | flagSYN (yhFlags hdr) = do
      -- Echo back Ping with ACK
      let respHdr =
            YamuxHeader
              { yhVersion = 0
              , yhType = FramePing
              , yhFlags = defaultFlags {flagACK = True}
              , yhStreamId = 0
              , yhLength = yhLength hdr -- echo opaque value
              }
      atomically $ writeTQueue (ysessSendCh sess) (respHdr, BS.empty)
  | flagACK (yhFlags hdr) = do
      -- Resolve pending ping
      let pingId = yhLength hdr
      atomically $ do
        pMap <- readTVar (ysessPings sess)
        case Map.lookup pingId pMap of
          Just waiter -> putTMVar waiter (Right ())
          Nothing -> pure ()
  | otherwise = pure ()

-- | Handle a GoAway frame (StreamID must be 0).
-- Preserve the received error code so callers can distinguish a clean
-- shutdown (0x00) from a protocol (0x01) or internal (0x02) error.
-- A code outside the spec-defined range is itself a protocol violation
-- and is recorded as GoAwayProtocol.
handleGoAway :: YamuxSession -> YamuxHeader -> IO ()
handleGoAway sess hdr = do
  let code = case word32ToGoAwayCode (yhLength hdr) of
        Just c -> c
        Nothing -> GoAwayProtocol
  atomically $ writeTVar (ysessRemoteGoAway sess) (Just code)

-- | Send loop: dequeues frames from ysessSendCh and writes to transport.
sendLoop :: YamuxSession -> IO ()
sendLoop sess = go
  where
    go = do
      (hdr, payload) <- atomically $ readTQueue (ysessSendCh sess)
      ysessWrite sess (encodeHeader hdr)
      when (BS.length payload > 0) $ ysessWrite sess payload
      go

-- | Create a new YamuxStream with the given initial state.
newStream :: YamuxSession -> Word32 -> StreamState -> IO YamuxStream
newStream sess sid initState = do
  stateVar <- newTVarIO initState
  sendWin <- newTVarIO initialWindowSize
  recvWin <- newTVarIO initialWindowSize
  recvBuf <- newTQueueIO
  sendNotify <- newEmptyTMVarIO
  pure
    YamuxStream
      { ysStreamId = sid
      , ysState = stateVar
      , ysSendWindow = sendWin
      , ysRecvWindow = recvWin
      , ysRecvBuf = recvBuf
      , ysSendNotify = sendNotify
      , ysSession = sess
      }

-- | Validate an inbound SYN stream ID for parity and uniqueness.
-- Returns True if valid, False if protocol error (caller must send GoAway).
-- Remote peers must use the opposite parity: client expects even, server expects odd.
validateInboundSYN :: YamuxSession -> Word32 -> STM Bool
validateInboundSYN sess sid = do
  let validParity = case ysessRole sess of
        -- Server expects odd IDs (from client)
        RoleServer -> odd sid
        -- Client expects even IDs (from server)
        RoleClient -> even sid
  if sid == 0 || not validParity
    then pure False
    else do
      streams <- readTVar (ysessStreams sess)
      pure (not (Map.member sid streams))

-- | Helper: execute action when condition is True.
when :: Bool -> IO () -> IO ()
when True action = action
when False _ = pure ()
