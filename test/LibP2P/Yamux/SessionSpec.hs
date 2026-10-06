module LibP2P.Yamux.SessionSpec (spec) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.Async (async, concurrently, concurrently_, poll, wait, withAsync)
import Control.Concurrent.STM
import Control.Monad (replicateM_)
import qualified Data.ByteString as BS
import Data.Maybe (isNothing)
import Data.Word (Word32)
import System.Timeout (timeout)
import LibP2P.Yamux.Frame
import LibP2P.Yamux.HostilePeer
import LibP2P.Yamux.Session
import LibP2P.Yamux.Stream (streamClose, streamRead, streamReset, streamWrite)
import LibP2P.Yamux.Types
import Test.Hspec

-- | Create an in-memory transport pair for testing.
mkMemoryTransportPair ::
  IO
    ( (BS.ByteString -> IO (), Int -> IO BS.ByteString)
    , (BS.ByteString -> IO (), Int -> IO BS.ByteString)
    )
mkMemoryTransportPair = do
  qAtoB <- newTQueueIO
  qBtoA <- newTQueueIO
  let writeTo q bs = mapM_ (atomically . writeTQueue q) (BS.unpack bs)
      readFrom q n = BS.pack <$> mapM (const (atomically (readTQueue q))) [1 .. n]
  pure ((writeTo qAtoB, readFrom qBtoA), (writeTo qBtoA, readFrom qAtoB))

-- | Create a session pair and run action with all background loops running.
withSessionPair :: ((YamuxSession, YamuxSession) -> IO a) -> IO a
withSessionPair action = do
  ((writeA, readA), (writeB, readB)) <- mkMemoryTransportPair
  client <- newSession RoleClient writeA readA
  server <- newSession RoleServer writeB readB
  withAsync (sendLoop client) $ \_ ->
    withAsync (recvLoop client) $ \_ ->
      withAsync (sendLoop server) $ \_ ->
        withAsync (recvLoop server) $ \_ ->
          action (client, server)

spec :: Spec
spec = do
  describe "Stream ID allocation" $ do
    it "client session allocates odd IDs: 1, 3, 5" $ do
      withSessionPair $ \(client, server) -> do
        ids <- concurrently
          ( do
              Right s1 <- openStream client
              Right s2 <- openStream client
              Right s3 <- openStream client
              pure [ysStreamId s1, ysStreamId s2, ysStreamId s3]
          )
          ( do
              Right _ <- acceptStream server
              Right _ <- acceptStream server
              Right _ <- acceptStream server
              pure ()
          )
        fst ids `shouldBe` [1, 3, 5]

    it "server session allocates even IDs: 2, 4, 6" $ do
      withSessionPair $ \(client, server) -> do
        ids <- concurrently
          ( do
              Right _ <- acceptStream client
              Right _ <- acceptStream client
              Right _ <- acceptStream client
              pure ()
          )
          ( do
              Right s1 <- openStream server
              Right s2 <- openStream server
              Right s3 <- openStream server
              pure [ysStreamId s1, ysStreamId s2, ysStreamId s3]
          )
        snd ids `shouldBe` [2, 4, 6]

  describe "Stream open/accept" $ do
    it "openStream sends Data frame with SYN flag" $ do
      withSessionPair $ \(client, server) -> do
        Right _stream <- openStream client
        Right serverStream <- acceptStream server
        ysStreamId serverStream `shouldBe` 1

    it "acceptStream returns stream on remote SYN" $ do
      withSessionPair $ \(client, server) -> do
        (clientStream, serverStream) <-
          concurrently
            (openStream client >>= \(Right s) -> pure s)
            (acceptStream server >>= \(Right s) -> pure s)
        ysStreamId clientStream `shouldBe` 1
        ysStreamId serverStream `shouldBe` 1

  describe "Data exchange" $ do
    it "bidirectional data exchange: client -> server, server -> client" $ do
      withSessionPair $ \(client, server) -> do
        (clientStream, serverStream) <-
          concurrently
            (openStream client >>= \(Right s) -> pure s)
            (acceptStream server >>= \(Right s) -> pure s)
        atomically $ do
          st <- readTVar (ysState clientStream)
          check (st == StreamEstablished)
        -- Client sends to server
        Right () <- streamWrite clientStream "hello"
        Right received <- streamRead serverStream
        received `shouldBe` "hello"
        -- Server sends to client
        Right () <- streamWrite serverStream "world"
        Right received2 <- streamRead clientStream
        received2 `shouldBe` "world"

    it "optimistic sending: data piggybacked on SYN frame" $ do
      withSessionPair $ \(client, server) -> do
        Right clientStream <- openStream client
        st <- readTVarIO (ysState clientStream)
        st `shouldBe` StreamSYNSent
        Right () <- streamWrite clientStream "early"
        -- Server accepts and reads
        Right serverStream <- acceptStream server
        Right received <- streamRead serverStream
        received `shouldBe` "early"

  describe "Stream rejection" $ do
    it "RST response to SYN -> streamWrite returns Reset" $ do
      withSessionPair $ \(client, server) -> do
        Right clientStream <- openStream client
        Right serverStream <- acceptStream server
        streamReset serverStream
        atomically $ do
          st <- readTVar (ysState clientStream)
          check (st == StreamReset)
        result <- streamWrite clientStream "data"
        result `shouldBe` Left YamuxStreamReset

  describe "Concurrent streams" $ do
    it "4 concurrent streams on single session" $ do
      withSessionPair $ \(client, server) -> do
        let numStreams = 4 :: Int
        concurrently_
          ( do
              streams <- mapM (\_ -> openStream client >>= \(Right s) -> pure s) [1 .. numStreams]
              mapM_
                ( \(i, s) -> do
                    atomically $ do
                      st <- readTVar (ysState s)
                      check (st == StreamEstablished)
                    Right () <- streamWrite s (BS.pack [fromIntegral i])
                    pure ()
                )
                (zip [1 :: Int ..] streams)
          )
          ( do
              streams <- mapM (\_ -> acceptStream server >>= \(Right s) -> pure s) [1 .. numStreams]
              mapM_
                ( \s -> do
                    Right _ <- streamRead s
                    pure ()
                )
                streams
          )

  describe "Ping" $ do
    it "Ping SYN -> ACK response received" $ do
      withSessionPair $ \(client, _server) -> do
        result <- ping client
        result `shouldBe` Right ()

    it "echoes the exact opaque value in the Ping ACK" $
      withHostilePeer RoleServer $ \hp -> do
        injectFrame hp (YamuxHeader 0 FramePing (defaultFlags {flagSYN = True}) 0 0xDEADBEEF) BS.empty
        (ack, _) <- expectFrame hp
        yhType ack `shouldBe` FramePing
        flagACK (yhFlags ack) `shouldBe` True
        yhStreamId ack `shouldBe` 0
        yhLength ack `shouldBe` 0xDEADBEEF

    it "sends Ping SYN on StreamID 0 and resolves on the matching ACK" $
      withHostilePeer RoleClient $ \hp -> do
        pingA <- async (ping (hpSession hp))
        (syn, _) <- expectFrame hp
        yhType syn `shouldBe` FramePing
        flagSYN (yhFlags syn) `shouldBe` True
        yhStreamId syn `shouldBe` 0
        injectFrame hp (YamuxHeader 0 FramePing (defaultFlags {flagACK = True}) 0 (yhLength syn)) BS.empty
        result <- timeout 1000000 (wait pingA)
        result `shouldBe` Just (Right ())

    it "does not resolve a pending ping from a mismatched opaque value" $
      withHostilePeer RoleClient $ \hp -> do
        pingA <- async (ping (hpSession hp))
        (syn, _) <- expectFrame hp
        let opaque = yhLength syn
        injectFrame hp (YamuxHeader 0 FramePing (defaultFlags {flagACK = True}) 0 (opaque + 100)) BS.empty
        threadDelay 100000
        stillPending <- poll pingA
        stillPending `shouldSatisfy` isNothing
        injectFrame hp (YamuxHeader 0 FramePing (defaultFlags {flagACK = True}) 0 opaque) BS.empty
        result <- timeout 1000000 (wait pingA)
        result `shouldBe` Just (Right ())

    it "ignores an unsolicited Ping ACK" $
      withHostilePeer RoleServer $ \hp -> do
        injectFrame hp (YamuxHeader 0 FramePing (defaultFlags {flagACK = True}) 0 99) BS.empty
        -- Session must survive: a subsequent Ping SYN still gets echoed
        injectFrame hp (YamuxHeader 0 FramePing (defaultFlags {flagSYN = True}) 0 7) BS.empty
        (ack, _) <- expectFrame hp
        yhType ack `shouldBe` FramePing
        yhLength ack `shouldBe` 7

    it "fails with YamuxPingTimeout when no ACK arrives in time, and drops the waiter" $
      withHostilePeerWithConfig (pingTimeoutConfig 100000) RoleClient $ \hp -> do
        result <- timeout 1000000 (ping (hpSession hp))
        result `shouldBe` Just (Left YamuxPingTimeout)
        waiters <- readTVarIO (ysessPings (hpSession hp))
        null waiters `shouldBe` True

    it "ignores an ACK that arrives after the timeout" $
      withHostilePeerWithConfig (pingTimeoutConfig 100000) RoleClient $ \hp -> do
        Left YamuxPingTimeout <- ping (hpSession hp)
        (syn, _) <- expectFrame hp
        injectFrame hp (pingAck (yhLength syn)) BS.empty
        -- The late ACK is dropped and the session keeps working
        pingA <- async (ping (hpSession hp))
        (syn2, _) <- expectFrame hp
        injectFrame hp (pingAck (yhLength syn2)) BS.empty
        result <- timeout 1000000 (wait pingA)
        result `shouldBe` Just (Right ())

    it "fails with YamuxPingTimeout when the SYN cannot be written in time" $ do
      -- The transport write never returns, so sendLoop never finishes
      -- writing the SYN
      gate <- newEmptyTMVarIO :: IO (TMVar ())
      sess <-
        newSessionWith (pingTimeoutConfig 100000) RoleClient
          (\_ -> atomically (takeTMVar gate)) (\_ -> pure BS.empty)
      withAsync (sendLoop sess) $ \_ -> do
        result <- timeout 1000000 (ping sess)
        result `shouldBe` Just (Left YamuxPingTimeout)
        waiters <- readTVarIO (ysessPings sess)
        null waiters `shouldBe` True

    it "times the ACK from the write, so waiting to write does not count against it" $ do
      -- A 400ms limit, 250ms to write the SYN, then 250ms more for the
      -- ACK: 500ms in all, yet each wait stays within its own limit
      ((writeA, readA), (writeB, _)) <- mkMemoryTransportPair
      gate <- newEmptyTMVarIO
      let gatedWrite bs = atomically (takeTMVar gate) >> writeA bs
      sess <- newSessionWith (pingTimeoutConfig 400000) RoleClient gatedWrite readA
      withAsync (sendLoop sess) $ \_ ->
        withAsync (recvLoop sess) $ \_ ->
          withAsync (ping sess) $ \pingA -> do
            threadDelay 250000
            atomically $ putTMVar gate ()
            threadDelay 250000
            -- The session's first ping id is 1
            writeB (encodeHeader (pingAck 1))
            result <- timeout 1000000 (wait pingA)
            result `shouldBe` Just (Right ())

  describe "Keepalive" $ do
    it "sends a Ping only after an interval with no frame received" $
      withHostilePeerWithConfig keepaliveConfig RoleClient $ \hp ->
        withAsync (keepaliveLoop (hpSession hp)) $ \_ -> do
          -- Feed a frame every half interval for longer than a full
          -- interval: the peer is never silent, so no Ping goes out. An
          -- unsolicited Ping ACK is ignored by the session, so it draws
          -- no reply of its own.
          replicateM_ 3 $ do
            injectFrame hp (pingAck 99) BS.empty
            noFrame <- timeout 50000 (hpNextFrame hp)
            fmap fst noFrame `shouldBe` Nothing
          -- Stop feeding: a Ping follows once a full interval passes
          -- with nothing received
          (syn, _) <- expectFrame hp
          yhType syn `shouldBe` FramePing
          flagSYN (yhFlags syn) `shouldBe` True
          yhStreamId syn `shouldBe` 0

    it "keeps pinging while the Pings are answered" $
      withHostilePeerWithConfig keepaliveConfig RoleClient $ \hp ->
        withAsync (keepaliveLoop (hpSession hp)) $ \_ -> do
          (first, _) <- expectFrame hp
          yhType first `shouldBe` FramePing
          injectFrame hp (pingAck (yhLength first)) BS.empty
          (second, _) <- expectFrame hp
          yhType second `shouldBe` FramePing
          yhLength second `shouldNotBe` yhLength first

    it "fails the session and unblocks readers when a Ping goes unanswered" $
      withHostilePeerWithConfig keepaliveConfig RoleClient $ \hp -> do
        Right stream <- openStream (hpSession hp)
        _ <- expectFrame hp
        withAsync (streamRead stream) $ \readerA ->
          withAsync (keepaliveLoop (hpSession hp)) $ \keepaliveA -> do
            keepaliveRes <- timeout 1000000 (wait keepaliveA)
            keepaliveRes `shouldBe` Just (Left YamuxPingTimeout)
            readerRes <- timeout 1000000 (wait readerA)
            readerRes `shouldBe` Just (Left YamuxStreamReset)
        openRes <- openStream (hpSession hp)
        shouldBeLeft YamuxSessionShutdown openRes

    it "stops without pinging once closeSession sent a GoAway" $
      withHostilePeerWithConfig keepaliveConfig RoleClient $ \hp ->
        withAsync (keepaliveLoop (hpSession hp)) $ \keepaliveA -> do
          closeSession (hpSession hp)
          keepaliveRes <- timeout 500000 (wait keepaliveA)
          keepaliveRes `shouldBe` Just (Right ())
          (goAway, _) <- expectFrame hp
          yhType goAway `shouldBe` FrameGoAway
          expectNoFrame hp

    it "stops without pinging once the peer sent a GoAway" $
      withHostilePeerWithConfig keepaliveConfig RoleClient $ \hp -> do
        injectFrame hp (YamuxHeader 0 FrameGoAway defaultFlags 0 0) BS.empty
        awaitRemoteGoAway (hpSession hp) GoAwayNormal
        withAsync (keepaliveLoop (hpSession hp)) $ \keepaliveA -> do
          keepaliveRes <- timeout 500000 (wait keepaliveA)
          keepaliveRes `shouldBe` Just (Right ())
          expectNoFrame hp

    it "does nothing when keepalive is disabled" $
      withHostilePeerWithConfig keepaliveConfig {ycEnableKeepAlive = False} RoleClient $ \hp -> do
        keepaliveRes <- timeout 1000000 (keepaliveLoop (hpSession hp))
        keepaliveRes `shouldBe` Just (Right ())
        expectNoFrame hp

  describe "Frame counters" $ do
    it "numbers queued frames consecutively from 1, including unnumbered enqueues" $ do
      sess <- newSession RoleClient (\_ -> pure ()) (\_ -> pure BS.empty)
      let pingSyn i = YamuxHeader 0 FramePing (defaultFlags {flagSYN = True}) 0 i
      first <- atomically $ enqueueFrameNumbered sess (pingSyn 1) BS.empty
      atomically $ enqueueFrame sess (pingSyn 2) BS.empty
      third <- atomically $ enqueueFrameNumbered sess (pingSyn 3) BS.empty
      (first, third) `shouldBe` (1, 3)

    it "awaitFrameWritten returns only once sendLoop has written the frame" $ do
      -- The transport write blocks until the gate opens, holding sendLoop
      -- in the middle of writing the frame
      gate <- newEmptyTMVarIO
      sess <- newSession RoleClient (\_ -> atomically (takeTMVar gate)) (\_ -> pure BS.empty)
      withAsync (sendLoop sess) $ \_ -> do
        n <- atomically $ enqueueFrameNumbered sess (YamuxHeader 0 FramePing (defaultFlags {flagSYN = True}) 0 1) BS.empty
        early <- timeout 100000 (atomically (awaitFrameWritten sess n))
        early `shouldBe` Nothing
        atomically $ putTMVar gate ()
        written <- timeout 1000000 (atomically (awaitFrameWritten sess n))
        written `shouldBe` Just ()

    it "counts every frame header recvLoop reads, whatever its type" $
      withHostilePeer RoleClient $ \hp -> do
        injectFrame hp (YamuxHeader 0 FramePing (defaultFlags {flagACK = True}) 0 99) BS.empty
        injectFrame hp (YamuxHeader 0 FramePing (defaultFlags {flagSYN = True}) 0 7) BS.empty
        injectFrame hp (YamuxHeader 0 FrameGoAway defaultFlags 0 0) BS.empty
        -- The GoAway is the last frame, so once it is handled all three were read
        awaitRemoteGoAway (hpSession hp) GoAwayNormal
        readTVarIO (ysessRecvCount (hpSession hp)) `shouldReturn` 3

  describe "GoAway" $ do
    it "GoAway Normal (0x00) sets ysessShutdown" $ do
      withSessionPair $ \(client, _server) -> do
        sendGoAway client GoAwayNormal
        shutdown <- readTVarIO (ysessShutdown client)
        shutdown `shouldBe` True

    it "openStream fails after local GoAway sent" $ do
      withSessionPair $ \(client, _server) -> do
        sendGoAway client GoAwayNormal
        result <- openStream client
        shouldBeLeft YamuxSessionShutdown result

    it "openStream fails after remote GoAway received, surfacing the code" $ do
      withSessionPair $ \(client, server) -> do
        sendGoAway server GoAwayNormal
        atomically $ do
          got <- readTVar (ysessRemoteGoAway client)
          check (got == Just GoAwayNormal)
        result <- openStream client
        shouldBeLeft (YamuxGoAway GoAwayNormal) result

    it "existing streams continue after GoAway" $ do
      withSessionPair $ \(client, server) -> do
        (clientStream, serverStream) <-
          concurrently
            (openStream client >>= \(Right s) -> pure s)
            (acceptStream server >>= \(Right s) -> pure s)
        atomically $ do
          st <- readTVar (ysState clientStream)
          check (st == StreamEstablished)
        sendGoAway client GoAwayNormal
        Right () <- streamWrite clientStream "still works"
        Right received <- streamRead serverStream
        received `shouldBe` "still works"

  describe "Full lifecycle" $ do
    it "open -> write -> read -> FIN -> close" $ do
      withSessionPair $ \(client, server) -> do
        (clientStream, serverStream) <-
          concurrently
            (openStream client >>= \(Right s) -> pure s)
            (acceptStream server >>= \(Right s) -> pure s)
        atomically $ do
          st <- readTVar (ysState clientStream)
          check (st == StreamEstablished)
        Right () <- streamWrite clientStream "hello"
        Right received <- streamRead serverStream
        received `shouldBe` "hello"
        Right () <- streamWrite serverStream "world"
        Right received2 <- streamRead clientStream
        received2 `shouldBe` "world"
        Right () <- streamClose clientStream
        Right () <- streamClose serverStream
        atomically $ do
          st <- readTVar (ysState clientStream)
          check (st == StreamClosed)
        stClient <- readTVarIO (ysState clientStream)
        stClient `shouldBe` StreamClosed

  describe "Half-close semantics" $ do
    it "keeps the remote-to-local direction open after a local FIN" $ do
      withSessionPair $ \(client, server) -> do
        (clientStream, serverStream) <-
          concurrently
            (openStream client >>= \(Right s) -> pure s)
            (acceptStream server >>= \(Right s) -> pure s)
        atomically $ do
          st <- readTVar (ysState clientStream)
          check (st == StreamEstablished)
        -- Client half-closes: its write side is dead
        Right () <- streamClose clientStream
        wr <- streamWrite clientStream "late"
        wr `shouldBe` Left YamuxStreamClosed
        -- Server observes EOF on its read side
        finSeen <- timeout 1000000 $ atomically $ do
          st <- readTVar (ysState serverStream)
          check (st == StreamRemoteClose)
        finSeen `shouldBe` Just ()
        eof <- streamRead serverStream
        eof `shouldBe` Left YamuxStreamClosed
        -- The other direction still flows: server writes, client reads
        Right () <- streamWrite serverStream "reply"
        Right got <- streamRead clientStream
        got `shouldBe` "reply"
        -- Server closes too; both ends reach Closed and client sees EOF
        Right () <- streamClose serverStream
        closed <- timeout 1000000 $ atomically $ do
          st <- readTVar (ysState clientStream)
          check (st == StreamClosed)
        closed `shouldBe` Just ()
        end <- streamRead clientStream
        end `shouldBe` Left YamuxStreamClosed

  describe "SYN validation" $ do
    it "SYN with wrong parity triggers GoAway (server rejects even ID)" $ do
      -- Server expects odd IDs from client; inject even SYN
      ((writeA, readA), (writeB, readB)) <- mkMemoryTransportPair
      server <- newSession RoleServer writeB readB
      -- We send a SYN Data frame with stream ID 2 (even = same parity as server)
      -- This should be rejected because server expects odd (client) IDs
      let synHdr = YamuxHeader
            { yhVersion = 0
            , yhType = FrameData
            , yhFlags = defaultFlags { flagSYN = True }
            , yhStreamId = 2  -- even ID, invalid for client->server direction
            , yhLength = 0
            }
      writeA (encodeHeader synHdr)
      withAsync (sendLoop server) $ \_ -> do
        withAsync (recvLoop server) $ \_ -> do
          atomically $ do
            shut <- readTVar (ysessShutdown server)
            check shut

    it "SYN with duplicate stream ID triggers GoAway" $ do
      withSessionPair $ \(client, server) -> do
        -- Open a normal stream (ID 1)
        (_, _) <- concurrently
          (openStream client >>= \(Right s) -> pure s)
          (acceptStream server >>= \(Right s) -> pure s)
        -- Inject duplicate SYN for stream ID 1 via raw frame
        -- We write directly to the transport that feeds the server's recvLoop
        let dupSynHdr = YamuxHeader
              { yhVersion = 0
              , yhType = FrameData
              , yhFlags = defaultFlags { flagSYN = True }
              , yhStreamId = 1  -- duplicate of existing stream
              , yhLength = 0
              }
        -- Send raw frame bytes through client's write function (goes to server's read)
        ysessWrite client (encodeHeader dupSynHdr)
        atomically $ do
          shut <- readTVar (ysessShutdown server)
          check shut

    it "valid SYN with correct parity accepted normally" $ do
      withSessionPair $ \(client, server) -> do
        (_, serverStream) <- concurrently
          (openStream client >>= \(Right s) -> pure s)
          (acceptStream server >>= \(Right s) -> pure s)
        -- Stream ID 1 (odd) should have been accepted
        ysStreamId serverStream `shouldBe` 1

  describe "Flow control: window underflow protection" $ do
    it "payload exceeding recv window triggers GoAway protocol error" $ do
      withSessionPair $ \(client, server) -> do
        (clientStream, serverStream) <-
          concurrently
            (openStream client >>= \(Right s) -> pure s)
            (acceptStream server >>= \(Right s) -> pure s)
        atomically $ do
          st <- readTVar (ysState clientStream)
          check (st == StreamEstablished)
        -- Shrink server recv window to 10 bytes (simulating near-exhaustion)
        atomically $ writeTVar (ysRecvWindow serverStream) 10
        -- Client sends 100 bytes (exceeds server's 10-byte window)
        _ <- streamWrite clientStream (BS.replicate 100 0xAA)
        -- Server should detect over-window and enter shutdown
        atomically $ do
          shut <- readTVar (ysessShutdown server)
          check shut

  describe "Flow control integration" $ do
    it "transfer data exceeding initial window (requires WindowUpdate exchange)" $ do
      withSessionPair $ \(client, server) -> do
        (clientStream, serverStream) <-
          concurrently
            (openStream client >>= \(Right s) -> pure s)
            (acceptStream server >>= \(Right s) -> pure s)
        atomically $ do
          st <- readTVar (ysState clientStream)
          check (st == StreamEstablished)
        -- Set a small window (100 bytes) to force WindowUpdate exchange
        atomically $ writeTVar (ysSendWindow clientStream) 100
        -- Write and read concurrently: writer sends 250 bytes, reader accumulates
        let totalData = BS.replicate 250 0xAB
        (_, received) <-
          concurrently
            (streamWrite clientStream totalData)
            (readAll serverStream 250)
        received `shouldBe` totalData

    it "concurrent read/write on 4 streams simultaneously" $ do
      withSessionPair $ \(client, server) -> do
        let numStreams = 4 :: Int
            payload = BS.replicate 100 0xCC
        concurrently_
          ( do
              streams <- mapM (\_ -> openStream client >>= \(Right s) -> pure s) [1 .. numStreams]
              mapM_ (\s -> atomically (readTVar (ysState s) >>= \st -> check (st == StreamEstablished))) streams
              -- Write to all streams concurrently
              mapM_ (\s -> async (streamWrite s payload)) streams
          )
          ( do
              streams <- mapM (\_ -> acceptStream server >>= \(Right s) -> pure s) [1 .. numStreams]
              -- Read from all streams
              results <- mapM (\s -> streamRead s >>= \(Right d) -> pure d) streams
              mapM_ (\d -> BS.length d `shouldBe` 100) results
          )

  describe "FIN handling in pre-established states (issue #142)" $ do
    it "should signal EOF when Data-frame FIN arrives while stream is in SYNReceived" $ do
      ((writeA, _readA), (writeB, readB)) <- mkMemoryTransportPair
      server <- newSession RoleServer writeB readB
      let synHdr =
            YamuxHeader
              { yhVersion = 0
              , yhType = FrameData
              , yhFlags = defaultFlags {flagSYN = True}
              , yhStreamId = 1
              , yhLength = 0
              }
          dataHdr =
            YamuxHeader
              { yhVersion = 0
              , yhType = FrameData
              , yhFlags = defaultFlags
              , yhStreamId = 1
              , yhLength = 5
              }
          finHdr =
            YamuxHeader
              { yhVersion = 0
              , yhType = FrameData
              , yhFlags = defaultFlags {flagFIN = True}
              , yhStreamId = 1
              , yhLength = 0
              }
      writeA (encodeHeader synHdr)
      writeA (encodeHeader dataHdr)
      writeA "hello"
      writeA (encodeHeader finHdr)
      withAsync (sendLoop server) $ \_ ->
        withAsync (recvLoop server) $ \_ -> do
          -- Let recvLoop process all frames before accepting, so the FIN
          -- is handled while the stream is still in StreamSYNReceived
          threadDelay 100000
          result <- timeout 1000000 $ do
            Right stream <- acceptStream server
            Right received <- streamRead stream
            received `shouldBe` "hello"
            eof <- streamRead stream
            eof `shouldBe` Left YamuxStreamClosed
          result `shouldBe` Just ()

    it "should signal EOF when WindowUpdate FIN arrives while stream is in SYNReceived (go-libp2p open pattern)" $ do
      ((writeA, _readA), (writeB, readB)) <- mkMemoryTransportPair
      server <- newSession RoleServer writeB readB
      let synHdr =
            YamuxHeader
              { yhVersion = 0
              , yhType = FrameWindowUpdate
              , yhFlags = defaultFlags {flagSYN = True}
              , yhStreamId = 1
              , yhLength = 0
              }
          dataHdr =
            YamuxHeader
              { yhVersion = 0
              , yhType = FrameData
              , yhFlags = defaultFlags
              , yhStreamId = 1
              , yhLength = 5
              }
          finHdr =
            YamuxHeader
              { yhVersion = 0
              , yhType = FrameWindowUpdate
              , yhFlags = defaultFlags {flagFIN = True}
              , yhStreamId = 1
              , yhLength = 0
              }
      writeA (encodeHeader synHdr)
      writeA (encodeHeader dataHdr)
      writeA "hello"
      writeA (encodeHeader finHdr)
      withAsync (sendLoop server) $ \_ ->
        withAsync (recvLoop server) $ \_ -> do
          threadDelay 100000
          result <- timeout 1000000 $ do
            Right stream <- acceptStream server
            Right received <- streamRead stream
            received `shouldBe` "hello"
            eof <- streamRead stream
            eof `shouldBe` Left YamuxStreamClosed
          result `shouldBe` Just ()

    it "should transition SYNSent to RemoteClose when WindowUpdate FIN arrives" $ do
      ((writeA, readA), (writeB, _readB)) <- mkMemoryTransportPair
      client <- newSession RoleClient writeA readA
      withAsync (sendLoop client) $ \_ ->
        withAsync (recvLoop client) $ \_ -> do
          Right stream <- openStream client
          -- Remote half-closes with WindowUpdate+FIN before ACKing the SYN
          let finHdr =
                YamuxHeader
                  { yhVersion = 0
                  , yhType = FrameWindowUpdate
                  , yhFlags = defaultFlags {flagFIN = True}
                  , yhStreamId = 1
                  , yhLength = 0
                  }
          writeB (encodeHeader finHdr)
          result <- timeout 1000000 $ atomically $ do
            st <- readTVar (ysState stream)
            check (st == StreamRemoteClose)
          result `shouldBe` Just ()

  describe "Flow control: declared length validated before payload read (issue #143)" $ do
    it "should reject a data frame declaring more than the recv window without reading its payload" $ do
      ((writeA, _readA), (writeB, readB)) <- mkMemoryTransportPair
      server <- newSession RoleServer writeB readB
      let synHdr =
            YamuxHeader
              { yhVersion = 0
              , yhType = FrameWindowUpdate
              , yhFlags = defaultFlags {flagSYN = True}
              , yhStreamId = 1
              , yhLength = 0
              }
          -- Declares 1 MiB (> 256 KiB initial window); no payload bytes follow.
          -- The violation must be detected on the header alone.
          bigHdr =
            YamuxHeader
              { yhVersion = 0
              , yhType = FrameData
              , yhFlags = defaultFlags
              , yhStreamId = 1
              , yhLength = 1048576
              }
      writeA (encodeHeader synHdr)
      writeA (encodeHeader bigHdr)
      withAsync (sendLoop server) $ \_ ->
        withAsync (recvLoop server) $ \recvA -> do
          result <- timeout 1000000 $ do
            atomically $ readTVar (ysessShutdown server) >>= check
            -- The violation must also terminate the receive loop
            wait recvA
          result `shouldBe` Just ()

    it "should reject a length of 0xFFFFFFFF on an unknown stream and stop the session" $ do
      ((writeA, _readA), (writeB, readB)) <- mkMemoryTransportPair
      server <- newSession RoleServer writeB readB
      let hugeHdr =
            YamuxHeader
              { yhVersion = 0
              , yhType = FrameData
              , yhFlags = defaultFlags
              , yhStreamId = 1
              , yhLength = 0xFFFFFFFF
              }
      writeA (encodeHeader hugeHdr)
      withAsync (sendLoop server) $ \_ ->
        withAsync (recvLoop server) $ \recvA -> do
          result <- timeout 1000000 $ do
            atomically $ readTVar (ysessShutdown server) >>= check
            wait recvA
          result `shouldBe` Just ()

-- | Read exactly n bytes from a stream by accumulating chunks.
readAll :: YamuxStream -> Int -> IO BS.ByteString
readAll stream n = go BS.empty
  where
    go acc
      | BS.length acc >= n = pure (BS.take n acc)
      | otherwise = do
          Right chunk <- streamRead stream
          go (acc <> chunk)

-- | Helper to assert an Either is a Left with a specific error value.
shouldBeLeft :: (Show e, Eq e) => e -> Either e a -> Expectation
shouldBeLeft expected (Left actual) = actual `shouldBe` expected
shouldBeLeft expected (Right _) =
  expectationFailure $ "Expected Left " <> show expected <> " but got Right"

-- | A Ping ACK echoing the given opaque value.
pingAck :: Word32 -> YamuxHeader
pingAck = YamuxHeader 0 FramePing (defaultFlags {flagACK = True}) 0

-- | The default configuration with a different ping timeout.
pingTimeoutConfig :: Int -> YamuxConfig
pingTimeoutConfig us = defaultYamuxConfig {ycPingTimeoutMicros = us}

-- | Short keepalive timings so the tests finish well within a second.
keepaliveConfig :: YamuxConfig
keepaliveConfig =
  defaultYamuxConfig
    { ycKeepAliveIntervalMicros = 100000 -- 100ms
    , ycPingTimeoutMicros = 350000 -- 350ms
    }

-- | Assert the session writes nothing for three keepalive intervals.
expectNoFrame :: HostilePeer -> Expectation
expectNoFrame hp = do
  mFrame <- timeout 300000 (hpNextFrame hp)
  fmap fst mFrame `shouldBe` Nothing
