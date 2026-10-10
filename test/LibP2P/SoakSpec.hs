-- | Bounded soak tests (T6 tier, #178).
--
-- The soak tier exists to catch monotonic leaks that only bite after N
-- cycles: stream-map growth in the muxer, reservation counters that
-- drift upward because a release path is missed, pool entries that
-- accumulate. A full wall-clock soak (hours of connect/disconnect
-- against a live peer) belongs in a separate slow suite; these tests
-- keep the same shape — many sequential cycles over one connection —
-- but bounded so they stay CI-friendly (well under 30 seconds).
--
-- The leak observables are exact, not statistical: after N cycles the
-- Switch's reservation counters must be back at their baseline and the
-- Yamux stream maps must be empty. A leak of even one slot per cycle
-- shows up as N.
module LibP2P.SoakSpec (spec) where

import Control.Concurrent.Async (withAsync)
import Control.Concurrent.STM
  ( atomically
  , newTQueueIO
  , readTQueue
  , readTVar
  , retry
  , writeTQueue
  )
import Control.Exception (bracket)
import Control.Monad (forM_, replicateM)
import qualified Data.ByteString as BS
import Data.Either (isLeft, isRight)
import qualified Data.Map.Strict as Map
import LibP2P.Crypto.Ed25519 (generateKeyPair)
import LibP2P.Crypto.Key (KeyPair, publicKey)
import LibP2P.Crypto.PeerId (PeerId, fromPublicKey)
import LibP2P.Multiaddr (Multiaddr (..))
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.MultistreamSelect.Negotiation
  ( NegotiationResult (..)
  , negotiateInitiator
  )
import LibP2P.NAT.AutoNAT (AutoNATConfig (..), handleAutoNAT, requestAutoNAT)
import LibP2P.NAT.AutoNAT.Message (autoNATProtocolId)
import LibP2P.Protocol.Identify (registerIdentifyHandlers, requestIdentify)
import LibP2P.Protocol.Ping (registerPingHandler, sendPing)
import LibP2P.Switch (addTransport, newSwitch, setStreamHandler, switchClose)
import LibP2P.Switch.Connection (newStream)
import LibP2P.Switch.Dial (dial)
import LibP2P.Switch.Listen (defaultConnectionGater, switchListen)
import LibP2P.Switch.ResourceManager
  ( ResourceManager (..)
  , ResourceScope (..)
  , ResourceUsage (..)
  )
import LibP2P.Switch.Types (Connection (..), Switch (..))
import LibP2P.Transport.TCP (newTCPTransport)
import qualified LibP2P.Yamux.Session as Yamux
import LibP2P.Yamux.Stream (streamClose, streamRead, streamWrite)
import LibP2P.Yamux.Types
  ( SessionRole (..)
  , YamuxSession (..)
  , ysStreamId
  )
import System.Timeout (timeout)
import Test.Hspec

-- | Number of sequential cycles per soak test. Large enough that a
-- one-slot-per-cycle leak is unmistakable, small enough for CI.
soakCycles :: Int
soakCycles = 500

-- | One-shot protocol soak: Identify and AutoNAT are heavier than ping
-- but a leak still shows up as N leftover reservations.
oneShotCycles :: Int
oneShotCycles = 50

-- | Generate a test identity (PeerId, KeyPair).
mkTestIdentity :: IO (PeerId, KeyPair)
mkTestIdentity = do
  Right kp <- generateKeyPair
  pure (fromPublicKey (publicKey kp), kp)

-- | Loopback address with port 0 (OS assigns ephemeral port).
loopbackAddr :: Multiaddr
loopbackAddr = Multiaddr [IP4 0x7f000001, TCP 0]

-- | A test node with TCP + Identify + Ping, torn down via bracket.
withNode :: ((Switch, PeerId) -> IO a) -> IO a
withNode action = bracket setup (switchClose . fst) action
  where
    setup = do
      (pid, kp) <- mkTestIdentity
      sw <- newSwitch pid kp
      tcp <- newTCPTransport
      addTransport sw tcp
      registerIdentifyHandlers sw
      registerPingHandler sw
      pure (sw, pid)

-- | Two connected nodes: B listens, A dials.
withConnectedPair
  :: ((Switch, PeerId) -> (Switch, PeerId) -> Connection -> IO a) -> IO a
withConnectedPair action =
  withNode $ \(swB, pidB) -> do
    addrs <- switchListen swB defaultConnectionGater [loopbackAddr]
    withNode $ \(swA, pidA) -> do
      dialResult <- dial swA pidB [head addrs]
      case dialResult of
        Left err -> fail $ "withConnectedPair: dial failed: " ++ show err
        Right conn -> action (swA, pidA) (swB, pidB) conn

-- | System-scope resource usage of a switch.
systemUsage :: Switch -> IO ResourceUsage
systemUsage sw =
  atomically $ readTVar (rsUsage (rmSystemScope (swResourceMgr sw)))

-- | Block (bounded) until both switches report zero stream
-- reservations at the system scope. The responder releases its inbound
-- reservation asynchronously when the handler thread exits, so the
-- test waits on the STM condition instead of sleeping.
waitForZeroStreams :: Switch -> Switch -> IO ()
waitForZeroStreams swA swB = do
  drained <- timeout 10000000 $ atomically $ do
    uA <- readTVar (rsUsage (rmSystemScope (swResourceMgr swA)))
    uB <- readTVar (rsUsage (rmSystemScope (swResourceMgr swB)))
    let zero u = ruStreamsInbound u == 0 && ruStreamsOutbound u == 0
    if zero uA && zero uB then pure () else retry
  case drained of
    Just () -> pure ()
    Nothing -> do
      uA <- systemUsage swA
      uB <- systemUsage swB
      fail $ "stream reservations never drained to zero: dialer=" ++ show uA
          ++ " listener=" ++ show uB

-- | In-memory byte-stream transport pair for Yamux sessions.
mkMemoryTransportPair ::
  IO
    ( (BS.ByteString -> IO (), Int -> IO BS.ByteString)
    , (BS.ByteString -> IO (), Int -> IO BS.ByteString)
    )
mkMemoryTransportPair = do
  qAtoB <- newTQueueIO
  qBtoA <- newTQueueIO
  let writeTo q bs = mapM_ (atomically . writeTQueue q) (BS.unpack bs)
      readFrom q n = BS.pack <$> replicateM n (atomically (readTQueue q))
  pure ((writeTo qAtoB, readFrom qBtoA), (writeTo qBtoA, readFrom qAtoB))

-- | A Yamux session pair with all background loops running.
withSessionPair :: ((YamuxSession, YamuxSession) -> IO a) -> IO a
withSessionPair action = do
  ((writeA, readA), (writeB, readB)) <- mkMemoryTransportPair
  client <- Yamux.newSession RoleClient writeA readA
  server <- Yamux.newSession RoleServer writeB readB
  withAsync (Yamux.sendLoop client) $ \_ ->
    withAsync (Yamux.recvLoop client) $ \_ ->
      withAsync (Yamux.sendLoop server) $ \_ ->
        withAsync (Yamux.recvLoop server) $ \_ ->
          action (client, server)

spec :: Spec
spec = do
  describe "Switch-level soak: repeated one-shot pings over one connection" $
    it "leaves zero stream reservations and one healthy pooled connection after 500 cycles" $
      withConnectedPair $ \(swA, pidA) (swB, pidB) conn -> do
        -- Each sendPing is a full stream lifecycle: reserve, open,
        -- negotiate /ipfs/ping/1.0.0, 32-byte echo, close, release.
        forM_ [1 .. soakCycles] $ \(i :: Int) -> do
          result <- sendPing swA conn
          case result of
            Right _ -> pure ()
            Left err -> fail $ "ping cycle " ++ show i ++ " failed: " ++ show err

        -- No reservation drift: every cycle released both its outbound
        -- (dialer) and inbound (responder) stream slot.
        waitForZeroStreams swA swB

        -- The connection itself is still the only reservation held.
        uA <- systemUsage swA
        uB <- systemUsage swB
        (ruConnsOutbound uA, ruConnsInbound uA) `shouldBe` (1, 0)
        (ruConnsInbound uB, ruConnsOutbound uB) `shouldBe` (1, 0)

        -- No pool growth: exactly one connection each way.
        poolA <- atomically $ readTVar (swConnPool swA)
        poolB <- atomically $ readTVar (swConnPool swB)
        fmap length (Map.lookup pidB poolA) `shouldBe` Just 1
        fmap length (Map.lookup pidA poolB) `shouldBe` Just 1

        -- The connection is still usable after the soak.
        finalPing <- sendPing swA conn
        finalPing `shouldSatisfy` isRight

  describe "Switch-level soak: repeated Identify over one connection" $
    it "leaves zero stream reservations after 50 identify exchanges" $
      withConnectedPair $ \(swA, _) (swB, _) conn -> do
        forM_ [1 .. oneShotCycles] $ \(i :: Int) -> do
          result <- requestIdentify swA conn
          case result of
            Right _ -> pure ()
            Left err -> fail $ "identify cycle " ++ show i ++ " failed: " ++ err
        waitForZeroStreams swA swB

  describe "Switch-level soak: repeated AutoNAT over one connection" $
    it "leaves zero stream reservations after 50 autonat exchanges" $
      withConnectedPair $ \(swA, pidA) (swB, _) conn -> do
        let config = AutoNATConfig
              { natThreshold = 3
              , natDialBack = \_pid _addrs -> pure (Right loopbackAddr)
              }
        setStreamHandler swB autoNATProtocolId $ \c stream ->
          handleAutoNAT config stream (connPeerId c) (connRemoteAddr c)
        forM_ [1 .. oneShotCycles] $ \(i :: Int) -> do
          streamOrErr <- newStream swA conn
          case streamOrErr of
            Left err ->
              fail $ "autonat cycle " ++ show i ++ " open failed: " ++ show err
            Right stream -> do
              negotiated <- negotiateInitiator stream [autoNATProtocolId]
              case negotiated of
                NoProtocol -> fail $ "autonat cycle " ++ show i ++ " not negotiated"
                Accepted _ -> do
                  result <- requestAutoNAT stream pidA [connLocalAddr conn]
                  case result of
                    Right _ -> pure ()
                    Left err ->
                      fail $ "autonat cycle " ++ show i ++ " failed: " ++ err
        waitForZeroStreams swA swB

  describe "Yamux-level soak: repeated stream open/close cycles on one session" $
    it "does not grow the stream maps over 500 full FIN/FIN lifecycles" $
      withSessionPair $ \(client, server) -> do
        forM_ [1 .. soakCycles] $ \(i :: Int) -> do
          Right sc <- Yamux.openStream client
          Right ss <- Yamux.acceptStream server
          Right () <- streamWrite sc "x"
          firstRead <- streamRead ss
          firstRead `shouldBe` Right "x"
          Right () <- streamClose sc
          -- The server observes EOF once the FIN arrives, then closes
          -- its own side, which reclaims the map slot on both ends.
          eof <- streamRead ss
          eof `shouldSatisfy` isLeft
          _ <- streamClose ss
          -- Stream IDs must keep advancing: a stale map entry would
          -- otherwise collide silently.
          ysStreamId sc `shouldBe` fromIntegral (2 * i - 1)

        -- Both session maps must be empty; even a single leaked slot
        -- per cycle would show up as 500 here.
        drained <- timeout 10000000 $ atomically $ do
          mClient <- readTVar (ysessStreams client)
          mServer <- readTVar (ysessStreams server)
          if Map.null mClient && Map.null mServer then pure () else retry
        drained `shouldBe` Just ()
