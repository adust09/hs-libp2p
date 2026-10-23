-- | Interop test daemon for the libp2p/unified-testing framework.
--
-- Implements the "modern" transport test-app contract
-- (unified-testing docs/write-a-transport-test-app.md): reads uppercase
-- environment variables, coordinates listener discovery through a shared
-- Redis instance namespaced by TEST_KEY, and reports dialer measurements
-- as YAML on stdout. All logging goes to stderr.
--
-- Environment variables (transport contract):
--   IS_DIALER      - "true" or "false"
--   REDIS_ADDR     - Redis host:port (default: "redis:6379")
--   TEST_KEY       - hex key namespacing Redis coordination keys
--   TRANSPORT      - "tcp", "ws", "quic-v1", or "webtransport"
--   SECURE_CHANNEL - "noise" or "tls" for TCP/WebSocket; unset for native transports
--   MUXER          - "yamux" for TCP/WebSocket; unset for native transports
--   LISTENER_IP    - bind address (default: "0.0.0.0")
--   DEBUG          - accepted but ignored; all logging goes to stderr
--
-- Local extension (not part of the upstream contract):
--   TEST_MODE      - "ping" (default) or "gossipsub"
module Main (main) where

import Control.Concurrent (threadDelay, forkIO, newEmptyMVar, putMVar, takeMVar)
import Control.Concurrent.STM (atomically, writeTVar)
import Control.Monad (forever, void)
import Data.Aeson (object, (.=))
import qualified Data.Aeson as Aeson
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Lazy.Char8 as LBS8
import Data.List (find)
import Data.Maybe (fromMaybe)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time.Clock (diffUTCTime, getCurrentTime)
import qualified Database.Redis as Redis
import LibP2P
  ( GossipSubNode (..)
  , Multiaddr (..)
  , PeerId
  , PingResult (..)
  , Protocol (..)
  , addTransport
  , defaultConnectionGater
  , defaultGossipSubParams
  , dial
  , fromPublicKey
  , fromText
  , generateKeyPair
  , gossipJoin
  , gossipPublish
  , newGossipSubNode
  , newSwitchWithConfig
  , defaultSwitchConfig
  , SwitchConfig (..)
  , newTCPTransport
  , newWebSocketTransport
  , newWebTransportTransport
  , newQUICTransport
  , peerIdBytes
  , registerPingHandler
  , sendPing
  , splitP2P
  , startGossipSub
  , stopGossipSub
  , switchClose
  , switchListen
  , toBase58
  , toText
  , GossipSubParams (..)
  )
import LibP2P.Crypto.Key (publicKey)
import LibP2P.Protocol.GossipSub.Types (GossipSubRouter (..), PubSubMessage (..))
import LibP2P.Switch.Types (Switch)
import Network.Socket
  ( AddrInfo (..)
  , SockAddr (..)
  , defaultHints
  , getAddrInfo
  , hostAddressToTuple
  )
import qualified Network.Socket as Socket
import System.Environment (lookupEnv)
import System.Exit (exitFailure, exitSuccess)
import System.IO (hFlush, hPutStrLn, stderr, stdout)
import System.Timeout (timeout)
import Text.Printf (printf)

-- | The runner kills containers itself; this bounds Redis polling and
-- local gossipsub waits.
testTimeoutSeconds :: Int
testTimeoutSeconds = 180

main :: IO ()
main = do
  isDialer  <- getEnvRequired "IS_DIALER"
  redisAddr <- fromMaybe "redis:6379" <$> lookupEnv "REDIS_ADDR"
  testKey   <- getEnvRequired "TEST_KEY"
  transport <- getEnvRequired "TRANSPORT"
  security  <- lookupEnv "SECURE_CHANNEL"
  muxer     <- lookupEnv "MUXER"
  ip        <- fromMaybe "0.0.0.0" <$> lookupEnv "LISTENER_IP"
  testMode  <- fromMaybe "ping" <$> lookupEnv "TEST_MODE"

  -- Validate supported protocols
  case validateProtocols transport security muxer of
    Left err -> do
      hPutStrLn stderr $ "Unsupported configuration: " ++ err
      exitFailure
    Right () -> pure ()

  let addrKey = BS8.pack (testKey ++ "_listener_multiaddr")

  -- Generate identity
  ekp <- generateKeyPair
  case ekp of
    Left err -> do
      hPutStrLn stderr $ "Key generation failed: " ++ err
      exitFailure
    Right kp -> do
      let pid = fromPublicKey (publicKey kp)
      logInfo $ "PeerId: " ++ T.unpack (toBase58 pid)

      -- Create Switch. SECURE_CHANNEL selects the only offered handshake so a
      -- TLS run cannot silently fall back to Noise.
      sw <- newSwitchWithConfig (switchConfigFor security) pid kp
      selectedTransport <- case transport of
        "tcp" -> newTCPTransport
        "ws" -> newWebSocketTransport
        "webtransport" -> newWebTransportTransport kp
        "quic-v1" -> newQUICTransport kp
        _ -> fail "validated transport is unavailable"
      addTransport sw selectedTransport

      -- Connect to Redis
      let (redisHost, redisPort) = parseHostPort redisAddr
      let redisConnInfo = Redis.defaultConnectInfo
            { Redis.connectHost = redisHost
            , Redis.connectPort = Redis.PortNumber (fromIntegral redisPort)
            }
      redisConn <- Redis.checkedConnect redisConnInfo

      dialer <- case isDialer of
        "true"  -> pure True
        "false" -> pure False
        other   -> do
          hPutStrLn stderr $ "Invalid IS_DIALER value: " ++ other
          switchClose sw
          exitFailure

      case (testMode, dialer) of
        ("gossipsub", False) -> runGossipSubListener sw pid transport ip redisConn addrKey
        ("gossipsub", True)  -> runGossipSubDialer sw pid redisConn addrKey
        (_, False) -> registerPingHandler sw >> runListener sw pid transport ip redisConn addrKey
        (_, True)  -> registerPingHandler sw >> runDialer sw pid redisConn addrKey

-- | Listener mode: bind, publish address to Redis, run until Docker
-- shuts the container down (transport contract, Listener step 5).
runListener :: Switch -> PeerId -> String -> String -> Redis.Connection -> BS8.ByteString -> IO ()
runListener sw pid transportName ip redisConn addrKey = do
  addrText <- listenAndResolve sw pid transportName ip

  logInfo $ "Listening on: " ++ T.unpack addrText

  publishListenerAddr redisConn addrKey addrText
  logInfo "Address published to Redis, waiting to be dialed..."
  forever $ threadDelay 3600000000

-- | Dialer mode: get address from Redis, dial, ping, output YAML.
runDialer :: Switch -> PeerId -> Redis.Connection -> BS8.ByteString -> IO ()
runDialer sw _pid redisConn addrKey = do
  logInfo "Polling Redis for listener address..."

  mAddr <- pollListenerAddr redisConn addrKey
  case mAddr of
    Nothing -> do
      hPutStrLn stderr "Timed out waiting for listener address"
      switchClose sw
      exitFailure
    Just addrBS -> do
      let addrText = TE.decodeUtf8 addrBS
      logInfo $ "Got listener address: " ++ T.unpack addrText

      case fromText addrText of
        Left err -> do
          hPutStrLn stderr $ "Failed to parse multiaddr: " ++ err
          switchClose sw
          exitFailure
        Right fullAddr -> case splitP2P fullAddr of
          Nothing -> do
            hPutStrLn stderr "Multiaddr has no /p2p/ component"
            switchClose sw
            exitFailure
          Just (transportAddr, remotePeerId) -> do
            logInfo $ "Dialing peer: " ++ T.unpack (toBase58 remotePeerId)

            -- handshakeStartInstant, recorded before connecting
            -- (transport contract, Dialer step 4).
            t0 <- getCurrentTime

            dialResult <- dial sw remotePeerId [transportAddr]
            case dialResult of
              Left err -> do
                hPutStrLn stderr $ "Dial failed: " ++ show err
                switchClose sw
                exitFailure
              Right conn -> do
                -- A single ping (contract steps 4-5): its round-trip time
                -- is ping_rtt, and the total elapsed since t0 is
                -- handshake_plus_one_rtt.
                pingResult <- sendPing sw conn
                t1 <- getCurrentTime

                case pingResult of
                  Left err -> do
                    hPutStrLn stderr $ "Ping failed: " ++ show err
                    switchClose sw
                    exitFailure
                  Right pr -> do
                    let handshakePlusOneRTT = realToFrac (diffUTCTime t1 t0) * 1000 :: Double
                        pingRTTMs = realToFrac (pingRTT pr) * 1000 :: Double

                    -- Results schema: YAML on stdout, stdout is used for
                    -- nothing else (transport contract, Results Schema).
                    printf "latency:\n  handshake_plus_one_rtt: %.3f\n  ping_rtt: %.3f\n  unit: ms\n"
                      handshakePlusOneRTT pingRTTMs
                    hFlush stdout

                    switchClose sw
                    exitSuccess

-- | GossipSub listener: join topic, wait for message, reply, report to Redis.
runGossipSubListener :: Switch -> PeerId -> String -> String -> Redis.Connection -> BS8.ByteString -> IO ()
runGossipSubListener sw pid transportName ip redisConn addrKey = do
  let gsParams = defaultGossipSubParams { paramHeartbeatInterval = 60.0 }
  gsNode <- newGossipSubNode sw gsParams
  startGossipSub gsNode

  -- Set up message callback
  msgMVar <- newEmptyMVar
  atomically $ writeTVar (gsOnMessage (gsnRouter gsNode))
    (\topic msg -> putMVar msgMVar (topic, msgData msg))

  addrText <- listenAndResolve sw pid transportName ip
  logInfo $ "GossipSub listener on: " ++ T.unpack addrText

  publishListenerAddr redisConn addrKey addrText
  logInfo "Address published to Redis"

  -- Join topic
  gossipJoin gsNode "interop-gossipsub-test"
  logInfo "Joined topic interop-gossipsub-test"

  -- Re-announce subscriptions to peers that connect after join.
  -- onNewConnection should handle this but cross-impl timing
  -- can cause the announcement to be lost.
  _ <- forkIO $ reannounceLoop gsNode "interop-gossipsub-test" 10

  -- Wait for message
  mResult <- timeout (testTimeoutSeconds * 1000000) $ takeMVar msgMVar
  case mResult of
    Nothing -> do
      hPutStrLn stderr "Timeout waiting for GossipSub message"
      let jsonOutput = object
            [ "gossipSubInterop" .= False
            , "role" .= ("listener" :: T.Text)
            , "error" .= ("timeout" :: T.Text)
            ]
      void $ Redis.runRedis redisConn $
        Redis.rpush "gossipResult" [LBS.toStrict (Aeson.encode jsonOutput)]
      stopGossipSub gsNode; switchClose sw
      exitFailure
    Just (_topic, msgBytes) -> do
      let received = BS8.unpack msgBytes
      logInfo $ "Received message: " ++ received

      -- Publish reply
      threadDelay 500000  -- 0.5s for stability
      let replyMsg = "hs-reply-to-" ++ received
      gossipPublish gsNode "interop-gossipsub-test" (BS8.pack replyMsg)
      logInfo $ "Published reply: " ++ replyMsg

      let jsonOutput = object
            [ "gossipSubInterop" .= True
            , "role" .= ("listener" :: T.Text)
            , "messageReceived" .= received
            , "messageSent" .= replyMsg
            ]
      void $ Redis.runRedis redisConn $
        Redis.rpush "gossipResult" [LBS.toStrict (Aeson.encode jsonOutput)]

      -- Keep alive briefly for reply delivery
      threadDelay 3000000
      stopGossipSub gsNode; switchClose sw

-- | GossipSub dialer: connect, publish message, wait for reply, report JSON.
runGossipSubDialer :: Switch -> PeerId -> Redis.Connection -> BS8.ByteString -> IO ()
runGossipSubDialer sw _pid redisConn addrKey = do
  let gsParams = defaultGossipSubParams { paramHeartbeatInterval = 60.0 }
  gsNode <- newGossipSubNode sw gsParams
  startGossipSub gsNode

  -- Set up message callback — filter out our own message
  let sentMsg = "hs-rust-interop-test" :: BS8.ByteString
  msgMVar <- newEmptyMVar
  atomically $ writeTVar (gsOnMessage (gsnRouter gsNode))
    (\topic msg -> do
      let d = msgData msg
      logInfo $ "gsOnMessage got: " ++ BS8.unpack d
      if d /= sentMsg
        then putMVar msgMVar (topic, d)
        else pure ()
    )

  logInfo "GossipSub dialer: polling Redis for listener address..."

  mAddr <- pollListenerAddr redisConn addrKey
  case mAddr of
    Nothing -> do
      hPutStrLn stderr "Timed out waiting for listener address"
      stopGossipSub gsNode; switchClose sw
      exitFailure
    Just addrBS -> do
      let addrText = TE.decodeUtf8 addrBS
      logInfo $ "Got listener address: " ++ T.unpack addrText

      case fromText addrText of
        Left err -> do
          hPutStrLn stderr $ "Failed to parse multiaddr: " ++ err
          stopGossipSub gsNode; switchClose sw
          exitFailure
        Right fullAddr -> case splitP2P fullAddr of
          Nothing -> do
            hPutStrLn stderr "Multiaddr has no /p2p/ component"
            stopGossipSub gsNode; switchClose sw
            exitFailure
          Just (transportAddr, remotePeerId) -> do
            logInfo $ "Dialing peer: " ++ T.unpack (toBase58 remotePeerId)

            t0 <- getCurrentTime

            dialResult <- dial sw remotePeerId [transportAddr]
            case dialResult of
              Left err -> do
                hPutStrLn stderr $ "Dial failed: " ++ show err
                stopGossipSub gsNode; switchClose sw
                exitFailure
              Right _conn -> do
                -- Wait for mux + stream setup
                threadDelay 2000000

                -- Join topic
                gossipJoin gsNode "interop-gossipsub-test"
                logInfo "Joined topic interop-gossipsub-test"

                -- Wait for subscription propagation
                threadDelay 2000000

                -- Publish test message
                let testMsg = "hs-rust-interop-test"
                gossipPublish gsNode "interop-gossipsub-test" testMsg
                logInfo $ "Published: " ++ BS8.unpack testMsg

                -- Wait for reply
                mResult <- timeout (testTimeoutSeconds * 1000000) $ takeMVar msgMVar
                t1 <- getCurrentTime
                let roundTripMs = realToFrac (diffUTCTime t1 t0) * 1000 :: Double

                case mResult of
                  Nothing -> do
                    hPutStrLn stderr "Timeout waiting for GossipSub reply"
                    let jsonOutput = object
                          [ "gossipSubInterop" .= False
                          , "role" .= ("dialer" :: T.Text)
                          , "error" .= ("timeout" :: T.Text)
                          ]
                    LBS8.putStrLn (Aeson.encode jsonOutput)
                    hFlush stdout
                    stopGossipSub gsNode; switchClose sw
                    exitFailure
                  Just (_topic, replyBytes) -> do
                    let received = BS8.unpack replyBytes
                    logInfo $ "Received reply: " ++ received

                    let jsonOutput = object
                          [ "gossipSubInterop" .= True
                          , "role" .= ("dialer" :: T.Text)
                          , "messageSent" .= ("hs-rust-interop-test" :: T.Text)
                          , "messageReceived" .= received
                          , "roundTripMs" .= roundTripMs
                          ]
                    LBS8.putStrLn (Aeson.encode jsonOutput)
                    hFlush stdout

                    void $ Redis.runRedis redisConn $
                      Redis.rpush "gossipResult" [LBS.toStrict (Aeson.encode jsonOutput)]

                    stopGossipSub gsNode; switchClose sw
                    exitSuccess

-- | Bind, resolve the non-localhost address, and return the full
-- multiaddr (with /p2p/ suffix) as text.
listenAndResolve :: Switch -> PeerId -> String -> String -> IO T.Text
listenAndResolve sw pid transportName ip = do
  let suffix = case transportName of
        "quic-v1" -> "/udp/0/quic-v1"
        "webtransport" -> "/udp/0/quic-v1/webtransport"
        "ws" -> "/tcp/0/ws"
        _ -> "/tcp/0"
      bindAddr = case fromText (T.pack ("/ip4/" ++ ip ++ suffix)) of
        Right ma -> ma
        Left err -> error $ "Invalid bind address: " ++ err

  addrs <- switchListen sw defaultConnectionGater [bindAddr]
  case addrs of
    [] -> do
      hPutStrLn stderr "switchListen returned no addresses"
      switchClose sw
      exitFailure
    (listenAddr : _) -> do
      -- Resolve actual IP if bound to 0.0.0.0
      actualAddr <- resolveListenAddr listenAddr ip
      let peerIdMH = peerIdBytes pid
      let fullAddr = encapsulateP2P actualAddr peerIdMH
      pure (toText fullAddr)

-- | RPUSH the listener multiaddr under the TEST_KEY-namespaced key.
--
-- The unified-testing coordination contract uses a Redis *list*: the
-- listener RPUSHes its multiaddr and the dialer BLPOPs it. The test
-- framework's redis-proxy only rewrites keys for RPUSH/BLPOP (legacy
-- `listenerAddr` -> `{TEST_KEY}_listener_multiaddr`); a plain SET/GET
-- string would collide with the list type and surface as Redis
-- WRONGTYPE errors in every cross-implementation pair.
publishListenerAddr :: Redis.Connection -> BS8.ByteString -> T.Text -> IO ()
publishListenerAddr redisConn addrKey addrText = do
  result <- Redis.runRedis redisConn $ Redis.rpush addrKey [TE.encodeUtf8 addrText]
  case result of
    Left err -> do
      hPutStrLn stderr $ "Redis RPUSH failed: " ++ show err
      exitFailure
    Right _ -> pure ()

-- | BLPOP the listener-multiaddr key (dialer contract step 2). Blocks
-- on Redis for up to 'testTimeoutSeconds' and returns the popped value,
-- or Nothing on timeout / Redis error.
pollListenerAddr :: Redis.Connection -> BS8.ByteString -> IO (Maybe BS8.ByteString)
pollListenerAddr redisConn addrKey = do
  result <- Redis.runRedis redisConn $
    Redis.blpop [addrKey] (fromIntegral testTimeoutSeconds)
  case result of
    Left err -> do
      hPutStrLn stderr $ "Redis BLPOP failed: " ++ show err
      pure Nothing
    Right Nothing -> pure Nothing
    Right (Just (_key, value)) -> pure (Just value)

-- | Periodically re-announce our topic subscription to all connected peers.
-- Ensures cross-implementation peers that connect after we've joined the topic
-- learn about our subscription even if the initial announcement is lost.
reannounceLoop :: GossipSubNode -> T.Text -> Int -> IO ()
reannounceLoop gsNode topic iterations = go iterations
  where
    go 0 = pure ()
    go n = do
      threadDelay 1000000  -- 1 second interval
      -- Re-join broadcasts subscription to all connected peers
      gossipJoin gsNode topic
      go (n - 1)

-- | Validate supported standalone and upgraded transport combinations.
validateProtocols :: String -> Maybe String -> Maybe String -> Either String ()
validateProtocols "tcp" security muxer = validateUpgradedTransport security muxer
validateProtocols "ws" security muxer = validateUpgradedTransport security muxer
validateProtocols "quic-v1" Nothing Nothing = Right ()
validateProtocols "quic-v1" _ _ =
  Left "SECURE_CHANNEL and MUXER must be unset for quic-v1"
validateProtocols "webtransport" Nothing Nothing = Right ()
validateProtocols "webtransport" _ _ =
  Left "SECURE_CHANNEL and MUXER must be unset for webtransport"
validateProtocols other _ _ =
  Left $ "transport " ++ other ++ " not supported (expected tcp, ws, webtransport, or quic-v1)"

validateUpgradedTransport :: Maybe String -> Maybe String -> Either String ()
validateUpgradedTransport security muxer = do
  case security of
    Just "noise" -> pure ()
    Just "tls" -> pure ()
    Just other -> Left $ "secure channel " ++ other ++ " not supported (expected noise or tls)"
    Nothing -> Left "SECURE_CHANNEL not set (required for tcp or ws)"
  case muxer of
    Just "yamux" -> pure ()
    Just other -> Left $ "muxer " ++ other ++ " not supported (only yamux)"
    Nothing -> Left "MUXER not set (required for tcp or ws)"

-- | Restrict byte-stream upgrades to the secure channel requested by the test.
switchConfigFor :: Maybe String -> SwitchConfig
switchConfigFor (Just "noise") =
  defaultSwitchConfig {scSecurityProtocols = ["/noise"]}
switchConfigFor (Just "tls") =
  defaultSwitchConfig {scSecurityProtocols = ["/tls/1.0.0"]}
switchConfigFor _ = defaultSwitchConfig

-- | Parse "host:port" string.
parseHostPort :: String -> (String, Int)
parseHostPort s = case break (== ':') s of
  (host, ':' : portStr) -> (host, read portStr)
  (host, _) -> (host, 6379)

-- | Resolve 0.0.0.0 to actual container IP for Docker networking.
resolveListenAddr :: Multiaddr -> String -> IO Multiaddr
resolveListenAddr addr ip
  | ip == "0.0.0.0" = do
      actualIP <- discoverContainerIP
      case protocols addr of
        (IP4 _ : rest) ->
          case fromText (T.pack ("/ip4/" ++ actualIP)) of
            Right (Multiaddr [IP4 w]) -> pure $ Multiaddr (IP4 w : rest)
            _ -> pure addr
        _ -> pure addr
  | otherwise = pure addr
  where
    protocols (Multiaddr ps) = ps

-- | Discover actual container IP via hostname resolution.
-- In Docker, HOSTNAME is set to the container ID, which resolves
-- to the container's IP address on the Docker network.
discoverContainerIP :: IO String
discoverContainerIP = do
  -- Docker sets HOSTNAME to container ID
  mHostname <- lookupEnv "HOSTNAME"
  case mHostname of
    Nothing -> pure "0.0.0.0"
    Just hostname -> do
      addrs <- getAddrInfo (Just defaultHints) (Just hostname) Nothing :: IO [AddrInfo]
      case find isNonLoopbackIPv4 addrs of
        Just ai -> pure $ sockAddrToIP (Socket.addrAddress ai)
        Nothing -> pure "0.0.0.0"

-- | Extract just the IP string from a SockAddr.
sockAddrToIP :: SockAddr -> String
sockAddrToIP (SockAddrInet _ hostAddr) =
  let (a, b, c, d) = hostAddressToTuple hostAddr
   in show a ++ "." ++ show b ++ "." ++ show c ++ "." ++ show d
sockAddrToIP other = show other

-- | Check if an AddrInfo is a non-loopback IPv4 address.
isNonLoopbackIPv4 :: AddrInfo -> Bool
isNonLoopbackIPv4 ai = case Socket.addrAddress ai of
  SockAddrInet _ hostAddr ->
    let (a, _, _, _) = hostAddressToTuple hostAddr
     in a /= 127
  _ -> False

-- | Encapsulate a /p2p/<peerId> suffix onto a multiaddr.
encapsulateP2P :: Multiaddr -> BS8.ByteString -> Multiaddr
encapsulateP2P (Multiaddr ps) mhBytes = Multiaddr (ps ++ [P2P mhBytes])

-- | Get a required environment variable, failing if not set.
getEnvRequired :: String -> IO String
getEnvRequired name = do
  val <- lookupEnv name
  case val of
    Just v  -> pure v
    Nothing -> do
      hPutStrLn stderr $ "Missing required environment variable: " ++ name
      exitFailure

-- | Log to stderr.
logInfo :: String -> IO ()
logInfo msg = hPutStrLn stderr msg >> hFlush stderr
