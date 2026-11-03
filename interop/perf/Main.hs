-- | Perf test daemon for the libp2p/unified-testing framework.
--
-- Implements the perf test-app contract
-- (unified-testing docs/write-a-perf-test-app.md): reads uppercase
-- environment variables, coordinates listener discovery through a
-- shared Redis instance namespaced by TEST_KEY, runs the /perf/1.0.0
-- upload/download/latency measurements, and reports statistics as YAML
-- on stdout. All logging goes to stderr.
--
-- Unlike the transport contract (RPUSH/BLPOP), the perf contract's
-- reference apps coordinate through a plain Redis string: the listener
-- SETs `{TEST_KEY}_listener_multiaddr` and the dialer polls GET.
--
-- Environment variables (perf contract):
--   IS_DIALER           - "true" or "false"
--   REDIS_ADDR          - Redis host:port (default: "redis:6379")
--   TEST_KEY            - hex key namespacing Redis coordination keys
--   TRANSPORT           - must be "tcp"
--   SECURE_CHANNEL      - "noise" or "tls"
--   MUXER               - must be "yamux"
--   LISTENER_IP         - bind address (default: "0.0.0.0")
--   DEBUG               - accepted but ignored; all logging goes to stderr
--   UPLOAD_BYTES        - bytes per upload iteration (default: 1073741824)
--   DOWNLOAD_BYTES      - bytes per download iteration (default: 1073741824)
--   UPLOAD_ITERATIONS   - upload repetitions (default: 10)
--   DOWNLOAD_ITERATIONS - download repetitions (default: 10)
--   LATENCY_ITERATIONS  - latency repetitions (default: 100)
module Main (main) where

import Control.Concurrent (threadDelay)
import Control.Monad (forM, forever)
import qualified Data.ByteString.Char8 as BS8
import Data.List (find)
import Data.Maybe (fromMaybe)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Word (Word64)
import qualified Database.Redis as Redis
import LibP2P
  ( Connection
  , Multiaddr (..)
  , PeerId
  , PerfResult (..)
  , Protocol (..)
  , Switch
  , addTransport
  , defaultConnectionGater
  , dial
  , fromPublicKey
  , fromText
  , generateKeyPair
  , newSwitchWithConfig
  , defaultSwitchConfig
  , SwitchConfig (..)
  , newTCPTransport
  , peerIdBytes
  , registerPerfHandler
  , runPerf
  , splitP2P
  , switchClose
  , switchListen
  , toBase58
  , toText
  )
import LibP2P.Crypto.Key (publicKey)
import Network.Socket
  ( AddrInfo (..)
  , SockAddr (..)
  , defaultHints
  , getAddrInfo
  , hostAddressToTuple
  )
import qualified Network.Socket as Socket
import PerfInterop.Stats (computeStats, renderStatsYaml)
import System.Environment (lookupEnv)
import System.Exit (exitFailure, exitSuccess)
import System.IO (hFlush, hPutStrLn, stderr, stdout)
import Text.Read (readMaybe)

-- | Bounds Redis polling for the listener address.
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

  uploadBytes   <- getEnvRead "UPLOAD_BYTES" (1073741824 :: Word64)
  downloadBytes <- getEnvRead "DOWNLOAD_BYTES" (1073741824 :: Word64)
  uploadIters   <- getEnvRead "UPLOAD_ITERATIONS" (10 :: Int)
  downloadIters <- getEnvRead "DOWNLOAD_ITERATIONS" (10 :: Int)
  latencyIters  <- getEnvRead "LATENCY_ITERATIONS" (100 :: Int)

  case validateProtocols transport security muxer of
    Left err -> do
      hPutStrLn stderr $ "Unsupported configuration: " ++ err
      exitFailure
    Right () -> pure ()

  let addrKey = BS8.pack (testKey ++ "_listener_multiaddr")

  ekp <- generateKeyPair
  case ekp of
    Left err -> do
      hPutStrLn stderr $ "Key generation failed: " ++ err
      exitFailure
    Right kp -> do
      let pid = fromPublicKey (publicKey kp)
      logInfo $ "PeerId: " ++ T.unpack (toBase58 pid)

      sw <- newSwitchWithConfig (switchConfigFor security) pid kp
      tcp <- newTCPTransport
      addTransport sw tcp
      registerPerfHandler sw

      let (redisHost, redisPort) = parseHostPort redisAddr
      let redisConnInfo = Redis.defaultConnectInfo
            { Redis.connectHost = redisHost
            , Redis.connectPort = Redis.PortNumber (fromIntegral redisPort)
            }
      redisConn <- Redis.checkedConnect redisConnInfo

      case isDialer of
        "false" -> runListener sw pid ip redisConn addrKey
        "true"  -> runDialer sw redisConn addrKey
                     uploadBytes downloadBytes
                     uploadIters downloadIters latencyIters
        other   -> dieWith sw ("Invalid IS_DIALER value: " ++ other)

-- | Listener mode: bind, SET the address in Redis, serve perf requests
-- until the test harness shuts the container down.
runListener :: Switch -> PeerId -> String -> Redis.Connection -> BS8.ByteString -> IO ()
runListener sw pid ip redisConn addrKey = do
  addrText <- listenAndResolve sw pid ip
  logInfo $ "Perf listener on: " ++ T.unpack addrText

  result <- Redis.runRedis redisConn $ Redis.set addrKey (TE.encodeUtf8 addrText)
  case result of
    Left err -> dieWith sw ("Redis SET failed: " ++ show err)
    Right _ -> pure ()

  logInfo "Address published to Redis, serving perf requests..."
  forever $ threadDelay 3600000000

-- | Dialer mode: GET the listener address, dial, run the three
-- measurement groups, and print the YAML results on stdout.
runDialer
  :: Switch -> Redis.Connection -> BS8.ByteString
  -> Word64 -> Word64 -> Int -> Int -> Int -> IO ()
runDialer sw redisConn addrKey uploadBytes downloadBytes uploadIters downloadIters latencyIters = do
  logInfo "Polling Redis for listener address..."
  addrBS <- pollListenerAddr redisConn addrKey
    >>= maybe (dieWith sw "Timed out waiting for listener address") pure
  let addrText = TE.decodeUtf8 addrBS
  logInfo $ "Got listener address: " ++ T.unpack addrText

  (transportAddr, remotePeerId) <-
    either (\err -> dieWith sw ("Failed to parse multiaddr: " ++ err)) pure $
      fromText addrText
        >>= \a -> maybe (Left "multiaddr has no /p2p/ component") Right (splitP2P a)

  logInfo $ "Dialing peer: " ++ T.unpack (toBase58 remotePeerId)
  conn <- dial sw remotePeerId [transportAddr]
    >>= either (\err -> dieWith sw ("Dial failed: " ++ show err)) pure

  logInfo $ "Running upload test (" ++ show uploadIters ++ " iterations)..."
  uploadSamples <- runGroup sw conn uploadBytes 0 uploadIters

  logInfo $ "Running download test (" ++ show downloadIters ++ " iterations)..."
  downloadSamples <- runGroup sw conn 0 downloadBytes downloadIters

  logInfo $ "Running latency test (" ++ show latencyIters ++ " iterations)..."
  latencySamples <- runGroup sw conn 1 1 latencyIters

  putStr $ renderStatsYaml "upload" uploadIters 2 "Gbps" (computeStats uploadSamples)
  putStrLn ""
  putStr $ renderStatsYaml "download" downloadIters 2 "Gbps" (computeStats downloadSamples)
  putStrLn ""
  putStr $ renderStatsYaml "latency" latencyIters 3 "ms" (computeStats latencySamples)
  hFlush stdout

  switchClose sw
  exitSuccess

-- | Run one measurement group: @iters@ perf exchanges, one stream each.
-- Transfers above 100 bytes report throughput in Gbps; smaller ones
-- report round-trip latency in milliseconds (contract convention).
runGroup :: Switch -> Connection -> Word64 -> Word64 -> Int -> IO [Double]
runGroup sw conn uploadBytes downloadBytes iters = do
  let transferBytes = max uploadBytes downloadBytes
  forM [1 .. iters] $ \(i :: Int) -> do
    r <- runPerf sw conn uploadBytes downloadBytes
      >>= either (\err -> dieWith sw ("Perf iteration " ++ show i ++ " failed: " ++ show err)) pure
    let secs = realToFrac (perfElapsed r) :: Double
    pure $ if transferBytes > 100
      then fromIntegral transferBytes * 8 / secs / 1e9
      else secs * 1000

-- | Bind, resolve the non-localhost address, and return the full
-- multiaddr (with /p2p/ suffix) as text.
listenAndResolve :: Switch -> PeerId -> String -> IO T.Text
listenAndResolve sw pid ip = do
  let bindAddr = case fromText (T.pack ("/ip4/" ++ ip ++ "/tcp/0")) of
        Right ma -> ma
        Left err -> error $ "Invalid bind address: " ++ err

  addrs <- switchListen sw defaultConnectionGater [bindAddr]
  case addrs of
    [] -> dieWith sw "switchListen returned no addresses"
    (listenAddr : _) -> do
      actualAddr <- resolveListenAddr listenAddr ip
      let peerIdMH = peerIdBytes pid
      let fullAddr = encapsulateP2P actualAddr peerIdMH
      pure (toText fullAddr)

-- | Poll GET on the listener-multiaddr key every 500ms until it holds a
-- value or 'testTimeoutSeconds' elapses (perf contract coordination).
pollListenerAddr :: Redis.Connection -> BS8.ByteString -> IO (Maybe BS8.ByteString)
pollListenerAddr redisConn addrKey = go (testTimeoutSeconds * 2)
  where
    go :: Int -> IO (Maybe BS8.ByteString)
    go 0 = pure Nothing
    go attemptsLeft = do
      result <- Redis.runRedis redisConn $ Redis.get addrKey
      case result of
        Left err -> do
          hPutStrLn stderr $ "Redis GET failed: " ++ show err
          pure Nothing
        Right (Just value) | not (BS8.null value) -> pure (Just value)
        Right _ -> do
          threadDelay 500000
          go (attemptsLeft - 1)

-- | Validate that we support the requested protocol combination.
validateProtocols :: String -> Maybe String -> Maybe String -> Either String ()
validateProtocols transport security muxer = do
  case transport of
    "tcp" -> pure ()
    other -> Left $ "transport " ++ other ++ " not supported (only tcp)"
  case security of
    Just "noise" -> pure ()
    Just "tls" -> pure ()
    Just other -> Left $ "secure channel " ++ other ++ " not supported (expected noise or tls)"
    Nothing -> Left "SECURE_CHANNEL not set (required for tcp)"
  case muxer of
    Just "yamux" -> pure ()
    Just other -> Left $ "muxer " ++ other ++ " not supported (only yamux)"
    Nothing -> Left "MUXER not set (required for tcp)"

-- | Restrict the upgrade to the secure channel selected by the harness.
switchConfigFor :: Maybe String -> SwitchConfig
switchConfigFor (Just "noise") =
  defaultSwitchConfig {scSecurityProtocols = ["/noise"]}
switchConfigFor (Just "tls") =
  defaultSwitchConfig {scSecurityProtocols = ["/tls/1.0.0"]}
switchConfigFor _ = defaultSwitchConfig

-- | Parse "host:port" string.
parseHostPort :: String -> (String, Int)
parseHostPort s = case break (== ':') s of
  (host, ':' : portStr) -> (host, fromMaybe 6379 (readMaybe portStr))
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

-- | Read an environment variable via 'Read' with a default.
getEnvRead :: Read a => String -> a -> IO a
getEnvRead name def = fromMaybe def . (>>= readMaybe) <$> lookupEnv name

-- | Log the error, close the Switch, and exit non-zero.
dieWith :: Switch -> String -> IO a
dieWith sw msg = do
  hPutStrLn stderr msg
  switchClose sw
  exitFailure

-- | Log to stderr.
logInfo :: String -> IO ()
logInfo msg = hPutStrLn stderr msg >> hFlush stderr
