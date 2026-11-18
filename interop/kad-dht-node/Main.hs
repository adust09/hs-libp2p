-- | Kademlia DHT interop test node for the libp2p/unified-testing framework.
--
-- Implements the kad-dht test-app contract with three roles:
--
--   * @bootstrap@ - listens, publishes its address to Redis, runs DHT server
--   * @provider@  - listens, dials bootstrap, calls 'provide' + 'putValue',
--                   signals completion via Redis
--   * @querier@   - dials bootstrap, calls 'findProviders' + 'iterativeGetValue',
--                   prints pass/fail YAML on stdout
--
-- All logging goes to stderr. Stdout is reserved for the final pass/fail report.
--
-- Every role registers the Identify handlers. dotnet-libp2p awaits
-- @\/ipfs\/id\/1.0.0@ on every outbound connection before its dial resolves, so
-- a node that does not serve it is undialable from dotnet.
--
-- Environment variables:
--   ROLE       - "bootstrap", "provider", or "querier"
--   TEST_KEY   - hex key namespacing Redis coordination keys
--   REDIS_ADDR - Redis host:port (default: "redis:6379")
module Main (main) where

import Control.Concurrent (threadDelay)
import Control.Monad (forever, join, void)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BS8
import Data.List (find)
import qualified Data.Map as Map
import Data.Maybe (fromMaybe)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Network.Socket
  ( AddrInfo (..)
  , SockAddr (..)
  , defaultHints
  , getAddrInfo
  , hostAddressToTuple
  )
import System.Environment (lookupEnv)
import System.Exit (exitFailure, exitSuccess)
import System.IO (hFlush, hPutStrLn, stderr, stdout)
import System.Timeout (timeout)
import qualified Database.Redis as Redis

import LibP2P
  ( Multiaddr (..)
  , PeerId
  , Protocol (..)
  , Switch
  , addTransport
  , defaultConnectionGater
  , dial
  , fromPublicKey
  , fromText
  , generateKeyPair
  , newSwitch
  , newTCPTransport
  , peerIdBytes
  , splitP2P
  , switchClose
  , switchListen
  , switchListenAddrs
  , toText
  )
import LibP2P.Crypto.Key (KeyPair, publicKey)
import LibP2P.DHT
  ( DHTMode (..)
  , DHTNode (..)
  , ProviderEntry (..)
  , newDHTNode
  , registerDHTHandler
  )
import LibP2P.DHT.API (findProviders, provide, putValue)
import LibP2P.DHT.Lookup (bootstrap, iterativeGetValue)
import LibP2P.DHT.Message (DHTRecord (..))
import LibP2P.Crypto.Protobuf (encodePublicKey)
import LibP2P.DHT.Validator (Validator (..), namespacedValidator, pkValidator)
import LibP2P.Protocol.Identify (registerIdentifyHandlers)

------------------------------------------------------------------------------
-- Constants
------------------------------------------------------------------------------

testTimeoutMicroseconds :: Int
testTimeoutMicroseconds = 120 * 1000000

pollIntervalMicroseconds :: Int
pollIntervalMicroseconds = 200000

------------------------------------------------------------------------------
-- Entry point
------------------------------------------------------------------------------

main :: IO ()
main = do
  role   <- getEnvRequired "ROLE"
  testKey <- getEnvRequired "TEST_KEY"
  logInfo $ "Starting role=" ++ role ++ " testKey=" ++ testKey

  case role of
    "bootstrap" -> runBootstrap testKey
    "provider"  -> runProvider testKey
    "querier"   -> runQuerier testKey
    "goroundtrip" -> runRoundTrip testKey
    other       -> do
      hPutStrLn stderr $ "Unknown ROLE: " ++ other
      exitFailure

------------------------------------------------------------------------------
-- Interop value contract
------------------------------------------------------------------------------

-- | Payload this node stores under the @/example/data/@ key.
--
-- The other implementations in the suite store @"hello from <impl> client"@
-- (py: @"hello from py client"@, dotnet: @"hello from dotnet client"@), so a
-- querier written against an exact payload can never read their records.
interopValue :: String
interopValue = "hello from haskell client"

-- | Substring every implementation's payload shares.
--
-- Queriers match on this marker rather than the full payload so that a record
-- published by any implementation is accepted.
interopMarker :: ByteString
interopMarker = BS8.pack "hello from"

------------------------------------------------------------------------------
-- Bootstrap role
------------------------------------------------------------------------------

runBootstrap :: String -> IO ()
runBootstrap testKey = do
  (kp, pid) <- genIdentity
  tcp <- newTCPTransport
  sw  <- newSwitch pid kp
  addTransport sw tcp
  registerIdentifyHandlers sw
  dhtNode0 <- newDHTNode sw DHTServer
  -- The interop contract stores values in the /example/ namespace, so
  -- configure the server to validate that namespace before serving PUT_VALUE.
  let dhtNode = dhtNode0 { dhtValidator = makeInteropValidator }
  registerDHTHandler dhtNode

  -- Listen on all interfaces
  let bindAddr = case fromText "/ip4/0.0.0.0/tcp/0" of
        Right a -> a
        Left e  -> error $ "invalid bind addr: " ++ e
  addrs <- switchListen sw defaultConnectionGater [bindAddr]
  case addrs of
    []      -> die "switchListen returned no addresses"
    (a : _) -> do
      actualAddr <- resolveListenAddr a "0.0.0.0"
      let fullAddr = encapsulateP2P actualAddr (peerIdBytes pid)

      -- Publish bootstrap address to Redis
      redisConn <- connectRedis
      let addrKey = BS8.pack (testKey ++ "_bootstrap_addr")
      void $ Redis.runRedis redisConn $ Redis.set addrKey (TE.encodeUtf8 (toText fullAddr))
      logInfo $ "Published bootstrap addr: " ++ T.unpack (toText fullAddr)

      -- Keep running
      forever $ threadDelay 1000000

------------------------------------------------------------------------------
-- Provider role
------------------------------------------------------------------------------

runProvider :: String -> IO ()
runProvider testKey = do
  (kp, pid) <- genIdentity
  tcp <- newTCPTransport
  sw  <- newSwitch pid kp
  addTransport sw tcp
  registerIdentifyHandlers sw
  dhtNode0 <- newDHTNode sw DHTServer
  let dhtNode = dhtNode0 { dhtValidator = makeInteropValidator }
  registerDHTHandler dhtNode

  -- Listen
  let bindAddr = case fromText "/ip4/0.0.0.0/tcp/0" of
        Right a -> a
        Left e  -> error $ "invalid bind addr: " ++ e
  addrs <- switchListen sw defaultConnectionGater [bindAddr]
  case addrs of
    [] -> die "switchListen returned no addresses"
    _  -> pure ()

  -- Resolve our actual listen addresses for provider announcement
  listenAddrs <- switchListenAddrs sw
  resolvedAddrs <- mapM (\a -> resolveListenAddr a "0.0.0.0") listenAddrs

  -- Connect to Redis and wait for bootstrap address
  redisConn <- connectRedis
  let addrKey        = BS8.pack (testKey ++ "_bootstrap_addr")
      providerDoneKey = BS8.pack (testKey ++ "_provider_done")

  -- Read bootstrap address
  mBootstrapBytes <- pollRedis redisConn addrKey
  case mBootstrapBytes of
    Nothing -> die "timed out waiting for bootstrap address"
    Just bs -> do
      let bootstrapStr = T.unpack (TE.decodeUtf8 bs)
      case fromText (T.pack bootstrapStr) of
        Left err -> die $ "failed to parse bootstrap addr: " ++ err
        Right ma -> case splitP2P ma of
          Nothing -> die "bootstrap addr missing /p2p/ component"
          Just (transportMA, bootstrapPeerId) -> do
            -- Dial bootstrap node
            result <- dial sw bootstrapPeerId [transportMA]
            case result of
              Left err -> die $ "failed to dial bootstrap: " ++ show err
              Right _  -> do
                logInfo "Connected to bootstrap node"
                -- Dialling alone does not populate a DHT routing table.
                -- Seed it explicitly so the subsequent announcements reach
                -- the bootstrap node.
                bootstrap dhtNode [bootstrapPeerId]

            -- Let the DHT settle
            threadDelay 2000000

            -- Build channel/value keys matching Python reference
            let channelKey    = "interop-test-key-" ++ testKey
                valueKey      = "/example/data/" ++ testKey
                value         = interopValue
                validator     = makeInteropValidator

            -- Provide the channel key
            logInfo $ "Providing content for key: " ++ channelKey
            provide dhtNode resolvedAddrs (BS8.pack channelKey)

            -- Put the value
            logInfo $ "Putting value for key: " ++ valueKey
            putResult <- putValue dhtNode validator (BS8.pack valueKey) (BS8.pack value)
            case putResult of
              Left err -> logInfo $ "putValue failed: " ++ err
              Right () -> logInfo "putValue succeeded"

            -- Signal provider done
            void $ Redis.runRedis redisConn $ Redis.set providerDoneKey (BS8.pack "done")
            logInfo "Provider signaled done"

            -- Keep running (DHT server must stay up for querier)
            forever $ threadDelay 1000000

------------------------------------------------------------------------------
-- Querier role
------------------------------------------------------------------------------

runQuerier :: String -> IO ()
runQuerier testKey = do
  (kp, pid) <- genIdentity
  tcp <- newTCPTransport
  sw  <- newSwitch pid kp
  addTransport sw tcp
  registerIdentifyHandlers sw
  dhtNode   <- newDHTNode sw DHTClient

  -- Build Redis keys
  redisConn       <- connectRedis
  let addrKey         = BS8.pack (testKey ++ "_bootstrap_addr")
      providerDoneKey  = BS8.pack (testKey ++ "_provider_done")

  -- Wait for bootstrap address
  mBootstrapBytes <- pollRedis redisConn addrKey
  case mBootstrapBytes of
    Nothing -> do
      logInfo "Timed out waiting for bootstrap address"
      printFail "bootstrap_addr_timeout"
    Just bs -> do
      let bootstrapStr = T.unpack (TE.decodeUtf8 bs)
      case fromText (T.pack bootstrapStr) of
        Left err -> do
          logInfo $ "Failed to parse bootstrap addr: " ++ err
          printFail "bootstrap_addr_parse_error"
        Right ma -> case splitP2P ma of
          Nothing -> do
            logInfo "Bootstrap addr missing /p2p/ component"
            printFail "bootstrap_missing_p2p"
          Just (transportMA, bootstrapPeerId) -> do
            -- Dial bootstrap node
            result <- dial sw bootstrapPeerId [transportMA]
            case result of
              Left err -> do
                logInfo $ "Failed to dial bootstrap: " ++ show err
                printFail "dial_failed"
              Right _ -> do
                logInfo "Connected to bootstrap node"
                -- Seed the client routing table; otherwise lookups have no
                -- initial candidate and return without sending an RPC.
                bootstrap dhtNode [bootstrapPeerId]

                -- Wait for provider to signal done
                mDone <- pollRedis redisConn providerDoneKey
                case mDone of
                  Nothing -> do
                    logInfo "Timed out waiting for provider done"
                    printFail "provider_timeout"
                  Just _ -> do
                    logInfo "Provider signaled done, starting queries"

                    -- Give DHT time to propagate
                    threadDelay 2000000

                    -- Build query keys
                    let channelKey    = "interop-test-key-" ++ testKey
                        valueKey      = "/example/data/" ++ testKey
                        validator     = makeInteropValidator

                    -- Test 1: findProviders
                    logInfo $ "Querying findProviders for key: " ++ channelKey
                    providers <- findProviders dhtNode (BS8.pack channelKey)
                    let providersOk = not (null providers)

                    -- Test 2: iterativeGetValue
                    logInfo $ "Querying getValue for key: " ++ valueKey
                    getResult <- iterativeGetValue dhtNode validator (BS8.pack valueKey)
                    let valueOk = case getResult of
                          Right rec -> interopMarker `BS8.isInfixOf` recValue rec
                          Left _    -> False

                    -- Print result
                    if providersOk && valueOk
                      then printPass
                      else printFail "query_mismatch"

------------------------------------------------------------------------------
-- go-libp2p GET_VALUE round trip
------------------------------------------------------------------------------

-- | PUT a /pk/ record into a stock go-libp2p Kad-DHT responder
-- (interop/get-value-roundtrip/go-peer) and GET it back with a fresh node.
-- This pins the request-key binding to the real go wire: go's ValueStore
-- only serves records whose embedded key matches the requested key, and the
-- querier must accept that conforming response.
runRoundTrip :: String -> IO ()
runRoundTrip testKey = do
  goAddr <- getEnvRequired "GO_PEER_ADDR"
  (goTransportAddr, goPeerId) <- parsePeerAddr goAddr
  keypair <- do
    ekp <- generateKeyPair
    either die pure ekp
  let recordPeerId = fromPublicKey (publicKey keypair)
      recordKey    = "/pk/" <> peerIdBytes recordPeerId
      recordValue  = encodePublicKey (publicKey keypair)
  publisher <- roundtripNode goTransportAddr goPeerId "publisher"
  -- Never log the raw key: /pk/ keys are binary multihashes and stderr runs
  -- in a non-UTF-8 locale in the interop runtime image.
  logInfo $ "PUT " ++ show (BS8.length recordKey) ++ " bytes into the go responder"
  putResult <- putValue publisher pkValidator recordKey recordValue
  case putResult of
    Left err -> printFail $ "put_failed: " ++ err
    Right () -> pure ()
  querier <- roundtripNode goTransportAddr goPeerId "querier"
  logInfo "GET the record back from the go responder"
  getResult <- iterativeGetValue querier pkValidator recordKey
  case getResult of
    Left err -> printFail $ "get_failed: " ++ err
    Right rec
      | recKey rec == recordKey && recValue rec == recordValue -> printPass
      | otherwise -> printFail "get_mismatch"

roundtripNode :: Multiaddr -> PeerId -> String -> IO DHTNode
roundtripNode transportAddr peerId label = do
  (kp, pid) <- genIdentity
  logInfo $ "Starting " ++ label ++ " node"
  tcp <- newTCPTransport
  sw  <- newSwitch pid kp
  addTransport sw tcp
  registerIdentifyHandlers sw
  dhtNode <- newDHTNode sw DHTClient
  dialResult <- dial sw peerId [transportAddr]
  case dialResult of
    Left err -> printFail (label ++ "_dial_failed: " ++ show err) >> die "dial"
    Right _ -> do
      -- Dialling does not populate the routing table; seed the responder so
      -- the PUT and the later GET have exactly one candidate.
      bootstrap dhtNode [peerId]
      pure dhtNode

-- | Split ".../p2p/<id>" into its transport multiaddr and peer ID.
parsePeerAddr :: String -> IO (Multiaddr, PeerId)
parsePeerAddr raw = case fromText (T.pack raw) of
  Left err -> die $ "failed to parse GO_PEER_ADDR: " ++ err
  Right ma -> case splitP2P ma of
    Nothing -> die "GO_PEER_ADDR is missing a /p2p/ component"
    Just (transportAddr, peerId) -> pure (transportAddr, peerId)

------------------------------------------------------------------------------
-- Identity helpers
------------------------------------------------------------------------------

genIdentity :: IO (KeyPair, PeerId)
genIdentity = do
  ekp <- generateKeyPair
  case ekp of
    Left err -> die $ "key generation failed: " ++ err
    Right kp -> pure (kp, fromPublicKey (publicKey kp))

------------------------------------------------------------------------------
-- Redis helpers
------------------------------------------------------------------------------

connectRedis :: IO Redis.Connection
connectRedis = do
  redisAddr <- fromMaybe "redis:6379" <$> lookupEnv "REDIS_ADDR"
  let (host, port) = parseHostPort redisAddr
      connInfo = Redis.defaultConnectInfo
        { Redis.connectHost = host
        , Redis.connectPort = Redis.PortNumber (fromIntegral port)
        }
  Redis.checkedConnect connInfo

-- | Poll a Redis key until it exists or timeout.
pollRedis :: Redis.Connection -> ByteString -> IO (Maybe ByteString)
pollRedis conn key =
  join <$> timeout testTimeoutMicroseconds loop
  where
    loop = do
      result <- Redis.runRedis conn $ Redis.get key
      case result of
        Left _err            -> threadDelay pollIntervalMicroseconds >> loop
        Right (Just v)       -> pure (Just v)
        Right Nothing        -> threadDelay pollIntervalMicroseconds >> loop

------------------------------------------------------------------------------
-- Network helpers
------------------------------------------------------------------------------

-- | Parse "host:port" string.
parseHostPort :: String -> (String, Int)
parseHostPort s = case break (== ':') s of
  (host, ':' : portStr) -> (host, read portStr)
  (host, _)            -> (host, 6379)

-- | Resolve 0.0.0.0 to actual container IP for Docker networking.
resolveListenAddr :: Multiaddr -> String -> IO Multiaddr
resolveListenAddr addr ip
  | ip == "0.0.0.0" = do
      actualIP <- discoverContainerIP
      case protocols addr of
        (IP4 _ : rest) ->
          case fromText (T.pack ("/ip4/" ++ actualIP)) of
            Right (Multiaddr [IP4 w]) -> pure $ Multiaddr (IP4 w : rest)
            _                         -> pure addr
        _ -> pure addr
  | otherwise = pure addr
  where
    protocols (Multiaddr ps) = ps

-- | Discover actual container IP via hostname resolution.
discoverContainerIP :: IO String
discoverContainerIP = do
  mHostname <- lookupEnv "HOSTNAME"
  case mHostname of
    Nothing     -> pure "0.0.0.0"
    Just hostname -> do
      addrs <- getAddrInfo (Just defaultHints) (Just hostname) Nothing :: IO [AddrInfo]
      case find isNonLoopbackIPv4 addrs of
        Just ai -> pure $ sockAddrToIP (addrAddress ai)
        Nothing -> pure "0.0.0.0"

-- | Extract just the IP string from a SockAddr.
sockAddrToIP :: SockAddr -> String
sockAddrToIP (SockAddrInet _ hostAddr) =
  let (a, b, c, d) = hostAddressToTuple hostAddr
  in show a ++ "." ++ show b ++ "." ++ show c ++ "." ++ show d
sockAddrToIP other = show other

-- | Check if an AddrInfo is a non-loopback IPv4 address.
isNonLoopbackIPv4 :: AddrInfo -> Bool
isNonLoopbackIPv4 ai = case addrAddress ai of
  SockAddrInet _ hostAddr ->
    let (a, _, _, _) = hostAddressToTuple hostAddr
    in a /= 127
  _ -> False

-- | Encapsulate a /p2p/<peerId> suffix onto a multiaddr.
encapsulateP2P :: Multiaddr -> ByteString -> Multiaddr
encapsulateP2P (Multiaddr ps) mhBytes = Multiaddr (ps ++ [P2P mhBytes])

------------------------------------------------------------------------------
-- DHT validator helpers
------------------------------------------------------------------------------

-- | Create a validator that accepts both "pk" and "example" namespaces.
-- The "pk" namespace uses the standard pkValidator (validates provider
-- records). The "example" namespace accepts all key/value pairs.
makeInteropValidator :: Validator
makeInteropValidator =
  namespacedValidator $ Map.fromList
    [ (BS8.pack "pk",      pkValidator)
    , (BS8.pack "example", permissiveValidator)
    ]

-- | A validator that accepts everything.
permissiveValidator :: Validator
permissiveValidator = Validator
  { valValidate = \_ _ -> Right ()
  , valSelect   = \_ _ -> Right 0
  }

------------------------------------------------------------------------------
-- Env helpers
------------------------------------------------------------------------------

getEnvRequired :: String -> IO String
getEnvRequired name = do
  val <- lookupEnv name
  case val of
    Just v  -> pure v
    Nothing -> do
      hPutStrLn stderr $ "Missing required environment variable: " ++ name
      exitFailure

------------------------------------------------------------------------------
-- Logging helpers (stdout = result, stderr = diagnostics)
------------------------------------------------------------------------------

logInfo :: String -> IO ()
logInfo msg = hPutStrLn stderr msg >> hFlush stderr

-- | Print failure YAML and exit with failure.
printFail :: String -> IO ()
printFail reason = do
  putStrLn "status: fail"
  putStrLn $ "reason: " ++ reason
  hFlush stdout
  exitFailure

-- | Print success YAML and exit successfully.
printPass :: IO ()
printPass = do
  putStrLn "status: pass"
  hFlush stdout
  exitSuccess

die :: String -> IO a
die msg = do
  hPutStrLn stderr msg
  exitFailure
