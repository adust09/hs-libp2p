module LibP2P.NAT.AutoNAT.ServiceSpec (spec) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.STM (
  TMVar,
  TVar,
  atomically,
  check,
  modifyTVar',
  newEmptyTMVarIO,
  newTVarIO,
  putTMVar,
  readTMVar,
  readTVar,
 )
import Control.Exception (SomeException, finally, try)
import Control.Monad (forM, void)
import Data.Word (Word8)
import LibP2P.Crypto.Ed25519 (generateKeyPair)
import LibP2P.Crypto.Key (KeyPair, publicKey)
import LibP2P.Crypto.PeerId (PeerId, fromPublicKey)
import LibP2P.Multiaddr (Multiaddr (..))
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.MultistreamSelect.Negotiation (StreamIO (..), closeQuietly)
import LibP2P.NAT.AutoNAT (NATStatus (..))
import LibP2P.NAT.AutoNAT.Message (
  AutoNATDialResponse (..),
  AutoNATMessage (..),
  AutoNATMessageType (..),
  ResponseStatus (..),
  autoNATProtocolId,
  maxAutoNATMessageSize,
  readAutoNATMessage,
  writeAutoNATMessage,
 )
import LibP2P.NAT.AutoNAT.Service (
  AutoNATClientConfig (..),
  AutoNATClientService,
  autoNATClientStatus,
  defaultAutoNATClientConfig,
  startAutoNATClient,
 )
import LibP2P.Switch (addTransport, newSwitch, setStreamHandler, switchClose)
import LibP2P.Switch.ConnPool (allConns)
import LibP2P.Switch.Dial (dial)
import LibP2P.Switch.Listen (defaultConnectionGater, switchListen)
import LibP2P.Switch.Types (Switch (..))
import LibP2P.Transport.TCP (newTCPTransport)
import System.Timeout (timeout)
import Test.Hspec

loopbackAddr :: Multiaddr
loopbackAddr = Multiaddr [IP4 0x7f000001, TCP 0]

mkIdentity :: IO (PeerId, KeyPair)
mkIdentity = do
  Right keyPair <- generateKeyPair
  pure (fromPublicKey (publicKey keyPair), keyPair)

newTCPNode :: IO (Switch, PeerId, Multiaddr)
newTCPNode = do
  (peerId, keyPair) <- mkIdentity
  sw <- newSwitch peerId keyPair
  addTransport sw =<< newTCPTransport
  addrs <- switchListen sw defaultConnectionGater [loopbackAddr]
  case addrs of
    addr : _ -> pure (sw, peerId, addr)
    [] -> fail "listener returned no addresses"

fastConfig :: Int -> AutoNATClientConfig
fastConfig peerCount =
  defaultAutoNATClientConfig
    { ancThreshold = 1
    , ancBootDelayMicros = 1000
    , ancRetryIntervalMicros = 20000
    , ancRefreshIntervalMicros = 1000000
    , ancRequestTimeoutMicros = 1000000
    , ancPeerThrottleMicros = 0
    , ancMaxPeers = peerCount
    }

responseMessage :: ResponseStatus -> AutoNATMessage
responseMessage status =
  AutoNATMessage
    { anMsgType = Just DIAL_RESPONSE
    , anMsgDial = Nothing
    , anMsgDialResponse =
        Just
          AutoNATDialResponse
            { anRespStatus = Just status
            , anRespStatusText = Nothing
            , anRespAddr = Nothing
            }
    }

registerResponseHandler :: Switch -> TVar Int -> ResponseStatus -> IO ()
registerResponseHandler sw probes status =
  setStreamHandler sw autoNATProtocolId $ \_ stream -> do
    request <- readAutoNATMessage stream maxAutoNATMessageSize
    case request of
      Left _ -> pure ()
      Right _ -> do
        atomically $ modifyTVar' probes (+ 1)
        writeAutoNATMessage stream (responseMessage status)
    closeQuietly stream

withProbeNetwork ::
  [ResponseStatus] ->
  (Switch -> TVar Int -> IO a) ->
  IO a
withProbeNetwork statuses action = do
  (client, _, _) <- newTCPNode
  probes <- newTVarIO 0
  servers <- forM statuses $ \status -> do
    (server, peerId, addr) <- newTCPNode
    registerResponseHandler server probes status
    result <- dial client peerId [addr]
    case result of
      Left err -> fail ("dial failed: " ++ show err)
      Right _ -> pure server
  action client probes `finally` mapM_ switchClose (client : servers)

withIndividuallyCountedProbeNetwork ::
  Int ->
  (Switch -> [TVar Int] -> IO a) ->
  IO a
withIndividuallyCountedProbeNetwork serverCount action = do
  (client, _, _) <- newTCPNode
  serversAndProbes <- forM [1 .. serverCount] $ \_ -> do
    probes <- newTVarIO 0
    (server, peerId, addr) <- newTCPNode
    registerResponseHandler server probes EDialRefused
    result <- dial client peerId [addr]
    case result of
      Left err -> fail ("dial failed: " ++ show err)
      Right _ -> pure (server, probes)
  let (servers, probes) = unzip serversAndProbes
  action client probes `finally` mapM_ switchClose (client : servers)

waitForProbeCount :: TVar Int -> Int -> IO ()
waitForProbeCount probes expected = do
  result <- timeout 5000000 $ atomically $ do
    count <- readTVar probes
    check (count >= expected)
  result `shouldBe` Just ()

waitForStatus :: AutoNATClientService -> NATStatus -> IO ()
waitForStatus service expected = do
  result <- timeout 5000000 loop
  result `shouldBe` Just ()
 where
  loop = do
    status <- autoNATClientStatus service
    if status == expected then pure () else threadDelay 1000 >> loop

assertAggregatedStatus :: [ResponseStatus] -> NATStatus -> Expectation
assertAggregatedStatus responses expected =
  withProbeNetwork responses $ \client probes -> do
    service <- startAutoNATClient client (fastConfig (length responses))
    waitForProbeCount probes (length responses)
    case expected of
      NATUnknown -> do
        threadDelay 50000
        autoNATClientStatus service `shouldReturn` NATUnknown
      _ -> waitForStatus service expected

registerBlockingHandler :: Switch -> TMVar () -> TMVar Bool -> IO ()
registerBlockingHandler sw started closed =
  setStreamHandler sw autoNATProtocolId $ \_ stream -> do
    _ <- readAutoNATMessage stream maxAutoNATMessageSize
    atomically $ putTMVar started ()
    result <- try (streamReadByte stream) :: IO (Either SomeException Word8)
    atomically $ putTMVar closed (either (const True) (const False) result)
    closeQuietly stream

spec :: Spec
spec = describe "AutoNAT client service" $ do
  it "becomes public after enough successful dial-back reports" $
    assertAggregatedStatus [StatusOK, StatusOK] NATPublic

  it "becomes private after enough failed dial-back reports" $
    assertAggregatedStatus [EDialError, EDialError] NATPrivate

  it "keeps conflicting reports unknown" $
    assertAggregatedStatus [StatusOK, EDialError] NATUnknown

  it "throttles repeated probes to the same peer" $
    withProbeNetwork [EDialRefused] $ \client probes -> do
      let config =
            (fastConfig 1)
              { ancThreshold = 0
              , ancPeerThrottleMicros = 1000000
              }
      _ <- startAutoNATClient client config
      waitForProbeCount probes 1
      threadDelay 100000
      atomically (readTVar probes) `shouldReturn` 1

  it "rotates probes across all eligible peers" $
    withIndividuallyCountedProbeNetwork 3 $ \client probes -> do
      let config =
            (fastConfig 1)
              { ancThreshold = 0
              , ancMaxPeers = 1
              }
      _ <- startAutoNATClient client config
      result <- timeout 5000000 $ atomically $ do
        counts <- mapM readTVar probes
        check (all (> 0) counts)
      result `shouldBe` Just ()

  it "stays unknown without connected peers and does not dial" $ do
    (client, _, _) <- newTCPNode
    service <- startAutoNATClient client (fastConfig 2)
    threadDelay 100000
    autoNATClientStatus service `shouldReturn` NATUnknown
    connections <- atomically (allConns (swConnPool client))
    length connections `shouldBe` 0
    switchClose client

  it "switchClose cancels an in-flight probe" $ do
    (client, _, _) <- newTCPNode
    (server, serverPeerId, serverAddr) <- newTCPNode
    started <- newEmptyTMVarIO
    closed <- newEmptyTMVarIO
    registerBlockingHandler server started closed
    dialResult <- dial client serverPeerId [serverAddr]
    case dialResult of
      Left err -> expectationFailure ("dial failed: " ++ show err)
      Right _ -> pure ()
    void $ startAutoNATClient client ((fastConfig 1){ancThreshold = 0})
    probeStarted <- timeout 5000000 (atomically $ readTMVar started)
    probeStarted `shouldBe` Just ()
    switchClose client
    streamClosed <- timeout 5000000 (atomically $ readTMVar closed)
    streamClosed `shouldBe` Just True
    switchClose server
