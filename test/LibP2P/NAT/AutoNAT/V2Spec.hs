module LibP2P.NAT.AutoNAT.V2Spec (spec) where

import Control.Concurrent.Async (async, cancel, wait, waitCatch)
import Control.Concurrent.MVar (newEmptyMVar, putMVar, takeMVar)
import Control.Concurrent.STM
  ( TQueue
  , TVar
  , atomically
  , newTQueueIO
  , newTVarIO
  , readTQueue
  , readTVar
  , writeTQueue
  , writeTVar
  )
import Control.Exception (SomeException, throwIO, try)
import Control.Monad (unless)
import Data.IORef (newIORef, readIORef, writeIORef)
import qualified Data.ByteString as BS
import Data.Word (Word8, Word64)
import LibP2P.Crypto.PeerId (PeerId (..))
import LibP2P.Multiaddr (Multiaddr (..), toBytes)
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.MultistreamSelect.Negotiation
  ( StreamIO
  , mkByteStreamIO
  , streamClose
  , streamWrite
  )
import LibP2P.NAT.AutoNAT (NATStatus (..))
import LibP2P.NAT.AutoNAT.V2
import LibP2P.NAT.AutoNAT.V2.Message
import System.Timeout (timeout)
import Test.Hspec

data ObservedStream = ObservedStream
  { observedIO :: !StreamIO
  , observedClosed :: !(TVar Bool)
  }

mkObservedStreamPair :: IO (ObservedStream, ObservedStream)
mkObservedStreamPair = do
  leftToRight <- newTQueueIO :: IO (TQueue (Maybe Word8))
  rightToLeft <- newTQueueIO :: IO (TQueue (Maybe Word8))
  leftClosed <- newTVarIO False
  rightClosed <- newTVarIO False
  let stream outgoing incoming closed = ObservedStream
        { observedIO = mkByteStreamIO
            (mapM_ (atomically . writeTQueue outgoing . Just) . BS.unpack)
            (atomically (readTQueue incoming) >>= maybe eof pure)
            (atomically $ do
              alreadyClosed <- readTVar closed
              unless alreadyClosed $ do
                writeTVar closed True
                writeTQueue outgoing Nothing)
        , observedClosed = closed
        }
      eof = throwIO (userError "test stream EOF")
  pure
    ( stream leftToRight rightToLeft leftClosed
    , stream rightToLeft leftToRight rightClosed
    )

mkStreamPair :: IO (StreamIO, StreamIO)
mkStreamPair = do
  (left, right) <- mkObservedStreamPair
  pure (observedIO left, observedIO right)

shouldBeClosed :: ObservedStream -> Expectation
shouldBeClosed stream = atomically (readTVar (observedClosed stream)) `shouldReturn` True

peerId :: PeerId
peerId = PeerId "autonat-v2-peer"

publicAddrA :: Multiaddr
publicAddrA = Multiaddr [IP4 0x08080808, TCP 4001]

publicAddrB :: Multiaddr
publicAddrB = Multiaddr [IP4 0x01010101, TCP 4002]

privateAddr :: Multiaddr
privateAddr = Multiaddr [IP4 0x7f000001, TCP 4003]

testConfig :: AutoNATV2Config
testConfig = defaultAutoNATV2Config
  { an2AllowPrivateAddrs = True
  , an2MinDialDataBytes = 5000
  , an2MaxDialDataBytes = 5000
  , an2MaxDialWaitMicros = 0
  , an2DialBackWaitMicros = 200000
  , an2RandomWord64 = pure 42
  , an2Now = pure 1000
  }

runServerClient
  :: AutoNATV2Config
  -> AutoNATV2ServerOps
  -> Multiaddr
  -> [AutoNATV2Request]
  -> IO (Either String AutoNATV2Result)
runServerClient config ops observed requests = do
  serverState <- newAutoNATV2State config
  clientState <- newAutoNATV2State config
  (clientStream, serverStream) <- mkStreamPair
  server <- async $
    handleAutoNATV2DialRequest serverState ops serverStream peerId observed
  result <- requestAutoNATV2 clientState clientStream requests
  cancel server
  pure result

spec :: Spec
spec = do
  describe "AutoNAT v2 server" $ do
    it "dials the first supported public address and reports its original index" $ do
      selectedRef <- newIORef Nothing
      let config = testConfig { an2AllowPrivateAddrs = False }
          ops = AutoNATV2ServerOps
            { an2CanDial = \_ address -> pure (address == publicAddrB)
            , an2DialBack = \_ address _ ->
                writeIORef selectedRef (Just address) >> pure DialStatusError
            }
      result <- runServerClient config ops publicAddrB
        [ AutoNATV2Request privateAddr True
        , AutoNATV2Request publicAddrA True
        , AutoNATV2Request publicAddrB True
        ]
      result `shouldBe` Right AutoNATV2Result
        { an2ResultAddr = Just publicAddrB
        , an2ResultIndex = Just 2
        , an2ResultReachability = NATPrivate
        , an2AllAddrsRefused = False
        }
      readIORef selectedRef `shouldReturn` Just publicAddrB

    it "requires dial data before a cross-IP dial-back" $ do
      dialedRef <- newIORef False
      let ops = AutoNATV2ServerOps
            { an2CanDial = \_ _ -> pure True
            , an2DialBack = \_ _ _ -> writeIORef dialedRef True >> pure DialStatusError
            }
      result <- runServerClient testConfig ops publicAddrA
        [AutoNATV2Request publicAddrB False]
      result `shouldSatisfy` isLeft
      readIORef dialedRef `shouldReturn` False

    it "accepts the bounded dial-data upload before dialing" $ do
      dialedRef <- newIORef False
      let ops = AutoNATV2ServerOps
            { an2CanDial = \_ _ -> pure True
            , an2DialBack = \_ _ _ -> writeIORef dialedRef True >> pure DialStatusError
            }
      result <- runServerClient testConfig ops publicAddrA
        [AutoNATV2Request publicAddrB True]
      fmap an2ResultReachability result `shouldBe` Right NATPrivate
      readIORef dialedRef `shouldReturn` True

    it "enforces the per-peer rolling request limit" $ do
      let config = testConfig { an2ServerPerPeerRPM = 1 }
          ops = AutoNATV2ServerOps
            { an2CanDial = \_ _ -> pure False
            , an2DialBack = \_ _ _ -> pure DialStatusError
            }
      state <- newAutoNATV2State config
      first <- runRawRequest state ops
      second <- runRawRequest state ops
      drsv2Status first `shouldBe` ResponseDialRefused
      drsv2Status second `shouldBe` ResponseRequestRejected

    it "accepts a 4096-byte data field and rejects 4097 bytes before dialing" $ do
      accepted <- runUploadScenario 4096 $ \_ stream ->
        writeAutoNATV2Message stream (V2DialDataResponse (BS.replicate 4096 0))
      uploadDialed accepted `shouldBe` True
      drsv2Status <$> uploadResponse accepted `shouldBe` Just ResponseOK
      uploadServerClosed accepted `shouldBe` True

      rejected <- runUploadScenario 4096 $ \_ stream ->
        writeAutoNATV2Message stream (V2DialDataResponse (BS.replicate 4097 0))
      uploadDialed rejected `shouldBe` False
      uploadResponse rejected `shouldBe` Nothing
      uploadServerClosed rejected `shouldBe` True

    it "rejects incomplete, wrong-kind, and zero-progress uploads without dialing" $ do
      incomplete <- runUploadScenario 5000 $ \_ stream -> do
        writeAutoNATV2Message stream (V2DialDataResponse (BS.replicate 4000 0))
        streamClose stream
      wrongKind <- runUploadScenario 5000 $ \_ stream ->
        writeAutoNATV2Message stream (V2DialRequest (DialRequestV2 [] 0))
      zeroProgress <- runUploadScenario 5000 $ \_ stream ->
        writeAutoNATV2Message stream (V2DialDataResponse BS.empty)
      map uploadDialed [incomplete, wrongKind, zeroProgress] `shouldBe` [False, False, False]
      map uploadServerClosed [incomplete, wrongKind, zeroProgress]
        `shouldBe` [True, True, True]

    it "counts data bytes only and permits a bounded final-chunk overshoot" $ do
      outcome <- runUploadScenario 4100 $ \_ stream -> do
        writeAutoNATV2Message stream (V2DialDataResponse (BS.replicate 4000 0))
        writeAutoNATV2Message stream (V2DialDataResponse (BS.replicate 200 0))
      uploadDialed outcome `shouldBe` True
      drsv2Status <$> uploadResponse outcome `shouldBe` Just ResponseOK

    it "enforces global and cross-IP dial-data rolling limits" $ do
      let ops = refusingOps
          globalConfig = testConfig { an2ServerRPM = 1, an2ServerPerPeerRPM = 2 }
      globalState <- newAutoNATV2State globalConfig
      first <- runRawRequestFor globalState ops (PeerId "peer-a") publicAddrA
      second <- runRawRequestFor globalState ops (PeerId "peer-b") publicAddrA
      drsv2Status first `shouldBe` ResponseDialRefused
      drsv2Status second `shouldBe` ResponseRequestRejected

      let dataConfig = testConfig { an2ServerDialDataRPM = 1 }
          dialingOps = AutoNATV2ServerOps
            { an2CanDial = \_ _ -> pure True
            , an2DialBack = \_ _ _ -> pure DialStatusError
            }
      dataState <- newAutoNATV2State dataConfig
      sameIP <- runClientAgainstState dataState dialingOps publicAddrA (PeerId "same-ip") publicAddrA
      crossIP <- runClientAgainstState dataState dialingOps publicAddrA (PeerId "cross-ip") publicAddrB
      limited <- runClientAgainstState dataState dialingOps publicAddrA (PeerId "limited") publicAddrB
      fmap an2ResultReachability sameIP `shouldBe` Right NATPrivate
      fmap an2ResultReachability crossIP `shouldBe` Right NATPrivate
      limited `shouldSatisfy` isLeft

    it "releases simultaneous-request capacity on cancellation and exceptions" $ do
      entered <- newEmptyMVar
      release <- newEmptyMVar
      let config = testConfig { an2MaxConcurrentPerPeer = 1 }
          blockingOps = AutoNATV2ServerOps
            { an2CanDial = \_ _ -> putMVar entered () >> takeMVar release >> pure False
            , an2DialBack = \_ _ _ -> pure DialStatusError
            }
      state <- newAutoNATV2State config
      (clientStream, serverStream) <- mkStreamPair
      worker <- async $ handleAutoNATV2DialRequest state blockingOps serverStream peerId publicAddrA
      writeAutoNATV2Message clientStream (V2DialRequest (DialRequestV2 [toBytes publicAddrA] 1))
      takeMVar entered
      concurrent <- runRawRequest state refusingOps
      drsv2Status concurrent `shouldBe` ResponseRequestRejected
      cancel worker
      afterCancel <- runRawRequest state refusingOps
      drsv2Status afterCancel `shouldBe` ResponseDialRefused

      let throwingOps = refusingOps
            { an2CanDial = \_ _ -> throwIO (userError "injected canDial failure") }
      (throwClient, throwServer) <- mkStreamPair
      failedWorker <- async $
        handleAutoNATV2DialRequest state throwingOps throwServer peerId publicAddrA
      writeAutoNATV2Message throwClient
        (V2DialRequest (DialRequestV2 [toBytes publicAddrA] 2))
      _ <- waitCatch failedWorker
      afterException <- runRawRequest state refusingOps
      drsv2Status afterException `shouldBe` ResponseDialRefused

    it "recovers rolling request capacity after sixty seconds" $ do
      nowRef <- newIORef 1000
      let config = testConfig
            { an2ServerRPM = 1
            , an2ServerPerPeerRPM = 1
            , an2Now = readIORef nowRef
            }
      state <- newAutoNATV2State config
      first <- runRawRequest state refusingOps
      blocked <- runRawRequest state refusingOps
      writeIORef nowRef 1060
      recovered <- runRawRequest state refusingOps
      drsv2Status first `shouldBe` ResponseDialRefused
      drsv2Status blocked `shouldBe` ResponseRequestRejected
      drsv2Status recovered `shouldBe` ResponseDialRefused

  describe "AutoNAT v2 client and dial-back" $ do
    it "reports public only after the matching nonce arrives on dial-back" $ do
      clientState <- newAutoNATV2State testConfig
      serverState <- newAutoNATV2State testConfig
      (clientStream, serverStream) <- mkStreamPair
      let ops = AutoNATV2ServerOps
            { an2CanDial = \_ _ -> pure True
            , an2DialBack = \_ address nonce -> do
                (dialBackClient, dialBackServer) <- mkStreamPair
                receiver <- async $
                  handleAutoNATV2DialBack clientState dialBackServer address
                writeDialBackV2 dialBackClient (DialBackV2 nonce)
                response <- readDialBackResponseV2 dialBackClient
                wait receiver
                pure $ either (const DialStatusBackError) (const DialStatusOK) response
            }
      server <- async $
        handleAutoNATV2DialRequest serverState ops serverStream peerId publicAddrA
      result <- requestAutoNATV2 clientState clientStream
        [AutoNATV2Request publicAddrA True]
      wait server
      result `shouldBe` Right AutoNATV2Result
        { an2ResultAddr = Just publicAddrA
        , an2ResultIndex = Just 0
        , an2ResultReachability = NATPublic
        , an2AllAddrsRefused = False
        }

    it "rejects an unsolicited nonce instead of trusting the server status" $ do
      let config = testConfig { an2DialBackWaitMicros = 50000 }
      state <- newAutoNATV2State config
      (clientStream, serverStream) <- mkStreamPair
      peer <- async $ do
        Right (V2DialRequest request) <- readAutoNATV2Message serverStream
        writeAutoNATV2Message serverStream . V2DialResponse $
          DialResponseV2 ResponseOK 0 DialStatusOK
        (dialBackClient, dialBackServer) <- mkStreamPair
        receiver <- async $
          handleAutoNATV2DialBack state dialBackServer publicAddrA
        writeDialBackV2 dialBackClient (DialBackV2 (drv2Nonce request + 1))
        wait receiver
      result <- requestAutoNATV2 state clientStream
        [AutoNATV2Request publicAddrA True]
      wait peer
      result `shouldSatisfy` isLeft

    it "rejects a dial-data request above the 100KB protocol maximum" $ do
      state <- newAutoNATV2State testConfig
      (clientStream, serverStream) <- mkStreamPair
      peer <- async $ do
        _ <- readAutoNATV2Message serverStream
        writeAutoNATV2Message serverStream . V2DialDataRequest $
          DialDataRequestV2 0 100001
      result <- requestAutoNATV2 state clientStream
        [AutoNATV2Request publicAddrA True]
      wait peer
      result `shouldSatisfy` isLeft

    it "rejects out-of-range indices and unknown response and dial statuses" $ do
      outOfRange <- runClientResponse (DialResponseV2 ResponseOK 9 DialStatusError)
      unknownResponse <- runClientResponse
        (DialResponseV2 (ResponseStatusUnknown 777) 0 DialStatusUnused)
      unknownDial <- runClientResponse
        (DialResponseV2 ResponseOK 0 (DialStatusUnknown 777))
      outOfRange `shouldBe` Left "AutoNAT v2 address index is out of range"
      unknownResponse `shouldBe` Left "AutoNAT v2 server returned an unknown response status"
      unknownDial `shouldBe` Left "AutoNAT v2 server returned an unknown dial status"

    it "does not accept a matching nonce on an inconsistent transport" $ do
      state <- newAutoNATV2State testConfig
      (clientStream, serverStream) <- mkStreamPair
      peer <- async $ do
        Right (V2DialRequest request) <- readAutoNATV2Message serverStream
        writeAutoNATV2Message serverStream
          (V2DialResponse (DialResponseV2 ResponseOK 0 DialStatusOK))
        deliverDialBack state (drv2Nonce request)
          (Multiaddr [IP4 0x08080808, UDP 4001, QuicV1])
      result <- requestAutoNATV2 state clientStream
        [AutoNATV2Request publicAddrA True]
      wait peer
      result `shouldBe` Left "AutoNAT v2 dial-back did not verify the selected address"

    it "does not reuse a completed nonce and rejects replay into a later request" $ do
      state <- newAutoNATV2State testConfig
      firstNonceRef <- newIORef Nothing
      first <- runSuccessfulClient state publicAddrA $ \nonce ->
        writeIORef firstNonceRef (Just nonce) >> deliverDialBack state nonce publicAddrA
      fmap an2ResultReachability first `shouldBe` Right NATPublic
      Just oldNonce <- readIORef firstNonceRef
      (clientStream, serverStream) <- mkStreamPair
      peer <- async $ do
        Right (V2DialRequest request) <- readAutoNATV2Message serverStream
        drv2Nonce request `shouldNotBe` oldNonce
        writeAutoNATV2Message serverStream
          (V2DialResponse (DialResponseV2 ResponseOK 0 DialStatusOK))
        deliverDialBack state oldNonce publicAddrA
      replayed <- requestAutoNATV2 state clientStream
        [AutoNATV2Request publicAddrA True]
      wait peer
      replayed `shouldSatisfy` isLeft

    it "distinguishes concurrent requests when the nonce source collides" $ do
      state <- newAutoNATV2State testConfig
      firstNonce <- newIORef Nothing
      secondNonce <- newIORef Nothing
      firstRegistered <- newEmptyMVar
      secondRegistered <- newEmptyMVar
      releaseFirst <- newEmptyMVar
      releaseSecond <- newEmptyMVar
      first <- async $ runSuccessfulClient state publicAddrA $ \nonce -> do
        writeIORef firstNonce (Just nonce)
        putMVar firstRegistered ()
        takeMVar releaseFirst
        deliverDialBack state nonce publicAddrA
      takeMVar firstRegistered
      second <- async $ runSuccessfulClient state publicAddrB $ \nonce -> do
        writeIORef secondNonce (Just nonce)
        putMVar secondRegistered ()
        takeMVar releaseSecond
        deliverDialBack state nonce publicAddrB
      takeMVar secondRegistered
      putMVar releaseFirst ()
      putMVar releaseSecond ()
      firstResult <- wait first
      secondResult <- wait second
      fmap an2ResultReachability firstResult `shouldBe` Right NATPublic
      fmap an2ResultReachability secondResult `shouldBe` Right NATPublic
      nonces <- (,) <$> readIORef firstNonce <*> readIORef secondNonce
      nonces `shouldSatisfy` \(left, right) -> left /= right

    it "closes client streams on success, rejection, malformed input, and cancellation" $ do
      state <- newAutoNATV2State testConfig
      (successClient, successServer) <- mkObservedStreamPair
      successPeer <- async $ do
        Right (V2DialRequest request) <- readAutoNATV2Message (observedIO successServer)
        writeAutoNATV2Message (observedIO successServer)
          (V2DialResponse (DialResponseV2 ResponseOK 0 DialStatusOK))
        deliverDialBack state (drv2Nonce request) publicAddrA
      success <- requestAutoNATV2 state (observedIO successClient)
        [AutoNATV2Request publicAddrA True]
      wait successPeer
      fmap an2ResultReachability success `shouldBe` Right NATPublic
      shouldBeClosed successClient

      (rejectedClient, rejectedServer) <- mkObservedStreamPair
      rejectedPeer <- async $ do
        _ <- readAutoNATV2Message (observedIO rejectedServer)
        writeAutoNATV2Message (observedIO rejectedServer)
          (V2DialResponse (DialResponseV2 ResponseDialRefused 0 DialStatusUnused))
      rejected <- requestAutoNATV2 state (observedIO rejectedClient)
        [AutoNATV2Request publicAddrA True]
      wait rejectedPeer
      fmap an2ResultReachability rejected `shouldBe` Right NATUnknown
      fmap an2AllAddrsRefused rejected `shouldBe` Right True
      shouldBeClosed rejectedClient

      (malformedClient, malformedServer) <- mkObservedStreamPair
      malformedPeer <- async $ do
        _ <- readAutoNATV2Message (observedIO malformedServer)
        streamWrite (observedIO malformedServer) (BS.pack [1, 0xff])
      malformed <- requestAutoNATV2 state (observedIO malformedClient)
        [AutoNATV2Request publicAddrA True]
      wait malformedPeer
      malformed `shouldSatisfy` isLeft
      shouldBeClosed malformedClient

      (cancelClient, cancelServer) <- mkObservedStreamPair
      request <- async $ requestAutoNATV2 state (observedIO cancelClient)
        [AutoNATV2Request publicAddrA True]
      _ <- readAutoNATV2Message (observedIO cancelServer)
      cancel request
      shouldBeClosed cancelClient

  describe "addressesConsistent" $ do
    it "allows NAT-mapped port changes but requires the transport stack" $ do
      addressesConsistent
        (Multiaddr [IP4 0x08080808, TCP 55000])
        (Multiaddr [IP4 0x08080808, TCP 4001])
        `shouldBe` True
      addressesConsistent
        (Multiaddr [IP4 0x08080808, UDP 4001, QuicV1])
        (Multiaddr [IP4 0x08080808, TCP 4001])
        `shouldBe` False

    it "allows a DNS request to resolve to the matching IP family" $ do
      addressesConsistent
        (Multiaddr [IP4 0x08080808, TCP 4001])
        (Multiaddr [DNS4 "example.com", TCP 4001])
        `shouldBe` True

    it "distinguishes secure and plaintext WebSocket transports" $ do
      addressesConsistent
        (Multiaddr [IP4 0x08080808, TCP 4001, WS])
        (Multiaddr [IP4 0x08080808, TCP 4001, WSS])
        `shouldBe` False

data UploadOutcome = UploadOutcome
  { uploadDialed :: !Bool
  , uploadResponse :: !(Maybe DialResponseV2)
  , uploadServerClosed :: !Bool
  }

runUploadScenario
  :: Word64
  -> (Word64 -> StreamIO -> IO ())
  -> IO UploadOutcome
runUploadScenario requestedBytes sendUpload = do
  let config = testConfig
        { an2MinDialDataBytes = requestedBytes
        , an2MaxDialDataBytes = requestedBytes
        }
  state <- newAutoNATV2State config
  dialedRef <- newIORef False
  let ops = AutoNATV2ServerOps
        { an2CanDial = \_ _ -> pure True
        , an2DialBack = \_ _ _ -> writeIORef dialedRef True >> pure DialStatusError
        }
  (client, serverStream) <- mkObservedStreamPair
  worker <- async $
    handleAutoNATV2DialRequest state ops (observedIO serverStream) peerId publicAddrA
  writeAutoNATV2Message (observedIO client)
    (V2DialRequest (DialRequestV2 [toBytes publicAddrB] 9))
  Right (V2DialDataRequest request) <- readAutoNATV2Message (observedIO client)
  sendUpload (ddrv2NumBytes request) (observedIO client)
  received <- timeout 2000000 $
    try (readAutoNATV2Message (observedIO client))
      :: IO (Maybe (Either SomeException (Either String AutoNATV2Message)))
  finished <- timeout 2000000 (waitCatch worker)
  case finished of
    Nothing -> cancel worker >> expectationFailure "AutoNAT v2 upload handler did not terminate"
    Just _ -> pure ()
  dialed <- readIORef dialedRef
  closed <- atomically $ readTVar (observedClosed serverStream)
  let response = case received of
        Just (Right (Right (V2DialResponse value))) -> Just value
        _ -> Nothing
  pure UploadOutcome
    { uploadDialed = dialed
    , uploadResponse = response
    , uploadServerClosed = closed
    }

refusingOps :: AutoNATV2ServerOps
refusingOps = AutoNATV2ServerOps
  { an2CanDial = \_ _ -> pure False
  , an2DialBack = \_ _ _ -> pure DialStatusError
  }

runClientAgainstState
  :: AutoNATV2State
  -> AutoNATV2ServerOps
  -> Multiaddr
  -> PeerId
  -> Multiaddr
  -> IO (Either String AutoNATV2Result)
runClientAgainstState serverState ops observed requestPeer address = do
  clientState <- newAutoNATV2State testConfig
  (clientStream, serverStream) <- mkStreamPair
  server <- async $
    handleAutoNATV2DialRequest serverState ops serverStream requestPeer observed
  result <- requestAutoNATV2 clientState clientStream [AutoNATV2Request address True]
  _ <- waitCatch server
  pure result

runClientResponse :: DialResponseV2 -> IO (Either String AutoNATV2Result)
runClientResponse response = do
  state <- newAutoNATV2State testConfig
  (clientStream, serverStream) <- mkStreamPair
  peer <- async $ do
    _ <- readAutoNATV2Message serverStream
    writeAutoNATV2Message serverStream (V2DialResponse response)
  result <- requestAutoNATV2 state clientStream [AutoNATV2Request publicAddrA True]
  wait peer
  pure result

runSuccessfulClient
  :: AutoNATV2State
  -> Multiaddr
  -> (Word64 -> IO ())
  -> IO (Either String AutoNATV2Result)
runSuccessfulClient state address onNonce = do
  (clientStream, serverStream) <- mkStreamPair
  peer <- async $ do
    Right (V2DialRequest request) <- readAutoNATV2Message serverStream
    writeAutoNATV2Message serverStream
      (V2DialResponse (DialResponseV2 ResponseOK 0 DialStatusOK))
    onNonce (drv2Nonce request)
  result <- requestAutoNATV2 state clientStream [AutoNATV2Request address True]
  wait peer
  pure result

deliverDialBack :: AutoNATV2State -> Word64 -> Multiaddr -> IO ()
deliverDialBack state nonce address = do
  (clientStream, serverStream) <- mkStreamPair
  receiver <- async $ handleAutoNATV2DialBack state serverStream address
  writeDialBackV2 clientStream (DialBackV2 nonce)
  response <- timeout 2000000
    (try (readDialBackResponseV2 clientStream) :: IO (Either SomeException (Either String ())))
  case response of
    Nothing -> expectationFailure "AutoNAT v2 dial-back response timed out"
    Just _ -> pure ()
  finished <- timeout 2000000 (waitCatch receiver)
  case finished of
    Nothing -> cancel receiver >> expectationFailure "AutoNAT v2 dial-back handler did not terminate"
    Just _ -> pure ()
  pure ()

runRawRequest
  :: AutoNATV2State
  -> AutoNATV2ServerOps
  -> IO DialResponseV2
runRawRequest state ops = runRawRequestFor state ops peerId publicAddrA

runRawRequestFor
  :: AutoNATV2State
  -> AutoNATV2ServerOps
  -> PeerId
  -> Multiaddr
  -> IO DialResponseV2
runRawRequestFor state ops requestPeer observed = do
  (clientStream, serverStream) <- mkStreamPair
  server <- async $
    handleAutoNATV2DialRequest state ops serverStream requestPeer observed
  writeAutoNATV2Message clientStream . V2DialRequest $
    DialRequestV2 [toBytes publicAddrA] 1
  response <- readAutoNATV2Message clientStream
  _ <- waitCatch server
  case response of
    Right (V2DialResponse value) -> pure value
    _ -> fail "expected AutoNAT v2 dial response"

isLeft :: Either a b -> Bool
isLeft (Left _) = True
isLeft _ = False
