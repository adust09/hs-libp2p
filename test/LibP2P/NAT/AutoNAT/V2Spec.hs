module LibP2P.NAT.AutoNAT.V2Spec (spec) where

import Control.Concurrent.Async (async, cancel, wait)
import Control.Concurrent.STM (TQueue, atomically, newTQueueIO, readTQueue, writeTQueue)
import Data.IORef (newIORef, readIORef, writeIORef)
import qualified Data.ByteString as BS
import Data.Word (Word8)
import LibP2P.Crypto.PeerId (PeerId (..))
import LibP2P.Multiaddr (Multiaddr (..), toBytes)
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.MultistreamSelect.Negotiation (StreamIO, mkByteStreamIO)
import LibP2P.NAT.AutoNAT (NATStatus (..))
import LibP2P.NAT.AutoNAT.V2
import LibP2P.NAT.AutoNAT.V2.Message
import Test.Hspec

mkStreamPair :: IO (StreamIO, StreamIO)
mkStreamPair = do
  leftToRight <- newTQueueIO :: IO (TQueue Word8)
  rightToLeft <- newTQueueIO :: IO (TQueue Word8)
  let stream leftQueue rightQueue = mkByteStreamIO
        (mapM_ (atomically . writeTQueue leftQueue) . BS.unpack)
        (atomically (readTQueue rightQueue))
        (pure ())
  pure
    ( stream leftToRight rightToLeft
    , stream rightToLeft leftToRight
    )

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

runRawRequest
  :: AutoNATV2State
  -> AutoNATV2ServerOps
  -> IO DialResponseV2
runRawRequest state ops = do
  (clientStream, serverStream) <- mkStreamPair
  server <- async $
    handleAutoNATV2DialRequest state ops serverStream peerId publicAddrA
  writeAutoNATV2Message clientStream . V2DialRequest $
    DialRequestV2 [toBytes publicAddrA] 1
  response <- readAutoNATV2Message clientStream
  wait server
  case response of
    Right (V2DialResponse value) -> pure value
    _ -> fail "expected AutoNAT v2 dial response"

isLeft :: Either a b -> Bool
isLeft (Left _) = True
isLeft _ = False
