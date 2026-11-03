-- | Tests for NAT protocol handler registration on the Switch (issue #152).
--
-- Verifies that registerNATHandlers registers AutoNAT v1/v2, Circuit Relay v2
-- hop/stop, and DCUtR protocol handlers, and that an inbound stream for each
-- protocol is dispatched to the right handler over a real TCP connection.
module LibP2P.NAT.RegistrationSpec (spec) where

import Control.Concurrent (threadDelay)
import Data.Maybe (isJust)
import LibP2P.Crypto.Ed25519 (generateKeyPair)
import LibP2P.Crypto.Key (KeyPair, publicKey)
import LibP2P.Crypto.PeerId (PeerId (..), fromPublicKey, peerIdBytes)
import LibP2P.Multiaddr (Multiaddr (..), toBytes)
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.MultistreamSelect.Negotiation
  ( NegotiationResult (..)
  , ProtocolId
  , StreamIO (..)
  , negotiateInitiator
  )
import LibP2P.NAT
  ( NATConfig (..)
  , NATServices (..)
  , autoNATClientStatus
  , checkAutoNATV2
  , defaultNATConfig
  , registerNATHandlers
  )
import LibP2P.NAT.AutoNAT (NATStatus (..), requestAutoNAT)
import LibP2P.NAT.AutoNAT.Message
  ( ResponseStatus (..)
  , anRespStatus
  , autoNATProtocolId
  )
import LibP2P.NAT.AutoNAT.V2
  ( AutoNATV2Config (..)
  , AutoNATV2Request (..)
  , AutoNATV2Result (..)
  , AutoNATV2State
  , defaultAutoNATV2Config
  )
import LibP2P.NAT.AutoNAT.V2.Message
  ( autoNATV2DialBackProtocolId
  , autoNATV2DialProtocolId
  )
import LibP2P.NAT.DCUtR.Message
  ( HolePunchMessage (..)
  , HolePunchType (..)
  , dcutrProtocolId
  , maxDCUtRMessageSize
  , readHolePunchMessage
  , writeHolePunchMessage
  )
import LibP2P.NAT.Relay.Client (makeReservation)
import LibP2P.NAT.Relay.Message
  ( HopMessage (..)
  , RelayPeer (..)
  , RelayStatus (..)
  , StopMessage (..)
  , StopMessageType (..)
  , hopProtocolId
  , maxRelayMessageSize
  , readStopMessage
  , stopProtocolId
  , writeStopMessage
  )
import LibP2P.Protocol.Identify (buildLocalIdentify)
import LibP2P.Protocol.Identify.Message (IdentifyInfo (..))
import LibP2P.Switch (addTransport, lookupStreamHandler, newSwitch, switchClose)
import LibP2P.Switch.Connection (newStream)
import LibP2P.Switch.Dial (dial)
import LibP2P.Switch.Listen (defaultConnectionGater, switchListen)
import LibP2P.Switch.Types (Connection (..), Switch)
import LibP2P.Transport.TCP (newTCPTransport)
import System.Timeout (timeout)
import Test.Hspec

-- | Generate a test identity (PeerId, KeyPair).
mkTestIdentity :: IO (PeerId, KeyPair)
mkTestIdentity = do
  Right kp <- generateKeyPair
  let pid = fromPublicKey (publicKey kp)
  pure (pid, kp)

-- | Loopback address with port 0 (OS assigns ephemeral port).
loopbackAddr :: Multiaddr
loopbackAddr = Multiaddr [IP4 0x7f000001, TCP 0]

-- | Server B registers NAT handlers and listens; client A (also listening,
-- so AutoNAT dial-back can succeed) dials B. The action receives A's switch,
-- peer id and listen addrs, B's switch and peer id, and A's connection to B.
withNATPair
  :: NATConfig
  -> ((Switch, PeerId, [Multiaddr], AutoNATV2State) -> (Switch, PeerId) -> Connection -> IO a)
  -> IO a
withNATPair config action = do
  -- Node B: NAT server
  (pidB, kpB) <- mkTestIdentity
  swB <- newSwitch pidB kpB
  addTransport swB =<< newTCPTransport
  _ <- registerNATHandlers swB config
  addrsB <- switchListen swB defaultConnectionGater [loopbackAddr]
  -- Node A: client, listening so B can dial back
  (pidA, kpA) <- mkTestIdentity
  swA <- newSwitch pidA kpA
  addTransport swA =<< newTCPTransport
  (_, _, natServicesA) <- registerNATHandlers swA config
  let autoNATV2StateA = nsAutoNATV2State natServicesA
  addrsA <- switchListen swA defaultConnectionGater [loopbackAddr]
  addrB <- case addrsB of
    address : _ -> pure address
    [] -> fail "withNATPair: server did not bind a listen address"
  dialResult <- dial swA pidB [addrB]
  case dialResult of
    Left err -> do
      switchClose swA
      switchClose swB
      fail $ "withNATPair: dial failed: " ++ show err
    Right conn -> do
      threadDelay 300000
      result <- action (swA, pidA, addrsA, autoNATV2StateA) (swB, pidB) conn
      switchClose swA
      switchClose swB
      pure result

-- | Open a stream on the connection and negotiate the given protocol.
openProtoStream :: Switch -> Connection -> ProtocolId -> IO StreamIO
openProtoStream sw conn proto = do
  streamOrErr <- newStream sw conn
  case streamOrErr of
    Left err -> fail $ "newStream failed: " ++ show err
    Right stream -> do
      result <- negotiateInitiator stream [proto]
      case result of
        Accepted _ -> pure stream
        NoProtocol -> fail $ "protocol not supported by remote: " ++ show proto

spec :: Spec
spec = do
  describe "registerNATHandlers" $ do
    it "registers AutoNAT v1/v2, relay hop/stop and DCUtR handlers" $ do
      (pid, kp) <- mkTestIdentity
      sw <- newSwitch pid kp
      (_, _, natServices) <- registerNATHandlers sw defaultNATConfig
      mapM_
        (\proto -> do
          mHandler <- lookupStreamHandler sw proto
          (proto, isJust mHandler) `shouldBe` (proto, True))
        [ autoNATProtocolId
        , autoNATV2DialProtocolId
        , autoNATV2DialBackProtocolId
        , hopProtocolId
        , stopProtocolId
        , dcutrProtocolId
        ]
      autoNATClientStatus (nsAutoNATClient natServices) `shouldReturn` NATUnknown
      switchClose sw

    it "registered NAT protocols appear in the local identify protocol list" $ do
      (pid, kp) <- mkTestIdentity
      sw <- newSwitch pid kp
      _state <- registerNATHandlers sw defaultNATConfig
      info <- buildLocalIdentify sw Nothing
      mapM_ (\proto -> idProtocols info `shouldContain` [proto])
        [ autoNATProtocolId
        , autoNATV2DialProtocolId
        , autoNATV2DialBackProtocolId
        , hopProtocolId
        , stopProtocolId
        , dcutrProtocolId
        ]
      switchClose sw

  describe "inbound stream dispatch" $ do
    it "dispatches /libp2p/autonat/1.0.0 to the AutoNAT handler (dial-back OK)" $ do
      withNATPair defaultNATConfig $ \(swA, pidA, addrsA, _v2State) _nodeB conn -> do
        result <- timeout 10000000 $ do
          stream <- openProtoStream swA conn autoNATProtocolId
          requestAutoNAT stream pidA addrsA
        case result of
          Nothing -> expectationFailure "autonat request timed out"
          Just (Left err) -> expectationFailure $ "autonat request failed: " ++ err
          Just (Right resp) -> anRespStatus resp `shouldBe` Just StatusOK

    it "dispatches AutoNAT v2 request and dial-back protocols over TCP" $ do
      let v2Config = defaultAutoNATV2Config
            { an2AllowPrivateAddrs = True
            , an2MaxDialWaitMicros = 0
            }
          config = defaultNATConfig { ncAutoNATV2Config = v2Config }
      withNATPair config $ \(swA, _pidA, addrsA, v2State) _nodeB conn -> do
        addrA <- case addrsA of
          address : _ -> pure address
          [] -> fail "AutoNAT v2 client did not bind a listen address"
        result <- timeout 10000000 $
          checkAutoNATV2 swA v2State conn
            [AutoNATV2Request addrA True]
        case result of
          Nothing -> expectationFailure "AutoNAT v2 request timed out"
          Just (Left err) -> expectationFailure $ "AutoNAT v2 request failed: " ++ err
          Just (Right response) -> do
            an2ResultAddr response `shouldBe` Just addrA
            an2ResultReachability response `shouldBe` NATPublic

    it "dispatches /libp2p/circuit/relay/0.2.0/hop to the relay hop handler" $ do
      withNATPair defaultNATConfig $ \(swA, _pidA, _addrsA, _v2State) _nodeB conn -> do
        result <- timeout 10000000 $ do
          stream <- openProtoStream swA conn hopProtocolId
          makeReservation stream
        case result of
          Nothing -> expectationFailure "hop reserve timed out"
          Just (Left err) -> expectationFailure $ "hop reserve failed: " ++ err
          Just (Right resp) -> hopStatus resp `shouldBe` Just RelayOK

    it "dispatches /libp2p/circuit/relay/0.2.0/stop to the relay stop handler" $ do
      -- After the CONNECT/OK exchange the stop stream becomes the relayed
      -- connection and is handed to the circuit transport. With no
      -- reservation held here there is no listener to accept it, so the
      -- observable evidence that the handler ran is the OK status.
      withNATPair defaultNATConfig $ \(swA, pidA, _addrsA, _v2State) _nodeB conn -> do
        result <- timeout 10000000 $ do
          stream <- openProtoStream swA conn stopProtocolId
          writeStopMessage stream StopMessage
            { stopType = Just StopConnect
            , stopPeer = Just RelayPeer { rpId = peerIdBytes pidA, rpAddrs = [] }
            , stopLimit = Nothing
            , stopStatus = Nothing
            }
          readStopMessage stream maxRelayMessageSize
        case result of
          Nothing -> expectationFailure "stop connect timed out"
          Just (Left err) -> expectationFailure $ "stop connect failed: " ++ err
          Just (Right resp) -> stopStatus resp `shouldBe` Just RelayOK

    it "dispatches /libp2p/dcutr to the DCUtR handler" $ do
      withNATPair defaultNATConfig $ \(swA, _pidA, addrsA, _v2State) _nodeB conn -> do
        result <- timeout 10000000 $ do
          stream <- openProtoStream swA conn dcutrProtocolId
          writeHolePunchMessage stream HolePunchMessage
            { hpType = HPConnect
            , hpObsAddrs = map toBytes addrsA
            }
          readHolePunchMessage stream maxDCUtRMessageSize
        case result of
          Nothing -> expectationFailure "dcutr exchange timed out"
          Just (Left err) -> expectationFailure $ "dcutr exchange failed: " ++ err
          Just (Right resp) -> do
            hpType resp `shouldBe` HPConnect
            -- The handler advertises B's listen addresses
            hpObsAddrs resp `shouldSatisfy` (not . null)

