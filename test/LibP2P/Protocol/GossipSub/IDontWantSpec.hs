module LibP2P.Protocol.GossipSub.IDontWantSpec (spec) where

import Control.Concurrent.STM
import Data.ByteString qualified as BS
import Data.IORef
import Data.Map.Strict qualified as Map
import Data.Set qualified as Set
import Data.Time (UTCTime)
import Data.Time.Clock.POSIX (posixSecondsToUTCTime)
import LibP2P.Crypto.PeerId (PeerId (..))
import LibP2P.Protocol.GossipSub.Heartbeat (heartbeatOnce)
import LibP2P.Protocol.GossipSub.MessageCache (cachePut)
import LibP2P.Protocol.GossipSub.Router
import LibP2P.Protocol.GossipSub.Types
import Test.Hspec

fixedTime :: UTCTime
fixedTime = posixSecondsToUTCTime 1000000

mkPeerId :: Int -> PeerId
mkPeerId n = PeerId (BS.singleton (fromIntegral n))

data Event
  = Sent !PeerId !RPC
  | Validated
  deriving (Show, Eq)

newEventRouter :: GossipSubParams -> IO (GossipSubRouter, IORef [Event])
newEventRouter params = do
  events <- newIORef []
  router <-
    newRouter
      params
      (mkPeerId 0)
      (\pid rpc -> modifyIORef' events (++ [Sent pid rpc]))
      (pure fixedTime)
  pure (router, events)

addTopicPeer :: GossipSubRouter -> PeerId -> PeerProtocol -> Topic -> IO ()
addTopicPeer router pid proto topic = do
  addPeer router pid proto False fixedTime
  atomically
    ( modifyTVar'
        (gsPeers router)
        (Map.adjust (\ps -> ps{psTopics = Set.singleton topic}) pid)
    )

setMesh :: GossipSubRouter -> Topic -> [PeerId] -> IO ()
setMesh router topic peers =
  atomically $
    modifyTVar' (gsMesh router) (Map.insert topic (Set.fromList peers))

unsignedMessage :: Topic -> BS.ByteString -> PubSubMessage
unsignedMessage topic payload =
  PubSubMessage
    { msgFrom = Nothing
    , msgData = payload
    , msgSeqNo = Nothing
    , msgTopic = topic
    , msgSignature = Nothing
    , msgKey = Nothing
    }

sendIDontWant :: GossipSubRouter -> PeerId -> [MessageId] -> IO ()
sendIDontWant router sender mids =
  handleRPC
    router
    sender
    emptyRPC
      { rpcControl =
          Just
            emptyControlMessage
              { ctrlIDontWant = [IDontWant mids]
              }
      }

sentRPCs :: [Event] -> [(PeerId, RPC)]
sentRPCs events = [(pid, rpc) | Sent pid rpc <- events]

idontwantIds :: RPC -> [MessageId]
idontwantIds rpc =
  [ mid
  | Just ctrl <- [rpcControl rpc]
  , idw <- ctrlIDontWant ctrl
  , mid <- idontwantMessageIds idw
  ]

publishedPayloads :: [(PeerId, RPC)] -> [BS.ByteString]
publishedPayloads sent =
  [msgData msg | (_, rpc) <- sent, msg <- rpcPublish rpc]

servePayloads ::
  GossipSubRouter -> IORef [Event] -> PeerId -> [MessageId] -> IO [BS.ByteString]
servePayloads router events requester mids = do
  writeIORef events []
  handleIWant router requester [IWant mids]
  publishedPayloads . sentRPCs <$> readIORef events

spec :: Spec
spec = describe "GossipSub v1.2 IDONTWANT" $ do
  announcementSpec
  suppressionSpec
  limitsSpec
  publishingSpec
  cleanupSpec

announcementSpec :: Spec
announcementSpec = do
  it "sends IDONTWANT before validation only to v1.2 mesh peers" $ do
    let params =
          defaultGossipSubParams
            { paramSignaturePolicy = StrictNoSign
            , paramIDontWantMessageThreshold = 4
            }
        sender = mkPeerId 1
        v12Peer = mkPeerId 2
        v11Peer = mkPeerId 3
        msg = unsignedMessage "blocks" (BS.replicate 4 0x2a)
        mid = defaultMessageId msg
    (router, events) <- newEventRouter params
    addTopicPeer router sender GossipSubV12Peer "blocks"
    addTopicPeer router v12Peer GossipSubV12Peer "blocks"
    addTopicPeer router v11Peer GossipSubPeer "blocks"
    setMesh router "blocks" [sender, v12Peer, v11Peer]
    registerValidator router "blocks" $ \_ _ -> do
      modifyIORef' events (++ [Validated])
      pure ValidationAccept

    handleRPC router sender emptyRPC{rpcPublish = [msg]}

    allEvents <- readIORef events
    take 2 allEvents `shouldBe` [idontwantEvent v12Peer mid, Validated]

  it "does not announce small messages and announces a duplicate only once" $ do
    let params =
          defaultGossipSubParams
            { paramSignaturePolicy = StrictNoSign
            , paramIDontWantMessageThreshold = 4
            }
        sender = mkPeerId 1
        target = mkPeerId 2
        small = unsignedMessage "blocks" (BS.replicate 3 0x01)
        large = unsignedMessage "blocks" (BS.replicate 4 0x02)
    (router, events) <- newEventRouter params
    addTopicPeer router sender GossipSubV12Peer "blocks"
    addTopicPeer router target GossipSubV12Peer "blocks"
    setMesh router "blocks" [sender, target]

    mapM_
      (\msg -> handleRPC router sender emptyRPC{rpcPublish = [msg]})
      [small, large, large]

    announced <- concatMap (idontwantIds . snd) . sentRPCs <$> readIORef events
    announced `shouldBe` [defaultMessageId large]

idontwantEvent :: PeerId -> MessageId -> Event
idontwantEvent pid mid =
  Sent
    pid
    emptyRPC
      { rpcControl =
          Just
            emptyControlMessage
              { ctrlIDontWant = [IDontWant [mid]]
              }
      }

suppressionSpec :: Spec
suppressionSpec =
  it "suppresses forwarding and IWANT responses to a peer that sent IDONTWANT" $ do
    let params = defaultGossipSubParams{paramSignaturePolicy = StrictNoSign}
        requester = mkPeerId 1
        propagationSource = mkPeerId 2
        recipient = mkPeerId 3
        msg = unsignedMessage "blocks" (BS.pack [1, 2, 3])
        mid = defaultMessageId msg
    (router, events) <- newEventRouter params
    mapM_
      (\pid -> addTopicPeer router pid GossipSubV12Peer "blocks")
      [requester, propagationSource, recipient]
    setMesh router "blocks" [requester, propagationSource, recipient]
    atomically $ modifyTVar' (gsMessageCache router) (cachePut mid msg)

    sendIDontWant router requester [mid]
    writeIORef events []
    forwardMessage router propagationSource msg
    handleIWant router requester [IWant [mid]]

    sent <- sentRPCs <$> readIORef events
    [pid | (pid, rpc) <- sent, not (null (rpcPublish rpc))]
      `shouldBe` [recipient]

limitsSpec :: Spec
limitsSpec =
  it "applies per-heartbeat and per-message limits and expires entries by TTL" $ do
    let params =
          defaultGossipSubParams
            { paramSignaturePolicy = StrictNoSign
            , paramMaxIDontWantLength = 1
            , paramMaxIDontWantMessages = 1
            , paramIDontWantMessageTTL = 2
            }
        requester = mkPeerId 1
        mid1 = BS.singleton 1
        mid2 = BS.singleton 2
        mid3 = BS.singleton 3
        mids = [mid1, mid2, mid3]
        payload1 = BS.singleton 11
        payload2 = BS.singleton 22
        payload3 = BS.singleton 33
        messages =
          [ (mid1, unsignedMessage "blocks" payload1)
          , (mid2, unsignedMessage "blocks" payload2)
          , (mid3, unsignedMessage "blocks" payload3)
          ]
    (router, events) <- newEventRouter params
    addTopicPeer router requester GossipSubV12Peer "blocks"
    atomically
      ( modifyTVar'
          (gsMessageCache router)
          ( \cache ->
              foldl (\acc (mid, msg) -> cachePut mid msg acc) cache messages
          )
      )

    sendIDontWant router requester [mid1, mid3]
    sendIDontWant router requester [mid2]
    servePayloads router events requester mids `shouldReturn` [payload2, payload3]

    heartbeatOnce router
    sendIDontWant router requester [mid2]
    servePayloads router events requester mids `shouldReturn` [payload3]

    heartbeatOnce router
    servePayloads router events requester mids `shouldReturn` [payload1, payload3]

    heartbeatOnce router
    servePayloads router events requester mids
      `shouldReturn` [payload1, payload2, payload3]

publishingSpec :: Spec
publishingSpec =
  it "suppresses local publishing to peers that already rejected the message ID" $ do
    let params = defaultGossipSubParams{paramSignaturePolicy = StrictNoSign}
        requester = mkPeerId 1
        topic = "blocks"
        payload = BS.pack [4, 5, 6]
        mid = defaultMessageId (unsignedMessage topic payload)
    (router, events) <- newEventRouter params
    addTopicPeer router requester GossipSubV12Peer topic
    sendIDontWant router requester [mid]
    writeIORef events []

    publish router topic payload Nothing

    sentRPCs <$> readIORef events `shouldReturn` []

cleanupSpec :: Spec
cleanupSpec =
  it "removes IDONTWANT state when a peer disconnects" $ do
    let requester = mkPeerId 1
    (router, _) <- newEventRouter defaultGossipSubParams
    addTopicPeer router requester GossipSubV12Peer "blocks"
    sendIDontWant router requester [BS.pack [1, 2, 3]]

    removePeer router requester

    counts <- readTVarIO (gsIDontWantCounts router)
    unwanted <- readTVarIO (gsDontSendMessageIds router)
    Map.member requester counts `shouldBe` False
    Map.member requester unwanted `shouldBe` False
