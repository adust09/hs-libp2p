module LibP2P.Protocol.GossipSub.PartialMessagesSpec (spec) where

import Control.Concurrent.STM
import Control.Monad (replicateM_)
import qualified Data.ByteString as BS
import Data.IORef
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import Data.Time (getCurrentTime)
import LibP2P.Crypto.PeerId (PeerId (..))
import LibP2P.Protocol.GossipSub.Extensions (markExtensionAdvertisementSent)
import LibP2P.Protocol.GossipSub.PartialMessages
import LibP2P.Protocol.GossipSub.Router
import LibP2P.Protocol.GossipSub.Types
import Test.Hspec

spec :: Spec
spec = describe "GossipSub partial messages" $ do
  it "publishes data only to requesting peers and metadata to capable peers" $ do
    (router, sent) <- mkRouter
    extension <- newExtension noIncoming noGossip
    installPartialMessages router extension `shouldReturn` Right ()
    joinPartial router topic RequestsPartialMessages
    let requester = mkPeer 1
        sender = mkPeer 2
    connectPeer router requester RequestsPartialMessages
    connectPeer router sender SupportsPartialMessages
    atomically $
      writeTVar
        (gsMesh router)
        (Map.singleton topic (Set.fromList [requester, sender]))
    writeIORef sent []

    let plan states requests = do
          requests requester `shouldBe` True
          requests sender `shouldBe` False
          Map.keysSet states `shouldBe` Set.fromList [requester, sender]
          pure
            PartialCallbackResult
              { partialUpdatedPeerStates = states
              , partialPublishActions =
                  [ PartialPublishAction requester (Just "part-a") (Just "meta-a")
                  , PartialPublishAction sender (Just "part-b") (Just "meta-b")
                  ]
              }
    publishPartial extension topic "group" plan `shouldReturn` Right ()

    messages <- readIORef sent
    lookupPartial requester messages
      `shouldBe` Just (PartialMessage topic "group" (Just "part-a") (Just "meta-a"))
    lookupPartial sender messages
      `shouldBe` Just (PartialMessage topic "group" Nothing (Just "meta-b"))

  it "does not send full publications to peers requesting partial messages" $ do
    (router, sent) <- mkRouter
    extension <- newExtension noIncoming noGossip
    installPartialMessages router extension `shouldReturn` Right ()
    joinPartial router topic SupportsPartialMessages
    let requester = mkPeer 3
        fullPeer = mkPeer 4
    connectPeer router requester RequestsPartialMessages
    connectFullPeer router fullPeer
    writeIORef sent []

    publish router topic "full-message" Nothing
    messages <- readIORef sent
    any (hasPublishedMessage requester) messages `shouldBe` False
    any (hasPublishedMessage fullPeer) messages `shouldBe` True

  it "does not forward full messages to peers requesting partial messages" $ do
    (router, sent) <- mkRouter
    extension <- newExtension noIncoming noGossip
    installPartialMessages router extension `shouldReturn` Right ()
    joinPartial router topic SupportsPartialMessages
    let source = mkPeer 12
        requester = mkPeer 13
        fullPeer = mkPeer 14
    connectFullPeer router source
    connectPeer router requester RequestsPartialMessages
    connectFullPeer router fullPeer
    atomically $
      writeTVar
        (gsMesh router)
        (Map.singleton topic (Set.fromList [source, requester, fullPeer]))
    writeIORef sent []

    let message = PubSubMessage Nothing "forward-me" Nothing topic Nothing Nothing
    handleRPC router source emptyRPC{rpcPublish = [message]}
    messages <- readIORef sent
    any (hasPublishedMessage requester) messages `shouldBe` False
    any (hasPublishedMessage fullPeer) messages `shouldBe` True

  it "skips IDONTWANT for peers that can satisfy a local partial request" $ do
    (router, sent) <- mkRouter
    extension <- newExtension noIncoming noGossip
    installPartialMessages router extension `shouldReturn` Right ()
    joinPartial router topic RequestsPartialMessages
    let source = mkPeer 15
        partialSender = mkPeer 16
    connectFullPeer router source
    connectPeer router partialSender SupportsPartialMessages
    atomically $
      writeTVar
        (gsMesh router)
        (Map.singleton topic (Set.fromList [source, partialSender]))
    writeIORef sent []

    let large = BS.replicate 1024 0x42
        message = PubSubMessage Nothing large Nothing topic Nothing Nothing
    handleRPC router source emptyRPC{rpcPublish = [message]}
    messages <- readIORef sent
    any (hasIDontWant partialSender) messages `shouldBe` False

  it "delivers inbound partial messages without requiring mesh membership" $ do
    (router, _) <- mkRouter
    received <- newIORef []
    let onIncoming peer states partial = do
          modifyIORef' received ((peer, partial) :)
          pure (PartialCallbackResult states [])
    extension <- newExtension onIncoming noGossip
    installPartialMessages router extension `shouldReturn` Right ()
    joinPartial router topic RequestsPartialMessages
    let peer = mkPeer 5
        partial = PartialMessage topic "remote-group" (Just "part") (Just "meta")
    connectPeer router peer SupportsPartialMessages

    handleRPC router peer emptyRPC{rpcPartial = Just partial}
    readIORef received `shouldReturn` [(peer, partial)]
    mesh <- readTVarIO (gsMesh router)
    Map.findWithDefault Set.empty topic mesh `shouldBe` Set.empty

  it "penalizes peer-initiated groups beyond the configured limits" $ do
    (router, _) <- mkRouter
    callbacks <- newIORef (0 :: Int)
    let onIncoming _ states _ = do
          modifyIORef' callbacks (+ 1)
          pure (PartialCallbackResult states [])
        config =
          (defaultPartialMessagesConfig 0 onIncoming noGossip)
            { partialPeerGroupLimitPerTopic = 1
            , partialPeerGroupLimitPerTopicPerPeer = 1
            }
    extension <- newPartialMessagesExtension config
    installPartialMessages router extension `shouldReturn` Right ()
    joinPartial router topic RequestsPartialMessages
    let peer = mkPeer 6
    connectPeer router peer SupportsPartialMessages

    handleRPC
      router
      peer
      emptyRPC
        { rpcPartial = Just (PartialMessage topic "group-1" (Just "a") Nothing)
        }
    handleRPC
      router
      peer
      emptyRPC
        { rpcPartial = Just (PartialMessage topic "group-2" (Just "b") Nothing)
        }

    readIORef callbacks `shouldReturn` 1
    peers <- readTVarIO (gsPeers router)
    psBehaviorPenalty (peers Map.! peer) `shouldBe` 1

  it "removes empty group state when its only peer disconnects" $ do
    (router, _) <- mkRouter
    gossipCalls <- newIORef (0 :: Int)
    let onGossip _ _ _ states = do
          modifyIORef' gossipCalls (+ 1)
          pure (PartialCallbackResult states [])
    extension <- newExtension noIncoming onGossip
    installPartialMessages router extension `shouldReturn` Right ()
    joinPartial router topic SupportsPartialMessages
    let meshPeer = mkPeer 10
        laterPeer = mkPeer 11
    connectPeer router meshPeer RequestsPartialMessages
    connectPeer router laterPeer RequestsPartialMessages
    atomically $
      writeTVar
        (gsMesh router)
        (Map.singleton topic (Set.singleton meshPeer))
    publishPartial
      extension
      topic
      "group"
      (\states _ -> pure (PartialCallbackResult states []))
      `shouldReturn` Right ()

    removePeer router meshPeer
    Just hooks <- readTVarIO (gsPartialMessagesHooks router)
    pmhEmitGossip hooks topic [laterPeer]
    readIORef gossipCalls `shouldReturn` 0

  it "expires locally initiated groups after the configured heartbeat TTL" $ do
    (router, _) <- mkRouter
    gossipCalls <- newIORef ([] :: [[PeerId]])
    let onGossip _ _ newPeers states = do
          modifyIORef' gossipCalls (newPeers :)
          pure (PartialCallbackResult states [])
        config =
          (defaultPartialMessagesConfig 0 noIncoming onGossip)
            { partialGroupTTLHeartbeats = 3
            }
    extension <- newPartialMessagesExtension config
    installPartialMessages router extension `shouldReturn` Right ()
    joinPartial router topic SupportsPartialMessages
    let meshPeer = mkPeer 7
        firstGossipPeer = mkPeer 8
        afterExpiryPeer = mkPeer 9
    mapM_
      (\peer -> connectPeer router peer RequestsPartialMessages)
      [meshPeer, firstGossipPeer, afterExpiryPeer]
    atomically $
      writeTVar
        (gsMesh router)
        (Map.singleton topic (Set.singleton meshPeer))

    publishPartial
      extension
      topic
      "group"
      (\states _ -> pure (PartialCallbackResult states []))
      `shouldReturn` Right ()
    Just hooks <- readTVarIO (gsPartialMessagesHooks router)
    pmhEmitGossip hooks topic [firstGossipPeer]
    readIORef gossipCalls `shouldReturn` [[firstGossipPeer]]
    replicateM_ 4 (pmhHeartbeat hooks)
    pmhEmitGossip hooks topic [afterExpiryPeer]
    readIORef gossipCalls `shouldReturn` [[firstGossipPeer]]

topic :: Topic
topic = "blocks"

mkRouter :: IO (GossipSubRouter, IORef [(PeerId, RPC)])
mkRouter = do
  sent <- newIORef []
  let params = defaultGossipSubParams{paramSignaturePolicy = StrictNoSign}
  router <-
    newRouter
      params
      (mkPeer 0)
      (\peer rpc -> modifyIORef' sent ((peer, rpc) :))
      getCurrentTime
  pure (router, sent)

newExtension ::
  (PeerId -> Map.Map PeerId Int -> PartialMessage -> IO (PartialCallbackResult Int)) ->
  ( Topic ->
    BS.ByteString ->
    [PeerId] ->
    Map.Map PeerId Int ->
    IO (PartialCallbackResult Int)
  ) ->
  IO (PartialMessagesExtension Int)
newExtension onIncoming onGossip =
  newPartialMessagesExtension (defaultPartialMessagesConfig 0 onIncoming onGossip)

noIncoming ::
  PeerId -> Map.Map PeerId Int -> PartialMessage -> IO (PartialCallbackResult Int)
noIncoming _ states _ = pure (PartialCallbackResult states [])

noGossip ::
  Topic ->
  BS.ByteString ->
  [PeerId] ->
  Map.Map PeerId Int ->
  IO (PartialCallbackResult Int)
noGossip _ _ _ states = pure (PartialCallbackResult states [])

connectPeer :: GossipSubRouter -> PeerId -> PartialTopicMode -> IO ()
connectPeer router peer mode = do
  now <- getCurrentTime
  addPeer router peer GossipSubV13Peer False now
  markExtensionAdvertisementSent router peer
  handleRPC
    router
    peer
    emptyRPC
      { rpcSubscriptions =
          [ SubOpts
              { subSubscribe = True
              , subTopicId = topic
              , subRequestsPartial = mode == RequestsPartialMessages
              , subSupportsSendingPartial = True
              }
          ]
      , rpcControl =
          Just
            emptyControlMessage
              { ctrlExtensions = Just (ControlExtensions True)
              }
      }

connectFullPeer :: GossipSubRouter -> PeerId -> IO ()
connectFullPeer router peer = do
  now <- getCurrentTime
  addPeer router peer GossipSubV13Peer False now
  handleRPC
    router
    peer
    emptyRPC
      { rpcSubscriptions = [SubOpts True topic False False]
      }

lookupPartial :: PeerId -> [(PeerId, RPC)] -> Maybe PartialMessage
lookupPartial peer messages =
  case [partial | (pid, rpc) <- messages, pid == peer, Just partial <- [rpcPartial rpc]] of
    partial : _ -> Just partial
    [] -> Nothing

hasPublishedMessage :: PeerId -> (PeerId, RPC) -> Bool
hasPublishedMessage peer (pid, rpc) = pid == peer && not (null (rpcPublish rpc))

hasIDontWant :: PeerId -> (PeerId, RPC) -> Bool
hasIDontWant peer (pid, rpc) =
  pid == peer && case rpcControl rpc of
    Nothing -> False
    Just control -> not (null (ctrlIDontWant control))

mkPeer :: Word -> PeerId
mkPeer value = PeerId (BS.singleton (fromIntegral value))
