module LibP2P.Protocol.GossipSub.ExtensionsSpec (spec) where

import Control.Concurrent.STM
import qualified Data.ByteString as BS
import Data.IORef
import qualified Data.Map.Strict as Map
import Data.Time (getCurrentTime)
import LibP2P.Crypto.PeerId (PeerId (..))
import LibP2P.Protocol.GossipSub.Extensions
import LibP2P.Protocol.GossipSub.Router (addPeer, handleRPC, newRouter)
import LibP2P.Protocol.GossipSub.Types
import Test.Hspec

spec :: Spec
spec = describe "GossipSub v1.3 extensions" $ do
  it "advertises partial messages only in v1.3 hello RPCs" $ do
    router <- mkRouter
    atomically $ writeTVar (gsPartialMessagesHooks router) (Just noOpHooks)
    v13Hello <- attachExtensionsToHello router GossipSubV13Peer emptyRPC
    v12Hello <- attachExtensionsToHello router GossipSubV12Peer emptyRPC
    (rpcControl v13Hello >>= ctrlExtensions)
      `shouldBe` Just (ControlExtensions True)
    v12Hello `shouldBe` emptyRPC

  it "records the first advertisement and penalizes a repeated one" $ do
    router <- mkRouter
    let peer = mkPeer 1
    now <- getCurrentTime
    addPeer router peer GossipSubV13Peer False now
    handleExtensionAdvertisement router peer emptyRPC
    handleExtensionAdvertisement router peer extensionRPC
    advertised <- readTVarIO (gsPeerExtensions router)
    extPartialMessages (advertised Map.! peer) `shouldBe` False
    peers <- readTVarIO (gsPeers router)
    psBehaviorPenalty (peers Map.! peer) `shouldBe` 1

  it "dispatches a partial payload advertised in the first RPC" $ do
    router <- mkRouter
    received <- newIORef []
    let peer = mkPeer 2
        hooks =
          noOpHooks
            { pmhHandleRPC = \pid payload ->
                modifyIORef' received ((pid, payload) :) >> pure False
            }
        partial = PartialMessage "blocks" "group" (Just "part") (Just "meta")
    atomically $ writeTVar (gsPartialMessagesHooks router) (Just hooks)
    markExtensionAdvertisementSent router peer
    now <- getCurrentTime
    addPeer router peer GossipSubV13Peer False now
    handleRPC router peer extensionRPC{rpcPartial = Just partial}
    readIORef received `shouldReturn` [(peer, partial)]

mkRouter :: IO GossipSubRouter
mkRouter = newRouter defaultGossipSubParams (mkPeer 0) (\_ _ -> pure ()) getCurrentTime

extensionRPC :: RPC
extensionRPC =
  emptyRPC
    { rpcControl =
        Just
          emptyControlMessage
            { ctrlExtensions = Just (ControlExtensions True)
            }
    }

noOpHooks :: PartialMessagesHooks
noOpHooks =
  PartialMessagesHooks
    { pmhHandleRPC = \_ _ -> pure False
    , pmhHeartbeat = pure ()
    , pmhEmitGossip = \_ _ -> pure ()
    , pmhPeerDisconnected = \_ -> pure ()
    }

mkPeer :: Word -> PeerId
mkPeer value = PeerId (BS.singleton (fromIntegral value))
