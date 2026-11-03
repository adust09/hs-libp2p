-- | GossipSub v1.3 extension advertisement and dispatch.
module LibP2P.Protocol.GossipSub.Extensions
  ( attachExtensionsToHello
  , markExtensionAdvertisementSent
  , handleExtensionAdvertisement
  , handlePartialMessageRPC
  , peerSupportsPartialExtension
  , peerRequestsPartial
  , peerSupportsSendingPartial
  , localPartialMode
  , runPartialHeartbeat
  , emitPartialGossip
  , notifyPartialPeerDisconnected
  ) where

import Control.Concurrent.STM
import Control.Monad (when)
import qualified Data.Map.Strict as Map
import Data.Maybe (fromMaybe, isJust)
import qualified Data.Set as Set
import LibP2P.Crypto.PeerId (PeerId)
import LibP2P.Protocol.GossipSub.Score (addP7Penalty)
import LibP2P.Protocol.GossipSub.Types

-- | Add our supported extensions to the first outbound v1.3 RPC.
attachExtensionsToHello :: GossipSubRouter -> PeerProtocol -> RPC -> IO RPC
attachExtensionsToHello router proto rpc
  | proto /= GossipSubV13Peer = pure rpc
  | otherwise = do
      hooks <- readTVarIO (gsPartialMessagesHooks router)
      pure $ case hooks of
        Nothing -> rpc
        Just _ ->
          rpc
            { rpcControl =
                Just
                  control
                    { ctrlExtensions = Just (ControlExtensions True)
                    }
            }
 where
  control = fromMaybe emptyControlMessage (rpcControl rpc)

-- | Record that our extension advertisement was successfully sent.
markExtensionAdvertisementSent :: GossipSubRouter -> PeerId -> IO ()
markExtensionAdvertisementSent router pid =
  atomically $
    modifyTVar' (gsSentExtensions router) (Set.insert pid)

-- | Record the first v1.3 extension advertisement and penalize repeats.
handleExtensionAdvertisement :: GossipSubRouter -> PeerId -> RPC -> IO ()
handleExtensionAdvertisement router sender rpc = do
  peers <- readTVarIO (gsPeers router)
  if not (supportsExtensions peers sender)
    then pure ()
    else atomically $ do
      advertised <- readTVar (gsPeerExtensions router)
      let extension = rpcControl rpc >>= ctrlExtensions
      if Map.member sender advertised
        then when (isJust extension) (penalize router sender)
        else
          writeTVar
            (gsPeerExtensions router)
            (Map.insert sender (fromMaybe noExtensions extension) advertised)

-- | Dispatch a partial-message RPC only when both peers advertised support.
handlePartialMessageRPC :: GossipSubRouter -> PeerId -> RPC -> IO ()
handlePartialMessageRPC router sender rpc =
  case rpcPartial rpc of
    Nothing -> pure ()
    Just partial -> do
      hooks <- readTVarIO (gsPartialMessagesHooks router)
      supported <- peerSupportsPartialExtension router sender
      case hooks of
        Just runtime | supported -> do
          violation <- pmhHandleRPC runtime sender partial
          when violation $ atomically (penalize router sender)
        _ -> atomically (penalize router sender)

-- | Whether a peer advertised the partial-messages extension on v1.3.
peerSupportsPartialExtension :: GossipSubRouter -> PeerId -> IO Bool
peerSupportsPartialExtension router pid = do
  advertised <- readTVarIO (gsPeerExtensions router)
  sent <- readTVarIO (gsSentExtensions router)
  pure $
    Set.member pid sent
      && maybe False extPartialMessages (Map.lookup pid advertised)

-- | Whether a peer requested partial messages for a topic.
peerRequestsPartial :: GossipSubRouter -> PeerId -> Topic -> IO Bool
peerRequestsPartial router pid topic = do
  peers <- readTVarIO (gsPeers router)
  pure $ case Map.lookup pid peers >>= Map.lookup topic . psPartialTopics of
    Just RequestsPartialMessages -> True
    _ -> False

-- | Whether a peer can send partial messages for a topic.
peerSupportsSendingPartial :: GossipSubRouter -> PeerId -> Topic -> IO Bool
peerSupportsSendingPartial router pid topic = do
  peers <- readTVarIO (gsPeers router)
  pure $ case Map.lookup pid peers >>= Map.lookup topic . psPartialTopics of
    Just SupportsPartialMessages -> True
    Just RequestsPartialMessages -> True
    Nothing -> False

-- | Local partial-message mode for a subscribed topic.
localPartialMode :: GossipSubRouter -> Topic -> IO (Maybe PartialTopicMode)
localPartialMode router topic =
  Map.lookup topic <$> readTVarIO (gsPartialTopics router)

-- | Run partial-message state expiry during the GossipSub heartbeat.
runPartialHeartbeat :: GossipSubRouter -> IO ()
runPartialHeartbeat router = do
  hooks <- readTVarIO (gsPartialMessagesHooks router)
  mapM_ pmhHeartbeat hooks

-- | Ask the partial-message runtime to gossip groups to selected peers.
emitPartialGossip :: GossipSubRouter -> Topic -> [PeerId] -> IO ()
emitPartialGossip router topic peers = do
  hooks <- readTVarIO (gsPartialMessagesHooks router)
  mapM_ (\runtime -> pmhEmitGossip runtime topic peers) hooks

-- | Remove per-peer partial-message state after disconnect.
notifyPartialPeerDisconnected :: GossipSubRouter -> PeerId -> IO ()
notifyPartialPeerDisconnected router pid = do
  hooks <- readTVarIO (gsPartialMessagesHooks router)
  mapM_ (`pmhPeerDisconnected` pid) hooks

supportsExtensions :: Map.Map PeerId PeerState -> PeerId -> Bool
supportsExtensions peers pid =
  maybe False ((== GossipSubV13Peer) . psProtocol) (Map.lookup pid peers)

noExtensions :: ControlExtensions
noExtensions = ControlExtensions False

penalize :: GossipSubRouter -> PeerId -> STM ()
penalize router pid =
  modifyTVar' (gsPeers router) (Map.adjust addP7Penalty pid)
