-- | GossipSub v1.2 IDONTWANT processing and bounded suppression state.
module LibP2P.Protocol.GossipSub.IDontWant (
  announceIDontWant,
  handleIDontWant,
  peerRejectsMessage,
  filterAllowedPeers,
  expireIDontWantState,
) where

import Control.Concurrent.STM
import Control.Monad (filterM, unless, when)
import Crypto.Hash qualified as Hash
import Data.ByteArray qualified as BA
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Map.Strict qualified as Map
import Data.Set qualified as Set
import LibP2P.Crypto.PeerId (PeerId)
import LibP2P.Protocol.GossipSub.Extensions
  ( localPartialMode
  , peerSupportsPartialExtension
  , peerSupportsSendingPartial
  )
import LibP2P.Protocol.GossipSub.Types

{- | Immediately tell v1.2 mesh peers not to send a duplicate large message.
The propagation source is excluded and older protocol versions never receive
the v1.2 control field.
-}
announceIDontWant :: GossipSubRouter -> PeerId -> PubSubMessage -> IO ()
announceIDontWant router sender msg =
  when (BS.length (msgData msg) >= paramIDontWantMessageThreshold params) $ do
    let mid = paramMessageIdFn params msg
    seen <- readTVarIO (gsSeen router)
    unless (Map.member mid seen) $ do
      mesh <- readTVarIO (gsMesh router)
      peers <- readTVarIO (gsPeers router)
      let topicPeers = Map.findWithDefault Set.empty (msgTopic msg) mesh
          targets = Set.filter (supportsIDontWant peers) (Set.delete sender topicPeers)
          rpc =
            emptyRPC
              { rpcControl =
                  Just
                    emptyControlMessage
                      { ctrlIDontWant = [IDontWant [mid]]
                      }
              }
      recipients <- filterM (shouldReceiveIDontWant router (msgTopic msg))
        (Set.toList targets)
      mapM_ (\pid -> gsSendRPC router pid rpc) recipients
 where
  params = gsParams router

supportsIDontWant :: Map.Map PeerId PeerState -> PeerId -> Bool
supportsIDontWant peers pid =
  maybe False ((`elem` [GossipSubV13Peer, GossipSubV12Peer]) . psProtocol)
    (Map.lookup pid peers)

shouldReceiveIDontWant :: GossipSubRouter -> Topic -> PeerId -> IO Bool
shouldReceiveIDontWant router topic pid = do
  mode <- localPartialMode router topic
  peerSupports <- peerSupportsSendingPartial router pid topic
  extension <- peerSupportsPartialExtension router pid
  pure (mode /= Just RequestsPartialMessages || not (peerSupports && extension))

-- | Record bounded IDONTWANT state received from a peer.
handleIDontWant :: GossipSubRouter -> PeerId -> [IDontWant] -> IO ()
handleIDontWant router sender batches = unless (null batches) $ do
  accepted <- atomically $ reserveBatch router sender
  when accepted $ do
    let params = gsParams router
        mids =
          take
            (max 0 (paramMaxIDontWantLength params))
            (concatMap idontwantMessageIds batches)
        ttl = paramIDontWantMessageTTL params
    when
      (ttl > 0 && not (null mids))
      ( atomically
          ( modifyTVar'
              (gsDontSendMessageIds router)
              ( Map.insertWith
                  Map.union
                  sender
                  (Map.fromList [(messageIdDigest mid, ttl) | mid <- mids])
              )
          )
      )

reserveBatch :: GossipSubRouter -> PeerId -> STM Bool
reserveBatch router sender = do
  counts <- readTVar (gsIDontWantCounts router)
  let current = Map.findWithDefault 0 sender counts
      limit = max 0 (paramMaxIDontWantMessages (gsParams router))
  if current >= limit
    then pure False
    else do
      writeTVar (gsIDontWantCounts router) (Map.insert sender (current + 1) counts)
      pure True

-- | Test whether a peer has rejected a message ID that is still live.
peerRejectsMessage ::
  Map.Map PeerId (Map.Map ByteString Int) -> PeerId -> MessageId -> Bool
peerRejectsMessage unwanted pid mid =
  maybe False (Map.member (messageIdDigest mid)) (Map.lookup pid unwanted)

-- | Remove peers that have rejected the message ID from a target set.
filterAllowedPeers ::
  Map.Map PeerId (Map.Map ByteString Int) ->
  MessageId ->
  Set.Set PeerId ->
  Set.Set PeerId
filterAllowedPeers unwanted mid =
  Set.filter (\pid -> not (peerRejectsMessage unwanted pid mid))

-- | Reset the per-heartbeat receive budget and age suppression entries.
expireIDontWantState :: GossipSubRouter -> IO ()
expireIDontWantState router = atomically $ do
  writeTVar (gsIDontWantCounts router) Map.empty
  modifyTVar' (gsDontSendMessageIds router) $ Map.mapMaybe agePeer
 where
  agePeer mids =
    let live = Map.mapMaybe age mids
     in if Map.null live then Nothing else Just live
  age ttl
    | ttl <= 1 = Nothing
    | otherwise = Just (ttl - 1)

messageIdDigest :: MessageId -> ByteString
messageIdDigest mid =
  BA.convert (Hash.hash mid :: Hash.Digest Hash.SHA256)
