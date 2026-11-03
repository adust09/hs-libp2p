-- | Dial peers advertised by an accepted GossipSub peer exchange.
--
-- 'handlePrune' already applies 'stAcceptPXThreshold' and drops envelopes
-- that do not open (gossipsub-v1.1.md Peer Exchange; RFC 0003). The
-- callback installed by 'newGossipSubNode' does the rest: keep a fresher
-- certified record, then dial so the pruned node can reform its mesh.
--
-- Self, duplicate entries, already-connected peers, and peers in
-- gossipsub or dial backoff are not dialed. At most 'pxMaxInFlight'
-- dials run at once (go-libp2p's connector count); further peers are
-- skipped until a slot frees. 'LibP2P.Switch.Dial.dial' enforces the
-- resource manager, so this path does not open a connection around it.
module LibP2P.Protocol.GossipSub.PeerExchange
  ( pxMaxInFlight
  , installPeerExchange
  , dialAcceptedPX
  ) where

import Control.Concurrent.Async (async)
import Control.Concurrent.STM
  ( TVar
  , atomically
  , modifyTVar'
  , newTVarIO
  , readTVar
  , readTVarIO
  , writeTVar
  )
import Control.Exception (finally)
import Control.Monad (unless, void, when)
import Data.ByteString (ByteString)
import qualified Data.Map.Strict as Map
import Data.Maybe (isJust, mapMaybe)
import qualified Data.Set as Set
import LibP2P.Core.Multihash (validateMultihash)
import LibP2P.Crypto.PeerId (PeerId (..))
import LibP2P.Multiaddr (Multiaddr, fromBytes)
import LibP2P.Protocol.GossipSub.Types
  ( GossipSubRouter (..)
  , PeerExchangeInfo (..)
  , Topic
  )
import LibP2P.Protocol.Identify.Message (IdentifyInfo (..))
import LibP2P.Switch.CertifiedRecords
  ( CertifiedRecord (..)
  , consumeCertifiedRecord
  , lookupCertifiedRecord
  , verifyPeerRecord
  )
import LibP2P.Switch.ConnPool (lookupConn)
import LibP2P.Switch.Dial (checkBackoff, dial)
import LibP2P.Switch.Types (Switch (..))

-- | Concurrent PX dials. go-libp2p's GossipSubConnectors default.
pxMaxInFlight :: Int
pxMaxInFlight = 8

-- | Replace the router's no-op PX callback with the production dialer.
installPeerExchange :: Switch -> GossipSubRouter -> IO ()
installPeerExchange sw router = do
  slots <- newTVarIO 0
  atomically $ writeTVar (gsOnPeerExchange router) (dialAcceptedPX sw router slots)

-- | Act on PX entries the router has already accepted.
dialAcceptedPX
  :: Switch
  -> GossipSubRouter
  -> TVar Int
  -> Topic
  -> [PeerExchangeInfo]
  -> IO ()
dialAcceptedPX sw router slots topic entries =
  mapM_ (considerEntry sw router slots topic) (deduped entries)
  where
    deduped = snd . foldl' keepFresh (Set.empty, [])
    keepFresh (seen, acc) entry = case decodePXPeer (pxPeerId entry) of
      Just peer | not (Set.member peer seen) ->
        (Set.insert peer seen, acc ++ [entry])
      _ -> (seen, acc)

considerEntry
  :: Switch -> GossipSubRouter -> TVar Int -> Topic -> PeerExchangeInfo -> IO ()
considerEntry sw router slots topic entry =
  case decodePXPeer (pxPeerId entry) of
    Nothing -> pure ()
    Just peer -> do
      skip <- shouldSkip sw router topic peer
      unless skip $ do
        maddrs <- resolveDialable sw peer entry
        maybe (pure ()) (spawnBoundedDial slots sw peer) maddrs

shouldSkip :: Switch -> GossipSubRouter -> Topic -> PeerId -> IO Bool
shouldSkip sw router topic peer = do
  now <- gsGetTime router
  connected <- isJust <$> atomically (lookupConn (swConnPool sw) peer)
  backoff <- readTVarIO (gsBackoff router)
  dialBlocked <- checkBackoff (swDialBackoffs sw) peer
  let gossipBlocked = case Map.lookup (peer, topic) backoff of
        Just expiry -> now < expiry
        Nothing -> False
  pure $ peer == swLocalPeerId sw
    || connected
    || gossipBlocked
    || isLeft dialBlocked

-- | Certified addresses from a fresher record, or ambient addresses when
-- the advertisement omitted the record. A stale or forged record does
-- not fall back to older addresses: that entry must not dial.
resolveDialable :: Switch -> PeerId -> PeerExchangeInfo -> IO (Maybe [Multiaddr])
resolveDialable sw peer entry = case pxSignedPeerRecord entry of
  Just envBytes -> case verifyPeerRecord peer envBytes of
    Left _ -> pure Nothing
    Right record -> do
      accepted <- atomically $
        consumeCertifiedRecord (swCertifiedRecords sw) peer record
      pure $ if accepted then nonEmpty (decodeAddrs (crAddresses record)) else Nothing
  Nothing -> nonEmpty . decodeAddrs <$> ambientAddrs sw peer

spawnBoundedDial :: TVar Int -> Switch -> PeerId -> [Multiaddr] -> IO ()
spawnBoundedDial slots sw peer addrs = do
  acquired <- atomically $ do
    n <- readTVar slots
    if n >= pxMaxInFlight
      then pure False
      else modifyTVar' slots (+ 1) >> pure True
  when acquired $ void $ async $
    dial sw peer addrs `finally` atomically (modifyTVar' slots (subtract 1))

decodePXPeer :: ByteString -> Maybe PeerId
decodePXPeer bs = case validateMultihash bs of
  Right _ -> Just (PeerId bs)
  Left _ -> Nothing

decodeAddrs :: [ByteString] -> [Multiaddr]
decodeAddrs = mapMaybe (either (const Nothing) Just . fromBytes)

ambientAddrs :: Switch -> PeerId -> IO [ByteString]
ambientAddrs sw peer = atomically $ do
  certified <- lookupCertifiedRecord (swCertifiedRecords sw) peer
  case certified of
    Just record -> pure (crAddresses record)
    Nothing -> do
      store <- readTVar (swPeerStore sw)
      pure $ maybe [] idListenAddrs (Map.lookup peer store)

nonEmpty :: [a] -> Maybe [a]
nonEmpty [] = Nothing
nonEmpty xs = Just xs

isLeft :: Either e a -> Bool
isLeft (Left _) = True
isLeft (Right _) = False
