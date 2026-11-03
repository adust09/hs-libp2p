-- | Keep configured GossipSub direct peers connected.
--
-- gossipsub-v1.1.md explicit peering: the router establishes a connection
-- to every configured direct peer and re-establishes it when it drops.
-- Addresses come from the Switch (certified record, else Identify listen
-- addresses). A peer with no stored addresses is skipped. Dialling goes
-- through 'LibP2P.Switch.Dial.dial', so backoff, deduplication, gating,
-- and the resource manager apply. This is not peer exchange: PX peers
-- are untrusted advertisements, direct peers are configured agreements.
module LibP2P.Protocol.GossipSub.DirectConnect
  ( DirectDialSlots
  , newDirectDialSlots
  , connectMissingDirectPeers
  , reconnectDirectPeer
  , runDirectConnectLoop
  , cancelDirectDials
  ) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.Async (Async, async, cancel)
import Control.Concurrent.STM
  ( TVar
  , atomically
  , modifyTVar'
  , newTVarIO
  , readTVar
  , readTVarIO
  , writeTVar
  )
import Control.Exception (SomeException, catch, finally)
import Control.Monad (unless, void, when)
import Data.ByteString (ByteString)
import qualified Data.Map.Strict as Map
import Data.Maybe (isJust, mapMaybe)
import qualified Data.Set as Set
import LibP2P.Crypto.PeerId (PeerId)
import LibP2P.Multiaddr (Multiaddr, fromBytes)
import LibP2P.Protocol.GossipSub.Types
  ( GossipSubParams (..)
  , GossipSubRouter (..)
  )
import LibP2P.Protocol.Identify.Message (IdentifyInfo (..))
import LibP2P.Switch.CertifiedRecords (CertifiedRecord (..), lookupCertifiedRecord)
import LibP2P.Switch.ConnPool (lookupConn)
import LibP2P.Switch.Dial (checkBackoff, dial)
import LibP2P.Switch.Types (Switch (..))

-- | In-flight direct dials. 'Nothing' is a claim that a worker is about
-- to start, so a second wake cannot spawn another one.
newtype DirectDialSlots = DirectDialSlots (TVar (Map.Map PeerId (Maybe (Async ()))))

newDirectDialSlots :: IO DirectDialSlots
newDirectDialSlots = DirectDialSlots <$> newTVarIO Map.empty

-- | Dial every configured direct peer that is down and has stored addresses.
connectMissingDirectPeers :: Switch -> GossipSubRouter -> DirectDialSlots -> IO ()
connectMissingDirectPeers sw router slots =
  mapM_ (reconnectDirectPeer sw router slots) (Set.toList (paramDirectPeers (gsParams router)))

-- | Dial one direct peer if it is configured, down, and addressable.
-- A non-direct peer is ignored, so a PX disconnect cannot enter this path.
reconnectDirectPeer :: Switch -> GossipSubRouter -> DirectDialSlots -> PeerId -> IO ()
reconnectDirectPeer sw router slots pid
  | not (Set.member pid (paramDirectPeers (gsParams router))) = pure ()
  | otherwise = do
      closed <- readTVarIO (swClosed sw)
      unless closed $ do
        skip <- shouldSkip sw pid
        unless skip $ do
          addrs <- storedAddrs sw pid
          case nonEmpty addrs of
            Nothing -> pure ()
            Just dialable -> spawnDial sw slots pid dialable

-- | Initial pass, then one pass per 'paramDirectConnectInterval', until
-- 'started' is false. An interval of 0 runs the initial pass only.
runDirectConnectLoop
  :: Switch -> GossipSubRouter -> TVar Bool -> DirectDialSlots -> IO ()
runDirectConnectLoop sw router started slots = loop
  where
    loop = do
      alive <- readTVarIO started
      when alive $ do
        connectMissingDirectPeers sw router slots
        let interval = paramDirectConnectInterval (gsParams router)
        when (interval > 0) $ do
          threadDelay (nominalToMicros interval)
          loop

-- | Cancel workers claimed by a slot map. Idempotent.
cancelDirectDials :: DirectDialSlots -> IO ()
cancelDirectDials (DirectDialSlots var) = do
  workers <- atomically $ do
    current <- readTVar var
    writeTVar var Map.empty
    pure current
  mapM_ cancelQuiet (Map.elems workers)

shouldSkip :: Switch -> PeerId -> IO Bool
shouldSkip sw pid = do
  connected <- isJust <$> atomically (lookupConn (swConnPool sw) pid)
  blocked <- checkBackoff (swDialBackoffs sw) pid
  pure $ connected || isLeft blocked

spawnDial :: Switch -> DirectDialSlots -> PeerId -> [Multiaddr] -> IO ()
spawnDial sw slots pid addrs = do
  claimed <- claim slots pid
  when claimed $ do
    worker <- async $
      void (dial sw pid addrs) `finally` release slots pid
    record slots pid worker

claim :: DirectDialSlots -> PeerId -> IO Bool
claim (DirectDialSlots var) pid = atomically $ do
  current <- readTVar var
  if Map.member pid current
    then pure False
    else writeTVar var (Map.insert pid Nothing current) >> pure True

record :: DirectDialSlots -> PeerId -> Async () -> IO ()
record (DirectDialSlots var) pid worker = atomically $
  modifyTVar' var $ \current ->
    if Map.member pid current
      then Map.insert pid (Just worker) current
      else current

release :: DirectDialSlots -> PeerId -> IO ()
release (DirectDialSlots var) pid = atomically $
  modifyTVar' var (Map.delete pid)

storedAddrs :: Switch -> PeerId -> IO [Multiaddr]
storedAddrs sw pid = do
  raw <- atomically $ do
    certified <- lookupCertifiedRecord (swCertifiedRecords sw) pid
    case certified of
      Just record -> pure (crAddresses record)
      Nothing -> do
        store <- readTVar (swPeerStore sw)
        pure $ maybe [] idListenAddrs (Map.lookup pid store)
  pure $ mapMaybe (either (const Nothing) Just . fromBytes) raw

cancelQuiet :: Maybe (Async ()) -> IO ()
cancelQuiet Nothing = pure ()
cancelQuiet (Just worker) =
  cancel worker `catch` \(_ :: SomeException) -> pure ()

nominalToMicros :: RealFrac a => a -> Int
nominalToMicros interval = max 0 (round (interval * 1000000))

nonEmpty :: [a] -> Maybe [a]
nonEmpty [] = Nothing
nonEmpty xs = Just xs

isLeft :: Either e a -> Bool
isLeft (Left _) = True
isLeft (Right _) = False
