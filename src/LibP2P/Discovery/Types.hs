{- | Types shared by the discovery modules (mDNS, Rendezvous).

Each discovery mechanism delivers peers it finds as a
'DiscoveryEvent' on an STM queue the application owns, so consumers
use one shape regardless of the mechanism and never couple to a
callback threading model.
-}
module LibP2P.Discovery.Types (
  DiscoveryEvent (..),
  newDiscoveryQueue,
  tryReadDiscoveryQueue,
  drainDiscoveryQueue,
) where

import Control.Concurrent.STM (
  TQueue,
  atomically,
  newTQueue,
  tryReadTQueue,
 )
import LibP2P.Crypto.PeerId (PeerId)
import LibP2P.Multiaddr (Multiaddr)

{- | A peer found by a discovery mechanism, with the addresses it
advertised. Deduplication is the consumer's job, not the queue's:
discovery runs concurrently with the Switch's peer store, and
suppressing re-announcements would hide refreshed address lists.
A 'TQueue' is unbounded, so producing never blocks; applications
are expected to drain or poll at their own cadence.
-}
data DiscoveryEvent = DiscoveryEvent
  { discoveryPeerId :: !PeerId
  -- ^ Discovered peer
  , discoveryAddrs :: ![Multiaddr]
  -- ^ Dialable addresses it advertised
  }
  deriving (Show, Eq)

-- | Create a discovery event queue.
newDiscoveryQueue :: IO (TQueue DiscoveryEvent)
newDiscoveryQueue = atomically newTQueue

-- | Read one event if any are queued.
tryReadDiscoveryQueue :: TQueue DiscoveryEvent -> IO (Maybe DiscoveryEvent)
tryReadDiscoveryQueue = atomically . tryReadTQueue

-- | Drain every currently queued event, in order.
drainDiscoveryQueue :: TQueue DiscoveryEvent -> IO [DiscoveryEvent]
drainDiscoveryQueue q = atomically go
 where
  go = do
    next <- tryReadTQueue q
    case next of
      Nothing -> pure []
      Just ev -> (ev :) <$> go
