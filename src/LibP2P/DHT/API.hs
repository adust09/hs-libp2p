-- | High-level DHT API for content publishing and retrieval.
--
-- Provides the user-facing operations that libp2p applications use:
-- 'provide', 'putValue', 'getValue', 'findProviders', and 'findPeer'.
-- These compose the lower-level iterative lookups with direct RPC sending
-- to the closest peers found.
module LibP2P.DHT.API
  ( -- * Content provider operations
    provide
  , putValue
  , getValue
  , findProviders
  , findPeer
  ) where

import Control.Concurrent.Async (mapConcurrently)
import Control.Exception
  ( SomeAsyncException
  , SomeException
  , catch
  , fromException
  , tryJust
  )
import Control.Monad (void)
import Data.ByteString (ByteString)
import Data.Time (getCurrentTime)
import Data.Time.Format.ISO8601 (iso8601Show)
import qualified Data.Text as T
import LibP2P.Crypto.PeerId (PeerId (..), peerIdBytes)
import LibP2P.DHT
  ( DHTNode (..)
  , ProviderEntry (..)
  , Validator (..)
  , addProvider
  , storeRecord
  )
import LibP2P.DHT.Lookup (iterativeFindNode, iterativeGetProviders, iterativeGetValue)
import LibP2P.DHT.Maintenance
  ( ensureProviderWorker
  , nextLocalProviderBatch
  , rememberLocalProvider
  )
import LibP2P.DHT.Message
import LibP2P.DHT.Types (BucketEntry (..), ConnectionType (..), entryPeerId, kValue)
import LibP2P.Multiaddr (Multiaddr, toBytes)

-- | Announce that the local node provides a given content key.
--
-- Performs an iterative FIND_NODE lookup for the content key, then sends
-- ADD_PROVIDER messages to the k closest peers found. The local peer's
-- listen addresses are included so remote peers can dial back.
provide :: DHTNode -> [Multiaddr] -> ByteString -> IO ()
provide node addrs key = do
  rememberLocalProvider (dhtMaintenance node) key addrs
  ensureProviderWorker
    (dhtMaintenance node)
    (dhtStopped node)
    (republishProviderBatch node)
  announceProvider node addrs key

-- | Reannounce one bounded, rotating batch of locally provided keys.
republishProviderBatch :: DHTNode -> IO Int
republishProviderBatch node = do
  batch <- nextLocalProviderBatch (dhtMaintenance node)
  void $ mapConcurrently republish batch
  pure (length batch)
  where
    republish (key, addrs) = void $
      tryJust synchronousException (announceProvider node addrs key)

-- | Run the normal provide lookup and announcement without registering the
-- key again. Value records are deliberately not auto-republished here: like
-- go-libp2p core, the DHT cannot infer application ownership of value keys;
-- applications must republish values before their configured maximum age.
announceProvider :: DHTNode -> [Multiaddr] -> ByteString -> IO ()
announceProvider node addrs key = do
  closest <- iterativeFindNode node (PeerId key)
  let providerPeer = DHTPeer (peerIdBytes (dhtLocalPeerId node))
                             (map toBytes addrs)
                             Connected
      providerMsg = emptyDHTMessage
        { msgType = AddProvider
        , msgKey  = key
        , msgProviderPeers = [providerPeer]
        }
  void $ mapConcurrently (sendProvider providerMsg) (take kValue closest)
  now <- getCurrentTime
  addProvider node key ProviderEntry
    { peProvider  = dhtLocalPeerId node
    , peAddrs     = addrs
    , peTimestamp = now
    }
  where
    sendProvider providerMsg entry = void $
      tryJust synchronousException
        (dhtSendRequest node (entryPeerId entry) providerMsg)

synchronousException :: SomeException -> Maybe SomeException
synchronousException exception =
  case fromException exception :: Maybe SomeAsyncException of
    Just _ -> Nothing
    Nothing -> Just exception

-- | Store a value in the DHT under the given key.
--
-- Performs an iterative FIND_NODE lookup for the key, then sends
-- PUT_VALUE messages to the k closest peers. Also stores the value
-- locally. The value is validated using the node's configured validator;
-- if validation fails, the function returns 'Left' with an error message.
putValue :: DHTNode -> Validator -> ByteString -> ByteString -> IO (Either String ())
putValue node validator key value = do
  -- Validate first
  case valValidate validator key value of
    Left err -> pure (Left $ "value validation failed: " ++ err)
    Right () -> do
      -- Find the k closest peers
      closest <- iterativeFindNode node (PeerId key)

      -- Create the record and send PUT_VALUE
      now <- getCurrentTime
      let record = DHTRecord key value (T.pack (iso8601Show now))
          putMsg = emptyDHTMessage
            { msgType = PutValue
            , msgKey  = key
            , msgRecord = Just record
            }

      void $ mapConcurrently (\entry ->
        (dhtSendRequest node) (entryPeerId entry) putMsg
          `catch` (\(_ :: SomeException) -> pure (Left "send failed"))
        ) (take kValue closest)

      -- Also store locally
      storeRecord node record
      pure (Right ())

-- | Retrieve a value from the DHT.
--
-- Convenience wrapper around 'iterativeGetValue'.
getValue :: DHTNode -> Validator -> ByteString -> IO (Either String DHTRecord)
getValue node validator key = iterativeGetValue node validator key

-- | Find providers for a content key.
--
-- Convenience wrapper around 'iterativeGetProviders'.
findProviders :: DHTNode -> ByteString -> IO [ProviderEntry]
findProviders node key = iterativeGetProviders node key

-- | Find the closest known peers to a target peer ID.
--
-- Convenience wrapper around 'iterativeFindNode'.
findPeer :: DHTNode -> PeerId -> IO [BucketEntry]
findPeer node target = iterativeFindNode node target
