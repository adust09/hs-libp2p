-- | Switch core operations.
--
-- The Switch is the central coordinator of the libp2p stack.
-- This module provides construction, transport management,
-- protocol handler registration, and shutdown.
module LibP2P.Switch
  ( newSwitch
  , subscribeSwitchEvents
  , addTransport
  , selectTransport
  , setConnectionGater
  , setStreamHandler
  , removeStreamHandler
  , lookupStreamHandler
  , switchClose
  ) where

import Control.Concurrent.Async (async, cancel)
import Control.Concurrent.STM (TChan, atomically, dupTChan, newBroadcastTChanIO, newTVarIO, readTVar, writeTVar)
import Control.Exception (SomeException, catch)
import Control.Monad (void)
import Data.List (find)
import qualified Data.Map.Strict as Map
import LibP2P.Crypto.Key (KeyPair)
import LibP2P.Crypto.PeerId (PeerId)
import LibP2P.Multiaddr (Multiaddr)
import LibP2P.MultistreamSelect.Negotiation (ProtocolId)
import LibP2P.Protocol.Identify (pushIdentify)
import LibP2P.Switch.Connection (closeAllConnections)
import LibP2P.Switch.ResourceManager (DefaultLimits (..), defaultPeerLimits, defaultSystemLimits, newResourceManager)
import LibP2P.Switch.Types
  ( ActiveListener (..)
  , ConnectionGater
  , StreamHandler
  , Switch (..)
  , SwitchEvent
  , defaultConnectionGater
  )
import LibP2P.Transport (Listener (..), Transport (..))

-- | Create a new Switch with the given local identity.
-- All internal state is initialized empty.
newSwitch :: PeerId -> KeyPair -> IO Switch
newSwitch pid kp = do
  transportsVar   <- newTVarIO []
  poolVar         <- newTVarIO Map.empty
  protosVar       <- newTVarIO Map.empty
  eventsChan      <- newBroadcastTChanIO
  closedVar       <- newTVarIO False
  backoffsVar     <- newTVarIO Map.empty
  pendingDialsVar <- newTVarIO Map.empty
  connectionGaterVar <- newTVarIO defaultConnectionGater
  resMgr <- newResourceManager DefaultLimits
    { dlSystemLimits = defaultSystemLimits
    , dlPeerLimits   = defaultPeerLimits
    }
  peerStoreVar <- newTVarIO Map.empty
  certifiedRecordsVar <- newTVarIO Map.empty
  notifiersVar <- newTVarIO []
  disconnectNotifiersVar <- newTVarIO []
  listenersVar <- newTVarIO []
  pure Switch
    { swLocalPeerId  = pid
    , swIdentityKey  = kp
    , swTransports   = transportsVar
    , swConnPool     = poolVar
    , swProtocols    = protosVar
    , swEvents       = eventsChan
    , swClosed       = closedVar
    , swDialBackoffs = backoffsVar
    , swPendingDials = pendingDialsVar
    , swConnectionGater = connectionGaterVar
    , swResourceMgr  = resMgr
    , swPeerStore    = peerStoreVar
    , swCertifiedRecords = certifiedRecordsVar
    , swNotifiers    = notifiersVar
    , swDisconnectNotifiers = disconnectNotifiersVar
    , swListeners    = listenersVar
    }

-- | Subscribe independently to future per-connection events (no replay).
-- Drop the channel to unsubscribe; unread channels retain queued events.
-- Shutdown neither waits for subscribers nor signals end-of-stream.
subscribeSwitchEvents :: Switch -> IO (TChan SwitchEvent)
subscribeSwitchEvents sw = atomically $ dupTChan (swEvents sw)

-- | Register a transport with the switch.
-- Appends to the list of transports; order matters for selectTransport.
addTransport :: Switch -> Transport -> IO ()
addTransport sw t = atomically $ do
  ts <- readTVar (swTransports sw)
  writeTVar (swTransports sw) (ts ++ [t])

-- | Find the first registered transport that can dial the given multiaddr.
selectTransport :: Switch -> Multiaddr -> IO (Maybe Transport)
selectTransport sw addr = atomically $ do
  ts <- readTVar (swTransports sw)
  pure $ find (\t -> transportCanDial t addr) ts

-- | Set the admission policy used by future inbound and outbound connections.
-- Configure this before starting listeners or dialing peers.
setConnectionGater :: Switch -> ConnectionGater -> IO ()
setConnectionGater sw gater = atomically $
  writeTVar (swConnectionGater sw) gater

-- | Register a protocol stream handler.
-- Overwrites any existing handler for the same protocol ID.
-- The changed protocol set is pushed to connected peers via
-- identify push (specs/identify) in the background.
setStreamHandler :: Switch -> ProtocolId -> StreamHandler -> IO ()
setStreamHandler sw proto handler = do
  atomically $ do
    protos <- readTVar (swProtocols sw)
    writeTVar (swProtocols sw) (Map.insert proto handler protos)
  void $ async (pushIdentify sw)

-- | Remove a protocol stream handler.
-- The changed protocol set is pushed to connected peers via
-- identify push (specs/identify) in the background.
removeStreamHandler :: Switch -> ProtocolId -> IO ()
removeStreamHandler sw proto = do
  atomically $ do
    protos <- readTVar (swProtocols sw)
    writeTVar (swProtocols sw) (Map.delete proto protos)
  void $ async (pushIdentify sw)

-- | Look up a registered stream handler by protocol ID.
lookupStreamHandler :: Switch -> ProtocolId -> IO (Maybe StreamHandler)
lookupStreamHandler sw proto = atomically $ do
  protos <- readTVar (swProtocols sw)
  pure $ Map.lookup proto protos

-- | Shut down the switch.
-- Cancels all accept loop threads, closes all listeners, tears down all
-- pooled connections, then sets the closed flag.
switchClose :: Switch -> IO ()
switchClose sw = do
  -- Read and clear listeners atomically
  listeners <- atomically $ do
    ls <- readTVar (swListeners sw)
    writeTVar (swListeners sw) []
    writeTVar (swClosed sw) True
    pure ls
  -- Cancel accept loops and close listeners outside STM
  mapM_ closeListener listeners
  -- Tear down every pooled connection (pool removal, resource release,
  -- muxer close, transport close)
  closeAllConnections sw
  where
    closeListener al = do
      cancel (alAcceptLoop al) `catch` (\(_ :: SomeException) -> pure ())
      listenerClose (alListener al) `catch` (\(_ :: SomeException) -> pure ())
