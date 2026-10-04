-- | Listen loop for the Switch.
--
-- Accepts inbound connections, applies connection gating policy,
-- upgrades to secure multiplexed connections, and dispatches
-- inbound streams to registered protocol handlers.
module LibP2P.Switch.Listen
  ( -- * Connection gating
    ConnectionGater (..)
  , defaultConnectionGater
    -- * Inbound connection handling
  , handleInbound
    -- * Stream dispatch
  , streamAcceptLoop
  , dispatchStream
    -- * Listen orchestration
  , switchListen
  , acceptLoop
  , switchListenAddrs
  , switchWithdrawListener
  ) where

import Control.Concurrent.Async (async, cancel)
import Control.Concurrent.STM (atomically, readTVar, writeTChan, writeTVar)
import Control.Exception (SomeException, catch, finally, try)
import Data.List (find, partition)
import qualified Data.Map.Strict as Map
import LibP2P.Crypto.PeerId (PeerId)
import LibP2P.Multiaddr (Multiaddr)
import LibP2P.MultistreamSelect.Negotiation
  ( NegotiationResult (..)
  , StreamIO (..)
  , closeQuietly
  , negotiateResponder
  )
import LibP2P.Protocol.Identify (pushIdentify)
import LibP2P.Switch.ConnPool (addConn)
import LibP2P.Switch.Connection (closeConnection)
import LibP2P.Switch.ResourceManager
  ( Direction (..)
  , releasePeerStream
  , reserveConnection
  , reservePeerStream
  )
import LibP2P.Switch.Types
  ( ActiveListener (..)
  , Connection (..)
  , MuxerSession (..)
  , Switch (..)
  , SwitchConfig (..)
  , SwitchEvent (..)
  )
import LibP2P.Switch.Upgrade (upgradeAsWith)
import LibP2P.Transport (Listener (..), RawConnection (..), Transport (..))

-- | Connection gater: policy-based admission control.
--
-- Called at multiple points during connection establishment to allow
-- or deny based on policy (IP blocklist, Peer ID allowlist, etc.).
data ConnectionGater = ConnectionGater
  { gateAccept  :: !(Multiaddr -> IO Bool)  -- ^ Check after accepting raw connection (before upgrade)
  , gateSecured :: !(PeerId -> IO Bool)     -- ^ Check after security handshake (remote PeerId known)
  }

-- | Default gater that allows all connections.
defaultConnectionGater :: ConnectionGater
defaultConnectionGater = ConnectionGater
  { gateAccept  = \_ -> pure True
  , gateSecured = \_ -> pure True
  }

-- | Handle a single inbound connection: gate → upgrade → pool → stream accept loop.
--
-- This function blocks until the connection closes. Each accepted connection
-- should be spawned in its own async thread from the accept loop.
handleInbound :: Switch -> ConnectionGater -> RawConnection -> IO ()
handleInbound sw gater rawConn = do
  -- Gate 1: check remote address before any upgrade work
  allowed <- gateAccept gater (rcRemoteAddr rawConn)
  if not allowed
    then rcClose rawConn
    else do
      -- Upgrade: Noise XX handshake + Yamux session
      conn <- upgradeAsWith (scYamuxConfig (swConfig sw)) Inbound (swIdentityKey sw) rawConn
      -- Gate 2: check remote PeerId after security handshake
      secured <- gateSecured gater (connPeerId conn)
      if not secured
        then muxClose (connSession conn)
        else do
          -- Gate 3: check resource limits (PeerId known after handshake)
          resCheck <- atomically $ reserveConnection (swResourceMgr sw) (connPeerId conn) Inbound
          case resCheck of
            Left _ -> muxClose (connSession conn)
            Right () -> do
              -- Add to connection pool and publish Connected event
              atomically $ do
                addConn (swConnPool sw) conn
                writeTChan (swEvents sw)
                  (Connected (connPeerId conn) Inbound (connRemoteAddr conn))
              -- Notify connection listeners (e.g. GossipSub auto-stream open)
              notifiers <- atomically $ readTVar (swNotifiers sw)
              mapM_ (\f -> async $ f conn) notifiers
              -- Block on stream accept loop until the session dies, then
              -- tear down: pool removal, resource release, muxer close.
              streamAcceptLoop sw conn `finally` closeConnection sw conn

-- | Accept inbound streams and dispatch to registered protocol handlers.
--
-- Runs forever, accepting streams from the muxer and spawning a handler
-- thread for each. Uses multistream-select to negotiate the protocol,
-- then dispatches to the registered StreamHandler.
streamAcceptLoop :: Switch -> Connection -> IO ()
streamAcceptLoop sw conn = loop
  where
    loop = do
      -- Accept the next inbound stream from the muxer
      result <- safeAccept
      case result of
        Nothing -> pure ()  -- Muxer closed or error, stop the loop
        Just stream -> do
          -- Spawn handler for this stream, continue accepting
          _ <- async $ dispatchStream sw conn stream
          loop
    -- Catch exceptions from muxAcceptStream (e.g. session shutdown)
    safeAccept =
      (Just <$> muxAcceptStream (connSession conn))
        `catch` (\(_ :: SomeException) -> pure Nothing)

-- | Dispatch a single inbound stream to the appropriate protocol handler.
--
-- Runs multistream-select as responder to determine which protocol
-- the remote peer wants, then looks up and invokes the registered handler.
dispatchStream :: Switch -> Connection -> StreamIO -> IO ()
dispatchStream sw conn stream = do
  -- Reserve an inbound stream slot against the peer's resource scope
  reserved <- atomically $
    reservePeerStream (swResourceMgr sw) (connPeerId conn) Inbound
  case reserved of
    Left _ ->
      -- Over the stream limit: refuse the stream without negotiating
      closeQuietly stream
    Right () -> negotiateAndDispatch `finally` release
  where
    release = atomically $
      releasePeerStream (swResourceMgr sw) (connPeerId conn) Inbound
    negotiateAndDispatch = do
      -- Get the list of supported protocols from the Switch
      supportedProtos <- atomically $
        Map.keys <$> readProtos
      -- Run multistream-select responder. A failed or aborted
      -- negotiation never reaches a handler, so dispatch closes.
      -- go-libp2p resets on mux negotiation failure for the same reason.
      negotiated <- try (negotiateResponder stream supportedProtos)
      case negotiated of
        Left (_ :: SomeException) -> closeQuietly stream
        Right NoProtocol -> closeQuietly stream
        Right (Accepted proto) -> do
          mHandler <- lookupHandler proto
          case mHandler of
            Just handler -> handler conn stream
            -- Protocol vanished from the registry after listing:
            -- no handler will close, so dispatch must.
            Nothing -> closeQuietly stream
    readProtos = readTVar (swProtocols sw)
    lookupHandler proto = atomically $
      Map.lookup proto <$> readTVar (swProtocols sw)

-- | Start listening on the given addresses.
--
-- For each address, selects a matching transport, binds a listener,
-- and spawns an accept loop that handles inbound connections.
-- Returns the actual bound addresses (port 0 resolved to actual port).
-- Fails if the switch is already closed.
switchListen :: Switch -> ConnectionGater -> [Multiaddr] -> IO [Multiaddr]
switchListen sw gater addrs = do
  closed <- atomically $ readTVar (swClosed sw)
  if closed
    then fail "switchListen: switch is closed"
    else do
      transports <- atomically $ readTVar (swTransports sw)
      activeListeners <- mapM (bindAndListen transports gater sw) addrs
      let newListeners = concat activeListeners
      atomically $ do
        existing <- readTVar (swListeners sw)
        writeTVar (swListeners sw) (existing ++ newListeners)
      -- Listen addresses changed: push updated identify info to
      -- connected peers in the background (specs/identify push).
      _ <- async (pushIdentify sw)
      pure (map alAddress newListeners)
  where
    -- Find a transport for the address, bind, and spawn accept loop
    bindAndListen transports gater' sw' addr = do
      case find (\t -> transportCanDial t addr) transports of
        Nothing -> fail $ "switchListen: no transport for " ++ show addr
        Just transport -> do
          listener <- transportListen transport addr
          loopThread <- async $ acceptLoop sw' gater' listener
          pure [ActiveListener
            { alListener   = listener
            , alAcceptLoop = loopThread
            , alAddress    = listenerAddr listener
            }]

-- | Accept loop: forever accepts connections and spawns handleInbound threads.
-- Catches exceptions from individual connections without stopping the loop.
-- Stops when the listener is closed (accept throws).
acceptLoop :: Switch -> ConnectionGater -> Listener -> IO ()
acceptLoop sw gater listener = loop
  where
    loop = do
      result <- (Right <$> listenerAccept listener)
                  `catch` (\(_ :: SomeException) -> pure (Left ()))
      case result of
        Left () -> pure ()  -- Listener closed, stop
        Right rawConn -> do
          _ <- async $ handleInbound sw gater rawConn
                         `catch` (\(_ :: SomeException) -> pure ())
          loop

-- | Get the current listen addresses from all active listeners.
switchListenAddrs :: Switch -> IO [Multiaddr]
switchListenAddrs sw = atomically $ do
  listeners <- readTVar (swListeners sw)
  pure (map alAddress listeners)

-- | Withdraw the listener bound to the given address: cancel its accept
-- loop, close the underlying transport listener, and remove it from the
-- Switch's listener set so 'switchListenAddrs' stops reporting it.
--
-- For listeners whose reachability guarantee can lapse independently of
-- the Switch's own lifetime (e.g. a circuit relay reservation that
-- expired or was refused on refresh), this withdraws just that one
-- address without tearing down the rest of the Switch. A no-op if no
-- listener is bound to the address (already withdrawn, or never was).
switchWithdrawListener :: Switch -> Multiaddr -> IO ()
switchWithdrawListener sw addr = do
  withdrawn <- atomically $ do
    listeners <- readTVar (swListeners sw)
    let (removed, remaining) = partition ((== addr) . alAddress) listeners
    writeTVar (swListeners sw) remaining
    pure removed
  mapM_ closeListener withdrawn
  where
    closeListener al = do
      cancel (alAcceptLoop al) `catch` (\(_ :: SomeException) -> pure ())
      listenerClose (alListener al) `catch` (\(_ :: SomeException) -> pure ())
