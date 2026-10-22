-- | Connection lifecycle for the Switch.
--
-- Provides the single teardown path for upgraded connections and a
-- resource-accounted outbound stream opener. Teardown fires from the
-- stream accept loop exit (remote disconnect or session death), from
-- explicit 'closeConnection' calls, and from 'switchClose' via
-- 'closeAllConnections'.
module LibP2P.Switch.Connection
  ( closeConnection
  , closeAllConnections
  , newStream
  , newStreamAllowingLimited
  , StreamOpenError (..)
  ) where

import Control.Concurrent.STM (atomically, readTVar, writeTChan, writeTVar)
import Control.Exception (Exception, SomeException, catch, mask, onException)
import Control.Monad (when)
import LibP2P.MultistreamSelect.Negotiation (StreamIO (..))
import LibP2P.Switch.ConnPool (allConns, removeConn)
import LibP2P.Switch.ResourceManager
  ( Direction (..)
  , ResourceError (..)
  , releaseConnection
  , releaseStream
  , reserveStream
  , scopeMemoryAccount
  )
import LibP2P.Transport (relayCircuitIsLimited)
import LibP2P.Switch.Types
  ( ConnState (..)
  , Connection (..)
  , MuxerSession (..)
  , Switch (..)
  , SwitchEvent (..)
  )

-- | Tear down a connection: remove it from the pool, release its
-- resource reservation, publish a Disconnected event, run the
-- disconnect notifiers, and close the muxer session together with the
-- underlying transport.
--
-- Idempotent: the state transition to ConnClosed is atomic, so
-- concurrent calls (accept loop exit, explicit close, switchClose)
-- perform the teardown exactly once, and the notifiers run once.
--
-- Notifiers run synchronously, after the pool removal has committed and
-- before the muxer is closed, so a notifier that asks whether the peer
-- still has a live connection (Circuit Relay v2 reservation cleanup)
-- never sees the connection being torn down. Each is isolated so a
-- failing notifier cannot abort the teardown.
closeConnection :: Switch -> Connection -> IO ()
closeConnection sw conn = do
  shouldClose <- atomically $ do
    st <- readTVar (connState conn)
    if st == ConnClosed
      then pure False
      else do
        writeTVar (connState conn) ConnClosed
        removeConn (swConnPool sw) conn
        releaseConnection (swResourceMgr sw) (connResourceScope conn)
        writeTChan (swEvents sw)
          (Disconnected (connPeerId conn) (connDirection conn) (connRemoteAddr conn))
        pure True
  when shouldClose $ do
    notifiers <- atomically $ readTVar (swDisconnectNotifiers sw)
    mapM_ (\f -> f conn `catch` \(_ :: SomeException) -> pure ()) notifiers
    muxClose (connSession conn) `catch` \(_ :: SomeException) -> pure ()

-- | Tear down every pooled connection (used by switchClose).
closeAllConnections :: Switch -> IO ()
closeAllConnections sw = do
  conns <- atomically $ allConns (swConnPool sw)
  mapM_ (closeConnection sw) conns

-- | Failure to open an outbound stream.
data StreamOpenError
  = StreamResourceLimit !ResourceError
    -- ^ Peer or connection stream budget is exhausted
  | StreamLimitedConnection
    -- ^ The connection is a relay circuit with an active budget, and
    -- the caller did not opt in. No stream slot is reserved.
  deriving (Show, Eq)

instance Exception StreamOpenError

-- | Open an outbound stream on a connection, reserving a stream slot
-- against the peer's resource scope. The slot is released when the
-- returned stream is closed (exactly once, even on double close).
--
-- Refuses a relay-limited connection. Protocols that must run over a
-- relay circuit (Identify, Ping, DCUtR) use 'newStreamAllowingLimited'.
newStream :: Switch -> Connection -> IO (Either StreamOpenError StreamIO)
newStream = openOutboundStream False

-- | Like 'newStream', but allows a relay-limited connection.
--
-- The circuit still dies when its budget is exhausted
-- ('LibP2P.NAT.Relay.Limit.RelayCircuitExhausted'). Opt in only for a
-- short exchange that can tolerate that.
newStreamAllowingLimited
  :: Switch -> Connection -> IO (Either StreamOpenError StreamIO)
newStreamAllowingLimited = openOutboundStream True

openOutboundStream
  :: Bool -> Switch -> Connection -> IO (Either StreamOpenError StreamIO)
openOutboundStream allowLimited sw conn
  | not allowLimited && relayCircuitIsLimited (connRelayLimit conn) =
      pure (Left StreamLimitedConnection)
  | otherwise = mask $ \restore -> do
      reserved <- atomically $
        reserveStream (swResourceMgr sw) (connResourceScope conn) Outbound
      case reserved of
        Left err -> pure (Left (StreamResourceLimit err))
        Right streamScope -> do
          let release = atomically $ releaseStream (swResourceMgr sw) streamScope
              account = scopeMemoryAccount (swResourceMgr sw) streamScope
          stream <- restore (muxOpenStream (connSession conn) account)
            `onException` release
          pure (Right stream)
