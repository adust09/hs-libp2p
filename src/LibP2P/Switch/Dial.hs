-- | Dial logic for the Switch.
--
-- Implements connection reuse, exponential backoff, dial deduplication,
-- and parallel staggered dialing (Happy Eyeballs, RFC 8305).
--
-- Dial flow:
--   1. Check connection pool for existing Open connection
--   2. Check per-peer backoff (reject if recently failed)
--   3. Deduplication: join pending dial if another thread is already dialing
--   4. Select transport per address, staggered parallel dial
--   5. Upgrade first successful raw connection
--   6. Add to pool / record backoff on failure
module LibP2P.Switch.Dial
  ( -- * Main entry point
    dial
    -- * Dial options
  , DialOpts (..)
  , defaultDialOpts
  , dialWith
    -- * Backoff management
  , checkBackoff
  , recordBackoff
  , clearBackoff
    -- * Constants (exported for testing)
  , initialBackoffSeconds
  , maxBackoffSeconds
  , staggerDelayUs
  ) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.Async (Async, async, cancel, waitAnyCatch, waitCatch)
import Control.Concurrent.STM
  ( STM
  , TMVar
  , TVar
  , atomically
  , newEmptyTMVar
  , putTMVar
  , readTMVar
  , readTVar
  , tryPutTMVar
  , writeTChan
  , writeTVar
  )
import Control.Exception (SomeException, bracketOnError, catch, finally, onException)
import Control.Monad (forM, forM_, when)
import Data.List (find)
import qualified Data.Map.Strict as Map
import Data.Time.Clock (NominalDiffTime, addUTCTime, getCurrentTime)
import LibP2P.Crypto.PeerId (PeerId)
import LibP2P.Multiaddr (Multiaddr (..), isRelayedAddr)
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.Switch.ConnPool (addConn, lookupConn)
import LibP2P.Switch.Connection (closeConnection)
import LibP2P.Switch.Listen (streamAcceptLoop, switchListenAddrs)
import LibP2P.Switch.ResourceManager (Direction (..), releaseConnection, reserveConnection)
import LibP2P.Switch.Types
  ( BackoffEntry (..)
  , Connection (..)
  , DialError (..)
  , MuxerSession (..)
  , Switch (..)
  , SwitchConfig (..)
  , SwitchEvent (..)
  )
import LibP2P.Switch.Upgrade (upgradeAsWith)
import LibP2P.Transport (RawConnection (..), Transport (..))

-- | Initial backoff duration after first failure: 5 seconds.
initialBackoffSeconds :: NominalDiffTime
initialBackoffSeconds = 5

-- | Maximum backoff duration: 300 seconds (5 minutes).
maxBackoffSeconds :: NominalDiffTime
maxBackoffSeconds = 300

-- | Stagger delay between parallel dial attempts: 250ms (RFC 8305).
staggerDelayUs :: Int
staggerDelayUs = 250000

-- | Check if a peer is currently in dial backoff.
-- Returns Right () if no backoff is active or the backoff has expired.
-- Expired entries are cleaned up atomically.
checkBackoff :: TVar (Map.Map PeerId BackoffEntry) -> PeerId -> IO (Either DialError ())
checkBackoff backoffsVar pid = do
  now <- getCurrentTime
  atomically $ do
    boffs <- readTVar backoffsVar
    case Map.lookup pid boffs of
      Nothing -> pure (Right ())
      Just be
        | beExpiry be <= now -> do
            -- Expired, clean up
            writeTVar backoffsVar (Map.delete pid boffs)
            pure (Right ())
        | otherwise -> pure (Left DialBackoff)

-- | Record a backoff after a failed dial.
-- First failure: 5s. Each subsequent: duration * 2, capped at 300s.
-- Backoff formula: min(initialBackoff * 2^(attempts-1), maxBackoff)
recordBackoff :: TVar (Map.Map PeerId BackoffEntry) -> PeerId -> IO ()
recordBackoff backoffsVar pid = do
  now <- getCurrentTime
  atomically $ do
    boffs <- readTVar backoffsVar
    let attempts = case Map.lookup pid boffs of
          Nothing -> 1
          Just be -> beAttempts be + 1
        -- Exponential backoff: 5s, 10s, 20s, 40s, ..., capped at 300s
        duration = min maxBackoffSeconds
                       (initialBackoffSeconds * fromIntegral (2 ^ (attempts - 1) :: Int))
        entry = BackoffEntry
          { beExpiry   = addUTCTime duration now
          , beAttempts = attempts
          }
    writeTVar backoffsVar (Map.insert pid entry boffs)

-- | Clear backoff for a peer (called on successful connection).
clearBackoff :: TVar (Map.Map PeerId BackoffEntry) -> PeerId -> IO ()
clearBackoff backoffsVar pid = atomically $ do
  boffs <- readTVar backoffsVar
  writeTVar backoffsVar (Map.delete pid boffs)

-- | Result of checking for a pending dial (used internally).
data PendingCheck
  = JoinExisting !(TMVar (Either DialError Connection))
  | StartNew     !(TMVar (Either DialError Connection))

-- | Per-dial options.
--
-- Mirrors the two orthogonal context values go-libp2p threads through a
-- dial: @network.WithForceDirectDial@ and @network.WithSimultaneousConnect@,
-- which its hole puncher sets together.
data DialOpts = DialOpts
  { doForceDirect :: !Bool
    -- ^ Bypass connection reuse, dial backoff and dial deduplication,
    -- and always establish a new transport connection. Hole punching
    -- needs this: reusing a pooled connection emits no packet at all, so
    -- the TCP simultaneous connect the DCUtR spec relies on cannot
    -- happen. go-libp2p likewise consults backoff only when the dial is
    -- not force-direct.
  , doUpgradeAsClient :: !Bool
    -- ^ Whether to run the client side of the security handshake and the
    -- muxer. False upgrades as the responder over a connection we
    -- dialled, which specs/relay/DCUtR requires of peer @B@: "For the
    -- purpose of all protocols run on top of this TCP connection, @A@ is
    -- assumed to be the client and @B@ the server."
  }

-- | Ordinary dial: reuse pooled connections, honour backoff, act as client.
defaultDialOpts :: DialOpts
defaultDialOpts = DialOpts
  { doForceDirect     = False
  , doUpgradeAsClient = True
  }

-- | Dial a peer, reusing existing connections or establishing new ones.
--
-- Implements the full dial flow:
--   1. Pool reuse: return existing Open connection if available
--   2. Backoff check: reject if peer recently failed
--   3. Deduplication: coalesce concurrent dials to same peer via TMVar
--   4. Staggered parallel dial with 250ms delay (Happy Eyeballs)
--   5. First success: upgrade, add to pool, return
--   6. All fail: record backoff, return error
dial :: Switch -> PeerId -> [Multiaddr] -> IO (Either DialError Connection)
dial sw = dialWith sw defaultDialOpts

-- | Dial a peer under explicit options.
--
-- A force-direct dial skips steps 1-3 entirely. Skipping deduplication
-- is required, not incidental: DCUtR calls its dialer once per address
-- so that every address is attempted at the same moment, and a shared
-- pending-dial TMVar carries one result for all waiters, so joining it
-- would collapse those attempts into a single address. Backoff is still
-- *recorded* on failure, as go-libp2p does.
dialWith :: Switch -> DialOpts -> PeerId -> [Multiaddr] -> IO (Either DialError Connection)
dialWith sw opts remotePeerId addrs = do
  -- 0. Check switch is open
  closed <- atomically $ readTVar (swClosed sw)
  if closed
    then pure (Left DialSwitchClosed)
    else if doForceDirect opts
      then establishAndRegister sw opts remotePeerId addrs
      else do
        -- 1. Check connection pool for existing Open connection
        existing <- atomically $ lookupConn (swConnPool sw) remotePeerId
        case existing of
          Just conn -> pure (Right conn)
          Nothing -> do
            -- 2. Check backoff
            backoffResult <- checkBackoff (swDialBackoffs sw) remotePeerId
            case backoffResult of
              Left err -> pure (Left err)
              Right () -> do
                -- 3. Deduplication: check for pending dial
                joinOrCreate <- atomically $ checkPendingDial sw remotePeerId
                case joinOrCreate of
                  JoinExisting tmvar ->
                    -- Another thread is already dialing; wait for its result
                    atomically $ readTMVar tmvar
                  StartNew tmvar ->
                    -- We own this dial; execute and broadcast result.
                    -- If the dial throws, fill the TMVar and drop the
                    -- pending entry so waiters and future dials never
                    -- wedge on a stale pending dial.
                    dialNewAndBroadcast sw opts remotePeerId addrs tmvar
                      `onException` abortPendingDial sw remotePeerId tmvar

-- | Clean up a pending dial whose worker threw an exception.
-- Fills the TMVar (if still empty) so joined waiters are released,
-- and removes the pending map entry so future dials can proceed.
abortPendingDial :: Switch -> PeerId -> TMVar (Either DialError Connection) -> IO ()
abortPendingDial sw pid tmvar = atomically $ do
  _ <- tryPutTMVar tmvar (Left (DialAllFailed ["dial aborted by exception"]))
  pending <- readTVar (swPendingDials sw)
  writeTVar (swPendingDials sw) (Map.delete pid pending)

-- | Atomically check for an existing pending dial or create one.
checkPendingDial :: Switch -> PeerId -> STM PendingCheck
checkPendingDial sw pid = do
  pending <- readTVar (swPendingDials sw)
  case Map.lookup pid pending of
    Just tmvar -> pure (JoinExisting tmvar)
    Nothing -> do
      tmvar <- newEmptyTMVar
      writeTVar (swPendingDials sw) (Map.insert pid tmvar pending)
      pure (StartNew tmvar)

-- | Execute the dial, broadcast the result to joined waiters, and drop
-- the pending-dial entry.
dialNewAndBroadcast
  :: Switch -> DialOpts -> PeerId -> [Multiaddr]
  -> TMVar (Either DialError Connection)
  -> IO (Either DialError Connection)
dialNewAndBroadcast sw opts remotePeerId addrs tmvar = do
  result <- establishAndRegister sw opts remotePeerId addrs
  atomically $ do
    putTMVar tmvar result
    pending <- readTVar (swPendingDials sw)
    writeTVar (swPendingDials sw) (Map.delete remotePeerId pending)
  pure result

-- | Reserve resources, dial, verify the peer id, and register the
-- resulting connection.
--
-- Shared by the ordinary dial path and the force-direct one, which
-- reaches it without touching the pool, backoff or pending-dial state.
--
-- The direction is taken from 'doUpgradeAsClient' and used for the
-- resource reservation, the upgrade roles and 'connDirection' alike, so
-- the release in 'closeConnection' -- which reads 'connDirection' --
-- always matches what was reserved.
establishAndRegister
  :: Switch -> DialOpts -> PeerId -> [Multiaddr]
  -> IO (Either DialError Connection)
establishAndRegister sw opts remotePeerId addrs = do
  let dir = if doUpgradeAsClient opts then Outbound else Inbound
  resCheck <- atomically $ reserveConnection (swResourceMgr sw) remotePeerId dir
  case resCheck of
    Left resErr -> pure (Left (DialResourceLimit resErr))
    Right () -> do
      result <- dialNewInner sw opts dir addrs
        `onException` atomically (releaseConnection (swResourceMgr sw) remotePeerId dir)
      -- Verify remote PeerId matches expected target
      let verified = case result of
            Right conn
              | connPeerId conn /= remotePeerId ->
                  Left (DialPeerIdMismatch remotePeerId (connPeerId conn))
            _ -> result
      case verified of
        Right conn -> do
          clearBackoff (swDialBackoffs sw) remotePeerId
          atomically $ do
            addConn (swConnPool sw) conn
            writeTChan (swEvents sw)
              (Connected (connPeerId conn) dir (connRemoteAddr conn))
          -- Start accepting inbound streams on the dialer side; tear the
          -- connection down when the session dies (pool removal,
          -- resource release, muxer + transport close).
          _ <- async $ streamAcceptLoop sw conn `finally` closeConnection sw conn
          -- Notify connection listeners (e.g. GossipSub auto-stream open)
          notifiers <- atomically $ readTVar (swNotifiers sw)
          mapM_ (\f -> async $ f conn) notifiers
          pure (Right conn)
        Left _ -> do
          -- Close the muxer session on PeerId mismatch
          case result of
            Right conn -> muxClose (connSession conn)
            Left _     -> pure ()
          -- Release the reserved connection since dial failed
          atomically $ releaseConnection (swResourceMgr sw) remotePeerId dir
          recordBackoff (swDialBackoffs sw) remotePeerId
          pure verified

-- | Inner dial logic: transport selection and staggered parallel dial.
dialNewInner :: Switch -> DialOpts -> Direction -> [Multiaddr] -> IO (Either DialError Connection)
dialNewInner _sw _opts _dir [] = pure (Left DialNoAddresses)
dialNewInner sw opts dir addrs = do
  transports <- atomically $ readTVar (swTransports sw)
  -- Find a transport for each address
  let dialable = filterMap (\addr ->
        case find (\t -> transportCanDial t addr) transports of
          Just t  -> Just (addr, t)
          Nothing -> Nothing) addrs
  case dialable of
    []    -> pure (Left (DialNoTransport (Prelude.head addrs)))
    pairs -> staggeredDial sw opts dir pairs

-- | Filter and map a list, keeping only Just results.
filterMap :: (a -> Maybe b) -> [a] -> [b]
filterMap _ [] = []
filterMap f (x:xs) = case f x of
  Nothing -> filterMap f xs
  Just y  -> y : filterMap f xs

-- | Attempt to dial using staggered parallel attempts (Happy Eyeballs, RFC 8305).
--
-- Addresses are tried with 250ms delay between each attempt.
-- The first successful connection wins; remaining attempts are cancelled.
staggeredDial
  :: Switch -> DialOpts -> Direction -> [(Multiaddr, Transport)]
  -> IO (Either DialError Connection)
staggeredDial sw opts dir pairs =
  bracketOnError spawnWorkers cancelAndCloseWorkers (`collectResults` [])
  where
    -- Spawn workers with staggered delays: 0ms, 250ms, 500ms, ...
    spawnWorkers = forM (zip [0 :: Int ..] pairs) $ \(i, (addr, transport)) ->
      async $ do
        when (i > 0) $ threadDelay (i * staggerDelayUs)
        localBind <- localBindFor sw (doForceDirect opts) addr
        rawConn <- transportDialFrom transport localBind addr
        upgradeAsWith (scYamuxConfig (swConfig sw)) dir (swIdentityKey sw) rawConn
          `onException` rcClose rawConn

-- | Hole-punch dials bind the outgoing socket to a same-family listen
-- address so the SYN shares the listen port. Ordinary dials leave the
-- source port ephemeral.
localBindFor :: Switch -> Bool -> Multiaddr -> IO (Maybe Multiaddr)
localBindFor _ False _ = pure Nothing
localBindFor sw True remote = do
  addrs <- switchListenAddrs sw
  pure $ find (sameIpFamily remote) (filter (not . isRelayedAddr) addrs)

sameIpFamily :: Multiaddr -> Multiaddr -> Bool
sameIpFamily a b = ipKind a == ipKind b && ipKind a /= Nothing
  where
    ipKind (Multiaddr (IP4 _ : _)) = Just (0 :: Int)
    ipKind (Multiaddr (IP6 _ : _)) = Just 1
    ipKind _ = Nothing

-- | Wait for the first successful async result, cancelling the rest.
-- If all fail, return DialAllFailed with all error messages.
collectResults :: [Async Connection] -> [String] -> IO (Either DialError Connection)
collectResults [] errs = pure (Left (DialAllFailed (reverse errs)))
collectResults workers errs = do
  (completed, result) <- waitAnyCatch workers
  let remaining = filter (/= completed) workers
  case result of
    Right conn -> do
      cancelAndCloseWorkers remaining
      pure (Right conn)
    Left (ex :: SomeException) ->
      collectResults remaining (show ex : errs)

-- | Stop losing dial workers and close any connection that crossed the
-- upgrade finish line before cancellation reached it.
cancelAndCloseWorkers :: [Async Connection] -> IO ()
cancelAndCloseWorkers workers = do
  mapM_ cancel workers
  forM_ workers $ \worker -> do
    outcome <- waitCatch worker
    case outcome of
      Right conn -> muxClose (connSession conn)
        `catch` \(_ :: SomeException) -> pure ()
      Left _ -> pure ()
