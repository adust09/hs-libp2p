-- | Hierarchical resource management for the Switch.
--
-- Resources are owned by a System -> Peer -> Connection -> Stream scope tree.
-- Reservations walk from the owning scope to the system scope in one STM
-- transaction, so a failed ancestor check never leaves partial usage behind.
module LibP2P.Switch.ResourceManager
  ( Direction (..)
  , ResourceUsage (..)
  , emptyUsage
  , ResourceLimits (..)
  , noLimits
  , DefaultLimits (..)
  , defaultSystemLimits
  , defaultPeerLimits
  , defaultConnectionLimits
  , defaultStreamLimits
  , ResourceScope (..)
  , ScopeName (..)
  , ResourceError (..)
  , MemoryAccount (..)
  , ResourceManager (..)
  , newResourceManager
  , getOrCreatePeerScope
  , reserveConnection
  , releaseConnection
  , reserveStream
  , releaseStream
  , reserveMemory
  , releaseMemory
  , scopeMemoryAccount
  , unlimitedMemoryAccount
  , withConnection
  , withStream
  ) where

import Control.Concurrent.STM
  ( STM
  , TVar
  , atomically
  , modifyTVar'
  , newTVar
  , readTVar
  , writeTVar
  )
import Control.Exception (Exception, bracket)
import Control.Monad (unless)
import qualified Data.Map.Strict as Map
import LibP2P.Crypto.PeerId (PeerId)

-- | Direction of a resource relative to this node.
data Direction = Inbound | Outbound
  deriving (Show, Eq)

-- | Tracked usage aggregated at a scope.
data ResourceUsage = ResourceUsage
  { ruConnsInbound :: !Int
  , ruConnsOutbound :: !Int
  , ruStreamsInbound :: !Int
  , ruStreamsOutbound :: !Int
  , ruMemory :: !Int
  } deriving (Show, Eq)

emptyUsage :: ResourceUsage
emptyUsage = ResourceUsage 0 0 0 0 0

-- | Configurable limits per scope. 'Nothing' means unlimited.
data ResourceLimits = ResourceLimits
  { rlMaxConnsInbound :: !(Maybe Int)
  , rlMaxConnsOutbound :: !(Maybe Int)
  , rlMaxConnsTotal :: !(Maybe Int)
  , rlMaxStreamsInbound :: !(Maybe Int)
  , rlMaxStreamsOutbound :: !(Maybe Int)
  , rlMaxStreamsTotal :: !(Maybe Int)
  , rlMaxMemory :: !(Maybe Int)
  } deriving (Show, Eq)

noLimits :: ResourceLimits
noLimits = ResourceLimits Nothing Nothing Nothing Nothing Nothing Nothing Nothing

-- | Stable names make sibling connection and stream scopes distinguishable.
data ScopeName
  = SystemScope
  | PeerScope !PeerId
  | ConnectionScope !Int
  | StreamScope !Int
  deriving (Show, Eq, Ord)

-- | A node in the resource ownership tree.
data ResourceScope = ResourceScope
  { rsName :: !ScopeName
  , rsUsage :: !(TVar ResourceUsage)
  , rsLimits :: !ResourceLimits
  , rsParent :: !(Maybe ResourceScope)
  , rsChildren :: !(TVar (Map.Map Int ResourceScope))
  , rsClosed :: !(TVar Bool)
  }

-- | Resource reservation failures.
data ResourceError
  = ResourceLimitExceeded !ScopeName !String
  | ResourceScopeClosed !ScopeName
  | InvalidMemoryReservation !Int
  | InvalidParentScope !ScopeName
  deriving (Show, Eq)

instance Exception ResourceError

-- | Generic memory hooks used by buffering layers without exposing the tree.
data MemoryAccount = MemoryAccount
  { maReserve :: !(Int -> STM (Either ResourceError ()))
  , maRelease :: !(Int -> STM ())
  , maClose :: !(STM ())
  }

-- | Limits used for automatically-created scopes.
data DefaultLimits = DefaultLimits
  { dlSystemLimits :: !ResourceLimits
  , dlPeerLimits :: !ResourceLimits
  , dlConnectionLimits :: !ResourceLimits
  , dlStreamLimits :: !ResourceLimits
  } deriving (Show, Eq)

defaultSystemLimits :: ResourceLimits
defaultSystemLimits = noLimits
  { rlMaxConnsInbound = Just 256
  , rlMaxConnsOutbound = Just 256
  , rlMaxConnsTotal = Just 512
  , rlMaxStreamsInbound = Just 4096
  , rlMaxStreamsOutbound = Just 4096
  , rlMaxStreamsTotal = Just 8192
  , rlMaxMemory = Just (256 * 1024 * 1024)
  }

defaultPeerLimits :: ResourceLimits
defaultPeerLimits = noLimits
  { rlMaxConnsInbound = Just 4
  , rlMaxConnsOutbound = Just 4
  , rlMaxConnsTotal = Just 8
  , rlMaxStreamsInbound = Just 256
  , rlMaxStreamsOutbound = Just 256
  , rlMaxStreamsTotal = Just 512
  , rlMaxMemory = Just (16 * 1024 * 1024)
  }

defaultConnectionLimits :: ResourceLimits
defaultConnectionLimits = noLimits

defaultStreamLimits :: ResourceLimits
defaultStreamLimits = noLimits

data ResourceManager = ResourceManager
  { rmSystemScope :: !ResourceScope
  , rmDefaults :: !DefaultLimits
  , rmPeerScopes :: !(TVar (Map.Map PeerId ResourceScope))
  , rmNextScopeId :: !(TVar Int)
  }

newResourceManager :: DefaultLimits -> IO ResourceManager
newResourceManager defaults = atomically $ do
  systemScope <- newScope SystemScope (dlSystemLimits defaults) Nothing
  peers <- newTVar Map.empty
  nextId <- newTVar 1
  pure ResourceManager
    { rmSystemScope = systemScope
    , rmDefaults = defaults
    , rmPeerScopes = peers
    , rmNextScopeId = nextId
    }

newScope :: ScopeName -> ResourceLimits -> Maybe ResourceScope -> STM ResourceScope
newScope name limits parent = do
  usage <- newTVar emptyUsage
  children <- newTVar Map.empty
  closed <- newTVar False
  pure ResourceScope
    { rsName = name
    , rsUsage = usage
    , rsLimits = limits
    , rsParent = parent
    , rsChildren = children
    , rsClosed = closed
    }

nextScopeId :: ResourceManager -> STM Int
nextScopeId rm = do
  scopeId <- readTVar (rmNextScopeId rm)
  writeTVar (rmNextScopeId rm) (scopeId + 1)
  pure scopeId

getOrCreatePeerScope :: ResourceManager -> PeerId -> STM ResourceScope
getOrCreatePeerScope rm pid = do
  peers <- readTVar (rmPeerScopes rm)
  case Map.lookup pid peers of
    Just scope -> pure scope
    Nothing -> do
      scope <- newScope (PeerScope pid) (dlPeerLimits (rmDefaults rm))
        (Just (rmSystemScope rm))
      writeTVar (rmPeerScopes rm) (Map.insert pid scope peers)
      pure scope

-- | Create and reserve one connection scope.
reserveConnection
  :: ResourceManager -> PeerId -> Direction
  -> STM (Either ResourceError ResourceScope)
reserveConnection rm pid direction = do
  peer <- getOrCreatePeerScope rm pid
  scopeId <- nextScopeId rm
  scope <- newScope (ConnectionScope scopeId)
    (dlConnectionLimits (rmDefaults rm)) (Just peer)
  result <- reserveUsage scope (incrementConnection direction)
  case result of
    Left err -> dropPeerIfUnused rm peer >> pure (Left err)
    Right () -> attachChild peer scopeId scope >> pure (Right scope)

-- | Close a connection and every stream it owns. Idempotent.
releaseConnection :: ResourceManager -> ResourceScope -> STM ()
releaseConnection rm scope = case rsName scope of
  ConnectionScope _ -> closeOwnedScope rm scope
  _ -> pure ()

-- | Create and reserve one stream below a connection scope.
reserveStream
  :: ResourceManager -> ResourceScope -> Direction
  -> STM (Either ResourceError ResourceScope)
reserveStream rm connection direction = case rsName connection of
  ConnectionScope _ -> do
    scopeId <- nextScopeId rm
    scope <- newScope (StreamScope scopeId)
      (dlStreamLimits (rmDefaults rm)) (Just connection)
    result <- reserveUsage scope (incrementStream direction)
    case result of
      Left err -> pure (Left err)
      Right () -> attachChild connection scopeId scope >> pure (Right scope)
  name -> pure (Left (InvalidParentScope name))

-- | Close a stream and release all usage it still owns. Idempotent.
releaseStream :: ResourceManager -> ResourceScope -> STM ()
releaseStream rm scope = case rsName scope of
  StreamScope _ -> closeOwnedScope rm scope
  _ -> pure ()

reserveMemory :: ResourceScope -> Int -> STM (Either ResourceError ())
reserveMemory _ bytes | bytes <= 0 = pure (Left (InvalidMemoryReservation bytes))
reserveMemory scope bytes = reserveUsage scope $ \usage ->
  usage {ruMemory = ruMemory usage + bytes}

releaseMemory :: ResourceScope -> Int -> STM ()
releaseMemory _ bytes | bytes <= 0 = pure ()
releaseMemory scope bytes = do
  closed <- readTVar (rsClosed scope)
  unless closed $ do
    usage <- readTVar (rsUsage scope)
    let released = min bytes (ruMemory usage)
    subtractMemoryFromChain scope released

scopeMemoryAccount :: ResourceManager -> ResourceScope -> MemoryAccount
scopeMemoryAccount rm scope = MemoryAccount
  { maReserve = reserveMemory scope
  , maRelease = releaseMemory scope
  , maClose = closeOwnedScope rm scope
  }

-- | An account for standalone protocol use where no manager is installed.
unlimitedMemoryAccount :: MemoryAccount
unlimitedMemoryAccount = MemoryAccount
  { maReserve = \bytes -> if bytes > 0
      then pure (Right ())
      else pure (Left (InvalidMemoryReservation bytes))
  , maRelease = const (pure ())
  , maClose = pure ()
  }

withConnection
  :: ResourceManager -> PeerId -> Direction
  -> (ResourceScope -> IO a) -> IO a
withConnection rm pid direction = bracket acquire release
  where
    acquire = atomically (reserveConnection rm pid direction)
      >>= either (fail . show) pure
    release = atomically . releaseConnection rm

withStream
  :: ResourceManager -> ResourceScope -> Direction
  -> (ResourceScope -> IO a) -> IO a
withStream rm connection direction = bracket acquire release
  where
    acquire = atomically (reserveStream rm connection direction)
      >>= either (fail . show) pure
    release = atomically . releaseStream rm

attachChild :: ResourceScope -> Int -> ResourceScope -> STM ()
attachChild parent scopeId child =
  modifyTVar' (rsChildren parent) (Map.insert scopeId child)

reserveUsage
  :: ResourceScope -> (ResourceUsage -> ResourceUsage)
  -> STM (Either ResourceError ())
reserveUsage scope update = do
  proposed <- collectUpdates scope update
  case proposed of
    Left err -> pure (Left err)
    Right updates -> do
      mapM_ (uncurry writeScopeUsage) updates
      pure (Right ())

writeScopeUsage :: ResourceScope -> ResourceUsage -> STM ()
writeScopeUsage = writeTVar . rsUsage

collectUpdates
  :: ResourceScope -> (ResourceUsage -> ResourceUsage)
  -> STM (Either ResourceError [(ResourceScope, ResourceUsage)])
collectUpdates scope update = do
  closed <- readTVar (rsClosed scope)
  if closed
    then pure (Left (ResourceScopeClosed (rsName scope)))
    else do
      proposed <- update <$> readTVar (rsUsage scope)
      case checkLimits scope proposed of
        Left err -> pure (Left err)
        Right () -> collectParentUpdates scope update proposed

collectParentUpdates
  :: ResourceScope -> (ResourceUsage -> ResourceUsage) -> ResourceUsage
  -> STM (Either ResourceError [(ResourceScope, ResourceUsage)])
collectParentUpdates scope update proposed = case rsParent scope of
  Nothing -> pure (Right [(scope, proposed)])
  Just parent -> do
    parentResult <- collectUpdates parent update
    pure $ ((scope, proposed) :) <$> parentResult

checkLimits :: ResourceScope -> ResourceUsage -> Either ResourceError ()
checkLimits scope usage = firstExceeded checks
  where
    limits = rsLimits scope
    checks =
      [ (rlMaxConnsInbound limits, ruConnsInbound usage, "inbound connections")
      , (rlMaxConnsOutbound limits, ruConnsOutbound usage, "outbound connections")
      , (rlMaxConnsTotal limits, totalConnections usage, "total connections")
      , (rlMaxStreamsInbound limits, ruStreamsInbound usage, "inbound streams")
      , (rlMaxStreamsOutbound limits, ruStreamsOutbound usage, "outbound streams")
      , (rlMaxStreamsTotal limits, totalStreams usage, "total streams")
      , (rlMaxMemory limits, ruMemory usage, "memory")
      ]
    firstExceeded [] = Right ()
    firstExceeded ((Just limit, actual, label) : rest)
      | actual > limit = Left (ResourceLimitExceeded (rsName scope) label)
      | otherwise = firstExceeded rest
    firstExceeded ((Nothing, _, _) : rest) = firstExceeded rest

incrementConnection :: Direction -> ResourceUsage -> ResourceUsage
incrementConnection Inbound usage =
  usage {ruConnsInbound = ruConnsInbound usage + 1}
incrementConnection Outbound usage =
  usage {ruConnsOutbound = ruConnsOutbound usage + 1}

incrementStream :: Direction -> ResourceUsage -> ResourceUsage
incrementStream Inbound usage =
  usage {ruStreamsInbound = ruStreamsInbound usage + 1}
incrementStream Outbound usage =
  usage {ruStreamsOutbound = ruStreamsOutbound usage + 1}

totalConnections :: ResourceUsage -> Int
totalConnections usage = ruConnsInbound usage + ruConnsOutbound usage

totalStreams :: ResourceUsage -> Int
totalStreams usage = ruStreamsInbound usage + ruStreamsOutbound usage

closeOwnedScope :: ResourceManager -> ResourceScope -> STM ()
closeOwnedScope rm scope = do
  closed <- readTVar (rsClosed scope)
  unless closed $ do
    usage <- readTVar (rsUsage scope)
    markSubtreeClosed scope
    subtractUsageFromParents (rsParent scope) usage
    detachFromParent scope
    maybeDropOwningPeer rm scope

markSubtreeClosed :: ResourceScope -> STM ()
markSubtreeClosed scope = do
  writeTVar (rsClosed scope) True
  writeTVar (rsUsage scope) emptyUsage
  children <- readTVar (rsChildren scope)
  mapM_ markSubtreeClosed (Map.elems children)
  writeTVar (rsChildren scope) Map.empty

subtractUsageFromParents :: Maybe ResourceScope -> ResourceUsage -> STM ()
subtractUsageFromParents Nothing _ = pure ()
subtractUsageFromParents (Just scope) usage = do
  modifyTVar' (rsUsage scope) (`minusUsage` usage)
  subtractUsageFromParents (rsParent scope) usage

subtractMemoryFromChain :: ResourceScope -> Int -> STM ()
subtractMemoryFromChain _ 0 = pure ()
subtractMemoryFromChain scope bytes = do
  modifyTVar' (rsUsage scope) $ \usage ->
    usage {ruMemory = max 0 (ruMemory usage - bytes)}
  case rsParent scope of
    Nothing -> pure ()
    Just parent -> subtractMemoryFromChain parent bytes

minusUsage :: ResourceUsage -> ResourceUsage -> ResourceUsage
minusUsage current released = ResourceUsage
  { ruConnsInbound = difference (ruConnsInbound current) (ruConnsInbound released)
  , ruConnsOutbound = difference (ruConnsOutbound current) (ruConnsOutbound released)
  , ruStreamsInbound = difference (ruStreamsInbound current) (ruStreamsInbound released)
  , ruStreamsOutbound = difference (ruStreamsOutbound current) (ruStreamsOutbound released)
  , ruMemory = difference (ruMemory current) (ruMemory released)
  }
  where
    difference a b = max 0 (a - b)

detachFromParent :: ResourceScope -> STM ()
detachFromParent scope = case (scopeIdOf (rsName scope), rsParent scope) of
  (Just scopeId, Just parent) ->
    modifyTVar' (rsChildren parent) (Map.delete scopeId)
  _ -> pure ()

scopeIdOf :: ScopeName -> Maybe Int
scopeIdOf (ConnectionScope scopeId) = Just scopeId
scopeIdOf (StreamScope scopeId) = Just scopeId
scopeIdOf _ = Nothing

maybeDropOwningPeer :: ResourceManager -> ResourceScope -> STM ()
maybeDropOwningPeer rm scope = case owningPeer scope of
  Nothing -> pure ()
  Just peer -> dropPeerIfUnused rm peer

owningPeer :: ResourceScope -> Maybe ResourceScope
owningPeer scope = case rsName scope of
  PeerScope _ -> Just scope
  _ -> rsParent scope >>= owningPeer

dropPeerIfUnused :: ResourceManager -> ResourceScope -> STM ()
dropPeerIfUnused rm peer = case rsName peer of
  PeerScope pid -> do
    usage <- readTVar (rsUsage peer)
    children <- readTVar (rsChildren peer)
    if usage == emptyUsage && Map.null children
      then do
        modifyTVar' (rmPeerScopes rm) (Map.delete pid)
        writeTVar (rsClosed peer) True
      else pure ()
  _ -> pure ()
