-- | AutoNAT v2 address-specific reachability client and server.
module LibP2P.NAT.AutoNAT.V2
  ( AutoNATV2Config (..)
  , defaultAutoNATV2Config
  , AutoNATV2State
  , AutoNATV2ServerOps (..)
  , AutoNATV2Request (..)
  , AutoNATV2Result (..)
  , newAutoNATV2State
  , handleAutoNATV2DialRequest
  , handleAutoNATV2DialBack
  , requestAutoNATV2
  , addressesConsistent
  ) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.STM
import Control.Exception
  ( SomeAsyncException
  , SomeException
  , catch
  , finally
  , fromException
  , throwIO
  )
import Control.Monad (when)
import Crypto.Random (getRandomBytes)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.List (find)
import Data.Maybe (listToMaybe)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Time.Clock.POSIX (POSIXTime, getPOSIXTime)
import Data.Word (Word32, Word64)
import LibP2P.Crypto.PeerId (PeerId)
import LibP2P.Multiaddr
  ( Multiaddr (..)
  , fromBytes
  , isPublicAddr
  , isRelayedAddr
  , toBytes
  )
import LibP2P.Multiaddr.Protocol (Protocol (..), protocolCode)
import LibP2P.MultistreamSelect.Negotiation (StreamIO, closeQuietly)
import LibP2P.NAT.AutoNAT (NATStatus (..))
import LibP2P.NAT.AutoNAT.V2.Message
import System.Timeout (timeout)

-- | AutoNAT v2 limits and injectable time/randomness.
data AutoNATV2Config = AutoNATV2Config
  { an2AllowPrivateAddrs :: !Bool
    -- ^ Permit private/loopback candidates. Intended for tests only.
  , an2ServerRPM :: !Int
    -- ^ Global dial requests accepted per rolling minute.
  , an2ServerPerPeerRPM :: !Int
    -- ^ Dial requests accepted from one peer per rolling minute.
  , an2ServerDialDataRPM :: !Int
    -- ^ Cross-IP requests accepted per rolling minute.
  , an2MaxConcurrentPerPeer :: !Int
    -- ^ Simultaneous requests accepted from one peer.
  , an2MaxPeerAddresses :: !Int
    -- ^ Maximum candidate addresses inspected from one request.
  , an2MinDialDataBytes :: !Word64
    -- ^ Minimum amplification-prevention upload requested.
  , an2MaxDialDataBytes :: !Word64
    -- ^ Maximum amplification-prevention upload requested.
  , an2MaxDialWaitMicros :: !Int
    -- ^ Random delay ceiling after receiving dial data.
  , an2DialBackWaitMicros :: !Int
    -- ^ How long a client waits for the nonce on the dial-back stream.
  , an2RandomWord64 :: !(IO Word64)
    -- ^ Random source for nonces, dial-data size, and dial delay.
  , an2Now :: !(IO POSIXTime)
    -- ^ Clock used by the rolling rate limiter.
  }

-- | go-libp2p-compatible AutoNAT v2 defaults.
defaultAutoNATV2Config :: AutoNATV2Config
defaultAutoNATV2Config = AutoNATV2Config
  { an2AllowPrivateAddrs = False
  , an2ServerRPM = 60
  , an2ServerPerPeerRPM = 12
  , an2ServerDialDataRPM = 12
  , an2MaxConcurrentPerPeer = 2
  , an2MaxPeerAddresses = 50
  , an2MinDialDataBytes = 30000
  , an2MaxDialDataBytes = 99999
  , an2MaxDialWaitMicros = 3000000
  , an2DialBackWaitMicros = 5000000
  , an2RandomWord64 = randomWord64
  , an2Now = getPOSIXTime
  }

-- | Server operations supplied by the Switch integration.
data AutoNATV2ServerOps = AutoNATV2ServerOps
  { an2CanDial :: !(PeerId -> Multiaddr -> IO Bool)
  , an2DialBack :: !(PeerId -> Multiaddr -> Word64 -> IO DialStatusV2)
  }

-- | One address offered by the client.
data AutoNATV2Request = AutoNATV2Request
  { an2RequestAddr :: !Multiaddr
  , an2SendDialData :: !Bool
  }
  deriving (Show, Eq)

-- | Address-specific reachability outcome.
data AutoNATV2Result = AutoNATV2Result
  { an2ResultAddr :: !(Maybe Multiaddr)
  , an2ResultIndex :: !(Maybe Int)
  , an2ResultReachability :: !NATStatus
  , an2AllAddrsRefused :: !Bool
  }
  deriving (Show, Eq)

data RateState = RateState
  { rateRequests :: ![(POSIXTime, PeerId)]
  , rateDialDataRequests :: ![POSIXTime]
  , rateActive :: !(Map PeerId Int)
  }

data AutoNATV2State = AutoNATV2State
  { an2Config :: !AutoNATV2Config
  , an2PendingDialBacks :: !(TVar (Map Word64 (TMVar Multiaddr)))
  , an2RateState :: !(TVar RateState)
  }

newAutoNATV2State :: AutoNATV2Config -> IO AutoNATV2State
newAutoNATV2State config = do
  validateConfig config
  pending <- newTVarIO Map.empty
  rateState <- newTVarIO (RateState [] [] Map.empty)
  pure AutoNATV2State
    { an2Config = config
    , an2PendingDialBacks = pending
    , an2RateState = rateState
    }

validateConfig :: AutoNATV2Config -> IO ()
validateConfig config
  | an2ServerRPM config < 1 = invalid "global request limit must be positive"
  | an2ServerPerPeerRPM config < 1 = invalid "per-peer request limit must be positive"
  | an2ServerDialDataRPM config < 1 = invalid "dial-data request limit must be positive"
  | an2MaxConcurrentPerPeer config < 1 = invalid "concurrency limit must be positive"
  | an2MaxPeerAddresses config < 1 = invalid "address limit must be positive"
  | an2MinDialDataBytes config < 1 = invalid "minimum dial data must be positive"
  | an2MinDialDataBytes config > an2MaxDialDataBytes config = invalid "dial-data range is reversed"
  | an2MaxDialDataBytes config > 100000 = invalid "maximum dial data exceeds the protocol limit"
  | an2MaxDialWaitMicros config < 0 = invalid "dial wait must not be negative"
  | an2DialBackWaitMicros config < 1 = invalid "dial-back wait must be positive"
  | otherwise = pure ()
  where
    invalid = ioError . userError . ("invalid AutoNAT v2 configuration: " <>)

-- | Serve one dial-request stream and close it on every exit path.
handleAutoNATV2DialRequest
  :: AutoNATV2State
  -> AutoNATV2ServerOps
  -> StreamIO
  -> PeerId
  -> Multiaddr
  -> IO ()
handleAutoNATV2DialRequest state ops stream peer observedAddr =
  serve `finally` closeQuietly stream
  where
    serve = do
      accepted <- acquireRequest state peer
      if not accepted
        then writeResponse stream ResponseRequestRejected 0 DialStatusUnused
        else serveAccepted `finally` releaseRequest state peer
    serveAccepted = do
      incoming <- readAutoNATV2Message stream
      case incoming of
        Right (V2DialRequest request) -> processRequest state ops stream peer observedAddr request
        _ -> pure ()

processRequest
  :: AutoNATV2State
  -> AutoNATV2ServerOps
  -> StreamIO
  -> PeerId
  -> Multiaddr
  -> DialRequestV2
  -> IO ()
processRequest state ops stream peer observedAddr request = do
  selected <- selectDialAddress state ops peer (drv2Addrs request)
  case selected of
    Nothing -> writeResponse stream ResponseDialRefused 0 DialStatusUnused
    Just (index, address) -> do
      let requiresData = dialDataRequired observedAddr address
      dataAccepted <- if requiresData then acquireDialDataRequest state else pure True
      if not dataAccepted
        then writeResponse stream ResponseRequestRejected 0 DialStatusUnused
        else do
          dataReceived <- if requiresData
            then requestDialData state stream index
            else pure True
          when dataReceived $ do
            when requiresData (waitBeforeDial state)
            status <- catchSync
              (an2DialBack ops peer address (drv2Nonce request))
              (const (pure DialStatusBackError))
            writeResponse stream ResponseOK (fromIntegral index) status

selectDialAddress
  :: AutoNATV2State
  -> AutoNATV2ServerOps
  -> PeerId
  -> [ByteString]
  -> IO (Maybe (Int, Multiaddr))
selectDialAddress state ops peer = go 0 . take limit
  where
    config = an2Config state
    limit = an2MaxPeerAddresses config
    go _ [] = pure Nothing
    go index (raw : rest) = case fromBytes raw of
      Left _ -> go (index + 1) rest
      Right address
        | not (allowedAddress config address) -> go (index + 1) rest
        | otherwise -> do
            dialable <- an2CanDial ops peer address
            if dialable
              then pure (Just (index, address))
              else go (index + 1) rest

requestDialData :: AutoNATV2State -> StreamIO -> Int -> IO Bool
requestDialData state stream index = do
  requested <- dialDataSize state
  writeAutoNATV2Message stream $ V2DialDataRequest DialDataRequestV2
    { ddrv2AddrIdx = fromIntegral index
    , ddrv2NumBytes = requested
    }
  receive requested
  where
    receive remaining = do
      incoming <- readAutoNATV2Message stream
      case incoming of
        Right (V2DialDataResponse bytes)
          | BS.length bytes <= 4096
          , BS.length bytes >= minimumChunk remaining ->
              if fromIntegral (BS.length bytes) >= remaining
                then pure True
                else receive (remaining - fromIntegral (BS.length bytes))
        _ -> pure False
    minimumChunk remaining
      | remaining <= 100 = fromIntegral remaining
      | otherwise = 100

waitBeforeDial :: AutoNATV2State -> IO ()
waitBeforeDial state = do
  let ceilingMicros = an2MaxDialWaitMicros (an2Config state)
  when (ceilingMicros > 0) $ do
    random <- an2RandomWord64 (an2Config state)
    threadDelay (fromIntegral (random `mod` fromIntegral (ceilingMicros + 1)))

dialDataSize :: AutoNATV2State -> IO Word64
dialDataSize state = do
  let config = an2Config state
      minimumBytes = an2MinDialDataBytes config
      maximumBytes = an2MaxDialDataBytes config
      width = maximumBytes - minimumBytes + 1
  random <- an2RandomWord64 config
  pure (minimumBytes + random `mod` width)

writeResponse
  :: StreamIO -> ResponseStatusV2 -> Word32 -> DialStatusV2 -> IO ()
writeResponse stream status index dialStatus =
  writeAutoNATV2Message stream . V2DialResponse $ DialResponseV2
    { drsv2Status = status
    , drsv2AddrIdx = index
    , drsv2DialStatus = dialStatus
    }

-- | Receive a nonce on the dial-back protocol and acknowledge only a pending
-- request. Unknown nonces are discarded without a response.
handleAutoNATV2DialBack
  :: AutoNATV2State -> StreamIO -> Multiaddr -> IO ()
handleAutoNATV2DialBack state stream localAddr =
  receive `finally` closeQuietly stream
  where
    receive = do
      incoming <- readDialBackV2 stream
      case incoming of
        Left _ -> pure ()
        Right dialBack -> do
          delivered <- atomically $ do
            pending <- readTVar (an2PendingDialBacks state)
            case Map.lookup (dbv2Nonce dialBack) pending of
              Nothing -> pure False
              Just result -> tryPutTMVar result localAddr
          when delivered (writeDialBackResponseV2 stream)

-- | Run one client request over an already-negotiated dial-request stream.
requestAutoNATV2
  :: AutoNATV2State
  -> StreamIO
  -> [AutoNATV2Request]
  -> IO (Either String AutoNATV2Result)
requestAutoNATV2 state stream requests = do
  let indexed = zip [0 ..] requests
      filtered = filter (allowedAddress config . an2RequestAddr . snd) indexed
  if null filtered
    then pure (Left "AutoNAT v2 requires at least one dialable address")
    else do
      (nonce, dialBackResult) <- registerPending state
      let cleanup = atomically $
            modifyTVar' (an2PendingDialBacks state) (Map.delete nonce)
      runClient state stream filtered nonce dialBackResult
        `finally` (cleanup >> closeQuietly stream)
  where
    config = an2Config state

runClient
  :: AutoNATV2State
  -> StreamIO
  -> [(Int, AutoNATV2Request)]
  -> Word64
  -> TMVar Multiaddr
  -> IO (Either String AutoNATV2Result)
runClient state stream indexed nonce dialBackResult = do
  writeAutoNATV2Message stream . V2DialRequest $ DialRequestV2
    { drv2Addrs = fmap (toBytes . an2RequestAddr . snd) indexed
    , drv2Nonce = nonce
    }
  firstMessage <- readAutoNATV2Message stream
  response <- case firstMessage of
    Right (V2DialResponse value) -> pure (Right value)
    Right (V2DialDataRequest request) -> do
      sent <- sendRequestedData stream indexed request
      if sent
        then expectDialResponse stream
        else pure (Left "AutoNAT v2 dial-data request was rejected")
    Right _ -> pure (Left "unexpected AutoNAT v2 response type")
    Left err -> pure (Left err)
  case response of
    Left err -> pure (Left err)
    Right value -> interpretResponse state indexed dialBackResult value

sendRequestedData
  :: StreamIO -> [(Int, AutoNATV2Request)] -> DialDataRequestV2 -> IO Bool
sendRequestedData stream indexed request
  | ddrv2NumBytes request > 100000 = pure False
  | otherwise = case lookupAt (fromIntegral (ddrv2AddrIdx request)) indexed of
      Nothing -> pure False
      Just (_, selected)
        | not (an2SendDialData selected) -> pure False
        | otherwise -> send (ddrv2NumBytes request)
  where
    chunk = BS.replicate 4000 0
    send 0 = pure True
    send remaining = do
      let payload = BS.take (fromIntegral (min remaining 4000)) chunk
      writeAutoNATV2Message stream (V2DialDataResponse payload)
      send (remaining - fromIntegral (BS.length payload))

expectDialResponse :: StreamIO -> IO (Either String DialResponseV2)
expectDialResponse stream = do
  incoming <- readAutoNATV2Message stream
  pure $ case incoming of
    Right (V2DialResponse response) -> Right response
    Right _ -> Left "unexpected AutoNAT v2 response after dial data"
    Left err -> Left err

interpretResponse
  :: AutoNATV2State
  -> [(Int, AutoNATV2Request)]
  -> TMVar Multiaddr
  -> DialResponseV2
  -> IO (Either String AutoNATV2Result)
interpretResponse state indexed dialBackResult response =
  case drsv2Status response of
    ResponseDialRefused -> pure . Right $ refusedResult
    ResponseOK -> interpretDialStatus state indexed dialBackResult response
    ResponseInternalError -> pure (Left "AutoNAT v2 server reported an internal error")
    ResponseRequestRejected -> pure (Left "AutoNAT v2 server rejected the request")
    ResponseStatusUnknown _ -> pure (Left "AutoNAT v2 server returned an unknown response status")

interpretDialStatus
  :: AutoNATV2State
  -> [(Int, AutoNATV2Request)]
  -> TMVar Multiaddr
  -> DialResponseV2
  -> IO (Either String AutoNATV2Result)
interpretDialStatus state indexed dialBackResult response =
  case lookupAt (fromIntegral (drsv2AddrIdx response)) indexed of
    Nothing -> pure (Left "AutoNAT v2 address index is out of range")
    Just (originalIndex, selected) -> case drsv2DialStatus response of
      DialStatusError -> pure . Right $ result selected originalIndex NATPrivate
      DialStatusOK -> verifyDialBack selected originalIndex
      DialStatusBackError -> verifyDialBack selected originalIndex
      DialStatusUnused -> pure (Left "AutoNAT v2 response omitted the dial status")
      DialStatusUnknown _ -> pure (Left "AutoNAT v2 server returned an unknown dial status")
  where
    result selected originalIndex reachability = AutoNATV2Result
      { an2ResultAddr = Just (an2RequestAddr selected)
      , an2ResultIndex = Just originalIndex
      , an2ResultReachability = reachability
      , an2AllAddrsRefused = False
      }
    verifyDialBack selected originalIndex = do
      received <- timeout (an2DialBackWaitMicros (an2Config state)) $
        atomically (takeTMVar dialBackResult)
      pure $ case received of
        Just localAddr
          | addressesConsistent localAddr (an2RequestAddr selected) ->
              Right (result selected originalIndex NATPublic)
        _ -> Left "AutoNAT v2 dial-back did not verify the selected address"

refusedResult :: AutoNATV2Result
refusedResult = AutoNATV2Result
  { an2ResultAddr = Nothing
  , an2ResultIndex = Nothing
  , an2ResultReachability = NATUnknown
  , an2AllAddrsRefused = True
  }

registerPending :: AutoNATV2State -> IO (Word64, TMVar Multiaddr)
registerPending state = do
  candidate <- an2RandomWord64 (an2Config state)
  result <- newEmptyTMVarIO
  nonce <- atomically $ do
    pending <- readTVar (an2PendingDialBacks state)
    let available = nextAvailableNonce candidate pending
    writeTVar (an2PendingDialBacks state) (Map.insert available result pending)
    pure available
  pure (nonce, result)

nextAvailableNonce :: Word64 -> Map Word64 a -> Word64
nextAvailableNonce candidate pending
  | Map.member candidate pending = nextAvailableNonce (candidate + 1) pending
  | otherwise = candidate

acquireRequest :: AutoNATV2State -> PeerId -> IO Bool
acquireRequest state peer = do
  now <- an2Now (an2Config state)
  atomically $ do
    current <- cleanupRateState now <$> readTVar (an2RateState state)
    let config = an2Config state
        peerRequests = length [() | (_, requestPeer) <- rateRequests current, requestPeer == peer]
        active = Map.findWithDefault 0 peer (rateActive current)
        accepted = length (rateRequests current) < an2ServerRPM config
          && peerRequests < an2ServerPerPeerRPM config
          && active < an2MaxConcurrentPerPeer config
        updated = current
          { rateRequests = if accepted then rateRequests current <> [(now, peer)] else rateRequests current
          , rateActive = if accepted then Map.insertWith (+) peer 1 (rateActive current) else rateActive current
          }
    writeTVar (an2RateState state) updated
    pure accepted

releaseRequest :: AutoNATV2State -> PeerId -> IO ()
releaseRequest state peer = atomically $
  modifyTVar' (an2RateState state) $ \current -> current
    { rateActive = Map.update decrement peer (rateActive current) }
  where
    decrement count = if count <= 1 then Nothing else Just (count - 1)

acquireDialDataRequest :: AutoNATV2State -> IO Bool
acquireDialDataRequest state = do
  now <- an2Now (an2Config state)
  atomically $ do
    current <- cleanupRateState now <$> readTVar (an2RateState state)
    let accepted = length (rateDialDataRequests current)
          < an2ServerDialDataRPM (an2Config state)
        updated = current
          { rateDialDataRequests =
              if accepted then rateDialDataRequests current <> [now] else rateDialDataRequests current
          }
    writeTVar (an2RateState state) updated
    pure accepted

cleanupRateState :: POSIXTime -> RateState -> RateState
cleanupRateState now current = current
  { rateRequests = filter (fresh . fst) (rateRequests current)
  , rateDialDataRequests = filter fresh (rateDialDataRequests current)
  }
  where
    fresh timestamp = now - timestamp < 60

allowedAddress :: AutoNATV2Config -> Multiaddr -> Bool
allowedAddress config address =
  not (isRelayedAddr address)
    && (an2AllowPrivateAddrs config || isPublicAddr address)

dialDataRequired :: Multiaddr -> Multiaddr -> Bool
dialDataRequired observed dialAddress =
  case (addressIP observed, addressIP dialAddress) of
    (Just observedIP, Just dialIP) -> observedIP /= dialIP
    _ -> True

addressIP :: Multiaddr -> Maybe Protocol
addressIP (Multiaddr protocols) = find isIP protocols
  where
    isIP (IP4 _) = True
    isIP (IP6 _) = True
    isIP _ = False

-- | Verify that the dial-back connection used the selected transport stack.
-- IP/DNS values and ports may legitimately differ because of NAT mappings.
addressesConsistent :: Multiaddr -> Multiaddr -> Bool
addressesConsistent localAddress requestedAddress =
  case (normalized localAddress, normalized requestedAddress) of
    ([], _) -> False
    (_, []) -> False
    (local : localRest, requested : requestedRest) ->
      firstCompatible local requested
        && fmap normalizedCode localRest == fmap normalizedCode requestedRest
  where
    normalized (Multiaddr protocols) = stripTrailing protocols
    stripTrailing protocols = reverse (dropWhile trailing (reverse protocols))
    trailing (P2P _) = True
    trailing (Certhash _) = True
    trailing _ = False
    firstCompatible local requested = case requested of
      DNS _ -> isAnyIP local
      DNSAddr _ -> isAnyIP local
      DNS4 _ -> isIPv4 local
      DNS6 _ -> isIPv6 local
      _ -> normalizedCode local == normalizedCode requested
    isAnyIP protocol = isIPv4 protocol || isIPv6 protocol
    isIPv4 (IP4 _) = True
    isIPv4 _ = False
    isIPv6 (IP6 _) = True
    isIPv6 _ = False
    normalizedCode protocol = protocolCode protocol

lookupAt :: Int -> [a] -> Maybe a
lookupAt index values
  | index < 0 = Nothing
  | otherwise = listToMaybe (drop index values)

catchSync :: IO a -> (SomeException -> IO a) -> IO a
catchSync action handler = action `catch` \exception ->
  case fromException exception :: Maybe SomeAsyncException of
    Just _ -> throwIO exception
    Nothing -> handler exception

randomWord64 :: IO Word64
randomWord64 = BS.foldl' step 0 <$> getRandomBytes 8
  where
    step acc byte = acc * 256 + fromIntegral byte
