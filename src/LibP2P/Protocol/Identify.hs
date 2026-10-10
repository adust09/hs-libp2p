-- | Identify protocol implementation (specs/identify).
--
-- Protocol ID: /ipfs/id/1.0.0
--
-- After a connection is established, both sides exchange IdentifyInfo
-- messages to learn about each other's capabilities, listen addresses,
-- and agent version. Like all libp2p protobuf streams, the message is
-- varint-length-delimited on the wire: uvarint(len) ++ protobuf. This
-- matches the delimited reader/writer used by go-libp2p (pbio),
-- rust-libp2p, and js-libp2p.
--
-- Also implements Identify Push (/ipfs/id/push/1.0.0) for proactive
-- updates when local state changes.
module LibP2P.Protocol.Identify
  ( -- * Protocol IDs
    identifyProtocolId
  , identifyPushProtocolId
    -- * Protocol logic
  , handleIdentify
  , requestIdentify
  , handleIdentifyPush
  , pushIdentify
  , mergeIdentify
    -- * Identify on connect
  , identifyPeer
  , identifyTimeoutMicros
    -- * Building local info
  , buildLocalIdentify
    -- * Registration
  , registerIdentifyHandlers
    -- * Wire framing
  , encodeFramedIdentify
  , readFramedIdentify
  ) where

import Control.Applicative ((<|>))
import Control.Concurrent.STM (atomically, modifyTVar', readTVar, writeTVar)
import Control.Exception (SomeException, bracket, catch, finally, try)
import LibP2P.Switch.Connection (newStream)
import Control.Monad (void)
import System.Timeout (timeout)
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import LibP2P.Core.Varint (decodeUvarint, encodeUvarint)
import LibP2P.Crypto.PeerId (PeerId, fromPublicKey, peerIdBytes)
import LibP2P.Crypto.PeerRecord
  ( PeerRecord (..)
  , sealPeerRecord
  , timestampSeq
  )
import LibP2P.Switch.CertifiedRecords
  ( CertifiedRecord (..)
  , consumeCertifiedRecord
  , verifyPeerRecord
  )
import LibP2P.Crypto.Protobuf (decodePublicKey, encodePublicKey)
import LibP2P.Crypto.Key (kpPublic)
import LibP2P.Crypto.SignedEnvelope (encodeSignedEnvelope)
import LibP2P.Multiaddr.Codec (encodeProtocols)
import LibP2P.Multiaddr (Multiaddr (..))
import LibP2P.MultistreamSelect.Negotiation
  ( ProtocolId
  , StreamIO (..)
  , closeQuietly
  , negotiateInitiator
  , NegotiationResult (..)
  , readExactBounded
  )
import LibP2P.Protocol.Identify.Message
  ( IdentifyInfo (..)
  , decodeIdentify
  , encodeIdentify
  , maxIdentifySize
  )
import LibP2P.Switch.ConnPool (allConns)
import LibP2P.Switch.Types
  ( ActiveListener (..)
  , Connection (..)
  , Switch (..)
  )

-- | Identify protocol ID.
identifyProtocolId :: ProtocolId
identifyProtocolId = "/ipfs/id/1.0.0"

-- | Identify Push protocol ID.
identifyPushProtocolId :: ProtocolId
identifyPushProtocolId = "/ipfs/id/push/1.0.0"

-- | Handle an inbound Identify request (responder side).
--
-- Sends our local IdentifyInfo as a varint-length-prefixed protobuf,
-- then closes the stream (per specs/identify: respond and close).
-- The connection provides the remote address used for observedAddr.
handleIdentify :: Switch -> Connection -> StreamIO -> IO ()
handleIdentify sw conn stream =
  (do
    info <- buildLocalIdentify sw (Just conn)
    streamWrite stream (encodeFramedIdentify info))
    `finally` closeQuietly stream

-- | Timeout for one Identify exchange: 5 seconds.
--
-- Matches go-libp2p's @identify.DefaultTimeout@, which it applies to all
-- id interactions in both directions.
identifyTimeoutMicros :: Int
identifyTimeoutMicros = 5000000

-- | Request Identify from a remote peer (initiator side).
--
-- Opens a new stream, negotiates /ipfs/id/1.0.0, then reads one
-- varint-length-prefixed protobuf message. The publicKey field is
-- validated against the connection's authenticated peer id (see
-- 'validatePublicKey').
--
-- Identify is a one-shot exchange, so the stream is closed on every exit
-- path — success, negotiation refusal, decode failure, timeout and
-- exception alike. A caller that runs this per connection would
-- otherwise leak a half-open stream per connection. The whole exchange
-- is bounded by 'identifyTimeoutMicros': a peer that negotiates and then
-- never answers must not pin a stream and a thread forever.
requestIdentify :: Switch -> Connection -> IO (Either String IdentifyInfo)
requestIdentify sw conn = do
  opened <- newStream sw conn
  case opened of
    Left err ->
      pure (Left ("stream reservation failed: " ++ show err))
    Right stream -> do
      outcome <- try $ bracket (pure stream) closeQuietly exchange
      pure $ case outcome of
        Left (e :: SomeException) -> Left ("identify failed: " ++ show e)
        Right Nothing             -> Left "identify timed out"
        Right (Just result)       -> result
  where
    exchange stream = timeout identifyTimeoutMicros $ do
      negotiated <- negotiateInitiator stream [identifyProtocolId]
      case negotiated of
        NoProtocol -> pure (Left "remote does not support identify")
        Accepted _ ->
          fmap (validateIdentify (connPeerId conn))
            <$> readFramedIdentify stream maxIdentifySize

-- | Run Identify against a freshly established connection and record the
-- result in the peer store (specs/identify).
--
-- This is what makes a peer's advertised addresses and protocols known
-- to us: without it 'swPeerStore' only ever fills from an inbound push,
-- so nothing is known about a peer we dialled or accepted. go-libp2p
-- drives its IDService from the swarm's Connected notification for the
-- same reason.
--
-- Failure is returned rather than thrown: the connection stays usable,
-- and no peer store entry is created. There is no retry — a peer that
-- does not answer Identify now will be picked up by a later push, if it
-- sends one.
identifyPeer :: Switch -> Connection -> IO (Either String ())
identifyPeer sw conn = do
  result <- requestIdentify sw conn
  case result of
    Left err -> pure (Left err)
    Right info -> do
      storeIdentify sw (connPeerId conn) info
      pure (Right ())

-- | Handle an inbound Identify Push (responder side).
--
-- Reads the pushed varint-length-prefixed IdentifyInfo from the remote
-- peer. The length prefix is the message boundary — identify push has
-- no stream-close boundary to fall back on. The local stream side is
-- still closed on every exit path so a one-shot push cannot leak a
-- half-open Yamux stream (go-libp2p's handleIdentifyResponse does the
-- same with defer s.Close()).
--
-- The pushed info is merged into the existing peer entry via
-- 'mergeIdentify': pushes may be partial updates, so fields absent
-- from the message must not erase what we already know.
handleIdentifyPush :: Switch -> Connection -> StreamIO -> IO ()
handleIdentifyPush sw conn stream =
  (do
    infoOrErr <- readFramedIdentify stream maxIdentifySize
    case infoOrErr of
      Left _ -> pure ()
      Right rawInfo ->
        storeIdentify sw (connPeerId conn)
          (validateIdentify (connPeerId conn) rawInfo))
    `finally` closeQuietly stream

-- | Merge validated Identify info into the peer store, enforcing RFC
-- 0003 record freshness on the way in.
--
-- Shared by the push responder and by 'identifyPeer' so both follow the
-- same rule: an update is merged into what is already known via
-- 'mergeIdentify' rather than replacing it, because a push may be a
-- partial update and must not erase fields it omits.
--
-- A signed peer record that is not strictly newer than the one already
-- retained for this peer is refused (see 'consumeCertifiedRecord'). Its
-- addresses have already been applied to 'idListenAddrs' by
-- 'validateSignedPeerRecord', so a refused record has to have that
-- undone: both the address list and the envelope are cleared from the
-- update, which leaves 'mergeIdentify' holding on to the certified
-- addresses and envelope already known. A replay therefore changes
-- nothing, which is the point of the rule.
--
-- The envelope is opened out here rather than inside the transaction so
-- an STM retry cannot make us re-verify a signature.
storeIdentify :: Switch -> PeerId -> IdentifyInfo -> IO ()
storeIdentify sw peerId info = do
  let offered = do
        envBytes <- idSignedPeerRecord info
        either (const Nothing) Just (verifyPeerRecord peerId envBytes)
  atomically $ do
    fresh <- case offered of
      Nothing     -> pure True
      Just record -> consumeCertifiedRecord (swCertifiedRecords sw) peerId record
    let update
          | fresh = info
          | otherwise = info { idSignedPeerRecord = Nothing, idListenAddrs = [] }
    store <- readTVar (swPeerStore sw)
    let merged = maybe update (`mergeIdentify` update) (Map.lookup peerId store)
    writeTVar (swPeerStore sw) (Map.insert peerId merged store)

-- | Validate the identity-bound fields of a received Identify message
-- against the peer id authenticated by the security handshake.
validateIdentify :: PeerId -> IdentifyInfo -> IdentifyInfo
validateIdentify remotePeer =
  validateSignedPeerRecord remotePeer . validatePublicKey remotePeer

-- | Enforce the identify spec's key/peer-id binding: the publicKey
-- field must derive the sender's peer id, which the security handshake
-- has already authenticated.
--
-- A key that fails to decode or derives a different peer id is an
-- identity claim the sender cannot back up, so it is dropped from the
-- message (matching go-libp2p, which discards the key and keeps the
-- connection — it is already authenticated). The rest of the message
-- is untouched, and previously known good data stays intact because
-- 'mergeIdentify' keeps the known key when the update carries none.
validatePublicKey :: PeerId -> IdentifyInfo -> IdentifyInfo
validatePublicKey remotePeer info = case idPublicKey info of
  Nothing -> info
  Just keyBytes -> case decodePublicKey keyBytes of
    Right pk | fromPublicKey pk == remotePeer -> info
    _ -> info { idPublicKey = Nothing }

-- | Verify a received signedPeerRecord (RFC 0003) against the
-- authenticated peer id: the envelope must open (valid signature,
-- payload type, key/record binding) and its signing key must derive
-- the peer id the security handshake authenticated.
--
-- A verified record's addresses are authoritative and replace the
-- unsigned listenAddrs (go-libp2p's certified addr book takes signed
-- addresses over unsigned ones). A record that fails verification is
-- dropped, keeping the unsigned listenAddrs as the fallback for peers
-- whose record we cannot trust.
--
-- Verification alone does not make a record current: a correctly signed
-- older record can be replayed. The sequence-number check that decides
-- whether it may replace what is already retained needs the peer store,
-- so it lives in 'storeIdentify'.
validateSignedPeerRecord :: PeerId -> IdentifyInfo -> IdentifyInfo
validateSignedPeerRecord remotePeer info = case idSignedPeerRecord info of
  Nothing -> info
  Just envBytes -> case verifyPeerRecord remotePeer envBytes of
    Right record -> info { idListenAddrs = crAddresses record }
    Left _       -> info { idSignedPeerRecord = Nothing }

-- | Merge a received (possibly partial) Identify update into the
-- previously known info for a peer.
--
-- Per specs/identify: "missing fields should be ignored, as peers may
-- choose to send partial updates containing only the fields whose
-- values have changed." Optional fields keep the known value when the
-- update omits them; repeated fields (protobuf cannot distinguish
-- absent from empty) keep the known list when the update's is empty
-- and are replaced wholesale otherwise, matching go-libp2p.
mergeIdentify :: IdentifyInfo -> IdentifyInfo -> IdentifyInfo
mergeIdentify known update = IdentifyInfo
  { idProtocolVersion = idProtocolVersion update <|> idProtocolVersion known
  , idAgentVersion    = idAgentVersion update <|> idAgentVersion known
  , idPublicKey       = idPublicKey update <|> idPublicKey known
  , idListenAddrs     = replaceUnlessEmpty (idListenAddrs known) (idListenAddrs update)
  , idObservedAddr    = idObservedAddr update <|> idObservedAddr known
  , idProtocols       = replaceUnlessEmpty (idProtocols known) (idProtocols update)
  , idSignedPeerRecord = idSignedPeerRecord update <|> idSignedPeerRecord known
  }
  where
    replaceUnlessEmpty old [] = old
    replaceUnlessEmpty _ new  = new

-- | Push our current IdentifyInfo to every connected peer (sender side
-- of /ipfs/id/push/1.0.0).
--
-- Per specs/identify: open a stream to each remote peer, negotiate the
-- push protocol id, send one Identify message and close the stream.
-- Call this whenever local state advertised via identify changes
-- (listen addresses, registered protocols). Failures on individual
-- peers (e.g. push protocol not supported) are ignored.
pushIdentify :: Switch -> IO ()
pushIdentify sw = do
  conns <- atomically $ allConns (swConnPool sw)
  mapM_ (\conn -> pushToConn conn `catch` \(_ :: SomeException) -> pure ()) conns
  where
    pushToConn conn = do
      opened <- newStream sw conn
      case opened of
        Left _ -> pure ()
        Right stream -> bracket (pure stream) closeQuietly $ \s -> do
          result <- negotiateInitiator s [identifyPushProtocolId]
          case result of
            Accepted _ -> do
              info <- buildLocalIdentify sw (Just conn)
              streamWrite s (encodeFramedIdentify info)
            NoProtocol -> pure ()

-- | Build our local IdentifyInfo from Switch state, including a signed
-- peer record (RFC 0003) over our listen addresses, sealed with the
-- identity key.
buildLocalIdentify :: Switch -> Maybe Connection -> IO IdentifyInfo
buildLocalIdentify sw mConn = do
  (protocols, listenAddrs) <- atomically $ do
    protos <- Map.keys <$> readTVar (swProtocols sw)
    listeners <- readTVar (swListeners sw)
    pure (protos, map alAddress listeners)
  seqNo <- timestampSeq
  let addrBytes = map (\(Multiaddr ps) -> encodeProtocols ps) listenAddrs
      record = PeerRecord
        { prPeerId    = peerIdBytes (swLocalPeerId sw)
        , prSeq       = seqNo
        , prAddresses = addrBytes
        }
      -- Sealing our own record with our own identity key cannot fail;
      -- if it somehow does, the optional field is omitted.
      signedRecord = either (const Nothing) (Just . encodeSignedEnvelope)
                       (sealPeerRecord (swIdentityKey sw) record)
  pure IdentifyInfo
    { idProtocolVersion = Just "ipfs/0.1.0"
    , idAgentVersion    = Just "hs-libp2p/0.1.0"
    , idPublicKey       = Just (encodePublicKey (kpPublic (swIdentityKey sw)))
    , idListenAddrs     = addrBytes
    , idObservedAddr    = (\(Multiaddr ps) -> encodeProtocols ps) . connRemoteAddr <$> mConn
    , idProtocols       = protocols
    , idSignedPeerRecord = signedRecord
    }

-- | Register Identify protocol handlers on the Switch.
--
-- Registers:
--   /ipfs/id/1.0.0      — respond to Identify requests
--   /ipfs/id/push/1.0.0 — handle Identify Push from remote
registerIdentifyHandlers :: Switch -> IO ()
registerIdentifyHandlers sw = do
  atomically $ do
    protos <- readTVar (swProtocols sw)
    let protos' = Map.insert identifyProtocolId (handleIdentify sw) protos
        protos'' = Map.insert identifyPushProtocolId (handleIdentifyPush sw) protos'
    writeTVar (swProtocols sw) protos''
  -- Identify every connection as it comes up, inbound and outbound, so
  -- the peer store reflects peers we dialled and accepted rather than
  -- only those that pushed to us. The notifier discards the outcome;
  -- callers that need to observe failure use 'identifyPeer' directly.
  atomically $ modifyTVar' (swNotifiers sw) (void . identifyPeer sw :)

-- | Encode an IdentifyInfo with its uvarint length prefix, as written
-- on the wire: uvarint(len) ++ protobuf.
encodeFramedIdentify :: IdentifyInfo -> BS.ByteString
encodeFramedIdentify info =
  let payload = encodeIdentify info
  in encodeUvarint (fromIntegral (BS.length payload)) <> payload

-- | Read one varint-length-prefixed Identify message from a stream.
--
-- Reads the uvarint length prefix, then exactly that many payload
-- bytes, and decodes the protobuf. Rejects messages larger than
-- maxSize before reading the payload.
readFramedIdentify :: StreamIO -> Int -> IO (Either String IdentifyInfo)
readFramedIdentify stream maxSize = readFramed `catch` onError
  where
    onError :: SomeException -> IO (Either String IdentifyInfo)
    onError e = pure (Left ("identify stream read failed: " ++ show e))

    readFramed = do
      varintBytes <- readVarintBytes stream
      case decodeUvarint varintBytes of
        Left err -> pure (Left ("identify length prefix decode error: " ++ err))
        Right (len, _) -> do
          let msgLen = fromIntegral len :: Int
          if msgLen > maxSize
            then pure (Left ("identify message too large: "
                             ++ show msgLen ++ " > " ++ show maxSize))
            else do
              payloadOrErr <- readExactBounded stream maxSize msgLen
              case payloadOrErr of
                Left err -> pure (Left ("identify read error: " ++ err))
                Right payload -> case decodeIdentify payload of
                  Left parseErr ->
                    pure (Left ("identify protobuf decode error: " ++ show parseErr))
                  Right info -> pure (Right info)

-- | Read the bytes of one unsigned varint from a stream (up to 10 bytes).
readVarintBytes :: StreamIO -> IO BS.ByteString
readVarintBytes stream = go [] (0 :: Int)
  where
    go acc n
      | n >= 10 = pure (BS.pack (reverse acc))  -- max varint length
      | otherwise = do
          b <- streamReadByte stream
          if b < 0x80
            then pure (BS.pack (reverse (b : acc)))
            else go (b : acc) (n + 1)
