-- | libp2p TLS 1.3 secure channel with mutual peer authentication.
module LibP2P.Security.TLS (
  TLSRole (..),
  TLSHandshakeResult (..),
  performTLSHandshake,
  performTLSHandshakeWithMuxers,
  tlsProtocolId,
  yamuxProtocolId,
  libp2pALPN,
) where

import Control.Exception (SomeException, catch)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as LBS
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import Data.List (find)
import Data.Text.Encoding qualified as TE
import Data.X509 (CertificateChain)
import Data.X509.Validation (FailedReason (..), SignatureFailure (..))
import LibP2P.Crypto.Key (KeyPair)
import LibP2P.Crypto.PeerId (PeerId)
import LibP2P.MultistreamSelect.Negotiation (ProtocolId, StreamIO (..))
import LibP2P.Security.TLS.Certificate (
  newIdentityCredential,
  verifyIdentityCertificate,
 )
import Network.TLS (
  Backend (..),
  CertificateRejectReason (..),
  CertificateUsage (..),
  ClientHooks (..),
  ClientParams (..),
  Context,
  Credential,
  Credentials (..),
  ServerHooks (..),
  ServerParams (..),
  Shared (..),
  Supported (..),
  Version (TLS13),
  bye,
  contextNew,
  defaultParamsClient,
  defaultParamsServer,
  getNegotiatedProtocol,
  handshake,
  recvData,
  sendData,
 )
import Network.TLS.Extra.Cipher (ciphersuite_default)

-- | TLS endpoint role on a libp2p byte stream.
data TLSRole = TLSClient | TLSServer
  deriving (Show, Eq)

-- | Authenticated TLS channel and the ALPN result selected by the peer.
data TLSHandshakeResult = TLSHandshakeResult
  { tlsRemotePeerId :: !PeerId
  , tlsNegotiatedALPN :: !(Maybe ByteString)
  , tlsStream :: !StreamIO
  , tlsClose :: !(IO ())
  }

-- | multistream-select protocol ID for the libp2p TLS handshake.
tlsProtocolId :: ProtocolId
tlsProtocolId = "/tls/1.0.0"

-- | Yamux protocol ID, also used as its inlined TLS ALPN value.
yamuxProtocolId :: ProtocolId
yamuxProtocolId = "/yamux/1.0.0"

libp2pALPN :: ByteString
libp2pALPN = "libp2p"

-- | Perform a TLS 1.3 handshake with Yamux offered for inlined negotiation.
performTLSHandshake :: KeyPair -> TLSRole -> StreamIO -> IO TLSHandshakeResult
performTLSHandshake = performTLSHandshakeWithMuxers [yamuxProtocolId]

{- | Perform a TLS 1.3 mutual-authentication handshake, advertising the given
muxers through ALPN and retaining @libp2p@ as the required fallback.
-}
performTLSHandshakeWithMuxers ::
  [ProtocolId] -> KeyPair -> TLSRole -> StreamIO -> IO TLSHandshakeResult
performTLSHandshakeWithMuxers muxers identity role rawStream = do
  credential <- newIdentityCredential identity
  remotePeerRef <- newIORef Nothing
  let alpnProtocols = fmap TE.encodeUtf8 muxers <> [libp2pALPN]
  context <- case role of
    TLSClient ->
      contextNew (streamBackend rawStream) $
        clientParams alpnProtocols credential remotePeerRef
    TLSServer ->
      contextNew (streamBackend rawStream) $
        serverParams alpnProtocols credential remotePeerRef
  handshake context
  remotePeer <-
    readIORef remotePeerRef
      >>= maybe
        (fail "TLS handshake completed without an authenticated peer")
        pure
  negotiated <- getNegotiatedProtocol context
  secureStream <- contextToStreamIO context
  pure
    TLSHandshakeResult
      { tlsRemotePeerId = remotePeer
      , tlsNegotiatedALPN = negotiated
      , tlsStream = secureStream
      , tlsClose = closeContext context
      }

streamBackend :: StreamIO -> Backend
streamBackend stream =
  Backend
    { backendFlush = pure ()
    , backendClose = pure ()
    , backendSend = streamWrite stream
    , backendRecv = streamReadChunk stream
    }

clientParams ::
  [ByteString] -> Credential -> IORef (Maybe PeerId) -> ClientParams
clientParams alpnProtocols credential remotePeerRef =
  base
    { clientUseServerNameIndication = False
    , clientShared =
        (clientShared base)
          { sharedCredentials = Credentials [credential]
          }
    , clientHooks =
        (clientHooks base)
          { onCertificateRequest = const (pure (Just credential))
          , onServerCertificate = authenticateServer remotePeerRef
          , onSuggestALPN = pure (Just alpnProtocols)
          }
    , clientSupported = tls13Only (clientSupported base)
    }
 where
  base = defaultParamsClient "" BS.empty

serverParams ::
  [ByteString] -> Credential -> IORef (Maybe PeerId) -> ServerParams
serverParams alpnProtocols credential remotePeerRef =
  base
    { serverWantClientCert = True
    , serverShared =
        (serverShared base)
          { sharedCredentials = Credentials [credential]
          }
    , serverHooks =
        (serverHooks base)
          { onClientCertificate = authenticateClient remotePeerRef
          , onALPNClientSuggest = Just (selectALPN alpnProtocols)
          }
    , serverSupported = tls13Only (serverSupported base)
    }
 where
  base = defaultParamsServer

tls13Only :: Supported -> Supported
tls13Only supported =
  supported
    { supportedVersions = [TLS13]
    , supportedCiphers = ciphersuite_default
    }

authenticateServer ::
  IORef (Maybe PeerId) ->
  certificateStore ->
  validationCache ->
  serviceId ->
  CertificateChain ->
  IO [FailedReason]
authenticateServer remotePeerRef _ _ _ chain = do
  result <- authenticatePeer remotePeerRef chain
  pure $ case result of
    Right () -> []
    Left _ -> [InvalidSignature SignatureInvalid]

authenticateClient ::
  IORef (Maybe PeerId) -> CertificateChain -> IO CertificateUsage
authenticateClient remotePeerRef chain = do
  result <- authenticatePeer remotePeerRef chain
  pure $ case result of
    Right () -> CertificateUsageAccept
    Left _ ->
      CertificateUsageReject $
        CertificateRejectOther "libp2p identity certificate rejected"

authenticatePeer ::
  IORef (Maybe PeerId) -> CertificateChain -> IO (Either String ())
authenticatePeer remotePeerRef chain = do
  result <- verifyIdentityCertificate chain
  case result of
    Left err -> pure (Left err)
    Right peerId -> writeIORef remotePeerRef (Just peerId) >> pure (Right ())

selectALPN :: [ByteString] -> [ByteString] -> IO ByteString
selectALPN supported protocols =
  pure $
    maybe BS.empty id (find (`elem` supported) protocols)

contextToStreamIO :: Context -> IO StreamIO
contextToStreamIO context = do
  readBuffer <- newIORef BS.empty
  pure
    StreamIO
      { streamWrite = sendData context . LBS.fromStrict
      , streamReadByte = BS.head <$> readTLSChunk context readBuffer 1
      , streamReadChunk = readTLSChunk context readBuffer
      , streamClose = closeContext context
      }

readTLSChunk :: Context -> IORef ByteString -> Int -> IO ByteString
readTLSChunk context readBuffer requested = do
  buffered <- readIORef readBuffer
  available <-
    if BS.null buffered
      then recvData context >>= requireData
      else pure buffered
  let (front, rest) = BS.splitAt requested available
  writeIORef readBuffer rest
  pure front
 where
  requireData bytes
    | BS.null bytes = fail "TLS connection closed"
    | otherwise = pure bytes

closeContext :: Context -> IO ()
closeContext context = bye context `catch` \(_ :: SomeException) -> pure ()
