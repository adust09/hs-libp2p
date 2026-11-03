{- | Short-lived certificates and certificate-hash verification for
WebTransport. Browsers permit self-signed WebTransport certificates when a
SHA-256 certificate hash is supplied out of band, but require a validity
period of at most 14 days.
-}
module LibP2P.Transport.WebTransport.Certificate (
  newWebTransportCredential,
  verifyWebTransportCertificate,
) where

import Crypto.Error qualified as Crypto
import Crypto.Hash (Digest, SHA256, hash)
import Crypto.PubKey.Ed25519 qualified as Ed25519
import Crypto.Random (getRandomBytes)
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import Data.Hourglass (
  DateTime,
  Duration (..),
  Elapsed (..),
  Hours (..),
  Minutes (..),
  NanoSeconds (..),
  Seconds (..),
  timeAdd,
  timeConvert,
  timeGetElapsed,
 )
import Data.X509 (
  Certificate (..),
  CertificateChain (..),
  DistinguishedName (..),
  Extensions (..),
  PrivKey (..),
  PubKey (..),
  PubKeyALG (..),
  SignatureALG (..),
  SignedCertificate,
  encodeSignedObject,
  getSigned,
  objectToSignedExact,
  signedObject,
 )
import LibP2P.Core.Multihash qualified as Multihash
import Network.TLS (Credential)
import Time.System (timeCurrent)

certificateValidityHours :: Int
certificateValidityHours = 13 * 24

maximumValiditySeconds :: Integer
maximumValiditySeconds = 14 * 24 * 60 * 60

certificateSignatureAlgorithm :: SignatureALG
certificateSignatureAlgorithm = SignatureALG_IntrinsicHash PubKeyALG_Ed25519

{- | Generate a browser-acceptable short-lived Ed25519 certificate and return
its SHA-256 multihash for use in a @/certhash@ multiaddr.
-}
newWebTransportCredential :: IO (Credential, ByteString)
newWebTransportCredential = do
  secret <- newTLSSecret
  now <- timeConvert <$> timeCurrent
  let publicKey = Ed25519.toPublic secret
      certificate = makeCertificate now (PubKeyEd25519 publicKey)
      signCertificate bytes =
        ( convert (Ed25519.sign secret publicKey bytes)
        , certificateSignatureAlgorithm
        , ()
        )
      (signedCertificate, ()) = objectToSignedExact signCertificate certificate
      der = encodeSignedObject signedCertificate
      credential = (CertificateChain [signedCertificate], PrivKeyEd25519 secret)
  pure (credential, Multihash.encodeMultihash Multihash.SHA256 der)

newTLSSecret :: IO Ed25519.SecretKey
newTLSSecret = do
  seed <- getRandomBytes 32 :: IO ByteString
  case Crypto.eitherCryptoError (Ed25519.secretKey seed) of
    Left err -> fail $ "newWebTransportCredential: " <> show err
    Right secret -> pure secret

makeCertificate :: DateTime -> PubKey -> Certificate
makeCertificate now publicKey =
  Certificate
    { certVersion = 2
    , certSerial = 1
    , certSignatureAlg = certificateSignatureAlgorithm
    , certIssuerDN = DistinguishedName []
    , certValidity =
        ( timeAdd now (hoursDuration (-1))
        , timeAdd now (hoursDuration certificateValidityHours)
        )
    , certSubjectDN = DistinguishedName []
    , certPubKey = publicKey
    , certExtensions = Extensions Nothing
    }

hoursDuration :: Int -> Duration
hoursDuration hours =
  Duration (Hours (fromIntegral hours)) (Minutes 0) (Seconds 0) (NanoSeconds 0)

{- | Verify a one-certificate WebTransport chain against any advertised
SHA-256 multihash and enforce the browser certificate constraints.
-}
verifyWebTransportCertificate ::
  [ByteString] -> CertificateChain -> IO (Either String ())
verifyWebTransportCertificate expected chain = do
  now <- timeConvert <$> timeCurrent
  pure $ verifyAt now expected chain

verifyAt :: DateTime -> [ByteString] -> CertificateChain -> Either String ()
verifyAt now expected (CertificateChain [signedCertificate]) = do
  digests <- mapM decodeSHA256 expected
  let actual = certificateDigest signedCertificate
      certificate = signedObject (getSigned signedCertificate)
  require (actual `elem` digests) "WebTransport certificate hash mismatch"
  verifyValidity now certificate
  verifyKeyType (certPubKey certificate)
verifyAt _ _ _ = Left "WebTransport TLS chain must contain exactly one certificate"

decodeSHA256 :: ByteString -> Either String ByteString
decodeSHA256 multihash = do
  (algorithm, digest) <- Multihash.validateMultihash multihash
  require (algorithm == Multihash.SHA256) "WebTransport certhash must use SHA-256"
  pure digest

certificateDigest :: SignedCertificate -> ByteString
certificateDigest certificate =
  convert (hash (encodeSignedObject certificate) :: Digest SHA256)

verifyValidity :: DateTime -> Certificate -> Either String ()
verifyValidity now certificate = do
  let (notBefore, notAfter) = certValidity certificate
      Elapsed (Seconds validitySeconds) =
        timeGetElapsed notAfter - timeGetElapsed notBefore
  require (now >= notBefore) "WebTransport certificate is not yet valid"
  require (now <= notAfter) "WebTransport certificate has expired"
  require
    (toInteger validitySeconds <= maximumValiditySeconds)
    "WebTransport certificate is valid for longer than 14 days"

verifyKeyType :: PubKey -> Either String ()
verifyKeyType PubKeyRSA{} = Left "WebTransport certificate must not use RSA"
verifyKeyType _ = Right ()

require :: Bool -> String -> Either String ()
require True _ = Right ()
require False message = Left message
