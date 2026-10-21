module LibP2P.Security.TLS.CertificateSpec (spec) where

import Control.Monad (forM_)
import Data.ByteString qualified as BS
import Data.Either (isLeft)
import Data.Hourglass (Date (..), DateTime (..), Month (..), TimeOfDay (..))
import Data.X509 (
  Certificate (..),
  CertificateChain (..),
  ExtensionRaw (..),
  Extensions (..),
  decodeSignedCertificate,
  getSigned,
  signedObject,
 )
import LibP2P.Crypto.Ed25519 qualified as Ed25519
import LibP2P.Crypto.Key (
  KeyPair (..),
  generateECDSAKeyPair,
  generateRSAKeyPair,
  generateSecp256k1KeyPair,
 )
import LibP2P.Crypto.PeerId (fromBase58, fromPublicKey)
import LibP2P.Security.TLS.Certificate (
  libp2pExtensionOID,
  newIdentityCredential,
  verifyIdentityCertificate,
  verifyIdentityCertificateAt,
 )
import Network.TLS (Credential)
import Numeric (readHex)
import Test.Hspec

spec :: Spec
spec = do
  describe "libp2p identity certificates" $ do
    it "authenticates the host Peer ID carried by a generated certificate" $ do
      identity <- generateIdentity
      let expectedPeerId = fromPublicKey (kpPublic identity)
      credential <- newIdentityCredential identity
      verifyIdentityCertificate (credentialChain credential)
        `shouldReturn` Right expectedPeerId

    forM_ identityGenerators $ \(keyType, generate) ->
      it ("authenticates a generated " <> keyType <> " host key") $ do
        identity <- generate
        credential <- newIdentityCredential identity
        verifyIdentityCertificate (credentialChain credential)
          `shouldReturn` Right (fromPublicKey (kpPublic identity))

    it "accepts the upstream Ed25519 certificate test vector" $ do
      certificateBytes <- either fail pure (decodeHex ed25519CertificateHex)
      certificate <- either fail pure (decodeSignedCertificate certificateBytes)
      expectedPeerId <-
        either fail pure $
          fromBase58 "12D3KooWM6CgA9iBFZmcYAHA6A2qvbAxqfkmrYiRQuz3XEsk4Ksv"
      verifyIdentityCertificateAt
        (midnight 2026 January 1)
        (CertificateChain [certificate])
        `shouldBe` Right expectedPeerId

    it "rejects the upstream mismatched host-signature test vector" $ do
      certificateBytes <- either fail pure (decodeHex invalidCertificateHex)
      certificate <- either fail pure (decodeSignedCertificate certificateBytes)
      verifyIdentityCertificateAt
        (midnight 2026 January 1)
        (CertificateChain [certificate])
        `shouldSatisfy` isLeft

    it "marks the libp2p identity extension critical" $ do
      identity <- generateIdentity
      credential <- newIdentityCredential identity
      extensions <- extractExtensions credential
      let identityExtensions =
            filter ((== libp2pExtensionOID) . extRawOID) extensions
      map extRawCritical identityExtensions `shouldBe` [True]

    it "rejects an empty certificate chain" $
      verifyIdentityCertificate (CertificateChain [])
        `shouldReturn` Left "libp2p identity certificate chain must contain exactly one certificate"

    it "rejects certificate chains containing intermediates" $ do
      identity <- generateIdentity
      credential <- newIdentityCredential identity
      let CertificateChain certificates = credentialChain credential
      verifyIdentityCertificate (CertificateChain (certificates <> certificates))
        `shouldReturn` Left "libp2p identity certificate chain must contain exactly one certificate"

    it "rejects a certificate that is not yet valid" $ do
      identity <- generateIdentity
      credential <- newIdentityCredential identity
      verifyIdentityCertificateAt (midnight 1969 December 31) (credentialChain credential)
        `shouldBe` Left "libp2p identity certificate is not yet valid"

    it "rejects an expired certificate" $ do
      identity <- generateIdentity
      credential <- newIdentityCredential identity
      verifyIdentityCertificateAt (midnight 4097 January 1) (credentialChain credential)
        `shouldBe` Left "libp2p identity certificate has expired"

    it "accepts a certificate at the edges of its validity window" $ do
      identity <- generateIdentity
      let expectedPeerId = fromPublicKey (kpPublic identity)
      credential <- newIdentityCredential identity
      verifyIdentityCertificateAt (midnight 1970 January 1) (credentialChain credential)
        `shouldBe` Right expectedPeerId
      verifyIdentityCertificateAt (midnight 4096 January 1) (credentialChain credential)
        `shouldBe` Right expectedPeerId

midnight :: Int -> Month -> Int -> DateTime
midnight year month day = DateTime (Date year month day) (TimeOfDay 0 0 0 0)

generateIdentity :: IO KeyPair
generateIdentity = do
  generated <- Ed25519.generateKeyPair
  either fail pure generated

identityGenerators :: [(String, IO KeyPair)]
identityGenerators =
  [ ("Ed25519", generateIdentity)
  , ("RSA", generateRSAKeyPair)
  , ("secp256k1", generateSecp256k1KeyPair)
  , ("ECDSA", generateECDSAKeyPair)
  ]

credentialChain :: Credential -> CertificateChain
credentialChain = fst

extractExtensions :: Credential -> IO [ExtensionRaw]
extractExtensions credential = case credentialChain credential of
  CertificateChain [signedCertificate] ->
    let certificate = signedObject (getSigned signedCertificate)
     in case certExtensions certificate of
          Extensions (Just extensions) -> pure extensions
          Extensions Nothing -> fail "generated certificate has no extensions"
  _ -> fail "generated credential has an invalid certificate chain"

decodeHex :: String -> Either String BS.ByteString
decodeHex = fmap BS.pack . go
 where
  go [] = Right []
  go [_] = Left "hex input has an odd number of digits"
  go (high : low : rest) = case readHex [high, low] of
    [(byte, "")] -> (fromIntegral (byte :: Int) :) <$> go rest
    _ -> Left "hex input contains a non-hexadecimal digit"

-- libp2p/specs tls/tls.md, valid Ed25519 certificate vector.
ed25519CertificateHex :: String
ed25519CertificateHex =
  "308201ae30820156a0030201020204499602d2300a06082a8648ce3d040302302031123010060355040a13096c69627032702e696f310a300806035504051301313020170d3735303130313133303030305a180f34303936303130313133303030305a302031123010060355040a13096c69627032702e696f310a300806035504051301313059301306072a8648ce3d020106082a8648ce3d030107034200040c901d423c831ca85e27c73c263ba132721bb9d7a84c4f0380b2a6756fd601331c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37e381569ea37c307a3078060a2b0601040183a25a0101046a3068042408011220a77f1d92fedb59dddaea5a1c4abd1ac2fbde7d7b879ed364501809923d7c11b90440d90d2769db992d5e6195dbb08e706b6651e024fda6cfb8846694a435519941cac215a8207792e42849cccc6cd8136c6e4bde92a58c5e08cfd4206eb5fe0bf909300a06082a8648ce3d0403020346003043021f50f6b6c52711a881778718238f650c9fb48943ae6ee6d28427dc6071ae55e702203625f116a7a454db9c56986c82a25682f7248ea1cb764d322ea983ed36a31b77"

-- libp2p/specs tls/tls.md, mismatched host-signature vector.
invalidCertificateHex :: String
invalidCertificateHex =
  "308201f73082019da0030201020204499602d2300a06082a8648ce3d040302302031123010060355040a13096c69627032702e696f310a300806035504051301313020170d3735303130313133303030305a180f34303936303130313133303030305a302031123010060355040a13096c69627032702e696f310a300806035504051301313059301306072a8648ce3d020106082a8648ce3d030107034200040c901d423c831ca85e27c73c263ba132721bb9d7a84c4f0380b2a6756fd601331c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37e381569ea381c23081bf3081bc060a2b0601040183a25a01010481ad3081aa045f0803125b3059301306072a8648ce3d020106082a8648ce3d03010703420004bf30511f909414ebdd3242178fd290f093a551cf75c973155de0bb5a96fedf6cb5d52da7563e794b512f66e60c7f55ba8a3acf3dd72a801980d205e8a1ad29f204473045022100bb6e03577b7cc7a3cd1558df0da2b117dfdcc0399bc2504ebe7de6f65cade72802206de96e2a5be9b6202adba24ee0362e490641ac45c240db71fe955f2c5cf8df6e300a06082a8648ce3d0403020348003045022100e847f267f43717358f850355bdcabbefb2cfbf8a3c043b203a14788a092fe8db022027c1d04a2d41fd6b57a7e8b3989e470325de4406e52e084e34a3fd56eef0d0df"
