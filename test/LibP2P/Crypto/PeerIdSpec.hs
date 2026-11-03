module LibP2P.Crypto.PeerIdSpec (spec) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Base58 as B58
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import LibP2P.Crypto.Ed25519 (generateKeyPair, keyPairFromSeed)
import LibP2P.Crypto.Key
import LibP2P.Crypto.PeerId
import LibP2P.Crypto.Protobuf
import Test.Hspec

spec :: Spec
spec = do
  describe "Protobuf encoding" $ do
    it "encodes Ed25519 pubkey to 36 bytes" $ do
      -- From specs/peer-ids:
      -- Ed25519 pubkey 0x1ed1e8fa... → protobuf 0x08011220... (36 bytes)
      let rawPubKey =
            BS.pack
              [ 0x1e, 0xd1, 0xe8, 0xfa, 0xe2, 0xc4, 0xa1, 0x44
              , 0xb8, 0xbe, 0x8f, 0xd4, 0xb4, 0x7b, 0xf3, 0xd3
              , 0xb3, 0x4b, 0x87, 0x1c, 0x3c, 0xac, 0xf6, 0x01
              , 0x0f, 0x0e, 0x42, 0xd4, 0x74, 0xfc, 0xe2, 0x7e
              ]
      let pk = PublicKey Ed25519 rawPubKey
      let encoded = encodePublicKey pk
      -- Should be: 08 01 12 20 <32 bytes>
      BS.length encoded `shouldBe` 36
      BS.take 4 encoded `shouldBe` BS.pack [0x08, 0x01, 0x12, 0x20]
      BS.drop 4 encoded `shouldBe` rawPubKey

    it "produces deterministic encoding (field order: Type=1, Data=2)" $ do
      let rawPubKey = BS.replicate 32 0xAA
      let pk = PublicKey Ed25519 rawPubKey
      let e1 = encodePublicKey pk
      let e2 = encodePublicKey pk
      e1 `shouldBe` e2

  describe "Protobuf round-trip" $ do
    it "decode(encode(pk)) == pk for Ed25519" $ do
      let rawPubKey = BS.replicate 32 0xBB
      let pk = PublicKey Ed25519 rawPubKey
      decodePublicKey (encodePublicKey pk) `shouldBe` Right pk

  describe "Protobuf canonical decoding" $ do
    it "rejects trailing bytes after the PublicKey message" $ do
      -- The peer-ids spec requires canonical serialization; accepting
      -- trailing bytes would give one key multiple byte representations.
      let pk = PublicKey Ed25519 (BS.replicate 32 0xCC)
          canonical = encodePublicKey pk
          padded = canonical <> BS.pack [0xde, 0xad, 0xbe, 0xef]
      decodePublicKey canonical `shouldBe` Right pk
      decodePublicKey padded `shouldSatisfy` isLeft

    it "rejects trailing bytes after the PrivateKey message" $ do
      let sk = PrivateKey Ed25519 (BS.replicate 64 0xDD)
          padded = encodePrivateKey sk <> BS.singleton 0x00
      isLeft (decodePrivateKey padded) `shouldBe` True

    it "rejects a non-minimal varint in the key type field" $ do
      -- 0x81 0x00 is a two-byte encoding of 1 (Ed25519); minimal is 0x01.
      let bs = BS.pack ([0x08, 0x81, 0x00, 0x12, 0x20] <> replicate 32 0xEE)
      decodePublicKey bs `shouldSatisfy` isLeft

  describe "PeerId derivation" $ do
    it "Ed25519 pubkey (36 bytes serialized) uses identity multihash" $ do
      -- From docs: 36 ≤ 42, so identity multihash:
      -- 00 24 08 01 12 20 <32 bytes>
      let rawPubKey =
            BS.pack
              [ 0x1e, 0xd1, 0xe8, 0xfa, 0xe2, 0xc4, 0xa1, 0x44
              , 0xb8, 0xbe, 0x8f, 0xd4, 0xb4, 0x7b, 0xf3, 0xd3
              , 0xb3, 0x4b, 0x87, 0x1c, 0x3c, 0xac, 0xf6, 0x01
              , 0x0f, 0x0e, 0x42, 0xd4, 0x74, 0xfc, 0xe2, 0x7e
              ]
      let pk = PublicKey Ed25519 rawPubKey
      let pid = fromPublicKey pk
      let bytes = peerIdBytes pid
      -- 38 bytes: 0x00 (identity) + 0x24 (36) + 36 bytes protobuf
      BS.length bytes `shouldBe` 38
      BS.take 2 bytes `shouldBe` BS.pack [0x00, 0x24]
      BS.index bytes 2 `shouldBe` 0x08
      BS.index bytes 3 `shouldBe` 0x01

    it "PeerId from known key matches expected bytes" $ do
      let rawPubKey =
            BS.pack
              [ 0x1e, 0xd1, 0xe8, 0xfa, 0xe2, 0xc4, 0xa1, 0x44
              , 0xb8, 0xbe, 0x8f, 0xd4, 0xb4, 0x7b, 0xf3, 0xd3
              , 0xb3, 0x4b, 0x87, 0x1c, 0x3c, 0xac, 0xf6, 0x01
              , 0x0f, 0x0e, 0x42, 0xd4, 0x74, 0xfc, 0xe2, 0x7e
              ]
      let pk = PublicKey Ed25519 rawPubKey
      let pid = fromPublicKey pk
      let expected =
            BS.pack $
              [0x00, 0x24, 0x08, 0x01, 0x12, 0x20]
                <> [ 0x1e, 0xd1, 0xe8, 0xfa, 0xe2, 0xc4, 0xa1, 0x44
                   , 0xb8, 0xbe, 0x8f, 0xd4, 0xb4, 0x7b, 0xf3, 0xd3
                   , 0xb3, 0x4b, 0x87, 0x1c, 0x3c, 0xac, 0xf6, 0x01
                   , 0x0f, 0x0e, 0x42, 0xd4, 0x74, 0xfc, 0xe2, 0x7e
                   ]
      peerIdBytes pid `shouldBe` expected

  describe "Base58 encoding" $ do
    it "Ed25519 PeerId starts with 12D3KooW" $ do
      let rawPubKey = BS.replicate 32 0x42
      let pk = PublicKey Ed25519 rawPubKey
      let pid = fromPublicKey pk
      let b58 = toBase58 pid
      T.take 8 b58 `shouldBe` ("12D3KooW" :: Text)

    it "base58 round-trip: fromBase58(toBase58(pid)) == pid" $ do
      let rawPubKey = BS.replicate 32 0x42
      let pk = PublicKey Ed25519 rawPubKey
      let pid = fromPublicKey pk
      fromBase58 (toBase58 pid) `shouldBe` Right pid

  describe "Ed25519 key generation" $ do
    it "generates a valid key pair" $ do
      result <- generateKeyPair
      case result of
        Right kp -> do
          let pk = publicKey kp
          pkType pk `shouldBe` Ed25519
          BS.length (pkBytes pk) `shouldBe` 32
        Left err -> expectationFailure err

    it "creates key pair from seed" $ do
      let seed = BS.replicate 32 0x01
      case keyPairFromSeed seed of
        Right kp -> do
          pkType (publicKey kp) `shouldBe` Ed25519
          BS.length (pkBytes (publicKey kp)) `shouldBe` 32
        Left err -> expectationFailure err

  describe "Sign and verify" $ do
    it "sign then verify succeeds" $ do
      Right kp <- generateKeyPair
      let msg = "hello libp2p" :: BS.ByteString
      case sign (kpPrivate kp) msg of
        Right sig -> verify (kpPublic kp) msg sig `shouldBe` True
        Left err -> expectationFailure err

    it "verify with wrong message fails" $ do
      Right kp <- generateKeyPair
      case sign (kpPrivate kp) ("correct" :: BS.ByteString) of
        Right sig -> verify (kpPublic kp) ("wrong" :: BS.ByteString) sig `shouldBe` False
        Left err -> expectationFailure err

    it "verify with wrong key fails" $ do
      Right kp1 <- generateKeyPair
      Right kp2 <- generateKeyPair
      case sign (kpPrivate kp1) ("message" :: BS.ByteString) of
        Right sig -> verify (kpPublic kp2) ("message" :: BS.ByteString) sig `shouldBe` False
        Left err -> expectationFailure err

    it "sign with invalid key returns Left" $ do
      let badKey = PrivateKey Ed25519 (BS.pack [0x00]) -- invalid 1-byte key
      sign badKey "test" `shouldSatisfy` isLeft

  describe "fromBase58 validation" $ do
    it "rejects base58-encoded non-multihash bytes" $ do
      -- base58(0xDE 0xAD 0xBE 0xEF) -- not a valid multihash (0xDE is unknown hash code)
      let invalidBytes = BS.pack [0xDE, 0xAD, 0xBE, 0xEF]
      let b58Text = TE.decodeUtf8 (B58.encode invalidBytes)
      fromBase58 b58Text `shouldSatisfy` isLeft

    it "rejects base58-encoded SHA-256 with wrong digest length" $ do
      -- SHA-256 code (0x12) with 16-byte digest instead of 32
      let invalidMh = BS.pack [0x12, 0x10] <> BS.replicate 16 0x42
      let b58Text = TE.decodeUtf8 (B58.encode invalidMh)
      fromBase58 b58Text `shouldSatisfy` isLeft

    it "accepts valid Ed25519 PeerId from base58" $ do
      let rawPubKey = BS.replicate 32 0x42
      let pk = PublicKey Ed25519 rawPubKey
      let pid = fromPublicKey pk
      fromBase58 (toBase58 pid) `shouldBe` Right pid

  describe "parsePeerId" $ do
    let rawPubKey = BS.replicate 32 0x42
        pid = fromPublicKey (PublicKey Ed25519 rawPubKey)
        base32Lower = "bafzaajaiaejcaqscijbeeqscijbeeqscijbeeqscijbeeqscijbeeqscijbeeqsc"
        base32Upper = "BAFZAAJAIAEJCAQSCIJBEEQSCIJBEEQSCIJBEEQSCIJBEEQSCIJBEEQSCIJBEEQSC"
        base58Btc = "z5AanNVJCxnKJ2m4jo6GbZqcPwFSzj8LskNziWTdP4zC7AQTtgHbdDB"
        identityMultihash = peerIdBytes pid
        sha256Multihash = BS.pack [0x12, 0x20] <> BS.replicate 32 0x42
        asBase58Cid bytes = "z" <> TE.decodeUtf8 (B58.encode bytes)

    it "parses legacy 1... and Qm... peer IDs" $ do
      parsePeerId (toBase58 pid) `shouldBe` Right pid
      parsePeerId (TE.decodeUtf8 (B58.encode sha256Multihash))
        `shouldBe` Right (PeerId sha256Multihash)

    it "parses the same CIDv1 from base32lower, base32upper, and base58btc" $ do
      mapM_ (`shouldParseAs` pid) [base32Lower, base32Upper, base58Btc]

    it "keeps base32lower as the default CIDv1 output" $
      toCIDv1 pid `shouldBe` base32Lower

    it "round-trips: parsePeerId(toCIDv1(pid)) == pid" $ do
      Right kp <- generateKeyPair
      let generatedPid = fromPublicKey (kpPublic kp)
      parsePeerId (toCIDv1 generatedPid) `shouldBe` Right generatedPid

    it "rejects arbitrary base58 text without a legacy prefix" $
      parsePeerId "2NEpo7TZRRrLZSi2U" `shouldSatisfy` isLeft

    it "rejects an unknown multibase prefix" $
      parsePeerId "f01720024080112204242424242424242424242424242424242424242424242424242424242424242"
        `shouldSatisfy` isLeft

    it "rejects CIDv0 wrapped in a multibase prefix" $
      parsePeerId (asBase58Cid sha256Multihash) `shouldSatisfy` isLeft

    it "rejects CIDv1 with the wrong version or codec" $ do
      parsePeerId (asBase58Cid (BS.pack [0x02, 0x72] <> identityMultihash))
        `shouldSatisfy` isLeft
      parsePeerId (asBase58Cid (BS.pack [0x01, 0x71] <> identityMultihash))
        `shouldSatisfy` isLeft

    it "rejects CIDv1 with trailing bytes" $
      parsePeerId (asBase58Cid (BS.pack [0x01, 0x72] <> identityMultihash <> BS.singleton 0x00))
        `shouldSatisfy` isLeft

    it "rejects CIDv1 with non-canonical varints" $ do
      parsePeerId (asBase58Cid (BS.pack [0x81, 0x00, 0x72] <> identityMultihash))
        `shouldSatisfy` isLeft
      parsePeerId (asBase58Cid (BS.pack [0x01, 0xf2, 0x00] <> identityMultihash))
        `shouldSatisfy` isLeft

    it "rejects malformed multibase payloads" $ do
      parsePeerId "bafza!" `shouldSatisfy` isLeft
      parsePeerId "z0OIl" `shouldSatisfy` isLeft

shouldParseAs :: Text -> PeerId -> Expectation
shouldParseAs encoded pid = parsePeerId encoded `shouldBe` Right pid

isLeft :: Either a b -> Bool
isLeft (Left _) = True
isLeft _ = False
