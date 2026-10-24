module LibP2P.Core.MultihashSpec (spec) where

import qualified Data.ByteString as BS
import Data.Word (Word8)
import LibP2P.Core.Multihash
import LibP2P.Core.Varint (encodeUvarint)
import Test.Hspec
import Test.QuickCheck

spec :: Spec
spec = do
  describe "encodeMultihash" $ do
    it "encodes identity multihash: 0x00 + varint(len) + data" $ do
      let input = BS.pack [0x08, 0x01, 0x12, 0x20] -- 4 bytes
      let result = encodeMultihash Identity input
      -- 0x00 (identity) + 0x04 (length=4) + data
      result `shouldBe` BS.pack ([0x00, 0x04] <> [0x08, 0x01, 0x12, 0x20])

    it "encodes SHA-256 multihash: 0x12 0x20 + 32-byte digest" $ do
      let input = BS.replicate 100 0xAB -- arbitrary data to hash
      let result = encodeMultihash SHA256 input
      -- First two bytes: 0x12 (sha2-256 code) + 0x20 (32 = digest length)
      BS.take 2 result `shouldBe` BS.pack [0x12, 0x20]
      -- Total length: 2 + 32 = 34
      BS.length result `shouldBe` 34

    it "identity multihash preserves original data" $ do
      let input = BS.pack [0x01, 0x02, 0x03]
      let result = encodeMultihash Identity input
      -- 0x00 + 0x03 + original data
      result `shouldBe` BS.pack [0x00, 0x03, 0x01, 0x02, 0x03]

    it "encodes SHA-256 of empty input to the known vector" $ do
      -- SHA-256("") = e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855
      let expectedDigest = BS.pack
            [ 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14
            , 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24
            , 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c
            , 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
            ]
      encodeMultihash SHA256 BS.empty `shouldBe` BS.pack [0x12, 0x20] <> expectedDigest

    it "encodes a 200-byte identity digest with a 2-byte length varint" $ do
      let input = BS.replicate 200 0x42
      -- varint(200) = 0xc8 0x01
      encodeMultihash Identity input `shouldBe` BS.pack [0x00, 0xc8, 0x01] <> input

  describe "encodeMultihashDigest" $ do
    it "wraps an existing SHA-256 digest without hashing it again" $ do
      let digest = BS.pack [0 .. 31]
      encodeMultihashDigest SHA256 digest
        `shouldBe` Right (BS.pack [0x12, 0x20] <> digest)

    it "rejects a SHA-256 digest with the wrong length" $ do
      encodeMultihashDigest SHA256 (BS.replicate 31 0)
        `shouldSatisfy` isLeft

  describe "decodeMultihash" $ do
    it "decodes identity multihash" $ do
      let encoded = BS.pack [0x00, 0x03, 0xAA, 0xBB, 0xCC]
      decodeMultihash encoded `shouldBe` Right (Identity, BS.pack [0xAA, 0xBB, 0xCC])

    it "decodes SHA-256 multihash" $ do
      let digest = BS.replicate 32 0x42
      let encoded = BS.pack [0x12, 0x20] <> digest
      decodeMultihash encoded `shouldBe` Right (SHA256, digest)

    it "fails on empty input" $
      decodeMultihash BS.empty `shouldSatisfy` isLeft

    it "fails on unknown hash function code" $ do
      let encoded = BS.pack [0xFF, 0x01, 0x00]
      decodeMultihash encoded `shouldSatisfy` isLeft

    it "fails when digest length mismatches" $ do
      -- Claims 5 bytes but only 2 available
      let encoded = BS.pack [0x00, 0x05, 0xAA, 0xBB]
      decodeMultihash encoded `shouldSatisfy` isLeft

    it "rejects a multihash claiming a digest length larger than the input" $ do
      -- Declared length 2^63-1 with zero digest bytes: must not decode
      -- as an empty digest via Int truncation.
      let encoded = BS.pack [0x00] <> encodeUvarint (2 ^ (63 :: Int) - 1)
      decodeMultihash encoded `shouldSatisfy` isLeft
      validateMultihash encoded `shouldSatisfy` isLeft

    it "never succeeds when the declared length exceeds the available bytes" $
      property $
        forAll (chooseInt (0, 200)) $ \avail ->
          forAll (chooseInt (avail + 1, avail + 300)) $ \declared ->
            let mh = BS.pack [0x00]
                    <> encodeUvarint (fromIntegral declared)
                    <> BS.replicate avail 0xAA
             in isLeft (decodeMultihash mh) && isLeft (validateMultihash mh)

  describe "round-trip property" $ do
    it "decode(encode(Identity, data)) == (Identity, data)" $
      property $ \(bs :: [Word8]) ->
        let input = BS.pack bs
            encoded = encodeMultihash Identity input
         in decodeMultihash encoded === Right (Identity, input)

    it "decode(encode(SHA256, data)) produces 32-byte digest" $
      property $ \(bs :: [Word8]) ->
        let input = BS.pack bs
            encoded = encodeMultihash SHA256 input
         in case decodeMultihash encoded of
              Right (SHA256, digest) -> BS.length digest === 32
              other -> counterexample (show other) False

  describe "validateMultihash" $ do
    it "accepts valid Identity multihash (≤42 bytes digest)" $ do
      let mh = BS.pack [0x00, 0x03, 0xAA, 0xBB, 0xCC]
      validateMultihash mh `shouldBe` Right (Identity, BS.pack [0xAA, 0xBB, 0xCC])

    it "accepts valid SHA-256 multihash (32-byte digest)" $ do
      let digest = BS.replicate 32 0x42
      let mh = BS.pack [0x12, 0x20] <> digest
      validateMultihash mh `shouldBe` Right (SHA256, digest)

    it "rejects SHA-256 with wrong digest length" $ do
      -- SHA-256 claims 16 bytes instead of 32
      let mh = BS.pack [0x12, 0x10] <> BS.replicate 16 0x42
      validateMultihash mh `shouldSatisfy` isLeft

    it "rejects Identity multihash with digest > 42 bytes" $ do
      let mh = BS.pack [0x00, 0x2B] <> BS.replicate 43 0x42  -- 43 bytes
      validateMultihash mh `shouldSatisfy` isLeft

    it "accepts Identity multihash with digest of exactly 42 bytes" $ do
      let digest = BS.replicate 42 0x42
      let mh = BS.pack [0x00, 0x2A] <> digest
      validateMultihash mh `shouldBe` Right (Identity, digest)

    it "rejects multihash with trailing bytes" $ do
      -- Valid SHA-256 multihash + extra byte
      let digest = BS.replicate 32 0x42
      let mh = BS.pack [0x12, 0x20] <> digest <> BS.singleton 0xFF
      validateMultihash mh `shouldSatisfy` isLeft

    it "rejects unknown hash code" $ do
      let mh = BS.pack [0xFF, 0x01, 0x42]
      validateMultihash mh `shouldSatisfy` isLeft

isLeft :: Either a b -> Bool
isLeft (Left _) = True
isLeft _ = False
