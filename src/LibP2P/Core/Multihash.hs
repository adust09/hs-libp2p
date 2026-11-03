-- | Multihash encoding/decoding.
--
-- Multihash is a self-describing hash format: <hash-function-code><digest-size><digest>
-- Used for Peer ID derivation and content addressing.
module LibP2P.Core.Multihash
  ( HashFunction (..)
  , encodeMultihash
  , encodeMultihashDigest
  , decodeMultihash
  , validateMultihash
  ) where

import Crypto.Hash (Digest, SHA256, hash)
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word64)
import Numeric (showHex)
import LibP2P.Core.Varint (decodeUvarint, encodeUvarint)

-- | Supported hash functions for multihash encoding.
data HashFunction
  = Identity -- ^ Code 0x00: raw bytes, no hashing
  | SHA256   -- ^ Code 0x12: SHA-256 (32-byte digest)
  deriving (Show, Eq)

-- | Multicodec code for each hash function.
hashCode :: HashFunction -> Word64
hashCode Identity = 0x00
hashCode SHA256 = 0x12

-- | Lookup hash function from multicodec code.
fromHashCode :: Word64 -> Either String HashFunction
fromHashCode 0x00 = Right Identity
fromHashCode 0x12 = Right SHA256
fromHashCode c = Left $ "decodeMultihash: unknown hash function code 0x" <> showHex c ""

-- | Encode data as a multihash.
-- For Identity: stores raw bytes. For SHA256: hashes first, stores digest.
encodeMultihash :: HashFunction -> ByteString -> ByteString
encodeMultihash hf input =
  let digest = case hf of
        Identity -> input
        SHA256 -> convert (hash input :: Digest SHA256)
   in encodeDigest hf digest

-- | Encode a digest that was computed by an external protocol.
encodeMultihashDigest :: HashFunction -> ByteString -> Either String ByteString
encodeMultihashDigest hf digest = do
  case hf of
    SHA256
      | BS.length digest /= 32 ->
          Left $ "encodeMultihashDigest: SHA-256 digest must be 32 bytes, got " <> show (BS.length digest)
    Identity
      | BS.length digest > 42 ->
          Left $ "encodeMultihashDigest: Identity digest must be ≤42 bytes, got " <> show (BS.length digest)
    _ -> Right ()
  pure (encodeDigest hf digest)

encodeDigest :: HashFunction -> ByteString -> ByteString
encodeDigest hf digest =
  encodeUvarint (hashCode hf)
    <> encodeUvarint (fromIntegral (BS.length digest))
    <> digest

-- | Decode a multihash into its hash function and digest/data.
-- Note: does not reject trailing bytes after the digest.
decodeMultihash :: ByteString -> Either String (HashFunction, ByteString)
decodeMultihash bs = do
  (code, rest1) <- decodeUvarint bs
  hf <- fromHashCode code
  (len, rest2) <- decodeUvarint rest1
  let digestLen = fromIntegral len :: Int
  if BS.length rest2 < digestLen
    then Left $ "decodeMultihash: expected " <> show digestLen <> " bytes but got " <> show (BS.length rest2)
    else Right (hf, BS.take digestLen rest2)

-- | Validate a multihash strictly: decode, check digest length constraints,
-- and reject trailing bytes.
validateMultihash :: ByteString -> Either String (HashFunction, ByteString)
validateMultihash bs = do
  (code, rest1) <- decodeUvarint bs
  hf <- fromHashCode code
  (len, rest2) <- decodeUvarint rest1
  let digestLen = fromIntegral len :: Int
  if BS.length rest2 < digestLen
    then Left $ "validateMultihash: expected " <> show digestLen <> " bytes but got " <> show (BS.length rest2)
    else do
      let digest = BS.take digestLen rest2
          trailing = BS.drop digestLen rest2
      if not (BS.null trailing)
        then Left $ "validateMultihash: " <> show (BS.length trailing) <> " trailing bytes"
        else case hf of
          SHA256
            | digestLen /= 32 ->
                Left $ "validateMultihash: SHA-256 digest must be 32 bytes, got " <> show digestLen
          Identity
            | digestLen > 42 ->
                Left $ "validateMultihash: Identity digest must be ≤42 bytes, got " <> show digestLen
          _ -> Right (hf, digest)
