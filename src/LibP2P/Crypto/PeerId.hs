-- | Peer ID derivation from public keys.
--
-- A Peer ID is a multihash of the serialized PublicKey protobuf message.
-- Ed25519 keys (36 bytes serialized) use identity multihash.
-- Larger keys (RSA) use SHA-256 multihash.
module LibP2P.Crypto.PeerId
  ( PeerId (..)
  , fromPublicKey
  , toBase58
  , fromBase58
  , peerIdBytes
  , parsePeerId
  , toCIDv1
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base58 as B58
import Data.ByteArray.Encoding (Base (Base32), convertFromBase, convertToBase)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Word (Word8, Word64)
import LibP2P.Core.Multihash (HashFunction (..), encodeMultihash, validateMultihash)
import LibP2P.Core.Varint (encodeUvarint, decodeUvarint)
import LibP2P.Crypto.Key (PublicKey)
import LibP2P.Crypto.Protobuf (encodePublicKey)

-- | A Peer ID is a multihash of the serialized public key.
newtype PeerId = PeerId ByteString
  deriving (Show, Eq, Ord)

-- | Maximum serialized size for identity multihash.
maxInlineKeyLength :: Int
maxInlineKeyLength = 42

-- | Derive a Peer ID from a public key.
fromPublicKey :: PublicKey -> PeerId
fromPublicKey pk =
  let serialized = encodePublicKey pk
      mh =
        if BS.length serialized <= maxInlineKeyLength
          then encodeMultihash Identity serialized
          else encodeMultihash SHA256 serialized
   in PeerId mh

-- | Encode a Peer ID as base58btc text.
toBase58 :: PeerId -> Text
toBase58 (PeerId bs) = TE.decodeUtf8 (B58.encode bs)

-- | Decode a Peer ID from base58btc text.
-- Validates that decoded bytes are a well-formed multihash.
fromBase58 :: Text -> Either String PeerId
fromBase58 t = case B58.decode (TE.encodeUtf8 t) of
  Nothing -> Left "fromBase58: invalid base58 encoding"
  Just bs -> do
    _ <- validateMultihash bs
    Right (PeerId bs)

-- | Get the raw multihash bytes of a Peer ID.
peerIdBytes :: PeerId -> ByteString
peerIdBytes (PeerId bs) = bs

-- | Parse a Peer ID from either a legacy base58btc multihash or CIDv1.
-- Legacy strings start with @1@ or @Qm@. CIDv1 strings use a supported
-- multibase prefix: @b@ (base32lower), @B@ (base32upper), or @z@ (base58btc).
parsePeerId :: Text -> Either String PeerId
parsePeerId t
  | T.null t = Left "parsePeerId: empty input"
  | "1" `T.isPrefixOf` t || "Qm" `T.isPrefixOf` t = fromBase58 t
  | T.head t `elem` ['b', 'B', 'z'] = fromCIDv1 t
  | otherwise = Left "parsePeerId: unsupported peer ID representation"

-- | Encode a Peer ID as CIDv1 text (base32lower, no padding).
-- Format: 'b' + base32lower(varint(1) + varint(0x72) + multihash_bytes)
toCIDv1 :: PeerId -> Text
toCIDv1 (PeerId mhBytes) =
  let cidVersion = encodeUvarint (1 :: Word64)
      codec = encodeUvarint (0x72 :: Word64)  -- libp2p-key
      cidBytes = cidVersion <> codec <> mhBytes
      base32Upper = convertToBase Base32 cidBytes :: ByteString
      -- Strip padding '=' and convert to lowercase
      base32NoPad = BS.filter (/= 0x3D) base32Upper  -- 0x3D = '='
      base32Lower = BS.map (\w -> if w >= 0x41 && w <= 0x5A then w + 32 else w) base32NoPad
  in "b" <> TE.decodeUtf8 base32Lower

-- | Decode a multibase-encoded CIDv1 Peer ID.
fromCIDv1 :: Text -> Either String PeerId
fromCIDv1 t = do
  cidBytes <- decodeMultibase t
  (version, rest1) <- decodeUvarint cidBytes
  if version /= (1 :: Word64)
    then Left $ "fromCIDv1: expected CID version 1, got " <> show version
    else do
      (codec, multihash) <- decodeUvarint rest1
      if codec /= (0x72 :: Word64)
        then Left $ "fromCIDv1: expected libp2p-key codec 0x72, got 0x" <> showHexW64 codec
        else do
          _ <- validateMultihash multihash
          Right (PeerId multihash)

-- | Decode the multibase encodings recognized for Peer ID CIDs.
decodeMultibase :: Text -> Either String ByteString
decodeMultibase t
  | T.null t = Left "decodeMultibase: empty input"
  | T.null payload = Left "decodeMultibase: empty payload"
  | prefix == 'b' = decodeBase32 True payloadBytes
  | prefix == 'B' = decodeBase32 False payloadBytes
  | prefix == 'z' = decodeBase58Btc payloadBytes
  | otherwise = Left "decodeMultibase: unsupported prefix"
  where
    prefix = T.head t
    payload = T.tail t
    payloadBytes = TE.encodeUtf8 payload

-- | Decode unpadded RFC 4648 base32 and require its canonical letter case.
decodeBase32 :: Bool -> ByteString -> Either String ByteString
decodeBase32 lowercase encoded = do
  let upper = BS.map asciiToUpper encoded
      paddingLength = (8 - BS.length upper `mod` 8) `mod` 8
      padded = upper <> BS.replicate paddingLength 0x3d
  decoded <- case convertFromBase Base32 padded of
    Left _ -> Left "decodeMultibase: invalid base32 encoding"
    Right bytes -> Right bytes
  let canonicalUpper = BS.filter (/= 0x3d) (convertToBase Base32 decoded)
      canonical = if lowercase then BS.map asciiToLower canonicalUpper else canonicalUpper
  if canonical == encoded
    then Right decoded
    else Left "decodeMultibase: non-canonical base32 encoding"

-- | Decode canonical base58btc.
decodeBase58Btc :: ByteString -> Either String ByteString
decodeBase58Btc encoded = case B58.decode encoded of
  Nothing -> Left "decodeMultibase: invalid base58btc encoding"
  Just decoded
    | B58.encode decoded == encoded -> Right decoded
    | otherwise -> Left "decodeMultibase: non-canonical base58btc encoding"

asciiToUpper :: Word8 -> Word8
asciiToUpper byte
  | byte >= 0x61 && byte <= 0x7a = byte - 0x20
  | otherwise = byte

asciiToLower :: Word8 -> Word8
asciiToLower byte
  | byte >= 0x41 && byte <= 0x5a = byte + 0x20
  | otherwise = byte

-- | Show a Word64 as hex.
showHexW64 :: Word64 -> String
showHexW64 = go []
  where
    go acc 0 | null acc = "0"
             | otherwise = acc
    go acc n = go (hexDigit (fromIntegral (n `mod` 16)) : acc) (n `div` 16)
    hexDigit :: Int -> Char
    hexDigit d
      | d < 10 = toEnum (d + fromEnum '0')
      | otherwise = toEnum (d - 10 + fromEnum 'a')
