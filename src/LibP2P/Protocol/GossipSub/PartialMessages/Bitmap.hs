-- | Little-endian-per-byte bitmap helpers compatible with go-libp2p-pubsub.
module LibP2P.Protocol.GossipSub.PartialMessages.Bitmap
  ( Bitmap
  , emptyBitmap
  , fullBitmap
  , bitmapFromBytes
  , bitmapToBytes
  , bitmapSet
  , bitmapClear
  , bitmapMember
  , bitmapUnion
  , bitmapIntersection
  , bitmapDifference
  , bitmapCount
  , bitmapIsZero
  ) where

import Data.Bits
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word8)

newtype Bitmap = Bitmap ByteString
  deriving (Show, Eq)

-- | A zeroed bitmap large enough for the requested bit count.
emptyBitmap :: Int -> Bitmap
emptyBitmap bitCount = Bitmap (BS.replicate (byteCount bitCount) 0)

-- | A bitmap whose first @bitCount@ bits are set.
fullBitmap :: Int -> Bitmap
fullBitmap bitCount
  | bitCount <= 0 = emptyBitmap 0
  | otherwise =
      Bitmap $
        BS.pack
          [byteAt index | index <- [0 .. byteCount bitCount - 1]]
 where
  completeBytes = bitCount `div` 8
  remainder = bitCount `mod` 8
  byteAt index
    | index < completeBytes = maxBound
    | remainder == 0 = maxBound
    | otherwise = fromIntegral ((1 `shiftL` remainder) - 1 :: Int)

bitmapFromBytes :: ByteString -> Bitmap
bitmapFromBytes = Bitmap

bitmapToBytes :: Bitmap -> ByteString
bitmapToBytes (Bitmap bytes) = bytes

-- | Set one bit, growing the bitmap when necessary.
bitmapSet :: Int -> Bitmap -> Bitmap
bitmapSet index bitmap
  | index < 0 = bitmap
  | otherwise = modifyBit index (`setBit` bitOffset index) bitmap

bitmapClear :: Int -> Bitmap -> Bitmap
bitmapClear index bitmap
  | index < 0 = bitmap
  | otherwise = modifyExistingBit index (`clearBit` bitOffset index) bitmap

bitmapMember :: Int -> Bitmap -> Bool
bitmapMember index (Bitmap bytes)
  | index < 0 || byteOffset index >= BS.length bytes = False
  | otherwise = testBit (BS.index bytes (byteOffset index)) (bitOffset index)

bitmapUnion :: Bitmap -> Bitmap -> Bitmap
bitmapUnion = zipBitmaps (.|.)

bitmapIntersection :: Bitmap -> Bitmap -> Bitmap
bitmapIntersection = zipBitmaps (.&.)

bitmapDifference :: Bitmap -> Bitmap -> Bitmap
bitmapDifference = zipBitmaps (\left right -> left .&. complement right)

bitmapCount :: Bitmap -> Int
bitmapCount (Bitmap bytes) = BS.foldl' (\count byte -> count + popCount byte) 0 bytes

bitmapIsZero :: Bitmap -> Bool
bitmapIsZero (Bitmap bytes) = BS.all (== 0) bytes

modifyBit :: Int -> (Word8 -> Word8) -> Bitmap -> Bitmap
modifyBit index update (Bitmap bytes) =
  let needed = byteOffset index + 1
      extended = bytes <> BS.replicate (max 0 (needed - BS.length bytes)) 0
   in Bitmap (replaceByte (byteOffset index) update extended)

modifyExistingBit :: Int -> (Word8 -> Word8) -> Bitmap -> Bitmap
modifyExistingBit index update bitmap@(Bitmap bytes)
  | byteOffset index >= BS.length bytes = bitmap
  | otherwise = Bitmap (replaceByte (byteOffset index) update bytes)

replaceByte :: Int -> (Word8 -> Word8) -> ByteString -> ByteString
replaceByte index update bytes =
  BS.take index bytes <> BS.singleton (update (BS.index bytes index)) <> BS.drop (index + 1) bytes

zipBitmaps :: (Word8 -> Word8 -> Word8) -> Bitmap -> Bitmap -> Bitmap
zipBitmaps combine (Bitmap left) (Bitmap right) =
  Bitmap $
    BS.pack
      [ combine (at left index) (at right index)
      | index <- [0 .. max (BS.length left) (BS.length right) - 1]
      ]

at :: ByteString -> Int -> Word8
at bytes index
  | index < BS.length bytes = BS.index bytes index
  | otherwise = 0

byteCount :: Int -> Int
byteCount bitCount = max 0 ((bitCount + 7) `div` 8)

byteOffset :: Int -> Int
byteOffset index = index `div` 8

bitOffset :: Int -> Int
bitOffset index = index `mod` 8
