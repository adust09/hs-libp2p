module LibP2P.Protocol.GossipSub.PartialMessages.BitmapSpec (spec) where

import qualified Data.ByteString as BS
import LibP2P.Protocol.GossipSub.PartialMessages.Bitmap
import Test.Hspec

spec :: Spec
spec = describe "Partial-message bitmap" $ do
  it "uses go-libp2p little-endian bit positions within each byte" $ do
    bitmapToBytes (fullBitmap 10) `shouldBe` BS.pack [0xff, 0x03]
    bitmapToBytes (bitmapSet 9 (emptyBitmap 10)) `shouldBe` BS.pack [0x00, 0x02]

  it "supports immutable set, clear, and membership operations" $ do
    let bitmap = bitmapSet 12 (bitmapSet 1 (emptyBitmap 2))
    bitmapMember 1 bitmap `shouldBe` True
    bitmapMember 12 bitmap `shouldBe` True
    bitmapMember 13 bitmap `shouldBe` False
    bitmapMember 1 (bitmapClear 1 bitmap) `shouldBe` False
    bitmapCount bitmap `shouldBe` 2

  it "combines completion metadata" $ do
    let left = bitmapFromBytes (BS.pack [0x03, 0x01])
        right = bitmapFromBytes (BS.pack [0x06])
    bitmapToBytes (bitmapUnion left right) `shouldBe` BS.pack [0x07, 0x01]
    bitmapToBytes (bitmapIntersection left right) `shouldBe` BS.pack [0x02, 0x00]
    bitmapToBytes (bitmapDifference left right) `shouldBe` BS.pack [0x01, 0x01]
    bitmapIsZero (bitmapIntersection left (bitmapFromBytes (BS.pack [0x08])))
      `shouldBe` True
