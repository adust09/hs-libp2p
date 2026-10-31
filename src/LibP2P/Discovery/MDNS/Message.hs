-- | Minimal DNS wire-format codec for mDNS (RFC 1035 §4, RFC 6762).
--
-- Only what mDNS discovery needs:
--
--   * a 12-byte header with the byte counts of the four sections;
--   * question entries (domain name, type, class);
--   * resource records with @PTR@, @TXT@ and @SRV@ rdata decoded
--     (unknown types are passed through as raw bytes);
--   * name compression (RFC 1035 §4.1.4 pointers) on /read/: peers
--     using other implementations compress names, so we must follow
--     pointers. On write we emit plain, uncompressed names — valid
--     for every reader.
--
-- mDNS-specific notes (RFC 6762): the header ID is 0 on genuine
-- multicast traffic; legacy unicast queries keep their ID and are
-- answered unicast. Class values carry the cache-flush /
-- unicast-response bits in their high bits; we keep the raw 16-bit
-- class and never interpret those bits.
module LibP2P.Discovery.MDNS.Message
  ( -- * Packet types
    DnsPacket (..)
  , DnsQuestion (..)
  , DnsRecord (..)
  , DnsRData (..)
    -- * Record types (RFC 1035)
  , typePTR
  , typeTXT
  , typeSRV
  , classIN
    -- * Codec
  , encodeDnsPacket
  , decodeDnsPacket
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as B
import qualified Data.ByteString.Lazy as BL
import Data.Bits ((.&.))
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Text.Encoding (decodeUtf8With, encodeUtf8)
import Data.Text.Encoding.Error (lenientDecode)
import Data.Word (Word16, Word32)

-- | An mDNS packet: header plus the four sections (the name-server
-- section is ignored; mDNS never uses it).
data DnsPacket = DnsPacket
  { pkID :: !Word16
  -- ^ Transaction id; 0 on genuine mDNS traffic
  , pkFlags :: !Word16
  -- ^ Raw 16-bit flags (QR, opcode, AA, TC, RD, RA, rcode)
  , pkQuestion :: ![DnsQuestion]
  , pkAnswer :: ![DnsRecord]
  , pkAdditional :: ![DnsRecord]
  } deriving (Show, Eq)

-- | A question section entry.
data DnsQuestion = DnsQuestion
  { qName :: !Text
  -- ^ Domain name, dot-separated, lower case (mDNS names are
  -- case-insensitive, RFC 6762 §10)
  , qType :: !Word16
  , qClass :: !Word16
  -- ^ Class with the cache-flush / unicast-response bits as received
  } deriving (Show, Eq)

-- | A resource record from answer / additional sections.
data DnsRecord = DnsRecord
  { rName :: !Text
  -- ^ Domain name, dot-separated, lower case (compression resolved)
  , rType :: !Word16
  , rClass :: !Word16
  , rTTL :: !Word32
  , rData :: !DnsRData
  } deriving (Show, Eq)

-- | Decoded rdata for the record types mDNS discovery uses; anything
-- else travels as raw bytes, so a forward-compatible peer's extra
-- records never break parsing of the records we do care about.
data DnsRData
  = RdPtr !Text -- ^ @PTR@: the pointed-to name
  | RdTxt ![ByteString] -- ^ @TXT@: character-strings (len-prefixed on the wire)
  | RdSrv !Word16 !Word16 !Word16 !Text -- ^ @SRV@: priority weight port target
  | RdOther !ByteString
  deriving (Show, Eq)

-- | @PTR@ record type (RFC 1035).
typePTR :: Word16
typePTR = 12

-- | @TXT@ record type (RFC 1035).
typeTXT :: Word16
typeTXT = 16

-- | @SRV@ record type (RFC 2782).
typeSRV :: Word16
typeSRV = 33

-- | @IN@ class (RFC 1035) without any cache-flush bit.
classIN :: Word16
classIN = 1

--------------------------------------------------------------------------------
-- Encode
--------------------------------------------------------------------------------

-- | Encode a packet. Names are written uncompressed (valid for every
-- reader); 'RdPtr' / 'RdTxt' / 'RdSrv' rdata is re-encoded and
-- 'RdOther' passes through verbatim.
--
-- Section counts are derived from the lists, so a caller can never
-- set inconsistent counts.
encodeDnsPacket :: DnsPacket -> ByteString
encodeDnsPacket pk = BL.toStrict $ B.toLazyByteString $
     B.word16BE (pkID pk)
  <> B.word16BE (pkFlags pk)
  <> B.word16BE (fromIntegral (length (pkQuestion pk)))
  <> B.word16BE (fromIntegral (length (pkAnswer pk)))
  <> B.word16BE 0
  <> B.word16BE (fromIntegral (length (pkAdditional pk)))
  <> foldMap encodeQuestion (pkQuestion pk)
  <> foldMap encodeRecord (pkAnswer pk)
  <> foldMap encodeRecord (pkAdditional pk)

encodeQuestion :: DnsQuestion -> B.Builder
encodeQuestion DnsQuestion {qName = name, qType = qtype, qClass = qclass} =
  encodeName name <> B.word16BE qtype <> B.word16BE qclass

encodeRecord :: DnsRecord -> B.Builder
encodeRecord DnsRecord {rName = name, rType = rtype, rClass = rclass, rTTL = rttl, rData = rdata} =
  encodeName name
    <> B.word16BE rtype
    <> B.word16BE rclass
    <> B.word32BE rttl
    <> B.word16BE (fromIntegral (BS.length rdataBytes)) <> B.byteString rdataBytes
  where
    rdataBytes = encodeRData rdata

-- | Encode a dot-separated name as wire labels, terminated by the
-- zero label.
encodeName :: Text -> B.Builder
encodeName name
  | T.null name = B.word8 0
  | otherwise =
      foldMap
        ( \label ->
            B.word8 (fromIntegral (T.length label)) <> B.byteString (encodeUtf8 label)
        )
        (T.splitOn "." name)
        <> B.word8 0

encodeRData :: DnsRData -> ByteString
encodeRData rdata = BL.toStrict $ B.toLazyByteString $ case rdata of
  RdPtr name -> encodeName name
  RdTxt strings ->
    foldMap (\s -> B.word8 (fromIntegral (BS.length s)) <> B.byteString s) strings
  RdSrv priority weight port target ->
    B.word16BE priority <> B.word16BE weight <> B.word16BE port <> encodeName target
  RdOther bs -> B.byteString bs

--------------------------------------------------------------------------------
-- Decode
--------------------------------------------------------------------------------

-- headerSize is 12 bytes: ID, flags, and the four section counts.
headerSize :: Int
headerSize = 12

-- | Decode a packet, resolving name compression. A structurally
-- invalid packet is a 'Left'; the mDNS service ignores malformed
-- packets — multicast input is unauthenticated.
decodeDnsPacket :: ByteString -> Either String DnsPacket
decodeDnsPacket raw = do
  unlessLen (BS.length raw >= headerSize) "packet shorter than DNS header"
  let id' = be16 raw 0
      flags = be16 raw 2
      nQuestion = be16 raw 4
      nAnswer = be16 raw 6
      nNS = be16 raw 8
      nAdditional = be16 raw 10
  unlessLen (nNS == 0) "name-server section must be empty (mDNS)"
  (questions, off1) <- parseQuestions raw headerSize nQuestion
  (answers, off2) <- parseRecords raw off1 nAnswer
  (additional, _) <- parseRecords raw off2 nAdditional
  pure
    DnsPacket
      { pkID = id'
      , pkFlags = flags
      , pkQuestion = questions
      , pkAnswer = answers
      , pkAdditional = additional
      }

be16 :: ByteString -> Int -> Word16
be16 bs i = fromIntegral (BS.index bs i) * 256 + fromIntegral (BS.index bs (i + 1))

be32 :: ByteString -> Int -> Word32
be32 bs i =
  fromIntegral (BS.index bs i) * 0x1000000
    + fromIntegral (BS.index bs (i + 1)) * 0x10000
    + fromIntegral (BS.index bs (i + 2)) * 0x100
    + fromIntegral (BS.index bs (i + 3))

unlessLen :: Bool -> String -> Either String ()
unlessLen True _ = Right ()
unlessLen False err = Left err

parseQuestions :: ByteString -> Int -> Word16 -> Either String ([DnsQuestion], Int)
parseQuestions raw off n = parseQ off (fromIntegral n) []
  where
    parseQ o 0 acc = pure (reverse acc, o)
    parseQ o k acc = do
      (name, o1) <- decodeName raw o
      unlessLen (o1 + 4 <= BS.length raw) "truncated question (name/type/class)"
      parseQ (o1 + 4) (k - 1)
        (DnsQuestion name (be16 raw o1) (be16 raw (o1 + 2)) : acc)

parseRecords :: ByteString -> Int -> Word16 -> Either String ([DnsRecord], Int)
parseRecords raw off n = parseR off (fromIntegral n) []
  where
    parseR o 0 acc = pure (reverse acc, o)
    parseR o k acc = do
      (name, o1) <- decodeName raw o
      unlessLen (o1 + 10 <= BS.length raw) "truncated record header"
      let rtype = be16 raw o1
          rclass = be16 raw (o1 + 2)
          rttl = be32 raw (o1 + 4)
          rdataLen = fromIntegral (be16 raw (o1 + 8))
          bodyOff = o1 + 10
      unlessLen (bodyOff + rdataLen <= BS.length raw) "rdata runs past the packet"
      rdata <- parseRData raw bodyOff rdataLen rtype
      parseR (bodyOff + rdataLen) (k - 1)
        (DnsRecord name rtype rclass rttl rdata : acc)

parseRData :: ByteString -> Int -> Int -> Word16 -> Either String DnsRData
parseRData raw off len rtype = case rtype of
  t
    | t == typePTR -> do
        (name, _) <- decodeName raw off
        pure (RdPtr name)
    | t == typeTXT -> do
        strings <- parseTxt raw off len
        pure (RdTxt strings)
    | t == typeSRV -> parseSrv raw off len
    | otherwise -> pure (RdOther (BS.take len (BS.drop off raw)))

-- | TXT rdata (RFC 1035 §3.3.14): a sequence of character-strings,
-- each length-prefixed (1-255 bytes).
parseTxt :: ByteString -> Int -> Int -> Either String [ByteString]
parseTxt raw off len = go off []
  where
    end = off + len
    go o acc
      | o >= end = pure (reverse acc)
      | o + 1 > end = Left "truncated TXT string length"
      | otherwise = do
          let slen = fromIntegral (BS.index raw o)
          unlessLen (o + 1 + slen <= end) "TXT string runs past rdata"
          go (o + 1 + slen) (BS.take slen (BS.drop (o + 1) raw) : acc)

parseSrv :: ByteString -> Int -> Int -> Either String DnsRData
parseSrv raw off len = do
  unlessLen (len >= 6) "SRV rdata too short"
  let priority = be16 raw off
      weight = be16 raw (off + 2)
      port = be16 raw (off + 4)
  (target, _) <- decodeName raw (off + 6)
  pure (RdSrv priority weight port target)

-- | Decode a (possibly compressed) domain name (RFC 1035 §4.1.4).
--
-- Returns the lower-cased name and the offset just past it: a
-- compression pointer does not advance the cursor, so the first byte
-- after the pointer belongs to the enclosing record.
--
-- Guards against malformed compression: a pointer must jump
-- /backwards/ (RFC 1035: "an offset ... prior ... occurrence") and
-- pointer chains are capped at 127 jumps, so a crafted loop cannot
-- hang the reader.
decodeName :: ByteString -> Int -> Either String (Text, Int)
decodeName raw start = go start Nothing 0 []
  where
    total = BS.length raw
    decodeLabel = T.toLower . decodeUtf8With lenientDecode

    -- o: current offset; Just res: cursor past the /outermost/ name
    -- (fixed at the first pointer); d: pointer jumps so far; acc:
    -- labels collected so far (reverse order).
    go o mCursor d acc
      | d > 127 = Left "name compression chain too deep"
      | o >= total = Left "name runs past the packet"
      | lenByte == 0 =
          pure (T.intercalate "." (map decodeLabel (reverse acc)), fromMaybe (o + 1) mCursor)
      | lenByte >= 0xC0 = do
          unlessLen (o + 1 < total) "truncated compression pointer"
          unlessLen (lenByte < 0xC4) "compression pointer sets reserved bits"
          let target =
                fromIntegral (lenByte .&. 0x3F) * 256
                  + fromIntegral (BS.index raw (o + 1))
          unlessLen (target < o) "compression pointer must point backwards"
          go target (Just (fromMaybe (o + 2) mCursor)) (d + 1) acc
      | otherwise = do
          unlessLen (o + 1 + fromIntegral lenByte <= total) "label runs past the packet"
          let label = BS.take (fromIntegral lenByte) (BS.drop (o + 1) raw)
          go (o + 1 + fromIntegral lenByte) mCursor d (label : acc)
      where
        lenByte = BS.index raw o
