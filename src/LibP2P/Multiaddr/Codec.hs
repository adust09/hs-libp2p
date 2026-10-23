-- | Binary and text encoding/decoding for multiaddr.
module LibP2P.Multiaddr.Codec
  ( encodeProtocols
  , decodeProtocols
  , protocolsToText
  , textToProtocols
  ) where

import Data.Bits (shiftL, shiftR, (.&.))
import Data.ByteString (ByteString)
import Data.Char (isDigit)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64.URL as B64URL
import Data.IP (IPv6, fromHostAddress6, toHostAddress6)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Word (Word16, Word32, Word64)
import Text.Read (readMaybe)
import LibP2P.Core.Binary (readWord16BE, readWord32BE, word16BE, word32BE)
import LibP2P.Core.Multihash (validateMultihash)
import LibP2P.Core.Varint (decodeUvarint, encodeUvarint)
import qualified Data.ByteString.Base58 as B58
import LibP2P.Crypto.PeerId (parsePeerId, peerIdBytes)
import LibP2P.Multiaddr.Protocol

-- | Encode a list of protocols to binary multiaddr format.
encodeProtocols :: [Protocol] -> ByteString
encodeProtocols = BS.concat . map encodeOne
  where
    encodeOne :: Protocol -> ByteString
    encodeOne p =
      let code = encodeUvarint (protocolCode p)
          addr = encodeAddress p
       in code <> addr

    encodeAddress :: Protocol -> ByteString
    encodeAddress (IP4 w) = word32BE w
    encodeAddress (IP6 bs) = bs
    encodeAddress (TCP port) = word16BE port
    encodeAddress (UDP port) = word16BE port
    encodeAddress (P2P mh) = encodeVarBytes mh
    encodeAddress (Certhash mh) = encodeVarBytes mh
    encodeAddress (DNS t) = encodeVarText t
    encodeAddress (DNS4 t) = encodeVarText t
    encodeAddress (DNS6 t) = encodeVarText t
    encodeAddress (DNSAddr t) = encodeVarText t
    encodeAddress QuicV1 = BS.empty
    encodeAddress WS = BS.empty
    encodeAddress WSS = BS.empty
    encodeAddress P2PCircuit = BS.empty
    encodeAddress WebTransport = BS.empty
    encodeAddress NoiseProto = BS.empty

    encodeVarText :: Text -> ByteString
    encodeVarText = encodeVarBytes . TE.encodeUtf8

    encodeVarBytes :: ByteString -> ByteString
    encodeVarBytes bytes =
      encodeUvarint (fromIntegral (BS.length bytes)) <> bytes

-- | Decode binary multiaddr format to a list of protocols.
decodeProtocols :: ByteString -> Either String [Protocol]
decodeProtocols bs
  | BS.null bs = Right []
  | otherwise = do
      (code, rest1) <- decodeUvarint bs
      case protocolAddressSize code of
        Nothing -> Left $ "decodeProtocols: unknown protocol code " <> show code
        Just addrSize -> do
          (proto, rest2) <- decodeAddress code addrSize rest1
          rest <- decodeProtocols rest2
          Right (proto : rest)
  where
    decodeAddress :: Word64 -> AddressSize -> ByteString -> Either String (Protocol, ByteString)
    decodeAddress code (Fixed n) input
      | BS.length input < n =
          Left $ "decodeProtocols: not enough bytes for protocol " <> show code
      | otherwise =
          let (addr, rest) = BS.splitAt n input
           in case buildProtocol code addr of
                Just p -> Right (p, rest)
                Nothing -> Left $ "decodeProtocols: failed to parse address for code " <> show code
    decodeAddress code VarIntPrefixed input = do
      (len, rest1) <- decodeUvarint input
      let n = fromIntegral len :: Int
      if BS.length rest1 < n
        then Left $ "decodeProtocols: not enough bytes for varint-prefixed protocol " <> show code
        else
          let (addr, rest2) = BS.splitAt n rest1
           in case buildVarProtocol code addr of
                Just p -> Right (p, rest2)
                Nothing -> Left $ "decodeProtocols: failed to parse varint-prefixed address for code " <> show code
    decodeAddress code NoAddress input =
      case buildNoAddrProtocol code of
        Just p -> Right (p, input)
        Nothing -> Left $ "decodeProtocols: unknown no-address protocol " <> show code

    buildProtocol :: Word64 -> ByteString -> Maybe Protocol
    buildProtocol 4 bs'
      | BS.length bs' == 4 = Just $ IP4 (readWord32BE bs')
    buildProtocol 41 bs'
      | BS.length bs' == 16 = Just $ IP6 bs'
    buildProtocol 6 bs'
      | BS.length bs' == 2 = Just $ TCP (readWord16BE bs')
    buildProtocol 273 bs'
      | BS.length bs' == 2 = Just $ UDP (readWord16BE bs')
    buildProtocol _ _ = Nothing

    buildVarProtocol :: Word64 -> ByteString -> Maybe Protocol
    buildVarProtocol 421 mh = case validateMultihash mh of
      Right _ -> Just $ P2P mh
      Left _  -> Nothing
    buildVarProtocol 466 mh = case validateMultihash mh of
      Right _ -> Just $ Certhash mh
      Left _  -> Nothing
    buildVarProtocol 53 bs' = DNS <$> decodeUtf8Safe bs'
    buildVarProtocol 54 bs' = DNS4 <$> decodeUtf8Safe bs'
    buildVarProtocol 55 bs' = DNS6 <$> decodeUtf8Safe bs'
    buildVarProtocol 56 bs' = DNSAddr <$> decodeUtf8Safe bs'
    buildVarProtocol _ _ = Nothing

    buildNoAddrProtocol :: Word64 -> Maybe Protocol
    buildNoAddrProtocol 461 = Just QuicV1
    buildNoAddrProtocol 477 = Just WS
    buildNoAddrProtocol 478 = Just WSS
    buildNoAddrProtocol 290 = Just P2PCircuit
    buildNoAddrProtocol 465 = Just WebTransport
    buildNoAddrProtocol 454 = Just NoiseProto
    buildNoAddrProtocol _ = Nothing

-- | Convert a list of protocols to human-readable text form.
protocolsToText :: [Protocol] -> Text
protocolsToText = T.concat . map renderOne
  where
    renderOne :: Protocol -> Text
    renderOne p@(IP4 w) = "/" <> protocolName p <> "/" <> renderIPv4 w
    renderOne p@(IP6 bs) = "/" <> protocolName p <> "/" <> renderIPv6 bs
    renderOne p@(TCP port) = "/" <> protocolName p <> "/" <> T.pack (show port)
    renderOne p@(UDP port) = "/" <> protocolName p <> "/" <> T.pack (show port)
    renderOne p@(P2P mh) = "/" <> protocolName p <> "/" <> renderBase58 mh
    renderOne p@(Certhash mh) = "/" <> protocolName p <> "/u" <> renderBase64URL mh
    renderOne p@(DNS t) = "/" <> protocolName p <> "/" <> t
    renderOne p@(DNS4 t) = "/" <> protocolName p <> "/" <> t
    renderOne p@(DNS6 t) = "/" <> protocolName p <> "/" <> t
    renderOne p@(DNSAddr t) = "/" <> protocolName p <> "/" <> t
    renderOne p = "/" <> protocolName p

    renderIPv4 :: Word32 -> Text
    renderIPv4 w =
      let a = (w `shiftR` 24) .&. 0xff
          b = (w `shiftR` 16) .&. 0xff
          c = (w `shiftR` 8) .&. 0xff
          d = w .&. 0xff
       in T.pack $ show a <> "." <> show b <> "." <> show c <> "." <> show d

    -- | Render 16-byte IPv6 address to RFC5952 text form.
    renderIPv6 :: ByteString -> Text
    renderIPv6 bs = T.pack $ show (bytesToIPv6 bs)

    -- Minimal base58btc encoding for PeerId display
    renderBase58 :: ByteString -> Text
    renderBase58 = TE.decodeUtf8 . B58.encode

    renderBase64URL :: ByteString -> Text
    renderBase64URL = TE.decodeUtf8 . B64URL.encodeUnpadded

-- | Parse human-readable text form to a list of protocols.
--
-- Strict per the multiaddr spec and go-multiaddr behaviour: the input
-- must be non-empty, must begin with @/@, and must not contain empty
-- components (so a bare @/@, doubled slashes, and trailing slashes are
-- all rejected).
textToProtocols :: Text -> Either String [Protocol]
textToProtocols input
  | T.null input = Left "textToProtocols: empty multiaddr"
  | T.head input /= '/' = Left "textToProtocols: multiaddr must begin with /"
  | otherwise =
      let parts = T.splitOn "/" (T.drop 1 input)
       in if any T.null parts
            then Left "textToProtocols: empty component in multiaddr"
            else parseParts parts
  where
    parseParts :: [Text] -> Either String [Protocol]
    parseParts [] = Right []
    parseParts (name : rest) = case name of
      "ip4" -> withAddr rest $ \addr remaining -> do
        w <- parseIPv4 addr
        Right (IP4 w, remaining)
      "ip6" -> withAddr rest $ \addr remaining -> do
        w <- parseIPv6 addr
        Right (IP6 w, remaining)
      "tcp" -> withAddr rest $ \addr remaining -> do
        port <- parsePort addr
        Right (TCP port, remaining)
      "udp" -> withAddr rest $ \addr remaining -> do
        port <- parsePort addr
        Right (UDP port, remaining)
      -- "ipfs" is the legacy name for "p2p"; both map to code 421 and are
      -- equivalent in binary form. Rendering always emits "p2p".
      _ | name == "p2p" || name == "ipfs" ->
        withAddr rest $ \addr remaining -> do
          mh <- parsePeerIdAddr addr
          Right (P2P mh, remaining)
      "certhash" -> withAddr rest $ \addr remaining -> do
        mh <- parseCerthash addr
        Right (Certhash mh, remaining)
      "dns" -> withAddr rest $ \addr remaining ->
        Right (DNS addr, remaining)
      "dns4" -> withAddr rest $ \addr remaining ->
        Right (DNS4 addr, remaining)
      "dns6" -> withAddr rest $ \addr remaining ->
        Right (DNS6 addr, remaining)
      "dnsaddr" -> withAddr rest $ \addr remaining ->
        Right (DNSAddr addr, remaining)
      "quic-v1" -> do
        more <- parseParts rest
        Right (QuicV1 : more)
      "ws" -> do
        more <- parseParts rest
        Right (WS : more)
      "wss" -> do
        more <- parseParts rest
        Right (WSS : more)
      "p2p-circuit" -> do
        more <- parseParts rest
        Right (P2PCircuit : more)
      "webtransport" -> do
        more <- parseParts rest
        Right (WebTransport : more)
      "noise" -> do
        more <- parseParts rest
        Right (NoiseProto : more)
      other -> Left $ "textToProtocols: unknown protocol " <> T.unpack other

    withAddr :: [Text] -> (Text -> [Text] -> Either String (Protocol, [Text])) -> Either String [Protocol]
    withAddr [] _ = Left "textToProtocols: expected address but got end of input"
    withAddr (addr : remaining) f = do
      (proto, rest) <- f addr remaining
      more <- parseParts rest
      Right (proto : more)

    -- Strict dotted-decimal: exactly four octets, digits only (no sign,
    -- hex, or whitespace), no leading zeros, each in 0..255. Matches
    -- go-multiaddr, which rejects e.g. "010.0.0.1" and "-1.0.0.1".
    parseIPv4 :: Text -> Either String Word32
    parseIPv4 t = case mapM parseOctet (T.splitOn "." t) of
      Just [a, b, c, d] ->
        Right $
          (fromIntegral a `shiftL` 24)
            + (fromIntegral b `shiftL` 16)
            + (fromIntegral c `shiftL` 8)
            + fromIntegral d
      _ -> Left $ "textToProtocols: invalid IPv4 address: " <> T.unpack t

    parseOctet :: Text -> Maybe Integer
    parseOctet o
      | T.length o > 1 && T.head o == '0' = Nothing -- no leading zeros
      | otherwise = do
          n <- parseDecimal o
          if n <= 255 then Just n else Nothing

    -- | Parse IPv6 text (e.g. "::1", "fe80::1") to 16-byte ByteString.
    parseIPv6 :: Text -> Either String ByteString
    parseIPv6 t =
      case readMaybe (T.unpack t) :: Maybe IPv6 of
        Just ipv6 -> Right (ipv6ToBytes ipv6)
        Nothing -> Left $ "textToProtocols: invalid IPv6 address: " <> T.unpack t

    -- Strict decimal port: digits only (no sign, hex, or whitespace),
    -- in 0..65535. Leading zeros are accepted, matching go-multiaddr's
    -- strconv.ParseUint behaviour.
    parsePort :: Text -> Either String Word16
    parsePort t = case parseDecimal t of
      Just n
        | n <= 65535 -> Right (fromIntegral n)
      _ -> Left $ "textToProtocols: invalid port: " <> T.unpack t

    -- Non-negative decimal, digits only. Parsed via Integer so absurdly
    -- long digit strings cannot wrap around a fixed-width type.
    parseDecimal :: Text -> Maybe Integer
    parseDecimal t
      | T.null t = Nothing
      | not (T.all isDigit t) = Nothing
      | otherwise = readMaybe (T.unpack t)

    -- | Parse a peer ID from text, accepting both base58btc and CIDv1 formats.
    -- Validates the decoded bytes as a well-formed multihash.
    parsePeerIdAddr :: Text -> Either String ByteString
    parsePeerIdAddr t = case parsePeerId t of
      Right pid -> Right (peerIdBytes pid)
      Left err -> Left $ "textToProtocols: invalid peer ID: " <> err

    parseCerthash :: Text -> Either String ByteString
    parseCerthash text = do
      bytes <- case T.uncons text of
        Just ('u', encoded) -> B64URL.decodeUnpadded (TE.encodeUtf8 encoded)
        Just ('z', encoded) ->
          maybe (Left "invalid base58btc") Right $
            B58.decode (TE.encodeUtf8 encoded)
        _ -> Left "unsupported multibase prefix"
      case validateMultihash bytes of
        Right _ -> Right bytes
        Left err -> Left $ "textToProtocols: invalid certhash: " <> err

-- | Safely decode UTF-8 bytes to Text, returning Nothing on invalid input.
decodeUtf8Safe :: ByteString -> Maybe Text
decodeUtf8Safe bs = case TE.decodeUtf8' bs of
  Right t -> Just t
  Left _ -> Nothing

-- | Convert 16-byte ByteString to IPv6 address via HostAddress6 tuple.
bytesToIPv6 :: ByteString -> IPv6
bytesToIPv6 bs =
  let w0 = readWord32BE bs
      w1 = readWord32BE (BS.drop 4 bs)
      w2 = readWord32BE (BS.drop 8 bs)
      w3 = readWord32BE (BS.drop 12 bs)
   in fromHostAddress6 (w0, w1, w2, w3)

-- | Convert IPv6 address to 16-byte ByteString.
ipv6ToBytes :: IPv6 -> ByteString
ipv6ToBytes ipv6 =
  let (w0, w1, w2, w3) = toHostAddress6 ipv6
   in word32BE w0 <> word32BE w1 <> word32BE w2 <> word32BE w3
