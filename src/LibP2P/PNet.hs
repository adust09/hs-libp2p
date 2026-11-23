{- | Pre-shared key private networks (specs/pnet/Private-Networks-PSK-V1.md).

Every byte of a connection is XSalsa20-encrypted with the network's 256-bit
key before security negotiation. Each side sends a fresh 24-byte nonce ahead
of its first write and encrypts what it writes with it; it decrypts what it
reads with the nonce the peer sent first. There is no handshake: a peer
holding a different key, or none, reads noise and the following
multistream-select negotiation fails.
-}
module LibP2P.PNet (
  PSK,
  pskFromBytes,
  decodeSwarmKey,
  protectStream,
  protectStreamWithNonce,
  protectConnection,
) where

import Control.Concurrent.MVar (modifyMVar, modifyMVar_, newMVar)
import Crypto.Cipher.XSalsa qualified as XSalsa
import Crypto.Random (getRandomBytes)
import Data.ByteArray.Encoding (Base (..), convertFromBase)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Char8 qualified as BC
import LibP2P.MultistreamSelect.Negotiation (StreamIO (..))
import LibP2P.Transport (ConnectionEndpoint (..), RawConnection (..))

-- | A private network's 256-bit pre-shared key.
newtype PSK = PSK ByteString
  deriving (Eq)

instance Show PSK where
  show _ = "PSK <redacted>"

pskLength, nonceLength, xsalsaRounds :: Int
pskLength = 32
nonceLength = 24
xsalsaRounds = 20

-- | A key from its 32 raw bytes.
pskFromBytes :: ByteString -> Either String PSK
pskFromBytes bytes
  | BS.length bytes == pskLength = Right (PSK bytes)
  | otherwise = Left ("pnet: key must be 32 bytes, got " <> show (BS.length bytes))

{- | Decode a @swarm.key@ file: the @/key/swarm/psk/1.0.0/@ codec line, an
encoding line (@/base16/@, @/base64/@ or @/bin/@), then the key. Like
go-libp2p, lines may end in CRLF and data after the key is ignored.
-}
decodeSwarmKey :: ByteString -> Either String PSK
decodeSwarmKey file = do
  (codec, afterCodec) <- line file
  if codec == "/key/swarm/psk/1.0.0/"
    then pure ()
    else Left ("pnet: unknown key codec " <> show codec)
  (encoding, body) <- line afterCodec
  keyBytes <- case encoding of
    "/base16/" -> decodeAs Base16 (BS.take (2 * pskLength) body)
    -- 32 bytes take 44 base64 characters with padding.
    "/base64/" -> decodeAs Base64 (BS.take 44 (BC.filter (`notElem` ("\r\n" :: String)) body))
    "/bin/" -> Right (BS.take pskLength body)
    _ -> Left ("pnet: unknown key encoding " <> show encoding)
  pskFromBytes keyBytes
 where
  line bytes = case BC.break (== '\n') bytes of
    (_, rest) | BS.null rest -> Left "pnet: truncated key file"
    (header, rest) -> Right (BC.filter (/= '\r') header, BS.drop 1 rest)
  decodeAs base encoded = either (Left . ("pnet: " <>)) Right (convertFromBase base encoded)

-- | Encrypt a stream with a fresh random nonce for the outgoing direction.
protectStream :: PSK -> StreamIO -> IO StreamIO
protectStream psk raw = do
  nonce <- getRandomBytes nonceLength
  protectStreamWithNonce psk nonce raw

{- | 'protectStream' with a given outgoing nonce, for test vectors.

Both directions start lazily, as in go-libp2p: the nonce goes out with the
first write and the peer's nonce is read on the first read. A side that
waited for the peer's nonce before writing would deadlock against a peer
that only writes after reading.
-}
protectStreamWithNonce :: PSK -> ByteString -> StreamIO -> IO StreamIO
protectStreamWithNonce (PSK key) nonce raw = do
  writer <- newMVar Nothing
  reader <- newMVar Nothing
  let write plaintext = modifyMVar_ writer $ \started -> do
        state <- case started of
          Just state -> pure state
          Nothing -> do
            streamWrite raw nonce
            pure (XSalsa.initialize xsalsaRounds key nonce)
        let (ciphertext, next) = XSalsa.combine state plaintext
        streamWrite raw ciphertext
        pure (Just next)
      readChunk size = modifyMVar reader $ \started -> do
        state <- case started of
          Just state -> pure state
          Nothing -> XSalsa.initialize xsalsaRounds key <$> readExactly raw nonceLength
        ciphertext <- streamReadChunk raw size
        let (plaintext, next) = XSalsa.combine state ciphertext
        pure (Just next, plaintext)
  pure
    StreamIO
      { streamWrite = write
      , streamReadByte = BS.head <$> readChunk 1
      , streamReadChunk = readChunk
      , streamClose = streamClose raw
      }

{- | Protect a raw connection's byte stream. Native multiplexed transports
(QUIC, WebTransport, WebRTC) have no byte stream to encrypt, so their connections are
closed and refused rather than allowed outside the private network.
-}
protectConnection :: PSK -> RawConnection -> IO RawConnection
protectConnection psk raw = case rcEndpoint raw of
  ByteStreamEndpoint stream -> do
    protected <- protectStream psk stream
    pure raw{rcEndpoint = ByteStreamEndpoint protected}
  NativeMuxerEndpoint _ -> do
    rcClose raw
    fail "pnet: private networks require a transport with a raw byte stream; QUIC, WebTransport and WebRTC are not supported"

readExactly :: StreamIO -> Int -> IO ByteString
readExactly stream = go []
 where
  go chunks remaining
    | remaining <= 0 = pure (BS.concat (reverse chunks))
    | otherwise = do
        chunk <- streamReadChunk stream remaining
        go (chunk : chunks) (remaining - BS.length chunk)
