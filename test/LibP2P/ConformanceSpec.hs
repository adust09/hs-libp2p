-- | Spec-clause conformance tests (T3a tier, #178).
--
-- One test per normative clause, named after the clause. This module
-- pins the clauses of the core specs (multistream-select, noise) that
-- were testable in-process but not yet covered by any other spec file.
-- The full clause-by-clause sweep of multistream-select, noise, yamux,
-- identify and ping — mapping every MUST/SHOULD to the spec file that
-- covers it — lives in the PR that introduced this module.
--
-- Clauses that require a live foreign implementation are delegated to
-- the interop harness (#129); clauses whose behaviour is not implemented
-- yet are tracked as their own issues rather than as permanently
-- failing tests.
module LibP2P.ConformanceSpec (spec) where

import Control.Concurrent.Async (concurrently)
import Control.Monad (replicateM)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.IORef (modifyIORef', newIORef, readIORef, writeIORef)
import LibP2P.Crypto.Ed25519 (generateKeyPair)
import LibP2P.Crypto.Key (KeyPair, kpPublic)
import LibP2P.Crypto.PeerId (PeerId, fromPublicKey)
import LibP2P.MultistreamSelect.Negotiation
  ( NegotiationResult (..)
  , StreamIO (..)
  , mkByteStreamIO
  , mkMemoryStreamPair
  , negotiateInitiator
  , negotiateResponder
  )
import LibP2P.Noise.Handshake
  ( HandshakeResult (..)
  , decodePublicKey
  , initHandshakeResponder
  , readHandshakeMsg
  , writeHandshakeMsg
  )
import LibP2P.Noise.Handshake.Payload
  ( NoisePayload (..)
  , buildHandshakePayload
  , decodeNoisePayload
  , encodeNoisePayload
  )
import LibP2P.Switch.Types (Direction (..))
import LibP2P.Switch.Upgrade
  ( performStreamHandshake
  , readFramedMessage
  , writeFramedMessage
  )
import System.Timeout (timeout)
import Test.Hspec

-- | A scripted stream: reads come from a canned byte sequence, writes
-- are captured for byte-exact assertion. Reading past the script
-- raises EOF. (Same shape as the WireConformanceSpec helper.)
mkScriptedStream :: ByteString -> IO (StreamIO, IO ByteString)
mkScriptedStream canned = do
  writtenRef <- newIORef BS.empty
  readRef <- newIORef canned
  let readB = do
        buf <- readIORef readRef
        case BS.uncons buf of
          Nothing -> ioError (userError "scripted stream: EOF")
          Just (b, rest) -> writeIORef readRef rest >> pure b
      stream = mkByteStreamIO
        (\bs -> modifyIORef' writtenRef (`BS.append` bs))
        readB
        (pure ())
  pure (stream, readIORef writtenRef)

-- multistream-select messages, hand-derived from the spec:
-- <varint-length><UTF-8 payload>\n, length includes the trailing \n.

-- | varint(19) "/multistream/1.0.0" \n
mssHeader :: ByteString
mssHeader = BS.singleton 0x13 <> "/multistream/1.0.0\n"

-- | A header for a protocol version we do not speak (same length).
mssWrongHeader :: ByteString
mssWrongHeader = BS.singleton 0x13 <> "/multistream/2.0.0\n"

-- | varint(7) "/noise" \n
mssNoise :: ByteString
mssNoise = BS.singleton 0x07 <> "/noise\n"

-- | varint(13) "/yamux/1.0.0" \n
mssYamux :: ByteString
mssYamux = BS.singleton 0x0d <> "/yamux/1.0.0\n"

-- | varint(3) "na" \n
mssNa :: ByteString
mssNa = BS.singleton 0x03 <> "na\n"

-- | varint(3) "ls" \n
mssLs :: ByteString
mssLs = BS.singleton 0x03 <> "ls\n"

-- | Generate a test identity (PeerId, KeyPair).
mkTestIdentity :: IO (PeerId, KeyPair)
mkTestIdentity = do
  Right kp <- generateKeyPair
  pure (fromPublicKey (kpPublic kp), kp)

-- | Read exactly n bytes from a stream.
readN :: StreamIO -> Int -> IO ByteString
readN stream n = BS.pack <$> replicateM n (streamReadByte stream)

spec :: Spec
spec = do
  describe "multistream-select conformance (multiformats/multistream-select README)" $ do
    -- The protocol id header is part of the negotiation: a peer that
    -- answers with a different multistream version cannot be talked to.
    it "initiator verifies the peer's multistream header and aborts on a mismatch" $ do
      (stream, getWritten) <- mkScriptedStream mssWrongHeader
      result <- negotiateInitiator stream ["/noise"]
      result `shouldBe` NoProtocol
      -- The first proposal is pipelined with the header (spec SHOULD),
      -- so it is already on the wire when the mismatch is detected; the
      -- initiator must abort there and propose nothing further.
      written <- getWritten
      written `shouldBe` (mssHeader <> mssNoise)

    it "responder verifies the initiator's multistream header and stays silent on a mismatch" $ do
      (stream, getWritten) <- mkScriptedStream (mssWrongHeader <> mssNoise)
      result <- negotiateResponder stream ["/noise"]
      result `shouldBe` NoProtocol
      written <- getWritten
      written `shouldBe` BS.empty

    -- "Implementations MAY support ls" / "Implementations MUST NOT
    -- depend on a remote node supporting ls": a responder without ls
    -- support answers it like any unknown proposal (na) and the
    -- negotiation continues.
    it "responder without ls support answers na to an ls request and negotiation continues" $ do
      (stream, getWritten) <- mkScriptedStream (mssHeader <> mssLs <> mssNoise)
      result <- negotiateResponder stream ["/noise"]
      result `shouldBe` Accepted "/noise"
      written <- getWritten
      written `shouldBe` (mssHeader <> mssNa <> mssNoise)

    -- The only valid responses to a proposal are the echoed protocol id
    -- or na; anything else means the peer is broken or malicious.
    it "initiator aborts when the response is neither an echo of the proposal nor na" $ do
      (stream, getWritten) <- mkScriptedStream (mssHeader <> mssYamux)
      result <- negotiateInitiator stream ["/noise"]
      result `shouldBe` NoProtocol
      written <- getWritten
      written `shouldBe` (mssHeader <> mssNoise)

  describe "noise conformance (specs/noise/README.md, XX pattern)" $ do
    -- XX message 1 is "-> e": the unencrypted 32-byte X25519 ephemeral
    -- key and nothing else. The identity payload is only sent in
    -- messages 2 and 3. This pins both the DH choice (25519 keys are
    -- 32 bytes) and the absence of a payload in message 1, end-to-end
    -- through the production framing (2-byte big-endian length prefix).
    it "initiator's first message is the bare 32-byte ephemeral key with no payload" $ do
      (initSide, foreignSide) <- mkMemoryStreamPair
      (pidA, kpA) <- mkTestIdentity
      (pidB, kpB) <- mkTestIdentity
      done <- timeout 10000000 $ concurrently
        (performStreamHandshake kpA Nothing Outbound initSide)
        (runForeignResponderCapturingMsg1 kpB foreignSide)
      case done of
        Nothing -> expectationFailure "handshake against the foreign responder hung"
        Just ((_sess, hr), (msg1Frame, seenInitiator)) -> do
          -- 2-byte BE length prefix declares exactly 32 bytes.
          BS.take 2 msg1Frame `shouldBe` BS.pack [0x00, 0x20]
          BS.length msg1Frame `shouldBe` 34
          -- Both sides authenticated each other from the payloads in
          -- messages 2 and 3, so the handshake as a whole is honest.
          hrRemotePeerId hr `shouldBe` pidB
          seenInitiator `shouldBe` pidA

-- | A hand-rolled honest XX responder that records the raw framed
-- message 1 exactly as it appeared on the wire, then completes the
-- handshake and returns the initiator identity from the msg3 payload.
runForeignResponderCapturingMsg1
  :: KeyPair -> StreamIO -> IO (ByteString, PeerId)
runForeignResponderCapturingMsg1 kp stream = do
  (st0, staticPub) <- initHandshakeResponder kp

  -- Capture the raw frame: length prefix plus declared payload.
  prefix <- readN stream 2
  let declared = fromIntegral (BS.index prefix 0) * 256
              + fromIntegral (BS.index prefix 1)
  msg1 <- readN stream declared
  (_p1, st1) <- either fail pure $ readHandshakeMsg st0 msg1

  -- Message 2: -> e, ee, s, es with our identity payload.
  payload <- either fail pure $
    encodeNoisePayload <$> buildHandshakePayload kp staticPub Nothing
  (msg2, st2) <- either fail pure $ writeHandshakeMsg st1 payload
  writeFramedMessage stream msg2

  -- Message 3: <- s, se with the initiator's identity payload.
  msg3 <- readFramedMessage stream
  (p3, _stFinal) <- either fail pure $ readHandshakeMsg st2 msg3
  np <- either (fail . show) pure $ decodeNoisePayload p3
  pk <- either fail pure $ decodePublicKey (npIdentityKey np)
  pure (prefix <> msg1, fromPublicKey pk)
