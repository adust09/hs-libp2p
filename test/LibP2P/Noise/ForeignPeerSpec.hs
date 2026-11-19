-- | Foreign-peer tests for the production Noise XX handshake path.
--
-- Every other Noise test in this repository pairs two instances of the
-- production code with each other, which can only validate internal
-- consistency: both ends build their messages from the same functions, so
-- they can never disagree. These tests drive one endpoint BY HAND from the
-- low-level handshake primitives, so the remote side can deviate from
-- anything our own production path would send — in particular an
-- identity_sig computed over the wrong Noise static key (a replayed or
-- forged payload). This is the closest a single-implementation suite can
-- get to a foreign peer before the cross-implementation interop harness
-- (#129) lands.
module LibP2P.Noise.ForeignPeerSpec (spec) where

import Control.Concurrent.Async (concurrently, withAsync)
import Control.Exception (IOException, try)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.List (isInfixOf)
import LibP2P.Crypto.Ed25519 (generateKeyPair)
import LibP2P.Crypto.Key (KeyPair (..), PublicKey)
import LibP2P.Crypto.PeerId (PeerId, fromPublicKey)
import LibP2P.EofStream (mkEofStreamPair)
import LibP2P.MultistreamSelect.Negotiation (StreamIO (..), mkMemoryStreamPair)
import LibP2P.Noise.Handshake
  ( HandshakeResult (..)
  , HandshakeState (..)
  , decodePublicKey
  , initHandshakeInitiator
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
import LibP2P.Noise.Session (NoiseSession, encryptMessage, mkNoiseSession)
import LibP2P.Switch.Types (Direction (..))
import LibP2P.Switch.Upgrade
  ( noiseSessionToStreamIO
  , performStreamHandshake
  , readExact
  , readFramedMessage
  , writeFramedMessage
  )
import Data.IORef (newIORef)
import System.Timeout (timeout)
import Test.Hspec

-- | Assert that an IO action fails with an 'IOException' within the
-- given number of microseconds — neither hanging nor succeeding. The
-- EOF failure mode being guarded against is a hang, so a plain
-- 'shouldThrow' would be insufficient.
shouldFailCleanlyWithin :: Int -> IO a -> Expectation
shouldFailCleanlyWithin us action = do
  result <- timeout us (try action)
  case result of
    Just (Left (_ :: IOException)) -> pure ()
    Just (Right _) ->
      expectationFailure "expected a clean failure, but the action succeeded"
    Nothing ->
      expectationFailure "expected a clean failure, but the action hung"

-- | Generate a test identity (PeerId, KeyPair).
mkTestIdentity :: IO (PeerId, KeyPair)
mkTestIdentity = do
  Right kp <- generateKeyPair
  pure (fromPublicKey (kpPublic kp), kp)

-- | A hand-rolled Noise XX responder driven from the low-level handshake
-- primitives. 'sigTarget' selects which bytes the identity signature
-- covers: 'id' signs the actual session static key (an honest peer);
-- @const other@ signs unrelated bytes (a forged or replayed payload).
-- Returns the initiator identity extracted from the msg3 payload.
runForeignResponder
  :: KeyPair -> (ByteString -> ByteString) -> StreamIO -> IO (PeerId, PublicKey)
runForeignResponder identityKP sigTarget stream = do
  (st0, staticPub) <- initHandshakeResponder identityKP

  -- Message 1: <- e (empty payload)
  msg1 <- readFramedMessage stream
  (_p1, st1) <- either fail pure $ readHandshakeMsg st0 msg1

  -- Message 2: -> e, ee, s, es (identity payload, signature over sigTarget)
  payload <- either fail pure $
    encodeNoisePayload <$> buildHandshakePayload identityKP (sigTarget staticPub) Nothing
  (msg2, st2) <- either fail pure $ writeHandshakeMsg st1 payload
  writeFramedMessage stream msg2

  -- Message 3: <- s, se (initiator identity payload)
  msg3 <- readFramedMessage stream
  (p3, _stFinal) <- either fail pure $ readHandshakeMsg st2 msg3
  np <- either (fail . show) pure $ decodeNoisePayload p3
  pk <- either fail pure $ decodePublicKey (npIdentityKey np)
  pure (fromPublicKey pk, pk)

-- | A hand-rolled Noise XX initiator, mirror of 'runForeignResponder'.
-- Returns the responder identity extracted from the msg2 payload.
runForeignInitiator
  :: KeyPair -> (ByteString -> ByteString) -> StreamIO -> IO (PeerId, PublicKey)
runForeignInitiator identityKP sigTarget stream = do
  (st0, staticPub) <- initHandshakeInitiator identityKP

  -- Message 1: -> e (empty payload)
  (msg1, st1) <- either fail pure $ writeHandshakeMsg st0 BS.empty
  writeFramedMessage stream msg1

  -- Message 2: <- e, ee, s, es (responder identity payload)
  msg2 <- readFramedMessage stream
  (p2, st2) <- either fail pure $ readHandshakeMsg st1 msg2
  np <- either (fail . show) pure $ decodeNoisePayload p2
  pk <- either fail pure $ decodePublicKey (npIdentityKey np)

  -- Message 3: -> s, se (identity payload, signature over sigTarget)
  payload <- either fail pure $
    encodeNoisePayload <$> buildHandshakePayload identityKP (sigTarget staticPub) Nothing
  (msg3, _stFinal) <- either fail pure $ writeHandshakeMsg st2 payload
  writeFramedMessage stream msg3
  pure (fromPublicKey pk, pk)

-- | The production handshake terminates with this error when the payload
-- signature does not bind the identity key to the session's static key.
isSignatureRejection :: IOException -> Bool
isSignatureRejection e = "identity signature verification failed" `isInfixOf` show e

-- | Static key bytes that no session actually uses: signing these
-- simulates a replayed payload (signed for a different Noise session)
-- or a forged one (attacker without the identity private key).
foreignStaticKey :: ByteString
foreignStaticKey = BS.replicate 32 0x5A

-- | An honest hand-rolled responder that completes the handshake and
-- returns its transport-mode Noise session, so the test can craft
-- arbitrary post-handshake transport messages on the foreign side.
runForeignResponderSession :: KeyPair -> StreamIO -> IO NoiseSession
runForeignResponderSession identityKP stream = do
  (st0, staticPub) <- initHandshakeResponder identityKP
  msg1 <- readFramedMessage stream
  (_p1, st1) <- either fail pure $ readHandshakeMsg st0 msg1
  payload <- either fail pure $
    encodeNoisePayload <$> buildHandshakePayload identityKP staticPub Nothing
  (msg2, st2) <- either fail pure $ writeHandshakeMsg st1 payload
  writeFramedMessage stream msg2
  msg3 <- readFramedMessage stream
  (_p3, stFinal) <- either fail pure $ readHandshakeMsg st2 msg3
  pure (mkNoiseSession (hsNoiseState stFinal))

spec :: Spec
spec = do
  describe "Production handshake against a hand-rolled foreign peer" $ do
    it "initiator extracts the foreign responder's identity from the payload" $ do
      (pidA, kpA) <- mkTestIdentity
      (pidB, kpB) <- mkTestIdentity
      (streamA, streamB) <- mkMemoryStreamPair
      ((_sess, result), (foreignSeenPid, foreignSeenKey)) <-
        concurrently
          (performStreamHandshake kpA Nothing Outbound streamA)
          (runForeignResponder kpB id streamB)
      -- Production side sees the foreign peer's identity ...
      hrRemotePeerId result `shouldBe` pidB
      hrRemotePublicKey result `shouldBe` kpPublic kpB
      -- ... and the foreign peer sees ours.
      foreignSeenPid `shouldBe` pidA
      foreignSeenKey `shouldBe` kpPublic kpA

    it "responder extracts the foreign initiator's identity from the payload" $ do
      (pidA, kpA) <- mkTestIdentity
      (pidB, kpB) <- mkTestIdentity
      (streamA, streamB) <- mkMemoryStreamPair
      ((_sess, result), (foreignSeenPid, foreignSeenKey)) <-
        concurrently
          (performStreamHandshake kpA Nothing Inbound streamA)
          (runForeignInitiator kpB id streamB)
      hrRemotePeerId result `shouldBe` pidB
      hrRemotePublicKey result `shouldBe` kpPublic kpB
      foreignSeenPid `shouldBe` pidA
      foreignSeenKey `shouldBe` kpPublic kpA

    it "initiator rejects a responder whose identity_sig covers the wrong static key" $ do
      (_pidA, kpA) <- mkTestIdentity
      (_pidB, kpB) <- mkTestIdentity
      (streamA, streamB) <- mkMemoryStreamPair
      -- The foreign responder advertises kpB's identity but its signature
      -- covers a static key from some other session — exactly what a MitM
      -- replaying an intercepted payload looks like on the wire. It blocks
      -- waiting for msg3 (which never comes) and is cancelled by withAsync.
      withAsync (runForeignResponder kpB (const foreignStaticKey) streamB) $ \_ ->
        performStreamHandshake kpA Nothing Outbound streamA
          `shouldThrow` isSignatureRejection

    it "responder rejects an initiator whose identity_sig covers the wrong static key" $ do
      (_pidA, kpA) <- mkTestIdentity
      (_pidB, kpB) <- mkTestIdentity
      (streamA, streamB) <- mkMemoryStreamPair
      withAsync (runForeignInitiator kpB (const foreignStaticKey) streamB) $ \_ ->
        performStreamHandshake kpA Nothing Inbound streamA
          `shouldThrow` isSignatureRejection

    it "empty transport messages between data frames do not kill the connection" $ do
      -- A Noise transport message with an empty plaintext (frame carrying
      -- only the 16-byte AEAD tag) is legal and used as a keepalive by
      -- some implementations; a zero-length frame carries no message at
      -- all. Both must yield zero application bytes, with reading
      -- continuing at the next frame.
      (_pidA, kpA) <- mkTestIdentity
      (_pidB, kpB) <- mkTestIdentity
      (streamA, streamB) <- mkMemoryStreamPair
      ((prodSess, _result), foreignSess) <-
        concurrently
          (performStreamHandshake kpA Nothing Outbound streamA)
          (runForeignResponderSession kpB streamB)
      -- Foreign peer sends: data, zero-length frame, tag-only frame, data.
      (ct1, fs1) <- either fail pure $ encryptMessage foreignSess "hello"
      (ctEmpty, fs2) <- either fail pure $ encryptMessage fs1 BS.empty
      (ct2, _fs3) <- either fail pure $ encryptMessage fs2 "world"
      BS.length ctEmpty `shouldBe` 16 -- AEAD tag only
      writeFramedMessage streamB ct1
      streamWrite streamB (BS.pack [0x00, 0x00]) -- zero-length frame
      writeFramedMessage streamB ctEmpty
      writeFramedMessage streamB ct2
      -- Production side reads through the Noise-encrypted StreamIO.
      sendRef <- newIORef prodSess
      recvRef <- newIORef prodSess
      bufRef <- newIORef BS.empty
      let encryptedIO = noiseSessionToStreamIO sendRef recvRef bufRef streamA
      got <- readExact encryptedIO 10
      got `shouldBe` "helloworld"

    it "initiator rejects a responder that advertises another peer's identity key" $ do
      -- Eve presents Bob's public key but cannot produce Bob's signature
      -- over her own session's static key: she signs with her own key.
      (_pidA, kpA) <- mkTestIdentity
      (_pidBob, kpBob) <- mkTestIdentity
      (_pidEve, kpEve) <- mkTestIdentity
      (streamA, streamB) <- mkMemoryStreamPair
      let impersonate staticPub = do
            honest <- buildHandshakePayload kpEve staticPub Nothing
            bobPayload <- buildHandshakePayload kpBob staticPub Nothing
            Right honest {npIdentityKey = npIdentityKey bobPayload}
          eveResponder stream = do
            (st0, staticPub) <- initHandshakeResponder kpEve
            msg1 <- readFramedMessage stream
            (_p1, st1) <- either fail pure $ readHandshakeMsg st0 msg1
            payload <- either fail pure $ encodeNoisePayload <$> impersonate staticPub
            (msg2, _st2) <- either fail pure $ writeHandshakeMsg st1 payload
            writeFramedMessage stream msg2
      withAsync (eveResponder streamB) $ \_ ->
        performStreamHandshake kpA Nothing Outbound streamA
          `shouldThrow` isSignatureRejection

  describe "Peer disconnect during the handshake (EOF harness)" $ do
    -- Deterministic, in-process counterparts of the real-TCP disconnect
    -- tests in FaultInjectionSpec (which assert whole-node survival
    -- over sockets): here the assertion is that each handshake phase
    -- fails cleanly — an IOException, not a hang and not a bogus
    -- success — when the peer vanishes. The EOF-capable pair makes the
    -- disconnect expressible in process; 'mkMemoryStreamPair' cannot
    -- model it (reads on an empty queue block forever).
    it "initiator fails cleanly when the peer disconnects before msg2" $ do
      (_pidA, kpA) <- mkTestIdentity
      (streamA, streamB) <- mkEofStreamPair
      -- The peer hangs up immediately: msg1 is written into the open
      -- direction, but the reply direction is already at EOF.
      streamClose streamB
      shouldFailCleanlyWithin 2000000 $
        performStreamHandshake kpA Nothing Outbound streamA

    it "initiator fails cleanly when the peer disconnects mid-frame of msg2" $ do
      (_pidA, kpA) <- mkTestIdentity
      (streamA, streamB) <- mkEofStreamPair
      -- A frame header declaring 96 bytes, 10 bytes of payload, then
      -- EOF: the disconnect lands inside 'readFramedMessage'.
      streamWrite streamB (BS.pack [0x00, 0x60] <> BS.replicate 10 0xAA)
      streamClose streamB
      shouldFailCleanlyWithin 2000000 $
        performStreamHandshake kpA Nothing Outbound streamA

    it "responder fails cleanly when the peer disconnects before msg1" $ do
      (_pidB, kpB) <- mkTestIdentity
      (streamA, streamB) <- mkEofStreamPair
      streamClose streamA
      shouldFailCleanlyWithin 2000000 $
        performStreamHandshake kpB Nothing Inbound streamB

    it "responder fails cleanly when the peer disconnects after msg1, before msg3" $ do
      -- A well-formed foreign initiator sends a real msg1 and then
      -- hangs up: the responder consumes msg1, sends msg2 into the
      -- still-open direction, and must fail cleanly awaiting msg3.
      (_pidA, kpA) <- mkTestIdentity
      (_pidB, kpB) <- mkTestIdentity
      (streamA, streamB) <- mkEofStreamPair
      (st0, _staticPub) <- initHandshakeInitiator kpA
      (msg1, _st1) <- either fail pure $ writeHandshakeMsg st0 BS.empty
      writeFramedMessage streamA msg1
      streamClose streamA
      shouldFailCleanlyWithin 2000000 $
        performStreamHandshake kpB Nothing Inbound streamB

    it "established connection: EOF mid-encrypted-frame is a clean error, not a partial read" $ do
      (_pidA, kpA) <- mkTestIdentity
      (_pidB, kpB) <- mkTestIdentity
      (streamA, streamB) <- mkEofStreamPair
      ((prodSess, _result), foreignSess) <-
        concurrently
          (performStreamHandshake kpA Nothing Outbound streamA)
          (runForeignResponderSession kpB streamB)
      -- Foreign peer sends one complete frame, then a frame whose
      -- header declares the full ciphertext length but whose body is
      -- cut off by the disconnect.
      (ct1, fs1) <- either fail pure $ encryptMessage foreignSess "hello"
      (ct2, _fs2) <- either fail pure $ encryptMessage fs1 "world!"
      writeFramedMessage streamB ct1
      streamWrite streamB
        (BS.pack [0x00, fromIntegral (BS.length ct2)] <> BS.take 5 ct2)
      streamClose streamB
      sendRef <- newIORef prodSess
      recvRef <- newIORef prodSess
      bufRef <- newIORef BS.empty
      let encryptedIO = noiseSessionToStreamIO sendRef recvRef bufRef streamA
      -- The complete frame decrypts normally ...
      got <- readExact encryptedIO 5
      got `shouldBe` "hello"
      -- ... and the truncated one surfaces as a clean error: no hang,
      -- and no partially-read or corrupted plaintext handed to the app.
      shouldFailCleanlyWithin 2000000 $ readExact encryptedIO 6
