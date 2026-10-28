module LibP2P.Noise.HandshakeSpec (spec) where

import qualified Data.ByteString as BS
import LibP2P.Crypto.Ed25519 (generateKeyPair)
import LibP2P.Crypto.Key
import LibP2P.Crypto.PeerId (PeerId, fromPublicKey)
import LibP2P.Core.Varint (encodeUvarint)
import LibP2P.Crypto.Protobuf (encodePublicKey)
import LibP2P.Noise.Framing
import LibP2P.Noise.Handshake
import LibP2P.Noise.Session
import Test.Hspec

spec :: Spec
spec = do
  describe "Framing" $ do
    it "encodes with 2-byte BE length prefix" $ do
      let msg = BS.pack [0x01, 0x02, 0x03]
      encodeFrame msg `shouldBe` Right (BS.pack [0x00, 0x03, 0x01, 0x02, 0x03])

    it "accepts a message of exactly maxNoiseMessageSize bytes" $ do
      let msg = BS.replicate maxNoiseMessageSize 0x42
      case encodeFrame msg of
        Right framed -> do
          BS.length framed `shouldBe` maxNoiseMessageSize + 2
          BS.take 2 framed `shouldBe` BS.pack [0xFF, 0xFF]
        Left err -> expectationFailure err

    it "rejects a message larger than maxNoiseMessageSize bytes" $ do
      let msg = BS.replicate (maxNoiseMessageSize + 1) 0x42
      encodeFrame msg `shouldSatisfy` isLeft

    it "decodes framed message" $ do
      let framed = BS.pack [0x00, 0x03, 0x01, 0x02, 0x03]
      decodeFrame framed `shouldBe` Right (BS.pack [0x01, 0x02, 0x03], BS.empty)

    it "decodes with remaining bytes" $ do
      let framed = BS.pack [0x00, 0x02, 0xAA, 0xBB, 0xCC]
      decodeFrame framed `shouldBe` Right (BS.pack [0xAA, 0xBB], BS.pack [0xCC])

    it "fails on short input" $
      decodeFrame (BS.pack [0x00]) `shouldSatisfy` isLeft

    it "fails when not enough payload bytes" $ do
      let framed = BS.pack [0x00, 0x05, 0x01, 0x02]
      decodeFrame framed `shouldSatisfy` isLeft

    it "round-trip" $ do
      let msg = BS.replicate 100 0x42
      case encodeFrame msg >>= decodeFrame of
        Right (decoded, remaining) -> do
          decoded `shouldBe` msg
          remaining `shouldBe` BS.empty
        Left err -> expectationFailure err

    it "boundary table: every size up to 65535 round-trips, everything above is rejected" $ do
      let accepted = [0, 1, 65534, maxNoiseMessageSize]
          rejected = [maxNoiseMessageSize + 1, 70000]
      mapM_
        (\n -> case encodeFrame (BS.replicate n 0x42) >>= decodeFrame of
            Right (decoded, remaining) -> do
              BS.length decoded `shouldBe` n
              remaining `shouldBe` BS.empty
            Left err -> expectationFailure $ "size " <> show n <> ": " <> err)
        accepted
      mapM_
        (\n -> encodeFrame (BS.replicate n 0x42) `shouldSatisfy` isLeft)
        rejected

  describe "chunkPlaintext" $ do
    it "keeps a small plaintext as a single chunk" $
      chunkPlaintext (BS.replicate 100 0x01) `shouldBe` [BS.replicate 100 0x01]

    it "keeps a plaintext of exactly maxNoisePlaintextSize as a single chunk" $ do
      let msg = BS.replicate maxNoisePlaintextSize 0x01
      chunkPlaintext msg `shouldBe` [msg]

    it "splits a plaintext one byte over the limit into two chunks" $ do
      let msg = BS.replicate (maxNoisePlaintextSize + 1) 0x01
      map BS.length (chunkPlaintext msg) `shouldBe` [maxNoisePlaintextSize, 1]

    it "splits a 70000-byte plaintext into spec-sized chunks that reassemble" $ do
      let msg = BS.pack (take 70000 (cycle [0 .. 255]))
          chunks = chunkPlaintext msg
      map BS.length chunks `shouldBe` [maxNoisePlaintextSize, 70000 - maxNoisePlaintextSize]
      BS.concat chunks `shouldBe` msg

    it "yields a single empty chunk for empty input" $
      chunkPlaintext BS.empty `shouldBe` [BS.empty]

    it "every chunk plus the 16-byte AEAD tag fits in a Noise message" $ do
      let msg = BS.replicate 200000 0x01
      chunkPlaintext msg `shouldSatisfy` all (\c -> BS.length c + 16 <= maxNoiseMessageSize)

  describe "Static key signing" $ do
    it "signStaticKey produces verifiable signature" $ do
      Right kp <- generateKeyPair
      let noiseStaticPK = BS.replicate 32 0xAA -- simulated X25519 pubkey
      case signStaticKey (kpPrivate kp) noiseStaticPK of
        Right sig -> verifyStaticKey (kpPublic kp) noiseStaticPK sig `shouldBe` True
        Left err -> expectationFailure err

    it "verification fails with wrong static key" $ do
      Right kp <- generateKeyPair
      let noiseStaticPK = BS.replicate 32 0xAA
      case signStaticKey (kpPrivate kp) noiseStaticPK of
        Right sig -> do
          let wrongPK = BS.replicate 32 0xBB
          verifyStaticKey (kpPublic kp) wrongPK sig `shouldBe` False
        Left err -> expectationFailure err

    it "verification fails with wrong identity key" $ do
      Right kp1 <- generateKeyPair
      Right kp2 <- generateKeyPair
      let noiseStaticPK = BS.replicate 32 0xAA
      case signStaticKey (kpPrivate kp1) noiseStaticPK of
        Right sig -> verifyStaticKey (kpPublic kp2) noiseStaticPK sig `shouldBe` False
        Left err -> expectationFailure err

    it "identity_sig covers the literal domain-separation prefix bytes" $ do
      -- The prefix is built here from a string literal on purpose: this
      -- pins the constant in Handshake.hs to the bytes the Noise spec
      -- mandates, independently of the constant itself. A typo in the
      -- prefix would keep every self-paired test green while silently
      -- breaking interop with go-libp2p/rust-libp2p.
      Right kp <- generateKeyPair
      let noiseStaticPK = BS.replicate 32 0xAA
          literalMsg = "noise-libp2p-static-key:" <> noiseStaticPK
      case signStaticKey (kpPrivate kp) noiseStaticPK of
        Right sig -> verify (kpPublic kp) literalMsg sig `shouldBe` True
        Left err -> expectationFailure err
      case sign (kpPrivate kp) literalMsg of
        Right sig -> verifyStaticKey (kpPublic kp) noiseStaticPK sig `shouldBe` True
        Left err -> expectationFailure err

  describe "NoisePayload protobuf" $ do
    it "encodes and decodes identity_key and identity_sig" $ do
      Right kp <- generateKeyPair
      let identKey = encodePublicKey (kpPublic kp)
      let noiseStaticPK = BS.replicate 32 0xCC
      case signStaticKey (kpPrivate kp) noiseStaticPK of
        Right identSig -> do
          let payload = NoisePayload identKey identSig
          let encoded = encodeNoisePayload payload
          decodeNoisePayload encoded `shouldBe` Right payload
        Left err -> expectationFailure err

    it "round-trip with various sizes" $ do
      let key = BS.replicate 36 0x11
      let sig = BS.replicate 64 0x22
      let payload = NoisePayload key sig
      decodeNoisePayload (encodeNoisePayload payload) `shouldBe` Right payload

    it "decodes fields in reversed order (identity_sig before identity_key)" $ do
      -- Protobuf does not constrain field order on the wire: a payload
      -- serialized with field 2 before field 1 must decode identically.
      let key = BS.replicate 36 0x11
          sig = BS.replicate 64 0x22
          reversed =
            BS.singleton 0x12 <> encodeUvarint (fromIntegral (BS.length sig)) <> sig
              <> BS.singleton 0x0a <> encodeUvarint (fromIntegral (BS.length key)) <> key
      decodeNoisePayload reversed `shouldBe` Right (NoisePayload key sig)

    it "skips an unknown trailing length-delimited field (extensions, field 4)" $ do
      -- go-libp2p appends a NoiseExtensions message as field 4.
      let key = BS.replicate 36 0x11
          sig = BS.replicate 64 0x22
          ext = BS.pack [0xDE, 0xAD, 0xBE, 0xEF]
          encoded =
            encodeNoisePayload (NoisePayload key sig)
              <> BS.singleton 0x22 <> encodeUvarint (fromIntegral (BS.length ext)) <> ext
      decodeNoisePayload encoded `shouldBe` Right (NoisePayload key sig)

    it "round-trips WebTransport certhashes in Noise extensions" $ do
      let payload = NoisePayload (BS.replicate 36 0x11) (BS.replicate 64 0x22)
          hashes =
            [ BS.pack ([0x12, 0x20] <> replicate 32 0xAA)
            , BS.pack ([0x12, 0x20] <> replicate 32 0xBB)
            ]
          encoded = encodeNoisePayloadWithCerthashes payload hashes
      decodeNoisePayload encoded `shouldBe` Right payload
      decodeNoiseCerthashes encoded `shouldBe` Right hashes

    it "returns no certhashes when extensions are absent" $ do
      let payload = NoisePayload (BS.replicate 36 0x11) (BS.replicate 64 0x22)
      decodeNoiseCerthashes (encodeNoisePayload payload) `shouldBe` Right []

    it "ignores other Noise extension fields" $ do
      let payload = NoisePayload (BS.replicate 36 0x11) (BS.replicate 64 0x22)
          streamMuxer = BS.singleton 0x12 <> encodeUvarint 12 <> "/yamux/1.0.0"
          extension = BS.singleton 0x22 <> encodeUvarint (fromIntegral (BS.length streamMuxer)) <> streamMuxer
      decodeNoiseCerthashes (encodeNoisePayload payload <> extension) `shouldBe` Right []

    it "skips an unknown high-numbered varint field between known fields" $ do
      -- Field 2047, wire type 0: tag = 2047 << 3 = 16376 (multi-byte tag).
      let key = BS.replicate 36 0x11
          sig = BS.replicate 64 0x22
          field1 = BS.singleton 0x0a <> encodeUvarint (fromIntegral (BS.length key)) <> key
          field2 = BS.singleton 0x12 <> encodeUvarint (fromIntegral (BS.length sig)) <> sig
          unknown = encodeUvarint 16376 <> encodeUvarint 300
      decodeNoisePayload (field1 <> unknown <> field2)
        `shouldBe` Right (NoisePayload key sig)

    it "skips unknown fixed32 and fixed64 fields" $ do
      let key = BS.replicate 36 0x11
          sig = BS.replicate 64 0x22
          field1 = BS.singleton 0x0a <> encodeUvarint (fromIntegral (BS.length key)) <> key
          field2 = BS.singleton 0x12 <> encodeUvarint (fromIntegral (BS.length sig)) <> sig
          -- Field 5, wire type 5 (fixed32): tag = 5 << 3 | 5 = 0x2D.
          fixed32 = BS.singleton 0x2D <> BS.replicate 4 0xAB
          -- Field 6, wire type 1 (fixed64): tag = 6 << 3 | 1 = 0x31.
          fixed64 = BS.singleton 0x31 <> BS.replicate 8 0xCD
      decodeNoisePayload (fixed32 <> field1 <> fixed64 <> field2)
        `shouldBe` Right (NoisePayload key sig)

    it "fails when identity_key (field 1) is missing" $ do
      let sig = BS.replicate 64 0x22
          onlySig = BS.singleton 0x12 <> encodeUvarint (fromIntegral (BS.length sig)) <> sig
      decodeNoisePayload onlySig `shouldSatisfy` isLeft

    it "fails when identity_sig (field 2) is missing" $ do
      let key = BS.replicate 36 0x11
          onlyKey = BS.singleton 0x0a <> encodeUvarint (fromIntegral (BS.length key)) <> key
      decodeNoisePayload onlyKey `shouldSatisfy` isLeft

    it "fails on a truncated length-delimited field" $ do
      let truncated = BS.singleton 0x0a <> encodeUvarint 36 <> BS.replicate 10 0x11
      decodeNoisePayload truncated `shouldSatisfy` isLeft

    it "fails on empty input" $
      decodeNoisePayload BS.empty `shouldSatisfy` isLeft

    it "fails on a truncated tag (a lone field-1 tag byte)" $
      -- A tag byte with nothing after it: neither a length nor a payload.
      decodeNoisePayload (BS.singleton 0x0a) `shouldSatisfy` isLeft

    it "buildHandshakePayload returns Left when the private key is malformed" $ do
      -- A malformed identity key must surface as Left from pure code,
      -- not abort the process (issue #166, item 3).
      Right kp <- generateKeyPair
      let badKP = kp {kpPrivate = PrivateKey Ed25519 (BS.replicate 10 0x00)}
      case buildHandshakePayload badKP (BS.replicate 32 0xAA) of
        Left err -> err `shouldContain` "buildHandshakePayload"
        Right _ -> expectationFailure "expected Left for a malformed private key"

  describe "Noise XX handshake" $ do
    it "completes 3-message handshake between initiator and responder" $ do
      -- Generate identity key pairs for both peers
      Right aliceIdentity <- generateKeyPair
      Right bobIdentity <- generateKeyPair

      -- Create handshake states
      (aliceInit, aliceNoiseStaticPub) <- initHandshakeInitiator aliceIdentity
      (bobInit, bobNoiseStaticPub) <- initHandshakeResponder bobIdentity

      -- Message 1: Alice -> Bob (ephemeral key, empty payload)
      (msg1, aliceState1) <- either fail pure $ writeHandshakeMsg aliceInit BS.empty
      (payload1, bobState1) <- either fail pure $ readHandshakeMsg bobInit msg1

      -- Message 1 has no encrypted payload
      payload1 `shouldBe` BS.empty

      -- Message 2: Bob -> Alice (ephemeral + static key, identity payload)
      bobPayload <- either fail pure $
        encodeNoisePayload <$> buildHandshakePayload bobIdentity bobNoiseStaticPub
      (msg2, bobState2) <- either fail pure $ writeHandshakeMsg bobState1 bobPayload
      (payload2, aliceState2) <- either fail pure $ readHandshakeMsg aliceState1 msg2

      -- Alice can decode Bob's identity from payload2
      case decodeNoisePayload payload2 of
        Left err -> expectationFailure $ "Failed to decode Bob's payload: " <> err
        Right np -> do
          let remotePubKey = decodePublicKey (npIdentityKey np)
          remotePubKey `shouldSatisfy` isRight

      -- Message 3: Alice -> Bob (static key, identity payload)
      alicePayload <- either fail pure $
        encodeNoisePayload <$> buildHandshakePayload aliceIdentity aliceNoiseStaticPub
      (msg3, aliceSession) <- either fail pure $ writeHandshakeMsg aliceState2 alicePayload
      (payload3, bobSession) <- either fail pure $ readHandshakeMsg bobState2 msg3

      -- Bob can decode Alice's identity from payload3
      case decodeNoisePayload payload3 of
        Left err -> expectationFailure $ "Failed to decode Alice's payload: " <> err
        Right np -> do
          let remotePubKey = decodePublicKey (npIdentityKey np)
          remotePubKey `shouldSatisfy` isRight

      -- Both sides should indicate handshake is complete
      sessionComplete aliceSession `shouldBe` True
      sessionComplete bobSession `shouldBe` True

    it "derives correct remote Peer IDs" $ do
      Right aliceIdentity <- generateKeyPair
      Right bobIdentity <- generateKeyPair

      let alicePeerId = fromPublicKey (kpPublic aliceIdentity)
      let bobPeerId = fromPublicKey (kpPublic bobIdentity)

      result <- performFullHandshake aliceIdentity bobIdentity
      case result of
        Left err -> expectationFailure err
        Right (aliceRemotePeerId, bobRemotePeerId) -> do
          -- Alice sees Bob's PeerId
          aliceRemotePeerId `shouldBe` bobPeerId
          -- Bob sees Alice's PeerId
          bobRemotePeerId `shouldBe` alicePeerId

    it "replayed identity payload is detected by verifyStaticKey (MitM scenario)" $ do
      -- Scenario: Eve intercepts and runs her own Noise session with Alice,
      -- but sends Bob's identity payload (key + signature). The signature was
      -- over Bob's Noise static key, not Eve's, so verification fails.
      Right aliceIdentity <- generateKeyPair
      Right bobIdentity <- generateKeyPair

      (aliceInit, _aliceNoiseStaticPub) <- initHandshakeInitiator aliceIdentity
      -- Eve runs her own Noise session (different Noise keys than Bob)
      (eveInit, _eveNoiseStaticPub) <- initHandshakeResponder bobIdentity

      -- Bob's payload signed over a DIFFERENT Noise static key (not the one in this session)
      -- Simulate: Bob pre-signed his identity for a different Noise session
      let bobOtherNoiseKey = BS.replicate 32 0xBB  -- arbitrary, not the actual session key
      replayedPayload <- either fail pure $
        encodeNoisePayload <$> buildHandshakePayload bobIdentity bobOtherNoiseKey

      -- Message 1 (normal)
      (msg1, aliceState1) <- either fail pure $ writeHandshakeMsg aliceInit BS.empty
      (_payload1, eveState1) <- either fail pure $ readHandshakeMsg eveInit msg1

      -- Message 2: Eve sends Bob's identity payload (replay attack)
      (msg2, _eveState2) <- either fail pure $ writeHandshakeMsg eveState1 replayedPayload
      (payload2, aliceState2) <- either fail pure $ readHandshakeMsg aliceState1 msg2

      -- Alice decodes payload (valid protobuf, Bob's key)
      let Right remoteNP = decodeNoisePayload payload2
      let Right remotePubKey = decodePublicKey (npIdentityKey remoteNP)

      -- Alice extracts the ACTUAL Noise static key from the handshake state
      case getRemoteNoiseStaticKey aliceState2 of
        Nothing -> expectationFailure "expected remote Noise static key"
        Just remoteNoisePub -> do
          -- Verification MUST fail: Bob's signature was over bobOtherNoiseKey,
          -- but the actual Noise static key is Eve's
          verifyStaticKey remotePubKey remoteNoisePub (npIdentitySig remoteNP)
            `shouldBe` False

    it "valid identity signature passes verifyStaticKey" $ do
      Right aliceIdentity <- generateKeyPair
      Right bobIdentity <- generateKeyPair

      (aliceInit, _aliceNoiseStaticPub) <- initHandshakeInitiator aliceIdentity
      (bobInit, bobNoiseStaticPub) <- initHandshakeResponder bobIdentity

      -- Normal 3-message handshake
      (msg1, aliceState1) <- either fail pure $ writeHandshakeMsg aliceInit BS.empty
      (_payload1, bobState1) <- either fail pure $ readHandshakeMsg bobInit msg1

      bobPayload <- either fail pure $
        encodeNoisePayload <$> buildHandshakePayload bobIdentity bobNoiseStaticPub
      (msg2, _bobState2) <- either fail pure $ writeHandshakeMsg bobState1 bobPayload
      (payload2, aliceState2) <- either fail pure $ readHandshakeMsg aliceState1 msg2

      -- Alice decodes Bob's legitimate payload
      let Right remoteNP = decodeNoisePayload payload2
      let Right remotePubKey = decodePublicKey (npIdentityKey remoteNP)

      -- Verification MUST pass: Bob signed his own Noise static key
      case getRemoteNoiseStaticKey aliceState2 of
        Nothing -> expectationFailure "expected remote Noise static key"
        Just remoteNoisePub ->
          verifyStaticKey remotePubKey remoteNoisePub (npIdentitySig remoteNP)
            `shouldBe` True

    -- NOTE: performFullHandshake builds both payloads internally, so a
    -- replayed payload cannot be injected through it. The production-path
    -- rejection of a replayed/forged identity payload is covered in
    -- LibP2P.Noise.ForeignPeerSpec, which drives one endpoint by hand
    -- against performStreamHandshake.

    it "post-handshake encrypted transport works" $ do
      Right aliceIdentity <- generateKeyPair
      Right bobIdentity <- generateKeyPair

      result <- performFullHandshakeWithSessions aliceIdentity bobIdentity
      case result of
        Left err -> expectationFailure err
        Right (aliceSession, bobSession) -> do
          -- Alice encrypts a message for Bob
          let plaintext = "Hello Bob from Alice!"
          (ciphertext, aliceSession') <- either fail pure $ encryptMessage aliceSession plaintext
          (decrypted, bobSession') <- either fail pure $ decryptMessage bobSession ciphertext
          decrypted `shouldBe` plaintext

          -- Bob encrypts a message for Alice
          let reply = "Hello Alice from Bob!"
          (ciphertext2, _bobSession'') <- either fail pure $ encryptMessage bobSession' reply
          (decrypted2, _aliceSession'') <- either fail pure $ decryptMessage aliceSession' ciphertext2
          decrypted2 `shouldBe` reply

    it "a 65519-byte plaintext fills exactly one maximum-size Noise message" $ do
      Right aliceIdentity <- generateKeyPair
      Right bobIdentity <- generateKeyPair

      result <- performFullHandshakeWithSessions aliceIdentity bobIdentity
      case result of
        Left err -> expectationFailure err
        Right (aliceSession, _bobSession) -> do
          -- 65519 bytes of plaintext + 16-byte AEAD tag = 65535-byte
          -- ciphertext, the largest Noise message the 2-byte length
          -- prefix can declare. This is the true chunking boundary.
          let atLimit = BS.replicate maxNoisePlaintextSize 0x01
          (ct, aliceSession') <- either fail pure $ encryptMessage aliceSession atLimit
          BS.length ct `shouldBe` maxNoiseMessageSize
          case encodeFrame ct of
            Right framed -> BS.take 2 framed `shouldBe` BS.pack [0xFF, 0xFF]
            Left err -> expectationFailure err
          -- One byte more can never reach the wire as a single frame:
          -- either the cipher refuses the oversized message, or the
          -- 65536-byte ciphertext is rejected by encodeFrame. Callers
          -- must chunk first (see chunkPlaintext / encryptAndWrite).
          let overLimit = BS.replicate (maxNoisePlaintextSize + 1) 0x01
          case encryptMessage aliceSession' overLimit of
            Left _ -> pure ()
            Right (ct2, _) -> do
              BS.length ct2 `shouldBe` maxNoiseMessageSize + 1
              encodeFrame ct2 `shouldSatisfy` isLeft

    it "post-handshake messages are order-dependent (nonce)" $ do
      Right aliceIdentity <- generateKeyPair
      Right bobIdentity <- generateKeyPair

      result <- performFullHandshakeWithSessions aliceIdentity bobIdentity
      case result of
        Left err -> expectationFailure err
        Right (aliceSession, bobSession) -> do
          -- Alice sends two messages
          (ct1, aliceSession') <- either fail pure $ encryptMessage aliceSession "msg1"
          (ct2, _aliceSession'') <- either fail pure $ encryptMessage aliceSession' "msg2"

          -- Bob must decrypt in order
          (_pt1, bobSession') <- either fail pure $ decryptMessage bobSession ct1
          (pt2, _bobSession'') <- either fail pure $ decryptMessage bobSession' ct2
          pt2 `shouldBe` "msg2"

          -- Decrypting out of order should fail
          case decryptMessage bobSession ct2 of
            Left _ -> pure ()
            Right _ -> expectationFailure "expected decryption to fail out of order"

isLeft :: Either a b -> Bool
isLeft (Left _) = True
isLeft _ = False

isRight :: Either a b -> Bool
isRight (Right _) = True
isRight _ = False
