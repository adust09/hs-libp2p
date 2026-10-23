module LibP2P.Protocol.GossipSub.TypesSpec (spec) where

import Test.Hspec

import qualified Data.ByteString as BS
import LibP2P.Protocol.GossipSub.Types

spec :: Spec
spec = do
  describe "GossipSub.Types" $ do
    describe "defaultGossipSubParams" $ do
      it "has D=6, D_lo=4, D_hi=12" $ do
        paramD defaultGossipSubParams `shouldBe` 6
        paramDlo defaultGossipSubParams `shouldBe` 4
        paramDhi defaultGossipSubParams `shouldBe` 12

      it "has D_lazy=6, D_score=4, D_out=2" $ do
        paramDlazy defaultGossipSubParams `shouldBe` 6
        paramDscore defaultGossipSubParams `shouldBe` 4
        paramDout defaultGossipSubParams `shouldBe` 2

      it "has heartbeat=1s, fanoutTTL=60s, seenTTL=120s" $ do
        paramHeartbeatInterval defaultGossipSubParams `shouldBe` 1
        paramFanoutTTL defaultGossipSubParams `shouldBe` 60
        paramSeenTTL defaultGossipSubParams `shouldBe` 120

      it "has pruneBackoff=60s, unsubBackoff=10s" $ do
        paramPruneBackoff defaultGossipSubParams `shouldBe` 60
        paramUnsubBackoff defaultGossipSubParams `shouldBe` 10

      it "has gossipFactor=0.25, floodPublish=True, StrictSign" $ do
        paramGossipFactor defaultGossipSubParams `shouldBe` 0.25
        paramFloodPublish defaultGossipSubParams `shouldBe` True
        paramSignaturePolicy defaultGossipSubParams `shouldBe` StrictSign

      it "has mcacheLen=5, mcacheGossip=3" $ do
        paramMcacheLen defaultGossipSubParams `shouldBe` 5
        paramMcacheGossip defaultGossipSubParams `shouldBe` 3

      it "checks direct-peer connectivity every 300s" $ do
        paramDirectConnectInterval defaultGossipSubParams `shouldBe` 300

      it "has opportunistic graft ticks=60 and peers=2" $ do
        paramOpportunisticGraftTicks defaultGossipSubParams `shouldBe` 60
        paramOpportunisticGraftPeers defaultGossipSubParams `shouldBe` 2

      it "uses go-libp2p-compatible IDONTWANT limits" $ do
        paramMaxIDontWantLength defaultGossipSubParams `shouldBe` 10
        paramMaxIDontWantMessages defaultGossipSubParams `shouldBe` 1000
        paramIDontWantMessageThreshold defaultGossipSubParams `shouldBe` 1024
        paramIDontWantMessageTTL defaultGossipSubParams `shouldBe` 3

    describe "protocol identifiers" $ do
      it "prefers GossipSub v1.2 while retaining v1.1 and v1.0" $ do
        gossipSubProtocolId `shouldBe` "/meshsub/1.2.0"
        gossipSubProtocolIdV11 `shouldBe` "/meshsub/1.1.0"
        gossipSubProtocolIdV10 `shouldBe` "/meshsub/1.0.0"

    describe "defaultMessageId" $ do
      it "concatenates from and seqno" $ do
        let msg = PubSubMessage
              { msgFrom      = Just (BS.pack [1, 2, 3])
              , msgData      = BS.empty
              , msgSeqNo     = Just (BS.pack [0, 0, 0, 0, 0, 0, 0, 42])
              , msgTopic     = "test"
              , msgSignature = Nothing
              , msgKey       = Nothing
              }
        defaultMessageId msg `shouldBe` BS.pack [1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 42]

      -- Anonymous (StrictNoSign) messages carry neither from nor seqno; a
      -- shared empty id would collapse seen-cache dedup, the mcache and
      -- IHAVE/IWANT tracking (#217), so the id must be content-addressed.
      it "falls back to SHA-256 of topic and data when from and seqno are absent" $ do
        let msg = PubSubMessage
              { msgFrom      = Nothing
              , msgData      = BS.pack [1, 2, 3]
              , msgSeqNo     = Nothing
              , msgTopic     = "test"
              , msgSignature = Nothing
              , msgKey       = Nothing
              }
        -- sha256(0x74657374 <> 0x010203), digest computed independently
        defaultMessageId msg `shouldBe` BS.pack
          [ 0xce, 0xd4, 0x9a, 0x0a, 0x8c, 0x5c, 0x38, 0xa2
          , 0x38, 0xb6, 0x0b, 0xf3, 0x35, 0x87, 0xcf, 0x58
          , 0x73, 0x8f, 0x16, 0xdc, 0x6c, 0x4f, 0xf9, 0xbd
          , 0x2b, 0x75, 0x95, 0x51, 0xe9, 0xfa, 0xe3, 0x47 ]

      it "derives distinct ids for distinct anonymous messages" $ do
        let anon topic payload = PubSubMessage
              { msgFrom      = Nothing
              , msgData      = payload
              , msgSeqNo     = Nothing
              , msgTopic     = topic
              , msgSignature = Nothing
              , msgKey       = Nothing
              }
        defaultMessageId (anon "t" (BS.pack [1]))
          `shouldNotBe` defaultMessageId (anon "t" (BS.pack [2]))
        defaultMessageId (anon "t1" (BS.pack [1]))
          `shouldNotBe` defaultMessageId (anon "t2" (BS.pack [1]))
        defaultMessageId (anon "t" (BS.pack [1]))
          `shouldBe` defaultMessageId (anon "t" (BS.pack [1]))

    describe "emptyRPC" $ do
      it "has no subscriptions, messages, or control" $ do
        rpcSubscriptions emptyRPC `shouldBe` []
        rpcPublish emptyRPC `shouldBe` []
        rpcControl emptyRPC `shouldBe` Nothing

    describe "emptyControlMessage" $ do
      it "has empty IHAVE/IWANT/GRAFT/PRUNE/IDONTWANT lists" $ do
        ctrlIHave emptyControlMessage `shouldBe` []
        ctrlIWant emptyControlMessage `shouldBe` []
        ctrlGraft emptyControlMessage `shouldBe` []
        ctrlPrune emptyControlMessage `shouldBe` []
        ctrlIDontWant emptyControlMessage `shouldBe` []
