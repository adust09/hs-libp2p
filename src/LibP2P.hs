-- | hs-libp2p: Haskell implementation of the libp2p networking stack.
--
-- This is the public API facade for the library. Import this module
-- for the common types and functions needed to build a libp2p node:
--
-- @
-- import LibP2P
--
-- main :: IO ()
-- main = do
--   (pid, kp) <- generateAndPeerId
--   sw <- newSwitch pid kp
--   tcp <- newTCPTransport
--   addTransport sw tcp
--   registerIdentifyHandlers sw
--   registerPingHandler sw
--   (_relayState, _circuitState) <- registerNATHandlers sw defaultNATConfig
--   addrs <- switchListen sw defaultConnectionGater [fromText "/ip4/127.0.0.1/tcp/0"]
--   print addrs
--   -- ... dial other peers, etc.
--   switchClose sw
-- @
module LibP2P
  ( -- * Identity
    PeerId
  , KeyPair
  , generateKeyPair
  , fromPublicKey
  , peerIdBytes
  , toBase58
  , parsePeerId
  , toCIDv1

    -- * Addressing
  , Multiaddr (..)
  , Protocol (..)
  , splitP2P
  , toText
  , fromText

    -- * Switch (central coordinator)
  , Switch
  , Direction (..)
  , newSwitch
  , subscribeSwitchEvents
  , SwitchEvent (..)
  , addTransport
  , switchListen
  , switchListenAddrs
  , switchClose
  , dial
  , closeConnection
  , newStream
  , DialError (..)
  , ResourceError (..)
  , setStreamHandler
  , removeStreamHandler
  , StreamIO (..)
  , StreamHandler
  , ProtocolId
  , Connection (..)

    -- * Transport
  , Transport (..)
  , newTCPTransport
  , newQUICTransport

    -- * Connection gating
  , ConnectionGater (..)
  , defaultConnectionGater
  , setConnectionGater

    -- * Identify protocol
  , registerIdentifyHandlers
  , requestIdentify
  , identifyPeer
  , pushIdentify

    -- * Ping protocol
  , registerPingHandler
  , sendPing
  , PingSession
  , openPingSession
  , ping
  , pingWithTimeout
  , closePingSession
  , withPingSession
  , PingResult (..)
  , PingError (..)

    -- * Perf protocol
  , registerPerfHandler
  , runPerf
  , perfProtocolId
  , PerfResult (..)
  , PerfError (..)

    -- * Kademlia DHT
  , DHTNode
  , DHTMode (..)
  , Validator (..)
  , defaultValidator
  , DHTRecord
  , recValue
  , ProviderEntry
  , peProvider
  , peAddrs
  , BucketEntry
  , entryPeerId
  , entryAddrs
  , newDHTNode
  , stopDHTNode
  , registerDHTHandler
  , bootstrap
  , startBootstrap
  , provide
  , putValue
  , getValue
  , findProviders
  , findPeer

    -- * NAT traversal (AutoNAT, Circuit Relay v2, DCUtR)
  , NATConfig (..)
  , defaultNATConfig
  , registerNATHandlers
  , registerAutoNATHandler
  , registerRelayHopHandler
  , registerRelayStopHandler
  , registerDCUtRHandler
  , RelayState
  , RelayConfig (..)
  , defaultRelayConfig
  , newRelayState
  , CircuitState
  , circuitTransport
  , newCircuitState
  , ReservationRefreshConfig (..)
  , defaultReservationRefreshConfig

    -- * GossipSub
  , GossipSubNode (..)
  , GossipSubParams (..)
  , defaultGossipSubParams
  , newGossipSubNode
  , startGossipSub
  , stopGossipSub
  , gossipJoin
  , gossipLeave
  , gossipPublish
  ) where

import LibP2P.Crypto.Ed25519 (generateKeyPair)
import LibP2P.Crypto.Key (KeyPair)
import LibP2P.Crypto.PeerId (PeerId, fromPublicKey, peerIdBytes, toBase58, parsePeerId, toCIDv1)
import LibP2P.DHT
  ( DHTMode (..)
  , DHTNode
  , ProviderEntry
  , Validator (..)
  , defaultValidator
  , newDHTNode
  , peAddrs
  , peProvider
  , registerDHTHandler
  , stopDHTNode
  )
import LibP2P.DHT.API (findPeer, findProviders, getValue, provide, putValue)
import LibP2P.DHT.Lookup
  ( bootstrap
  , startBootstrap
  )
import LibP2P.DHT.Message (DHTRecord, recValue)
import LibP2P.DHT.Types
  ( BucketEntry
  , entryAddrs
  , entryPeerId
  )
import LibP2P.Multiaddr (Multiaddr (..), fromText, splitP2P, toText)
import LibP2P.Multiaddr.Protocol (Protocol (..))
import LibP2P.MultistreamSelect.Negotiation (ProtocolId, StreamIO (..))
import LibP2P.NAT
  ( NATConfig (..)
  , defaultNATConfig
  , registerAutoNATHandler
  , registerDCUtRHandler
  , registerNATHandlers
  , registerRelayHopHandler
  , registerRelayStopHandler
  )
import LibP2P.NAT.Relay (RelayConfig (..), RelayState, defaultRelayConfig, newRelayState)
import LibP2P.NAT.Relay.Transport
  ( CircuitState
  , ReservationRefreshConfig (..)
  , circuitTransport
  , defaultReservationRefreshConfig
  , newCircuitState
  )
import LibP2P.Protocol.GossipSub.Handler
  ( GossipSubNode (..)
  , gossipJoin
  , gossipLeave
  , gossipPublish
  , newGossipSubNode
  , startGossipSub
  , stopGossipSub
  )
import LibP2P.Protocol.GossipSub.Types (GossipSubParams (..), defaultGossipSubParams)
import LibP2P.Protocol.Identify
  ( identifyPeer
  , pushIdentify
  , registerIdentifyHandlers
  , requestIdentify
  )
import LibP2P.Protocol.Perf
  ( PerfError (..)
  , PerfResult (..)
  , perfProtocolId
  , registerPerfHandler
  , runPerf
  )
import LibP2P.Protocol.Ping
  ( PingError (..)
  , PingResult (..)
  , PingSession
  , closePingSession
  , openPingSession
  , ping
  , pingWithTimeout
  , registerPingHandler
  , sendPing
  , withPingSession
  )
import LibP2P.Switch.Connection (closeConnection, newStream)
import LibP2P.Switch.Dial (dial)
import LibP2P.Switch.Listen (ConnectionGater (..), defaultConnectionGater, switchListen, switchListenAddrs)
import LibP2P.Switch (addTransport, newSwitch, removeStreamHandler, setConnectionGater, setStreamHandler, subscribeSwitchEvents, switchClose)
import LibP2P.Switch.Types (Connection (..), DialError (..), Direction (..), ResourceError (..), StreamHandler, Switch, SwitchEvent (..))
import LibP2P.Transport.TCP (newTCPTransport)
import LibP2P.Transport.QUIC (newQUICTransport)
import LibP2P.Transport (Transport (..))
