{-# LANGUAGE CPP #-}

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
--   (_relayState, _circuitState, _natServices) <- registerNATHandlers sw defaultNATConfig
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
  , newSwitchWithConfig
  , SwitchConfig (..)
  , defaultSwitchConfig
  , YamuxConfig (..)
  , defaultYamuxConfig
  , Micros
  , mkMicros
  , microsToInt
  , subscribeSwitchEvents
  , SwitchEvent (..)
  , addTransport
  , switchListen
  , switchListenAddrs
  , switchClose
  , dial
  , closeConnection
  , newStream
  , newStreamAllowingLimited
  , StreamOpenError (..)
  , RelayCircuitLimit (..)
  , RelayCircuitExhausted (..)
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
  , WebSocketConfig (..)
  , defaultWebSocketConfig
  , webSocketServerParams
  , newWebSocketTransport
  , newWebSocketTransportWithConfig
  , newWebTransportTransport
#ifdef WITH_WEBRTC
  , STUNServer (..)
 , WebRTCConfig (..)
 , defaultWebRTCConfig
 , webRTCDirectTransport
 , webRTCTransport
#endif
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
  , DHTMaintenanceConfig (..)
  , defaultDHTMaintenanceConfig
  , newDHTNode
  , newDHTNodeWithConfig
  , stopDHTNode
  , registerDHTHandler
  , bootstrap
  , startBootstrap
  , provide
  , putValue
  , getValue
  , findProviders
  , findPeer

    -- * Discovery
  , DiscoveryEvent (..)
  , newDiscoveryQueue
  , drainDiscoveryQueue

    -- ** mDNS
  , MDNSConfig (..)
  , defaultMDNSConfig
  , MDNSService (..)
  , newMDNSService
  , stopMDNSService

    -- ** Rendezvous
  , RendezvousConfig (..)
  , defaultRendezvousConfig
  , RendezvousError (..)
  , registerRendezvousPoint
  , registeredCount
  , registerSelf
  , unregisterSelf
  , discover
  , inspectRegistration
  , pushDiscoverEvents
    -- * NAT traversal (AutoNAT, Circuit Relay v2, DCUtR)
  , NATConfig (..)
  , defaultNATConfig
  , NATStatus (..)
  , AutoNATClientConfig (..)
  , defaultAutoNATClientConfig
  , AutoNATClientService
  , NATServices (..)
  , startAutoNATClient
  , autoNATClientStatus
  , stopAutoNATClient
  , registerNATHandlers
  , registerAutoNATHandler
  , registerAutoNATV2Handlers
  , checkAutoNATV2
  , AutoNATV2Config (..)
  , defaultAutoNATV2Config
  , AutoNATV2State
  , AutoNATV2Request (..)
  , AutoNATV2Result (..)
  , autoNATV2DialProtocolId
  , autoNATV2DialBackProtocolId
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
  , enablePartialMessages
  , gossipJoin
  , gossipJoinPartial
  , gossipLeave
  , gossipPublish
  , PartialTopicMode (..)
  , PartialMessage (..)
  , PartialMessagesExtension
  , PartialMessagesConfig (..)
  , PartialCallbackResult (..)
  , PartialPublishAction (..)
  , PartialPublishPlan
  , PartialMessagesError (..)
  , defaultPartialMessagesConfig
  , newPartialMessagesExtension
  , partialMeshPeers
  , partialPeerRequests
  , publishPartial
  ) where

import LibP2P.Crypto.Ed25519 (generateKeyPair)
import LibP2P.Crypto.Key (KeyPair)
import LibP2P.Crypto.PeerId (PeerId, fromPublicKey, peerIdBytes, toBase58, parsePeerId, toCIDv1)
import LibP2P.DHT
  ( DHTMaintenanceConfig (..)
  , DHTMode (..)
  , DHTNode
  , ProviderEntry
  , Validator (..)
  , defaultDHTMaintenanceConfig
  , defaultValidator
  , newDHTNode
  , newDHTNodeWithConfig
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
  ( AutoNATClientConfig (..)
  , AutoNATClientService
  , NATConfig (..)
  , NATServices (..)
  , autoNATClientStatus
  , checkAutoNATV2
  , defaultAutoNATClientConfig
  , defaultNATConfig
  , registerAutoNATHandler
  , registerAutoNATV2Handlers
  , registerDCUtRHandler
  , registerNATHandlers
  , registerRelayHopHandler
  , registerRelayStopHandler
  , startAutoNATClient
  , stopAutoNATClient
  )
import LibP2P.NAT.AutoNAT (NATStatus (..))
import LibP2P.NAT.AutoNAT.V2
  ( AutoNATV2Config (..)
  , AutoNATV2Request (..)
  , AutoNATV2Result (..)
  , AutoNATV2State
  , defaultAutoNATV2Config
  )
import LibP2P.NAT.AutoNAT.V2.Message
  ( autoNATV2DialBackProtocolId
  , autoNATV2DialProtocolId
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
  , enablePartialMessages
  , gossipJoin
  , gossipJoinPartial
  , gossipLeave
  , gossipPublish
  , newGossipSubNode
  , startGossipSub
  , stopGossipSub
  )
import LibP2P.Protocol.GossipSub.PartialMessages
  ( PartialCallbackResult (..)
  , PartialMessagesConfig (..)
  , PartialMessagesError (..)
  , PartialMessagesExtension
  , PartialPublishAction (..)
  , PartialPublishPlan
  , defaultPartialMessagesConfig
  , newPartialMessagesExtension
  , partialMeshPeers
  , partialPeerRequests
  , publishPartial
  )
import LibP2P.Protocol.GossipSub.Types
  ( GossipSubParams (..)
  , PartialMessage (..)
  , PartialTopicMode (..)
  , defaultGossipSubParams
  )
import LibP2P.Discovery.MDNS
  ( MDNSConfig (..)
  , MDNSService (..)
  , defaultMDNSConfig
  , newMDNSService
  , stopMDNSService
  )
import LibP2P.Discovery.Rendezvous
  ( RendezvousConfig (..)
  , RendezvousError (..)
  , defaultRendezvousConfig
  , discover
  , inspectRegistration
  , pushDiscoverEvents
  , registerRendezvousPoint
  , registeredCount
  , registerSelf
  , unregisterSelf
  )
import LibP2P.Discovery.Types
  ( DiscoveryEvent (..)
  , drainDiscoveryQueue
  , newDiscoveryQueue
  )
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
import LibP2P.NAT.Relay.Limit (RelayCircuitExhausted (..))
import LibP2P.Switch.Connection
  ( StreamOpenError (..)
  , closeConnection
  , newStream
  , newStreamAllowingLimited
  )
import LibP2P.Switch.Dial (dial)
import LibP2P.Switch.Listen (ConnectionGater (..), defaultConnectionGater, switchListen, switchListenAddrs)
import LibP2P.Switch (addTransport, newSwitch, newSwitchWithConfig, removeStreamHandler, setConnectionGater, setStreamHandler, subscribeSwitchEvents, switchClose)
import LibP2P.Switch.Types (Connection (..), DialError (..), Direction (..), ResourceError (..), StreamHandler, Switch, SwitchConfig (..), SwitchEvent (..), defaultSwitchConfig)
import LibP2P.Transport.TCP (newTCPTransport)
import LibP2P.Transport.WebSocket
  ( WebSocketConfig (..)
  , defaultWebSocketConfig
  , newWebSocketTransport
  , newWebSocketTransportWithConfig
  , webSocketServerParams
  )
import LibP2P.Transport.WebTransport (newWebTransportTransport)
#ifdef WITH_WEBRTC
import LibP2P.Transport.WebRTC
  ( STUNServer (..)
  , WebRTCConfig (..)
  , defaultWebRTCConfig
  , webRTCDirectTransport
  , webRTCTransport
  )
#endif
import LibP2P.Transport.QUIC (newQUICTransport)
import LibP2P.Transport (RelayCircuitLimit (..), Transport (..))
import LibP2P.Yamux.Types (Micros, YamuxConfig (..), defaultYamuxConfig, microsToInt, mkMicros)
