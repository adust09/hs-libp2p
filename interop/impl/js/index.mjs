import { circuitRelayServer, circuitRelayTransport } from '@libp2p/circuit-relay-v2'
import { identify } from '@libp2p/identify'
import { noise } from '@libp2p/noise'
import { ping } from '@libp2p/ping'
import { tcp } from '@libp2p/tcp'
import { webRTC } from '@libp2p/webrtc'
import { yamux } from '@libp2p/yamux'
import { multiaddr } from '@multiformats/multiaddr'
import { WebRTC } from '@multiformats/multiaddr-matcher'
import { createLibp2p } from 'libp2p'
import { networkInterfaces } from 'node:os'
import { createClient } from 'redis'

const role = process.env.ROLE
const testKey = process.env.TEST_KEY ?? 'webrtc-interop'
const redisUrl = `redis://${process.env.REDIS_ADDR ?? 'redis:6379'}`
const listenerKey = `${testKey}_listener_multiaddr`
const relayKey = `${testKey}_relay_multiaddr`

if (role !== 'hs-listener' && role !== 'js-listener') {
  throw new Error('ROLE must be hs-listener or js-listener')
}

const relayIP = containerIPv4()
const redis = createClient({ url: redisUrl })
redis.on('error', err => process.stderr.write(`redis: ${err.message}\n`))
await redis.connect()

const relay = await createLibp2p({
  addresses: {
    listen: ['/ip4/0.0.0.0/tcp/4001'],
    announce: [`/ip4/${relayIP}/tcp/4001`]
  },
  transports: [tcp()],
  connectionEncrypters: [noise()],
  streamMuxers: [yamux()],
  connectionGater: { denyDialMultiaddr: async () => false },
  services: {
    identify: identify(),
    relay: circuitRelayServer()
  }
})

const relayAddress = multiaddr(`/ip4/${relayIP}/tcp/4001/p2p/${relay.peerId}`)
process.stderr.write(`relay: ${relayAddress}\n`)

const nodes = [relay]
const shutdown = async () => {
  await Promise.allSettled(nodes.reverse().map(async node => node.stop()))
  await redis.quit().catch(() => {})
}
process.on('SIGTERM', () => { void shutdown().finally(() => process.exit(0)) })
process.on('SIGINT', () => { void shutdown().finally(() => process.exit(0)) })

if (role === 'hs-listener') {
  await redis.rPush(relayKey, relayAddress.toString())
  const result = await redis.blPop(listenerKey, 180)
  if (result == null) {
    throw new Error('timed out waiting for Haskell listener')
  }
  const dialer = await createWebRTCNode(false)
  nodes.push(dialer)
  const latency = await dialer.services.ping.ping(multiaddr(result.element), {
    signal: AbortSignal.timeout(30_000)
  })
  process.stdout.write(`js_to_hs_ping_ms: ${latency}\n`)
  await shutdown()
  process.exit(0)
}

const listener = await createWebRTCNode(true)
nodes.push(listener)
await listener.dial(relayAddress, { signal: AbortSignal.timeout(30_000) })
const address = await waitForWebRTCAddress(listener)
await redis.rPush(listenerKey, address.toString())
process.stderr.write(`listener: ${address}\n`)
await new Promise(() => {})

function containerIPv4 () {
  for (const addresses of Object.values(networkInterfaces())) {
    const address = addresses?.find(candidate => candidate.family === 'IPv4' && !candidate.internal)
    if (address != null) {
      return address.address
    }
  }
  throw new Error('container IPv4 address not found')
}

async function createWebRTCNode (listen) {
  return createLibp2p({
    addresses: { listen: listen ? ['/p2p-circuit', '/webrtc'] : [] },
    transports: [webRTC(), tcp(), circuitRelayTransport()],
    connectionEncrypters: [noise()],
    streamMuxers: [yamux()],
    connectionGater: { denyDialMultiaddr: async () => false },
    services: {
      identify: identify(),
      ping: ping()
    }
  })
}

async function waitForWebRTCAddress (node) {
  const deadline = Date.now() + 30_000
  while (Date.now() < deadline) {
    const address = node.getMultiaddrs().find(candidate => WebRTC.matches(candidate))
    if (address != null) {
      return address
    }
    await new Promise(resolve => setTimeout(resolve, 100))
  }
  throw new Error('timed out waiting for WebRTC relay address')
}
