use libp2p::{
    gossipsub, identity, noise, tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder,
};
use libp2p::futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use redis::Commands;
use std::env;
use std::net::ToSocketAddrs;
use std::time::{Duration, Instant};
use tokio::time::timeout;

const TOPIC: &str = "interop-gossipsub-test";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_target(false)
        .init();

    let is_dialer = env::var("IS_DIALER").unwrap_or_else(|_| "false".to_string()) == "true";
    let redis_addr = env::var("REDIS_ADDR").unwrap_or_else(|_| "redis:6379".to_string());
    let test_key = env::var("TEST_KEY")?;
    let redis_url = format!("redis://{}/", redis_addr);
    let addr_key = format!("{}_listener_multiaddr", test_key);

    // Generate Ed25519 keypair
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    eprintln!("PeerId: {local_peer_id}");

    // Configure GossipSub with strict signature validation
    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .validation_mode(gossipsub::ValidationMode::Strict)
        .build()
        .expect("valid gossipsub config");

    let mut swarm = SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| {
            gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )
            .expect("valid gossipsub behaviour")
        })?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(120)))
        .build();

    let topic = gossipsub::IdentTopic::new(TOPIC);
    swarm.behaviour_mut().subscribe(&topic)?;

    if is_dialer {
        run_dialer(&mut swarm, &topic, &redis_url, &addr_key).await
    } else {
        run_listener(&mut swarm, &topic, &redis_url, &addr_key).await
    }
}

async fn run_listener(
    swarm: &mut Swarm<gossipsub::Behaviour>,
    topic: &gossipsub::IdentTopic,
    redis_url: &str,
    addr_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    // Wait for a listen address, collect all
    let mut listen_port: u16 = 0;
    // Drain initial listen events to get the port
    loop {
        if let Some(event) = swarm.next().await {
            if let SwarmEvent::NewListenAddr { address, .. } = event {
                eprintln!("Listening on: {address}");
                // Extract port from the address
                let addr_str = address.to_string();
                if let Some(port_str) = addr_str.rsplit("/tcp/").next() {
                    if let Ok(p) = port_str.parse::<u16>() {
                        listen_port = p;
                    }
                }
                break;
            }
        }
    }

    // Resolve container IP (Docker sets HOSTNAME to container ID)
    let container_ip = resolve_container_ip();
    let local_peer_id = *swarm.local_peer_id();
    let full_addr = format!("/ip4/{}/tcp/{}/p2p/{}", container_ip, listen_port, local_peer_id);
    eprintln!("Publishing to Redis: {full_addr}");

    let client = redis::Client::open(redis_url)?;
    let mut redis_conn = client.get_connection()?;
    redis_conn.rpush::<_, _, ()>(addr_key, &full_addr)?;

    // Wait for incoming messages — log all events for debugging
    let result = timeout(Duration::from_secs(60), async {
        loop {
            if let Some(event) = swarm.next().await {
                match &event {
                    SwarmEvent::Behaviour(gossipsub::Event::Message {
                        message, ..
                    }) => {
                        let data = String::from_utf8_lossy(&message.data).to_string();
                        eprintln!("Received message: {data}");

                        // Send response
                        let response = format!("rust-reply-to-{}", data);
                        if let Err(e) =
                            swarm.behaviour_mut().publish(topic.clone(), response.as_bytes())
                        {
                            eprintln!("Publish response failed: {e}");
                        }
                        return data;
                    }
                    SwarmEvent::Behaviour(gs_event) => {
                        eprintln!("GossipSub event: {gs_event:?}");
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        eprintln!("Connection established: {peer_id}");
                    }
                    SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                        eprintln!("Connection closed: {peer_id}, cause: {cause:?}");
                    }
                    SwarmEvent::IncomingConnection { local_addr, send_back_addr, .. } => {
                        eprintln!("Incoming connection: {local_addr} <- {send_back_addr}");
                    }
                    other => {
                        eprintln!("Other event: {other:?}");
                    }
                }
            }
        }
    })
    .await;

    let json = match &result {
        Ok(msg) => serde_json::json!({
            "gossipSubInterop": true,
            "role": "listener",
            "messageReceived": msg,
            "messageSent": format!("rust-reply-to-{}", msg)
        }),
        Err(_) => serde_json::json!({
            "gossipSubInterop": false,
            "role": "listener",
            "error": "timeout waiting for message"
        }),
    };

    eprintln!("Result: {json}");
    redis_conn.rpush::<_, _, ()>("gossipResult", json.to_string())?;

    if result.is_err() {
        return Err("timeout waiting for message".into());
    }

    // Swarm must keep being polled to flush the queued reply.
    let _ = timeout(Duration::from_secs(3), async {
        while swarm.next().await.is_some() {}
    })
    .await;
    Ok(())
}

async fn run_dialer(
    swarm: &mut Swarm<gossipsub::Behaviour>,
    topic: &gossipsub::IdentTopic,
    redis_url: &str,
    addr_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Polling Redis for listener address...");

    let client = redis::Client::open(redis_url)?;
    let mut redis_conn = client.get_connection()?;

    // Poll LPOP until the listener publishes its address (60s timeout).
    // The address sits on a Redis list (listener RPUSHes, dialer LPOPs)
    // per the unified-testing coordination contract.
    let addr_str = timeout(Duration::from_secs(60), async {
        loop {
            if let Some(addr) = redis_conn.lpop::<_, Option<String>>(addr_key, None)? {
                return Ok::<_, redis::RedisError>(addr);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .map_err(|_| "timeout waiting for listener address")??;
    eprintln!("Got listener address: {addr_str}");

    let remote_addr: Multiaddr = addr_str.parse()?;
    swarm.dial(remote_addr)?;

    // Start listening (needed for GossipSub bidirectional streams)
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    let start = Instant::now();
    let mut published = false;

    let result = timeout(Duration::from_secs(30), async {
        loop {
            if let Some(event) = swarm.next().await {
                match event {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } if !published => {
                        eprintln!("Connected to: {peer_id}");
                    }
                    SwarmEvent::Behaviour(gossipsub::Event::Subscribed { peer_id, topic: t }) if !published => {
                        eprintln!("Peer {peer_id} subscribed to {t}");

                        // Remote peer subscribed — now safe to publish
                        tokio::time::sleep(Duration::from_secs(1)).await;

                        let test_msg = format!("hs-rust-interop-{}", timestamp_ms());
                        eprintln!("Publishing: {test_msg}");
                        match swarm
                            .behaviour_mut()
                            .publish(topic.clone(), test_msg.as_bytes())
                        {
                            Ok(_) => eprintln!("Message published"),
                            Err(e) => eprintln!("Publish failed: {e}"),
                        }
                        published = true;
                    }
                    SwarmEvent::Behaviour(gossipsub::Event::Message { message, .. }) => {
                        let data = String::from_utf8_lossy(&message.data).to_string();
                        let elapsed = start.elapsed();
                        eprintln!("Received response: {data} ({}ms)", elapsed.as_millis());
                        return (data, elapsed);
                    }
                    _ => {}
                }
            }
        }
    })
    .await;

    match result {
        Ok((msg, elapsed)) => {
            let json = serde_json::json!({
                "gossipSubInterop": true,
                "role": "dialer",
                "messageReceived": msg,
                "roundTripMs": elapsed.as_millis() as u64
            });
            println!("{json}");
            redis_conn.rpush::<_, _, ()>("gossipResult", json.to_string())?;
            std::process::exit(0);
        }
        Err(_) => {
            let json = serde_json::json!({
                "gossipSubInterop": false,
                "role": "dialer",
                "error": "timeout or connection failure"
            });
            println!("{json}");
            redis_conn.rpush::<_, _, ()>("gossipResult", json.to_string())?;
            std::process::exit(1);
        }
    }
}

fn timestamp_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Resolve the container's IP address for Docker networking.
/// Docker sets HOSTNAME to the container ID, which resolves to the container IP.
fn resolve_container_ip() -> String {
    if let Ok(hostname) = env::var("HOSTNAME") {
        let lookup = format!("{}:0", hostname);
        if let Ok(mut addrs) = lookup.to_socket_addrs() {
            if let Some(addr) = addrs.find(|a| a.is_ipv4() && !a.ip().is_loopback()) {
                return addr.ip().to_string();
            }
        }
    }
    "0.0.0.0".to_string()
}
