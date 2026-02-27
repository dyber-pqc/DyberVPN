//! Main Broker event loop
//!
//! The Broker runs an async tokio loop that:
//! 1. Receives UDP packets from Clients and Connectors
//! 2. Identifies the peer by endpoint
//! 3. For data packets: stitches through session.rs (decrypt → policy → re-encrypt)
//! 4. For handshake packets: handles WireGuard handshake
//! 5. Spawns the control plane TCP server for Connector registration

use crate::config::BrokerConfig;
use crate::control;
use crate::error::{BrokerError, BrokerResult};
use crate::peer::{BrokerPeer, PeerRole};
use crate::registry::ServiceRegistry;
use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::{HybridHandshakeState, Packet, Tunn, TunnResult};
use dashmap::DashMap;
use dybervpn_tunnel::audit::AuditLogger;
use dybervpn_tunnel::policy::PolicyEngine;
use dybervpn_tunnel::revocation::RevocationEngine;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::net::UdpSocket;
use x25519_dalek::{PublicKey, StaticSecret};

/// The ZTNA Broker
pub struct Broker {
    /// Configuration
    config: Arc<BrokerConfig>,

    /// Async UDP socket for data plane
    socket: UdpSocket,

    /// All connected peers (keyed by X25519 public key)
    peers: Arc<DashMap<[u8; 32], BrokerPeer>>,

    /// Endpoint → public key reverse index
    endpoint_map: Arc<DashMap<SocketAddr, [u8; 32]>>,

    /// Client tunnel-IP → public key mapping (for reverse routing)
    client_ip_map: Arc<DashMap<IpAddr, [u8; 32]>>,

    /// Service registry (CIDR → Connector mapping)
    registry: Arc<ServiceRegistry>,

    /// Access control policy engine
    policy: Arc<RwLock<PolicyEngine>>,

    /// Key revocation engine
    revocation: Arc<RevocationEngine>,

    /// Structured audit logger
    audit: AuditLogger,
}

impl Broker {
    /// Create a new Broker instance
    pub async fn new(config: BrokerConfig) -> BrokerResult<Self> {
        let socket = UdpSocket::bind(config.listen_udp)
            .await
            .map_err(BrokerError::Io)?;

        tracing::info!("Broker UDP socket bound to {}", config.listen_udp);

        Ok(Self {
            config: Arc::new(config),
            socket,
            peers: Arc::new(DashMap::new()),
            endpoint_map: Arc::new(DashMap::new()),
            client_ip_map: Arc::new(DashMap::new()),
            registry: Arc::new(ServiceRegistry::new()),
            policy: Arc::new(RwLock::new(PolicyEngine::disabled())),
            revocation: Arc::new(RevocationEngine::disabled()),
            audit: AuditLogger::disabled(),
        })
    }

    /// Set the policy engine
    pub fn set_policy(&mut self, engine: PolicyEngine) {
        self.policy = Arc::new(RwLock::new(engine));
    }

    /// Set the revocation engine
    pub fn set_revocation(&mut self, engine: RevocationEngine) {
        self.revocation = Arc::new(engine);
    }

    /// Set the audit logger
    pub fn set_audit(&mut self, logger: AuditLogger) {
        self.audit = logger;
    }

    /// Run the Broker (async, blocks until shutdown)
    pub async fn run(&self) -> BrokerResult<()> {
        tracing::info!(
            "Starting ZTNA Broker (mode={:?}, max_clients={}, udp={}, control={})",
            self.config.mode,
            self.config.max_clients,
            self.config.listen_udp,
            self.config.listen_control,
        );

        // Spawn the control plane TCP server
        let ctrl_config = Arc::clone(&self.config);
        let ctrl_peers = Arc::clone(&self.peers);
        let ctrl_registry = Arc::clone(&self.registry);
        let ctrl_audit = self.audit.clone();
        let ctrl_revocation = Arc::clone(&self.revocation);

        tokio::spawn(async move {
            if let Err(e) = control::run_control_plane(
                ctrl_config,
                ctrl_peers,
                ctrl_registry,
                ctrl_audit,
                ctrl_revocation,
            )
            .await
            {
                tracing::error!("Control plane error: {}", e);
            }
        });

        // Spawn the stale-peer reaper
        let reaper_peers = Arc::clone(&self.peers);
        let reaper_registry = Arc::clone(&self.registry);
        let reaper_endpoint_map = Arc::clone(&self.endpoint_map);
        let heartbeat_timeout = self.config.heartbeat_timeout;
        let session_timeout = self.config.session_timeout;

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                reap_stale_peers(
                    &reaper_peers,
                    &reaper_registry,
                    &reaper_endpoint_map,
                    heartbeat_timeout,
                    session_timeout,
                );
            }
        });

        // Main UDP receive loop
        let mut buf = vec![0u8; 65535];

        loop {
            let (n, src) = self
                .socket
                .recv_from(&mut buf)
                .await
                .map_err(BrokerError::Io)?;

            let packet = &buf[..n];

            // Identify peer by endpoint
            if let Some(peer_key) = self.endpoint_map.get(&src) {
                let pk = *peer_key;
                drop(peer_key); // release DashMap ref

                self.handle_known_peer_packet(pk, src, packet).await;
            } else {
                // Unknown endpoint — could be a new Client handshake
                self.handle_unknown_packet(src, packet).await;
            }
        }
    }

    /// Handle a packet from a known peer
    async fn handle_known_peer_packet(&self, peer_key: [u8; 32], src: SocketAddr, packet: &[u8]) {
        // We need to get the peer, decapsulate, then decide what to do
        let mut decap_buf = vec![0u8; 65535];

        // First, decapsulate with the source peer
        let result = {
            let mut peer_ref = match self.peers.get_mut(&peer_key) {
                Some(p) => p,
                None => return,
            };
            peer_ref.touch();
            peer_ref.endpoint = src;
            peer_ref
                .tunn
                .decapsulate(Some(src.ip()), packet, &mut decap_buf)
        };

        match result {
            TunnResult::WriteToTunnelV4(plaintext, _)
            | TunnResult::WriteToTunnelV6(plaintext, _) => {
                let plaintext = plaintext.to_vec();

                // Extract src/dst IP for routing and learn Client tunnel IPs
                if let Some((src_ip, dst_ip, _, _)) =
                    dybervpn_tunnel::policy::inspect_packet(&plaintext)
                {
                    // Learn the source tunnel IP → peer key mapping (for reverse routing)
                    self.client_ip_map.insert(src_ip, peer_key);
                    self.route_plaintext(&peer_key, dst_ip, &plaintext).await;
                }
            }

            TunnResult::WriteToNetwork(data) => {
                // Handshake response — send back to source
                let _ = self.socket.send_to(data, src).await;
            }

            TunnResult::Done => {
                // Keepalive, no action needed
            }

            TunnResult::Err(e) => {
                tracing::debug!("Decapsulate error from {}: {:?}", src, e);
            }
        }
    }

    /// Route a decrypted plaintext packet to the appropriate destination peer
    async fn route_plaintext(&self, src_key: &[u8; 32], dst_ip: IpAddr, plaintext: &[u8]) {
        // Look up the Connector that serves this destination
        let dst_key = match self.registry.lookup(dst_ip) {
            Some(key) => key,
            None => {
                // Check if it's a Client IP (reverse traffic from Connector back to Client)
                // For now, we can try all peers to find one that has this IP in allowed_ips
                if let Some(key) = self.find_peer_for_ip(dst_ip) {
                    key
                } else {
                    tracing::debug!("No route for destination {}", dst_ip);
                    return;
                }
            }
        };

        if &dst_key == src_key {
            // Don't route back to sender
            return;
        }

        // Re-encrypt through destination peer's Tunn
        let mut out_buf = vec![0u8; 65535];
        let (result, endpoint) = {
            let mut dst_peer = match self.peers.get_mut(&dst_key) {
                Some(p) => p,
                None => {
                    tracing::debug!("Destination peer {} gone", hex::encode(&dst_key[..4]));
                    return;
                }
            };

            let encap = dst_peer.tunn.encapsulate(plaintext, &mut out_buf);
            let ep = dst_peer.endpoint;
            dst_peer.tx_bytes += plaintext.len() as u64;
            dst_peer.stitched_packets += 1;
            (encap, ep)
        };

        match result {
            TunnResult::WriteToNetwork(data) => {
                let _ = self.socket.send_to(data, endpoint).await;
            }
            TunnResult::Done => {
                tracing::debug!(
                    "Encapsulate to {} returned Done (session not established?)",
                    hex::encode(&dst_key[..4])
                );
            }
            TunnResult::Err(e) => {
                tracing::warn!(
                    "Re-encrypt to {} failed: {:?}",
                    hex::encode(&dst_key[..4]),
                    e
                );
            }
            _ => {}
        }
    }

    /// Find a peer whose tunnel IP matches the given destination IP (for reverse routing)
    ///
    /// Uses the learned client_ip_map populated when packets arrive from Clients.
    fn find_peer_for_ip(&self, ip: IpAddr) -> Option<[u8; 32]> {
        self.client_ip_map.get(&ip).map(|entry| *entry.value())
    }

    /// Handle a packet from an unknown endpoint (potential new Client)
    async fn handle_unknown_packet(&self, src: SocketAddr, packet: &[u8]) {
        // Parse the WireGuard message type
        if packet.len() < 4 {
            return;
        }

        let msg_type = u32::from_le_bytes([packet[0], packet[1], packet[2], packet[3]]);

        // Type 1 = Handshake Initiation
        if msg_type != 1 {
            tracing::debug!(
                "Ignoring non-handshake packet from unknown endpoint {} (type={})",
                src,
                msg_type
            );
            return;
        }

        // Check capacity
        if self.peers.len() >= self.config.max_clients {
            tracing::warn!(
                "Max clients reached ({}), rejecting {}",
                self.config.max_clients,
                src
            );
            return;
        }

        // Step 1: Extract the Client's static public key from the handshake initiation
        // using parse_handshake_anon, which decrypts the initiator's identity.
        let broker_secret = StaticSecret::from(self.config.private_key);
        let broker_public = PublicKey::from(&broker_secret);
        let peer_idx = self.peers.len() as u32;

        let parsed = match Tunn::parse_incoming_packet(packet) {
            Ok(Packet::HandshakeInit(init)) => {
                match parse_handshake_anon(&broker_secret, &broker_public, &init) {
                    Ok(half) => half,
                    Err(e) => {
                        tracing::debug!("Failed to parse handshake from {}: {:?}", src, e);
                        return;
                    }
                }
            }
            _ => {
                tracing::debug!("Could not parse handshake packet from {}", src);
                return;
            }
        };

        let client_pk = parsed.peer_static_public;

        // Check if this Client's key is revoked
        if self.revocation.is_revoked(&client_pk) {
            tracing::warn!(
                "Rejected handshake from revoked Client {}",
                hex::encode(&client_pk[..4])
            );
            return;
        }

        // Step 2: Create a Tunn for this Client (now we know their real public key)
        let broker_secret2 = StaticSecret::from(self.config.private_key);
        let client_public = PublicKey::from(client_pk);

        let mut tunn = if self.config.mode.uses_pq_kex() {
            let hs = HybridHandshakeState::new(self.config.mode);
            Tunn::new_hybrid(
                broker_secret2,
                client_public,
                None,
                Some(25),
                peer_idx,
                None,
                hs,
            )
        } else {
            Tunn::new(
                broker_secret2,
                client_public,
                None,
                Some(25),
                peer_idx,
                None,
            )
        };

        // Step 3: Process the handshake with the real Tunn
        let mut out_buf = vec![0u8; 65535];
        let result = tunn.decapsulate(Some(src.ip()), packet, &mut out_buf);

        match result {
            TunnResult::WriteToNetwork(data) => {
                // Handshake response — send it back
                let _ = self.socket.send_to(data, src).await;

                // Step 4: Register the Client as a BrokerPeer
                let mut peer = BrokerPeer::new(tunn, PeerRole::Client, src, client_pk);
                peer.authenticated = true;

                self.peers.insert(client_pk, peer);
                self.endpoint_map.insert(src, client_pk);

                tracing::info!(
                    "Client {} registered from {} (handshake response sent)",
                    hex::encode(&client_pk[..4]),
                    src,
                );
            }
            TunnResult::Err(e) => {
                tracing::debug!("Failed to process handshake from {}: {:?}", src, e);
            }
            _ => {
                tracing::debug!("Unexpected decapsulate result for handshake from {}", src);
            }
        }
    }
}

/// Remove peers that have been idle too long
pub fn reap_stale_peers(
    peers: &DashMap<[u8; 32], BrokerPeer>,
    registry: &ServiceRegistry,
    endpoint_map: &DashMap<SocketAddr, [u8; 32]>,
    heartbeat_timeout: Duration,
    session_timeout: Duration,
) {
    let mut to_remove = Vec::new();

    for entry in peers.iter() {
        let peer = entry.value();
        let timeout = match peer.role {
            PeerRole::Connector => heartbeat_timeout,
            PeerRole::Client => session_timeout,
        };

        if peer.is_idle(timeout) {
            to_remove.push(*entry.key());
        }
    }

    for key in to_remove {
        if let Some((_, peer)) = peers.remove(&key) {
            endpoint_map.remove(&peer.endpoint);
            if peer.role == PeerRole::Connector {
                registry.unregister(&key);
            }
            tracing::info!(
                "Reaped stale {:?} {} (idle {:?})",
                peer.role,
                hex::encode(&key[..4]),
                peer.last_activity.elapsed(),
            );
        }
    }
}
