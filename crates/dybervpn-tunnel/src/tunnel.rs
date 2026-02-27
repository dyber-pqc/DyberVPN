//! VPN Tunnel implementation
//!
//! This module implements the main VPN tunnel logic.

use crate::config::{PeerConfig, TunnelConfig};
use crate::error::{TunnelError, TunnelResult};

use boringtun::noise::{HybridHandshakeState, Tunn};

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{atomic::AtomicBool, Arc, RwLock};
use std::time::Instant;

use x25519_dalek::{PublicKey, StaticSecret};

/// Maximum packet size
#[allow(dead_code)]
const MAX_PACKET_SIZE: usize = 2048;

/// VPN tunnel state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelState {
    /// Tunnel is stopped
    Stopped,
    /// Tunnel is starting up
    Starting,
    /// Tunnel is running
    Running,
    /// Tunnel is stopping
    Stopping,
    /// Tunnel encountered an error
    Error,
}

/// Statistics for a peer
#[derive(Debug, Clone, Default)]
pub struct PeerStats {
    /// Bytes sent
    pub tx_bytes: u64,
    /// Bytes received
    pub rx_bytes: u64,
    /// Packets sent
    pub tx_packets: u64,
    /// Packets received
    pub rx_packets: u64,
    /// Last handshake time
    pub last_handshake: Option<Instant>,
    /// Current endpoint
    pub endpoint: Option<SocketAddr>,
    /// Estimated loss rate
    pub loss: f32,
    /// Round-trip time (ms)
    pub rtt: Option<u32>,
}

/// Active peer connection
#[allow(dead_code)]
struct PeerConnection {
    /// WireGuard tunnel for this peer
    tunn: Tunn,
    /// Peer configuration
    #[allow(dead_code)]
    config: PeerConfig,
    /// Current endpoint
    #[allow(dead_code)]
    endpoint: Option<SocketAddr>,
    /// Statistics
    stats: PeerStats,
}

/// VPN Tunnel
pub struct VpnTunnel {
    /// Configuration
    config: TunnelConfig,
    /// Peer connections indexed by public key
    peers: HashMap<[u8; 32], PeerConnection>,
    /// Current state
    state: Arc<RwLock<TunnelState>>,
    /// Shutdown flag
    #[allow(dead_code)]
    shutdown: Arc<AtomicBool>,
}

impl VpnTunnel {
    /// Create a new VPN tunnel
    pub fn new(config: TunnelConfig) -> TunnelResult<Self> {
        config.validate().map_err(TunnelError::Config)?;

        Ok(Self {
            config,
            peers: HashMap::new(),
            state: Arc::new(RwLock::new(TunnelState::Stopped)),
            shutdown: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Get current state
    pub fn state(&self) -> TunnelState {
        *self.state.read().unwrap()
    }

    /// Initialize peer connections
    pub fn init_peers(&mut self) -> TunnelResult<()> {
        let private_key = StaticSecret::from(self.config.private_key);

        for (idx, peer_config) in self.config.peers.iter().enumerate() {
            let peer_public = PublicKey::from(peer_config.public_key);

            // Create hybrid state if using PQ
            let hybrid_state = if self.config.mode.uses_pq_kex() {
                Some(HybridHandshakeState::new(self.config.mode))
            } else {
                None
            };

            // Create tunnel for this peer
            let tunn = if let Some(hybrid_state) = hybrid_state {
                Tunn::new_hybrid(
                    private_key.clone(),
                    peer_public,
                    peer_config.preshared_key,
                    peer_config.persistent_keepalive,
                    idx as u32,
                    None,
                    hybrid_state,
                )
            } else {
                Tunn::new(
                    private_key.clone(),
                    peer_public,
                    peer_config.preshared_key,
                    peer_config.persistent_keepalive,
                    idx as u32,
                    None,
                )
            };

            let connection = PeerConnection {
                tunn,
                config: peer_config.clone(),
                endpoint: peer_config.endpoint,
                stats: PeerStats::default(),
            };

            self.peers.insert(peer_config.public_key, connection);

            tracing::debug!(
                "Initialized peer {} with endpoint {:?}",
                hex::encode(&peer_config.public_key[..4]),
                peer_config.endpoint
            );
        }

        Ok(())
    }

    /// Get statistics for all peers
    pub fn get_stats(&self) -> Vec<PeerStats> {
        self.peers.values().map(|p| p.stats.clone()).collect()
    }
}

impl Drop for VpnTunnel {
    fn drop(&mut self) {
        if self.state() == TunnelState::Running {
            tracing::info!("Shutting down tunnel");
        }
    }
}
