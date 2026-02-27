//! Broker peer management
//!
//! Each peer (Client or Connector) connected to the Broker has a `BrokerPeer`
//! that holds the WireGuard tunnel state, role, endpoint, and metadata.

use boringtun::noise::Tunn;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

/// Role of a peer connected to the Broker
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRole {
    /// Remote user connecting through the Broker
    Client,
    /// Inside-network agent exposing services
    Connector,
}

/// A peer connected to the Broker
pub struct BrokerPeer {
    /// WireGuard tunnel for this peer
    pub tunn: Tunn,

    /// Role (Client or Connector)
    pub role: PeerRole,

    /// Last known UDP endpoint
    pub endpoint: SocketAddr,

    /// Peer's X25519 public key
    pub public_key: [u8; 32],

    /// Routes advertised by this peer (Connectors only)
    pub advertised_routes: Vec<(IpAddr, u8)>,

    /// Human-readable service name (Connectors only)
    pub service_name: Option<String>,

    /// Last heartbeat received (for Connectors) or last activity (for Clients)
    pub last_activity: Instant,

    /// Whether the peer has completed authentication
    pub authenticated: bool,

    /// Bytes sent to this peer
    pub tx_bytes: u64,

    /// Bytes received from this peer
    pub rx_bytes: u64,

    /// Packets stitched through this peer
    pub stitched_packets: u64,
}

impl BrokerPeer {
    /// Create a new BrokerPeer
    pub fn new(
        tunn: Tunn,
        role: PeerRole,
        endpoint: SocketAddr,
        public_key: [u8; 32],
    ) -> Self {
        Self {
            tunn,
            role,
            endpoint,
            public_key,
            advertised_routes: Vec::new(),
            service_name: None,
            last_activity: Instant::now(),
            authenticated: false,
            tx_bytes: 0,
            rx_bytes: 0,
            stitched_packets: 0,
        }
    }

    /// Check if the peer has been idle longer than the given duration
    pub fn is_idle(&self, timeout: std::time::Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }

    /// Touch the last activity timestamp
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Short hex identifier for logging
    pub fn short_id(&self) -> String {
        hex::encode(&self.public_key[..4])
    }
}

impl std::fmt::Debug for BrokerPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrokerPeer")
            .field("role", &self.role)
            .field("endpoint", &self.endpoint)
            .field("key", &hex::encode(&self.public_key[..4]))
            .field("authenticated", &self.authenticated)
            .field("routes", &self.advertised_routes.len())
            .finish()
    }
}
