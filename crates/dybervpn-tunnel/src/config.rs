//! Tunnel configuration

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use dybervpn_protocol::OperatingMode;

/// Configuration for a VPN tunnel
#[derive(Debug, Clone)]
pub struct TunnelConfig {
    /// Device name (e.g., "dvpn0")
    pub device_name: String,
    
    /// Private key (X25519)
    pub private_key: [u8; 32],
    
    /// Post-quantum private key (ML-KEM-768)
    pub pq_private_key: Option<Vec<u8>>,
    
    /// ML-DSA-65 signing private key (for pq-only mode authentication)
    pub mldsa_private_key: Option<Vec<u8>>,
    
    /// Listen address and port
    pub listen_addr: SocketAddr,
    
    /// Tunnel IP address
    pub address: IpAddr,
    
    /// Tunnel netmask (CIDR prefix length)
    pub netmask: u8,
    
    /// MTU
    pub mtu: u16,
    
    /// Operating mode
    pub mode: OperatingMode,
    
    /// Peers
    pub peers: Vec<PeerConfig>,
    
    /// DNS servers to use
    pub dns: Vec<IpAddr>,
    
    /// Keepalive interval
    pub keepalive_interval: Option<Duration>,
    
    /// Handshake timeout
    pub handshake_timeout: Duration,
    
    /// Enable logging
    pub verbose: bool,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            device_name: "dvpn0".to_string(),
            private_key: [0u8; 32],
            pq_private_key: None,
            mldsa_private_key: None,
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 51820),
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            netmask: 24,
            mtu: crate::DEFAULT_MTU,
            mode: OperatingMode::Hybrid,
            peers: Vec::new(),
            dns: Vec::new(),
            keepalive_interval: Some(Duration::from_secs(25)),
            handshake_timeout: Duration::from_secs(5),
            verbose: false,
        }
    }
}

/// Configuration for a peer
#[derive(Debug, Clone)]
pub struct PeerConfig {
    /// Human-readable peer name (from config comments or enrollment)
    pub name: Option<String>,
    
    /// Peer's public key (X25519)
    pub public_key: [u8; 32],
    
    /// Peer's post-quantum public key (ML-KEM-768)
    pub pq_public_key: Option<Vec<u8>>,
    
    /// Peer's ML-DSA-65 verification public key (for pq-only mode)
    pub mldsa_public_key: Option<Vec<u8>>,
    
    /// Peer's endpoint (address:port)
    pub endpoint: Option<SocketAddr>,
    
    /// Allowed IPs for this peer
    pub allowed_ips: Vec<(IpAddr, u8)>,
    
    /// Persistent keepalive interval
    pub persistent_keepalive: Option<u16>,
    
    /// Preshared key (optional additional security)
    pub preshared_key: Option<[u8; 32]>,
}

impl PeerConfig {
    /// Create a new peer config with just a public key
    pub fn new(public_key: [u8; 32]) -> Self {
        Self {
            name: None,
            public_key,
            pq_public_key: None,
            mldsa_public_key: None,
            endpoint: None,
            allowed_ips: Vec::new(),
            persistent_keepalive: None,
            preshared_key: None,
        }
    }
    
    /// Set the peer name
    pub fn with_name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }
    
    /// Set the endpoint
    pub fn with_endpoint(mut self, endpoint: SocketAddr) -> Self {
        self.endpoint = Some(endpoint);
        self
    }
    
    /// Add an allowed IP
    pub fn with_allowed_ip(mut self, ip: IpAddr, prefix: u8) -> Self {
        self.allowed_ips.push((ip, prefix));
        self
    }
    
    /// Set persistent keepalive
    pub fn with_keepalive(mut self, seconds: u16) -> Self {
        self.persistent_keepalive = Some(seconds);
        self
    }
    
    /// Set PQ public key
    pub fn with_pq_public_key(mut self, key: Vec<u8>) -> Self {
        self.pq_public_key = Some(key);
        self
    }
    
    /// Set ML-DSA public key (for pq-only mode)
    pub fn with_mldsa_public_key(mut self, key: Vec<u8>) -> Self {
        self.mldsa_public_key = Some(key);
        self
    }
}

impl TunnelConfig {
    /// Create a new tunnel config
    pub fn new(device_name: &str, private_key: [u8; 32]) -> Self {
        Self {
            device_name: device_name.to_string(),
            private_key,
            ..Default::default()
        }
    }
    
    /// Set the listen address
    pub fn with_listen_addr(mut self, addr: SocketAddr) -> Self {
        self.listen_addr = addr;
        self
    }
    
    /// Set the tunnel address
    pub fn with_address(mut self, addr: IpAddr, prefix: u8) -> Self {
        self.address = addr;
        self.netmask = prefix;
        self
    }
    
    /// Set MTU
    pub fn with_mtu(mut self, mtu: u16) -> Self {
        self.mtu = mtu;
        self
    }
    
    /// Set operating mode
    pub fn with_mode(mut self, mode: OperatingMode) -> Self {
        self.mode = mode;
        self
    }
    
    /// Add a peer
    pub fn with_peer(mut self, peer: PeerConfig) -> Self {
        self.peers.push(peer);
        self
    }
    
    /// Set PQ private key
    pub fn with_pq_private_key(mut self, key: Vec<u8>) -> Self {
        self.pq_private_key = Some(key);
        self
    }
    
    /// Set ML-DSA private key (for pq-only mode)
    pub fn with_mldsa_private_key(mut self, key: Vec<u8>) -> Self {
        self.mldsa_private_key = Some(key);
        self
    }
    
    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        // Check private key is not all zeros
        if self.private_key.iter().all(|&b| b == 0) {
            return Err("Private key is all zeros".into());
        }
        
        // Check MTU is reasonable
        if self.mtu < 576 || self.mtu > 9000 {
            return Err(format!("MTU {} is out of range (576-9000)", self.mtu));
        }
        
        // Check PQ key if hybrid mode
        if self.mode.uses_pq_kex() && self.pq_private_key.is_none() {
            return Err("PQ private key required for hybrid/pq-only mode".into());
        }
        
        // Check ML-DSA key if pq-only mode
        if self.mode.uses_pq_auth() && self.mldsa_private_key.is_none() {
            return Err("ML-DSA private key required for pq-only mode".into());
        }
        
        // Check each peer
        for (i, peer) in self.peers.iter().enumerate() {
            if peer.public_key.iter().all(|&b| b == 0) {
                return Err(format!("Peer {} has all-zero public key", i));
            }
            
            if self.mode.uses_pq_kex() && peer.pq_public_key.is_none() {
                return Err(format!("Peer {} requires PQ public key for hybrid/pq-only mode", i));
            }
            
            if self.mode.uses_pq_auth() && peer.mldsa_public_key.is_none() {
                return Err(format!("Peer {} requires ML-DSA public key for pq-only mode", i));
            }
        }
        
        Ok(())
    }
}
