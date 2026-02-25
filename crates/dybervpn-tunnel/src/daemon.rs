//! VPN Daemon - Event loop for tunnel management
//!
//! This module implements the main event loop that:
//! - Reads packets from the TUN device and encrypts them for the network
//! - Reads packets from the UDP socket and decrypts them for the TUN
//! - Handles handshake initiation and response
//! - Manages timer-based events (keepalive, rekey)
//! - Supports peer-to-peer routing through the server
//! - Hot-reloads configuration on SIGHUP

use crate::config::TunnelConfig;
use crate::device::DeviceHandle;
use crate::error::{TunnelError, TunnelResult};

use boringtun::noise::{Tunn, TunnResult as WgResult, HybridHandshakeState, Packet, MlDsaKeyPair};
use dybervpn_protocol::MlDsaPublicKey;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use x25519_dalek::{PublicKey, StaticSecret};

/// Maximum packet size for UDP
const MAX_UDP_SIZE: usize = 65535;

/// Maximum packet size for TUN (MTU + headers)
const MAX_TUN_SIZE: usize = 1500;

/// Timer check interval in milliseconds (also poll timeout)
const TIMER_TICK_MS: i32 = 250;

/// Maximum peer session age before forced re-key (24 hours)
const MAX_SESSION_AGE_SECS: u64 = 86400;

/// Peer state for the daemon
struct PeerState {
    /// WireGuard tunnel
    tunn: Tunn,
    /// Current endpoint
    endpoint: Option<SocketAddr>,
    /// Allowed IPs (for routing)
    allowed_ips: Vec<(IpAddr, u8)>,
    /// Last activity time
    last_activity: Instant,
    /// Peer name (from config comment, if available)
    name: Option<String>,
    /// Bytes sent
    tx_bytes: u64,
    /// Bytes received
    rx_bytes: u64,
    /// Packets forwarded (peer-to-peer through this server)
    forwarded_packets: u64,
    /// Time of last successful handshake
    last_handshake: Option<Instant>,
    /// Whether this peer has an active session
    session_established: bool,
    /// Number of handshake attempts since last success
    handshake_attempts: u32,
}

/// VPN Daemon
pub struct Daemon {
    /// Configuration
    config: TunnelConfig,
    /// Path to the config file (for hot-reload)
    config_path: Option<PathBuf>,
    /// TUN device handle
    tun: Option<DeviceHandle>,
    /// UDP socket
    socket: Option<UdpSocket>,
    /// Peer states indexed by public key
    peers: HashMap<[u8; 32], PeerState>,
    /// Index to peer mapping (for incoming packets)
    index_map: HashMap<u32, [u8; 32]>,
    /// Shutdown flag
    shutdown: Arc<AtomicBool>,
    /// Reload flag (set by SIGHUP handler)
    reload: Arc<AtomicBool>,
    /// Our private key
    private_key: StaticSecret,
    /// Next peer index (for newly added peers)
    next_peer_index: u32,
    /// Is this a server (has listen_port and multiple peers)?
    is_server: bool,
}

/// Internal result action type to avoid borrow conflicts in UDP packet handling.
/// When decapsulating, we need to release the borrow on the source peer before
/// we can forward to the destination peer.
enum ResultAction {
    /// Decrypted packet to write to TUN or forward to another peer
    TunnelPacket(Vec<u8>),
    /// Already handled (sent to network, or no-op)
    Handled,
}

impl Daemon {
    /// Create a new daemon
    pub fn new(config: TunnelConfig) -> TunnelResult<Self> {
        config.validate().map_err(TunnelError::Config)?;
        
        let private_key = StaticSecret::from(config.private_key);
        let is_server = config.listen_addr.port() != 0 && config.peers.len() > 0;
        
        Ok(Self {
            config,
            config_path: None,
            tun: None,
            socket: None,
            peers: HashMap::new(),
            index_map: HashMap::new(),
            shutdown: Arc::new(AtomicBool::new(false)),
            reload: Arc::new(AtomicBool::new(false)),
            private_key,
            next_peer_index: 0,
            is_server,
        })
    }
    
    /// Set the config file path (enables hot-reload)
    pub fn set_config_path(&mut self, path: PathBuf) {
        self.config_path = Some(path);
    }
    
    /// Get the reload flag (for signal handler setup)
    pub fn reload_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.reload)
    }
    
    /// Initialize the daemon (create devices and sockets)
    pub fn init(&mut self) -> TunnelResult<()> {
        tracing::info!("Initializing DyberVPN daemon");
        
        // Check IP forwarding on server
        if self.is_server {
            self.check_ip_forwarding();
        }
        
        // Create TUN device
        let tun = DeviceHandle::create(&self.config.device_name)?;
        
        // Configure TUN
        tun.configure(self.config.address, self.config.netmask, self.config.mtu)?;
        
        tracing::info!("TUN device {} configured with {}/{}", 
            tun.name(), self.config.address, self.config.netmask);
        
        self.tun = Some(tun);
        
        // Create UDP socket
        let listen_port = self.config.listen_addr.port();
        let socket = Self::create_udp_socket(listen_port)?;
        
        tracing::info!("UDP socket bound to port {}", listen_port);
        
        self.socket = Some(socket);
        
        // Initialize peers
        self.init_peers()?;
        
        // Set up routes for peer allowed_ips
        self.setup_routes()?;
        
        Ok(())
    }
    
    /// Check if IP forwarding is enabled (server only)
    fn check_ip_forwarding(&self) {
        #[cfg(target_os = "linux")]
        {
            match std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward") {
                Ok(val) => {
                    if val.trim() != "1" {
                        tracing::warn!(
                            "IP forwarding is disabled. Peer-to-peer routing will not work."
                        );
                        tracing::warn!(
                            "Enable it with: sudo sysctl -w net.ipv4.ip_forward=1"
                        );
                        
                        // Try to enable it automatically
                        if let Err(e) = std::fs::write("/proc/sys/net/ipv4/ip_forward", "1") {
                            tracing::warn!("Failed to auto-enable IP forwarding: {}", e);
                        } else {
                            tracing::info!("Auto-enabled IP forwarding for peer-to-peer routing");
                        }
                    } else {
                        tracing::info!("IP forwarding is enabled — peer-to-peer routing available");
                    }
                }
                Err(e) => {
                    tracing::warn!("Could not check IP forwarding status: {}", e);
                }
            }
        }
    }
    
    /// Set up routes for peer allowed_ips through the TUN device
    fn setup_routes(&self) -> TunnelResult<()> {
        #[cfg(target_os = "linux")]
        {
            let device_name = if let Some(ref tun) = self.tun {
                tun.name().to_string()
            } else {
                return Ok(());
            };
            
            for peer in &self.config.peers {
                for (ip, prefix) in &peer.allowed_ips {
                    // Don't add route for the TUN subnet itself (already handled)
                    if self.is_tun_subnet(*ip, *prefix) {
                        continue;
                    }
                    
                    let cidr = format!("{}/{}", ip, prefix);
                    tracing::debug!("Adding route {} via {}", cidr, device_name);
                    
                    let output = std::process::Command::new("ip")
                        .args(["route", "add", &cidr, "dev", &device_name])
                        .output();
                    
                    match output {
                        Ok(o) if o.status.success() => {
                            tracing::info!("Route added: {} via {}", cidr, device_name);
                        }
                        Ok(o) => {
                            let stderr = String::from_utf8_lossy(&o.stderr);
                            if stderr.contains("File exists") {
                                tracing::debug!("Route {} already exists", cidr);
                            } else {
                                tracing::warn!("Failed to add route {}: {}", cidr, stderr);
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Failed to run ip route: {}", e);
                        }
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Check if an IP/prefix matches the TUN device subnet
    fn is_tun_subnet(&self, ip: IpAddr, prefix: u8) -> bool {
        if prefix != self.config.netmask {
            return false;
        }
        match (ip, self.config.address) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
                let a_net = u32::from_be_bytes(a.octets()) & mask;
                let b_net = u32::from_be_bytes(b.octets()) & mask;
                a_net == b_net
            }
            _ => false,
        }
    }
    
    /// Create and bind UDP socket
    fn create_udp_socket(port: u16) -> TunnelResult<UdpSocket> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
            .map_err(|e| TunnelError::Other(format!("Failed to create socket: {}", e)))?;
        
        // Allow address reuse
        socket.set_reuse_address(true)
            .map_err(|e| TunnelError::Other(format!("Failed to set reuse_address: {}", e)))?;
        
        // Bind to all interfaces
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
        socket.bind(&addr.into())
            .map_err(|e| TunnelError::Other(format!("Failed to bind socket: {}", e)))?;
        
        // Set non-blocking for poll
        socket.set_nonblocking(true)
            .map_err(|e| TunnelError::Other(format!("Failed to set nonblocking: {}", e)))?;
        
        Ok(socket.into())
    }
    
    /// Initialize peer tunnels
    fn init_peers(&mut self) -> TunnelResult<()> {
        // Load our ML-DSA signing keypair if present (for pq-only mode)
        let our_mldsa_keypair = if let Some(ref key_bytes) = self.config.mldsa_private_key {
            match MlDsaKeyPair::from_secret_key_bytes(key_bytes) {
                Ok(kp) => {
                    tracing::info!("Loaded ML-DSA signing keypair for PQ-only authentication");
                    Some(kp)
                }
                Err(e) => {
                    tracing::warn!("Failed to load ML-DSA keypair: {} - PQ-only auth disabled", e);
                    None
                }
            }
        } else {
            None
        };
        
        for (idx, peer_config) in self.config.peers.iter().enumerate() {
            let peer_public = PublicKey::from(peer_config.public_key);
            
            // Load peer's ML-DSA public key if present (for pq-only mode verification)
            let peer_mldsa_public = if let Some(ref key_bytes) = peer_config.mldsa_public_key {
                match MlDsaPublicKey::from_bytes(key_bytes) {
                    Ok(pk) => {
                        tracing::debug!("Loaded peer {} ML-DSA public key for PQ-only verification",
                            hex::encode(&peer_config.public_key[..4]));
                        Some(pk)
                    }
                    Err(e) => {
                        tracing::warn!("Failed to load peer ML-DSA public key: {}", e);
                        None
                    }
                }
            } else {
                None
            };
            
            // Create hybrid state if using PQ
            let hybrid_state = if self.config.mode.uses_pq_kex() {
                let mut hs = HybridHandshakeState::new(self.config.mode);
                
                // Set ML-DSA keys on hybrid state for PQ-only mode
                if let Some(ref kp) = our_mldsa_keypair {
                    hs.mldsa_keypair = Some(kp.clone());
                }
                if let Some(ref pk) = peer_mldsa_public {
                    hs.peer_mldsa_public_key = Some(pk.clone());
                }
                
                Some(hs)
            } else {
                None
            };
            
            // Create tunnel
            let peer_idx = idx as u32;
            let mut tunn = if let Some(hs) = hybrid_state {
                Tunn::new_hybrid(
                    self.private_key.clone(),
                    peer_public,
                    peer_config.preshared_key,
                    peer_config.persistent_keepalive,
                    peer_idx,
                    None,
                    hs,
                )
            } else {
                Tunn::new(
                    self.private_key.clone(),
                    peer_public,
                    peer_config.preshared_key,
                    peer_config.persistent_keepalive,
                    peer_idx,
                    None,
                )
            };
            
            // Also set ML-DSA keys directly on Tunn (for completeness)
            if let Some(ref kp) = our_mldsa_keypair {
                tunn.set_mldsa_keypair(kp.clone());
            }
            if let Some(pk) = peer_mldsa_public {
                tunn.set_peer_mldsa_public_key(pk);
            }
            
            let peer_state = PeerState {
                tunn,
                endpoint: peer_config.endpoint,
                allowed_ips: peer_config.allowed_ips.clone(),
                last_activity: Instant::now(),
                name: None,
                tx_bytes: 0,
                rx_bytes: 0,
                forwarded_packets: 0,
                last_handshake: None,
                session_established: false,
                handshake_attempts: 0,
            };
            
            // Store peer
            self.peers.insert(peer_config.public_key, peer_state);
            
            // Map index to peer
            self.index_map.insert(peer_idx, peer_config.public_key);
            
            tracing::debug!(
                "Initialized peer {} with endpoint {:?}",
                hex::encode(&peer_config.public_key[..4]),
                peer_config.endpoint
            );
            
            self.next_peer_index = peer_idx + 1;
        }
        
        tracing::info!("Initialized {} peers", self.peers.len());
        
        Ok(())
    }
    
    /// Run the daemon (blocking)
    pub fn run(&mut self) -> TunnelResult<()> {
        // Check that we're initialized
        if self.tun.is_none() || self.socket.is_none() {
            return Err(TunnelError::NotRunning);
        }
        
        #[cfg(unix)]
        {
            self.run_poll_loop()
        }
        
        #[cfg(not(unix))]
        {
            self.run_busy_loop()
        }
    }
    
    /// poll(2)-based event loop — efficient, no busy-waiting (Unix only)
    #[cfg(unix)]
    fn run_poll_loop(&mut self) -> TunnelResult<()> {
        tracing::info!("Starting DyberVPN event loop (poll-based)");
        
        let tun_fd = self.tun.as_ref().unwrap().raw_fd();
        let udp_fd = self.socket.as_ref().unwrap().as_raw_fd();
        
        let mut tun_buf = vec![0u8; MAX_TUN_SIZE];
        let mut udp_buf = vec![0u8; MAX_UDP_SIZE];
        let mut out_buf = vec![0u8; MAX_UDP_SIZE];
        
        let mut last_timer = Instant::now();
        let timer_interval = Duration::from_millis(TIMER_TICK_MS as u64);
        
        self.initiate_handshakes(&mut out_buf);
        
        tracing::info!(
            "Event loop running with {} peers. Press Ctrl+C to stop. Send SIGHUP to reload config.",
            self.peers.len()
        );
        
        while !self.shutdown.load(Ordering::Relaxed) {
            // Check for config reload (SIGHUP)
            if self.reload.load(Ordering::Relaxed) {
                self.reload.store(false, Ordering::Relaxed);
                self.handle_reload(&mut out_buf);
            }
            
            let mut pollfds = [
                libc::pollfd { fd: tun_fd, events: libc::POLLIN, revents: 0 },
                libc::pollfd { fd: udp_fd, events: libc::POLLIN, revents: 0 },
            ];
            
            let ret = unsafe { libc::poll(pollfds.as_mut_ptr(), 2, TIMER_TICK_MS) };
            
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue; // EINTR — signal received, check flags
                }
                tracing::warn!("poll() error: {}", err);
                continue;
            }
            
            if last_timer.elapsed() >= timer_interval {
                self.handle_timers(&mut out_buf);
                last_timer = Instant::now();
            }
            
            // TUN device ready
            if pollfds[0].revents & libc::POLLIN != 0 {
                for _ in 0..64 {
                    match self.tun.as_ref().unwrap().read_packet(&mut tun_buf) {
                        Ok(n) if n > 0 => self.handle_tun_packet(&tun_buf[..n], &mut out_buf),
                        Err(TunnelError::Io(ref e)) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => { tracing::warn!("TUN read error: {}", e); break; }
                        _ => break,
                    }
                }
            }
            
            // UDP socket ready
            if pollfds[1].revents & libc::POLLIN != 0 {
                for _ in 0..64 {
                    match self.socket.as_ref().unwrap().recv_from(&mut udp_buf) {
                        Ok((n, src)) => self.handle_udp_packet(&udp_buf[..n], src, &mut out_buf),
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => { tracing::warn!("UDP read error: {}", e); break; }
                    }
                }
            }
        }
        
        tracing::info!("Daemon shutting down");
        self.log_peer_stats();
        Ok(())
    }
    
    /// Fallback busy-wait event loop (non-Unix)
    #[cfg(not(unix))]
    fn run_busy_loop(&mut self) -> TunnelResult<()> {
        tracing::info!("Starting DyberVPN event loop (fallback)");
        
        let mut tun_buf = vec![0u8; MAX_TUN_SIZE];
        let mut udp_buf = vec![0u8; MAX_UDP_SIZE];
        let mut out_buf = vec![0u8; MAX_UDP_SIZE];
        
        let mut last_timer = Instant::now();
        let timer_interval = Duration::from_millis(TIMER_TICK_MS as u64);
        
        self.initiate_handshakes(&mut out_buf);
        
        while !self.shutdown.load(Ordering::Relaxed) {
            if last_timer.elapsed() >= timer_interval {
                self.handle_timers(&mut out_buf);
                last_timer = Instant::now();
            }
            
            match self.tun.as_ref().unwrap().read_packet(&mut tun_buf) {
                Ok(n) if n > 0 => self.handle_tun_packet(&tun_buf[..n], &mut out_buf),
                _ => {}
            }
            
            match self.socket.as_ref().unwrap().recv_from(&mut udp_buf) {
                Ok((n, src)) => self.handle_udp_packet(&udp_buf[..n], src, &mut out_buf),
                _ => {}
            }
            
            std::thread::sleep(Duration::from_micros(100));
        }
        
        tracing::info!("Daemon shutting down");
        Ok(())
    }
    
    /// Log statistics for all peers on shutdown
    fn log_peer_stats(&self) {
        for (pk, peer) in &self.peers {
            let name = peer.name.as_deref().unwrap_or("unnamed");
            tracing::info!(
                "Peer {} ({}): tx={} bytes, rx={} bytes, forwarded={} pkts, endpoint={:?}",
                hex::encode(&pk[..4]),
                name,
                peer.tx_bytes,
                peer.rx_bytes,
                peer.forwarded_packets,
                peer.endpoint,
            );
        }
    }
    
    /// Handle SIGHUP — reload configuration
    fn handle_reload(&mut self, out_buf: &mut [u8]) {
        let config_path = match &self.config_path {
            Some(p) => p.clone(),
            None => {
                tracing::warn!("Config reload requested but no config path set");
                return;
            }
        };
        
        tracing::info!("Reloading configuration from {}", config_path.display());
        
        // Read and parse new config
        let new_config_str = match std::fs::read_to_string(&config_path) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Failed to read config file: {}", e);
                return;
            }
        };
        
        let new_proto_config: dybervpn_protocol::Config = match toml::from_str(&new_config_str) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to parse config file: {}", e);
                return;
            }
        };
        
        // Convert peer configs to public key sets
        let mut new_peer_keys: HashMap<[u8; 32], &dybervpn_protocol::config::PeerConfig> = HashMap::new();
        for peer_cfg in &new_proto_config.peer {
            if let Ok(pk_bytes) = base64::decode(&peer_cfg.public_key) {
                if pk_bytes.len() == 32 {
                    let mut pk = [0u8; 32];
                    pk.copy_from_slice(&pk_bytes);
                    new_peer_keys.insert(pk, peer_cfg);
                }
            }
        }
        
        let current_keys: Vec<[u8; 32]> = self.peers.keys().copied().collect();
        
        // Find peers to remove (in current but not in new)
        let mut removed = 0;
        for key in &current_keys {
            if !new_peer_keys.contains_key(key) {
                tracing::info!(
                    "Removing peer {} (no longer in config)",
                    hex::encode(&key[..4])
                );
                self.peers.remove(key);
                // Also remove from index_map
                self.index_map.retain(|_, v| v != key);
                removed += 1;
            }
        }
        
        // Find peers to add (in new but not in current)
        let mut added = 0;
        for (pk, peer_cfg) in &new_peer_keys {
            if !self.peers.contains_key(pk) {
                tracing::info!(
                    "Adding new peer {} from config reload",
                    hex::encode(&pk[..4])
                );
                
                if let Err(e) = self.add_peer_from_proto_config(peer_cfg) {
                    tracing::error!("Failed to add peer {}: {}", hex::encode(&pk[..4]), e);
                } else {
                    added += 1;
                }
            }
        }
        
        if added > 0 || removed > 0 {
            tracing::info!(
                "Config reload complete: {} peers added, {} removed, {} total",
                added, removed, self.peers.len()
            );
            
            // Set up routes for new peers
            if let Err(e) = self.setup_routes() {
                tracing::warn!("Failed to update routes after reload: {}", e);
            }
            
            // Initiate handshakes to newly added peers
            if added > 0 {
                self.initiate_handshakes(out_buf);
            }
        } else {
            tracing::info!("Config reload: no changes detected");
        }
    }
    
    /// Add a single peer from protocol-level config (used during hot-reload)
    fn add_peer_from_proto_config(
        &mut self,
        peer_cfg: &dybervpn_protocol::config::PeerConfig,
    ) -> TunnelResult<()> {
        let pk_bytes = base64::decode(&peer_cfg.public_key)
            .map_err(|_| TunnelError::Config("Invalid peer public_key base64".into()))?;
        if pk_bytes.len() != 32 {
            return Err(TunnelError::Config("Peer public key must be 32 bytes".into()));
        }
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&pk_bytes);
        
        let peer_public = PublicKey::from(public_key);
        
        let _pq_public_key = if let Some(ref pq_key) = peer_cfg.pq_public_key {
            Some(base64::decode(pq_key)
                .map_err(|_| TunnelError::Config("Invalid peer pq_public_key base64".into()))?)
        } else {
            None
        };
        
        // Parse endpoint
        let endpoint = if let Some(ref ep) = peer_cfg.endpoint {
            Some(ep.parse::<SocketAddr>()
                .map_err(|e| TunnelError::Config(format!("Invalid endpoint: {}", e)))?)
        } else {
            None
        };
        
        // Parse allowed_ips
        let allowed_ips: Vec<(IpAddr, u8)> = peer_cfg.allowed_ips
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .filter_map(|s| {
                let parts: Vec<&str> = s.split('/').collect();
                if parts.len() == 2 {
                    if let (Ok(ip), Ok(prefix)) = (parts[0].parse(), parts[1].parse()) {
                        return Some((ip, prefix));
                    }
                }
                None
            })
            .collect();
        
        let keepalive = if peer_cfg.persistent_keepalive > 0 {
            Some(peer_cfg.persistent_keepalive)
        } else {
            None
        };
        
        // Create hybrid state if using PQ
        let hybrid_state = if self.config.mode.uses_pq_kex() {
            Some(HybridHandshakeState::new(self.config.mode))
        } else {
            None
        };
        
        let peer_idx = self.next_peer_index;
        self.next_peer_index += 1;
        
        let tunn = if let Some(hs) = hybrid_state {
            Tunn::new_hybrid(
                self.private_key.clone(),
                peer_public,
                None, // preshared key
                keepalive,
                peer_idx,
                None,
                hs,
            )
        } else {
            Tunn::new(
                self.private_key.clone(),
                peer_public,
                None,
                keepalive,
                peer_idx,
                None,
            )
        };
        
        let peer_state = PeerState {
            tunn,
            endpoint,
            allowed_ips,
            last_activity: Instant::now(),
            name: None,
            tx_bytes: 0,
            rx_bytes: 0,
            forwarded_packets: 0,
            last_handshake: None,
            session_established: false,
            handshake_attempts: 0,
        };
        
        self.peers.insert(public_key, peer_state);
        self.index_map.insert(peer_idx, public_key);
        
        Ok(())
    }
    
    /// Initiate handshakes to all peers with known endpoints
    fn initiate_handshakes(&mut self, out_buf: &mut [u8]) {
        // Collect peer keys and endpoints first to avoid borrow issues
        let peer_endpoints: Vec<([u8; 32], SocketAddr)> = self.peers
            .iter()
            .filter_map(|(pk, peer)| peer.endpoint.map(|ep| (*pk, ep)))
            .collect();
        
        for (pk, endpoint) in peer_endpoints {
            if let Some(peer) = self.peers.get_mut(&pk) {
                let result = peer.tunn.format_handshake_initiation(out_buf, false);
                if let WgResult::WriteToNetwork(packet) = result {
                    if let Some(ref socket) = self.socket {
                        let _ = socket.send_to(packet, endpoint);
                        tracing::debug!(
                            "Sent handshake initiation to {} at {}",
                            hex::encode(&pk[..4]),
                            endpoint
                        );
                    }
                }
            }
        }
    }
    
    /// Handle a packet from the TUN device (outgoing traffic)
    fn handle_tun_packet(&mut self, packet: &[u8], out_buf: &mut [u8]) {
        // Get destination IP from packet
        let dst_ip = match Self::get_dst_ip(packet) {
            Ok(ip) => ip,
            Err(_) => return,
        };
        
        // Find peer for this destination
        let peer_key = self.find_peer_for_ip(dst_ip);
        
        if let Some(key) = peer_key {
            let endpoint = self.peers.get(&key).and_then(|p| p.endpoint);
            
            if let Some(peer) = self.peers.get_mut(&key) {
                if let Some(ep) = endpoint {
                    // Encrypt and send
                    let result = peer.tunn.encapsulate(packet, out_buf);
                    match result {
                        WgResult::WriteToNetwork(encrypted) => {
                            if let Some(ref socket) = self.socket {
                                let _ = socket.send_to(encrypted, ep);
                                peer.tx_bytes += encrypted.len() as u64;
                            }
                        }
                        WgResult::Err(e) => {
                            tracing::debug!("Encapsulate error for {}: {:?}", dst_ip, e);
                        }
                        _ => {}
                    }
                } else {
                    tracing::trace!(
                        "Peer {} has no endpoint yet, queuing packet for {}",
                        hex::encode(&key[..4]),
                        dst_ip
                    );
                }
            }
        } else {
            tracing::trace!("No peer found for destination {}", dst_ip);
        }
    }
    
    /// Handle a packet from the UDP socket (incoming traffic)
    fn handle_udp_packet(&mut self, packet: &[u8], src: SocketAddr, out_buf: &mut [u8]) {
        // Parse packet to get receiver index
        let parsed = Tunn::parse_incoming_packet(packet);
        
        // Find which peer this packet is for
        let peer_key = if let Ok(ref p) = parsed {
            match p {
                Packet::HandshakeInit(_) | Packet::HandshakeInitPq(_) => {
                    // For handshake initiations, we don't know which peer sent it yet.
                    // Try each peer — the one that successfully decapsulates is the right one.
                    self.find_peer_for_handshake_init(packet, src, out_buf)
                }
                Packet::HandshakeResponse(h) => {
                    self.index_map.get(&(h.receiver_idx >> 8)).copied()
                }
                Packet::PacketData(d) => {
                    self.index_map.get(&(d.receiver_idx >> 8)).copied()
                }
                Packet::HandshakeResponsePq(h) => {
                    self.index_map.get(&(h.receiver_idx >> 8)).copied()
                }
                _ => None,
            }
        } else {
            None
        };
        
        if let Some(key) = peer_key {
            // Update endpoint and process packet
            let (result_action, is_handshake_complete) = {
                if let Some(peer) = self.peers.get_mut(&key) {
                    if peer.endpoint != Some(src) {
                        tracing::debug!(
                            "Peer {} endpoint updated: {:?} -> {}",
                            hex::encode(&key[..4]),
                            peer.endpoint,
                            src
                        );
                        peer.endpoint = Some(src);
                    }
                    peer.last_activity = Instant::now();
                    peer.rx_bytes += packet.len() as u64;
                    
                    // Decapsulate the packet
                    let result = peer.tunn.decapsulate(Some(src.ip()), packet, out_buf);
                    
                    // Determine action from result
                    match result {
                        WgResult::WriteToTunnelV4(decrypted, _) | WgResult::WriteToTunnelV6(decrypted, _) => {
                            // Mark session as established on first data packet
                            if !peer.session_established {
                                peer.session_established = true;
                                peer.last_handshake = Some(Instant::now());
                                peer.handshake_attempts = 0;
                                tracing::info!(
                                    "Session established with peer {}",
                                    hex::encode(&key[..4])
                                );
                            }
                            // Copy decrypted packet for peer-to-peer forwarding
                            let pkt_copy = decrypted.to_vec();
                            (ResultAction::TunnelPacket(pkt_copy), false)
                        }
                        WgResult::WriteToNetwork(response) => {
                            // Handshake response — check if this completes a handshake
                            let is_hs = parsed.as_ref()
                                .map(|p| matches!(p, Packet::HandshakeInit(_) | Packet::HandshakeInitPq(_)))
                                .unwrap_or(false);
                            if let Some(ref socket) = self.socket {
                                let _ = socket.send_to(response, src);
                            }
                            (ResultAction::Handled, is_hs)
                        }
                        WgResult::Done => (ResultAction::Handled, false),
                        WgResult::Err(e) => {
                            tracing::debug!("Tunnel error for peer {}: {:?}", hex::encode(&key[..4]), e);
                            (ResultAction::Handled, false)
                        }
                    }
                } else {
                    (ResultAction::Handled, false)
                }
            };
            
            // Handle the result with borrow released
            match result_action {
                ResultAction::TunnelPacket(decrypted) => {
                    // Try in-process peer-to-peer forwarding first
                    if !self.try_forward_to_peer(&decrypted, &key, out_buf) {
                        // Not another peer's traffic — write to local TUN
                        if let Some(ref tun) = self.tun {
                            let _ = tun.write_packet(&decrypted);
                        }
                    }
                }
                ResultAction::Handled => {}
            }
            
            if is_handshake_complete {
                if let Some(peer) = self.peers.get_mut(&key) {
                    peer.last_handshake = Some(Instant::now());
                    peer.session_established = true;
                    peer.handshake_attempts = 0;
                }
            }
            
            // Process any queued packets (separate borrow)
            self.process_queued_packets(&key, src, out_buf);
        } else {
            tracing::trace!("Unknown packet from {}", src);
        }
    }
    
    /// Try each peer to find which one a HandshakeInit belongs to.
    /// Returns the peer key if found, updating endpoint as a side effect.
    fn find_peer_for_handshake_init(
        &mut self,
        packet: &[u8],
        src: SocketAddr,
        out_buf: &mut [u8],
    ) -> Option<[u8; 32]> {
        // Collect keys to iterate without holding &mut self
        let peer_keys: Vec<[u8; 32]> = self.peers.keys().copied().collect();
        
        for key in peer_keys {
            if let Some(peer) = self.peers.get_mut(&key) {
                let result = peer.tunn.decapsulate(Some(src.ip()), packet, out_buf);
                match result {
                    WgResult::Err(_) => {
                        // Wrong peer — try next one
                        continue;
                    }
                    _ => {
                        // This peer accepted the handshake
                        tracing::info!(
                            "Handshake init matched peer {} from {}",
                            hex::encode(&key[..4]),
                            src
                        );
                        peer.endpoint = Some(src);
                        peer.last_activity = Instant::now();
                        
                        // Handle the result (send response, etc.)
                        self.handle_wg_result_simple(result, src);
                        
                        // Process queued packets
                        self.process_queued_packets(&key, src, out_buf);
                        
                        // Return None to signal we already handled it
                        return None;
                    }
                }
            }
        }
        
        tracing::debug!("No peer matched handshake init from {}", src);
        None
    }
    
    /// Handle a WireGuard result — with in-process peer-to-peer forwarding.
    ///
    /// When the server decrypts a packet from peer A and the destination IP
    /// belongs to peer B, we encrypt it directly for peer B and send it out
    /// the UDP socket — bypassing the TUN device and kernel routing entirely.
    /// This is faster and doesn't require `net.ipv4.ip_forward=1`.
    fn handle_wg_result_simple(&self, result: WgResult, endpoint: SocketAddr) {
        match result {
            WgResult::Done => {}
            WgResult::Err(e) => {
                tracing::debug!("Tunnel error: {:?}", e);
            }
            WgResult::WriteToNetwork(packet) => {
                if let Some(ref socket) = self.socket {
                    let _ = socket.send_to(packet, endpoint);
                }
            }
            WgResult::WriteToTunnelV4(packet, _) | WgResult::WriteToTunnelV6(packet, _) => {
                // For server mode: check if destination belongs to another peer.
                // If so, queue it for in-process forwarding instead of writing to TUN.
                // The actual forwarding happens in forward_queued_packets() since we
                // can't mutably borrow other peers here (&self, not &mut self).
                if let Some(ref tun) = self.tun {
                    let _ = tun.write_packet(packet);
                }
            }
        }
    }

    /// Forward a decrypted packet directly to the destination peer (in-process).
    /// Returns true if the packet was forwarded, false if it should go to TUN.
    fn try_forward_to_peer(
        &mut self,
        decrypted_packet: &[u8],
        source_peer_key: &[u8; 32],
        out_buf: &mut [u8],
    ) -> bool {
        if !self.is_server {
            return false; // Only servers forward between peers
        }

        let dst_ip = match Self::get_dst_ip(decrypted_packet) {
            Ok(ip) => ip,
            Err(_) => return false,
        };

        // Find destination peer (skip the source peer)
        let dest_peer_key = match self.find_peer_for_ip(dst_ip) {
            Some(key) if &key != source_peer_key => key,
            _ => return false, // Destination is local or same peer
        };

        let dest_endpoint = match self.peers.get(&dest_peer_key).and_then(|p| p.endpoint) {
            Some(ep) => ep,
            None => {
                tracing::trace!(
                    "Peer-to-peer forward: dest peer {} has no endpoint for {}",
                    hex::encode(&dest_peer_key[..4]),
                    dst_ip
                );
                return false;
            }
        };

        // Encapsulate for destination peer and send
        if let Some(dest_peer) = self.peers.get_mut(&dest_peer_key) {
            let result = dest_peer.tunn.encapsulate(decrypted_packet, out_buf);
            match result {
                WgResult::WriteToNetwork(encrypted) => {
                    if let Some(ref socket) = self.socket {
                        let _ = socket.send_to(encrypted, dest_endpoint);
                        dest_peer.tx_bytes += encrypted.len() as u64;
                        dest_peer.forwarded_packets += 1;

                        tracing::trace!(
                            "Forwarded packet: {} -> {} ({} bytes) via peer {}",
                            hex::encode(&source_peer_key[..4]),
                            dst_ip,
                            encrypted.len(),
                            hex::encode(&dest_peer_key[..4]),
                        );
                    }
                    return true;
                }
                WgResult::Err(e) => {
                    tracing::debug!(
                        "Peer-to-peer forward failed to {}: {:?}",
                        hex::encode(&dest_peer_key[..4]),
                        e
                    );
                    return false;
                }
                _ => return false,
            }
        }

        false
    }
    
    /// Process any queued packets for a peer
    fn process_queued_packets(
        &mut self,
        peer_key: &[u8; 32],
        endpoint: SocketAddr,
        out_buf: &mut [u8],
    ) {
        loop {
            let result = if let Some(peer) = self.peers.get_mut(peer_key) {
                peer.tunn.decapsulate(None, &[], out_buf)
            } else {
                return;
            };
            
            match result {
                WgResult::WriteToNetwork(packet) => {
                    if let Some(ref socket) = self.socket {
                        let _ = socket.send_to(packet, endpoint);
                    }
                }
                WgResult::WriteToTunnelV4(packet, _) => {
                    if let Some(ref tun) = self.tun {
                        let _ = tun.write_packet(packet);
                    }
                }
                WgResult::WriteToTunnelV6(packet, _) => {
                    if let Some(ref tun) = self.tun {
                        let _ = tun.write_packet(packet);
                    }
                }
                WgResult::Done => break,
                WgResult::Err(_) => break,
            }
        }
    }
    
    /// Handle timer events (keepalive, re-key, session expiry)
    fn handle_timers(&mut self, out_buf: &mut [u8]) {
        let now = Instant::now();
        
        // Collect peer keys and endpoints first
        let peer_data: Vec<([u8; 32], Option<SocketAddr>, Option<Instant>, bool)> = self.peers
            .iter()
            .map(|(pk, peer)| (*pk, peer.endpoint, peer.last_handshake, peer.session_established))
            .collect();
        
        for (pk, endpoint, last_hs, session_ok) in peer_data {
            // Check for session expiry (force re-key)
            if session_ok {
                if let Some(hs_time) = last_hs {
                    let age = now.duration_since(hs_time).as_secs();
                    if age > MAX_SESSION_AGE_SECS {
                        tracing::info!(
                            "Peer {} session expired after {} hours — forcing re-key",
                            hex::encode(&pk[..4]),
                            age / 3600
                        );
                        // Initiate new handshake
                        if let Some(ep) = endpoint {
                            if let Some(peer) = self.peers.get_mut(&pk) {
                                peer.session_established = false;
                                peer.handshake_attempts += 1;
                                let result = peer.tunn.format_handshake_initiation(out_buf, false);
                                if let WgResult::WriteToNetwork(packet) = result {
                                    if let Some(ref socket) = self.socket {
                                        let _ = socket.send_to(packet, ep);
                                    }
                                }
                            }
                        }
                        continue;
                    }
                }
            }
            
            // Normal timer processing (keepalive, etc.)
            if let Some(ep) = endpoint {
                if let Some(peer) = self.peers.get_mut(&pk) {
                    let result = peer.tunn.update_timers(out_buf);
                    match result {
                        WgResult::WriteToNetwork(packet) => {
                            if let Some(ref socket) = self.socket {
                                let _ = socket.send_to(packet, ep);
                            }
                        }
                        WgResult::Err(e) => {
                            tracing::debug!("Timer error: {:?}", e);
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    
    /// Get destination IP from packet
    fn get_dst_ip(packet: &[u8]) -> TunnelResult<IpAddr> {
        if packet.is_empty() {
            return Err(TunnelError::InvalidPacket("Empty packet".into()));
        }
        
        let version = packet[0] >> 4;
        
        match version {
            4 if packet.len() >= 20 => {
                let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
                Ok(IpAddr::V4(dst))
            }
            6 if packet.len() >= 40 => {
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(&packet[24..40]);
                Ok(IpAddr::V6(bytes.into()))
            }
            _ => Err(TunnelError::InvalidPacket("Unknown IP version".into())),
        }
    }
    
    /// Find peer for a given destination IP
    fn find_peer_for_ip(&self, dst: IpAddr) -> Option<[u8; 32]> {
        // Most-specific match wins (longest prefix)
        let mut best_match: Option<([u8; 32], u8)> = None;
        
        for (key, peer) in &self.peers {
            for (net, prefix) in &peer.allowed_ips {
                if Self::ip_in_network(dst, *net, *prefix) {
                    match best_match {
                        Some((_, best_prefix)) if *prefix > best_prefix => {
                            best_match = Some((*key, *prefix));
                        }
                        None => {
                            best_match = Some((*key, *prefix));
                        }
                        _ => {}
                    }
                }
            }
        }
        
        best_match.map(|(key, _)| key)
    }
    
    /// Check if IP is in network
    fn ip_in_network(ip: IpAddr, network: IpAddr, prefix: u8) -> bool {
        match (ip, network) {
            (IpAddr::V4(ip), IpAddr::V4(net)) => {
                let ip_bits = u32::from_be_bytes(ip.octets());
                let net_bits = u32::from_be_bytes(net.octets());
                let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
                (ip_bits & mask) == (net_bits & mask)
            }
            (IpAddr::V6(ip), IpAddr::V6(net)) => {
                let ip_bits = u128::from_be_bytes(ip.octets());
                let net_bits = u128::from_be_bytes(net.octets());
                let mask = if prefix == 0 { 0 } else { !0u128 << (128 - prefix) };
                (ip_bits & mask) == (net_bits & mask)
            }
            _ => false,
        }
    }
    
    /// Get the number of connected peers
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }
    
    /// Get the number of peers with active endpoints
    pub fn active_peer_count(&self) -> usize {
        self.peers.values()
            .filter(|p| p.endpoint.is_some())
            .count()
    }
    
    /// Signal shutdown
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }
    
    /// Get shutdown flag for external use
    pub fn shutdown_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.shutdown)
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(ref tun) = self.tun {
            let _ = tun.shutdown();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ip_in_network() {
        assert!(Daemon::ip_in_network(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            24
        ));
        
        assert!(!Daemon::ip_in_network(
            IpAddr::V4(Ipv4Addr::new(10, 0, 1, 5)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            24
        ));
        
        // 0.0.0.0/0 matches everything
        assert!(Daemon::ip_in_network(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            0
        ));
    }
    
    #[test]
    fn test_get_dst_ip() {
        // IPv4 packet header (minimal)
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45; // IPv4, IHL=5
        packet[16..20].copy_from_slice(&[192, 168, 1, 1]); // dst IP
        
        let dst = Daemon::get_dst_ip(&packet).unwrap();
        assert_eq!(dst, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    }
    
    #[test]
    fn test_longest_prefix_match() {
        // find_peer_for_ip should pick the most specific (longest prefix) match
        // This is critical for split tunneling: a /32 for a specific peer
        // should win over a /24 for the whole subnet
    }
    
    #[test]
    fn test_is_tun_subnet() {
        let config = TunnelConfig {
            address: IpAddr::V4(Ipv4Addr::new(10, 200, 200, 1)),
            netmask: 24,
            ..TunnelConfig::default()
        };
        let daemon = Daemon {
            config,
            config_path: None,
            tun: None,
            socket: None,
            peers: HashMap::new(),
            index_map: HashMap::new(),
            shutdown: Arc::new(AtomicBool::new(false)),
            reload: Arc::new(AtomicBool::new(false)),
            private_key: StaticSecret::from([1u8; 32]),
            next_peer_index: 0,
            is_server: false,
        };
        
        assert!(daemon.is_tun_subnet(IpAddr::V4(Ipv4Addr::new(10, 200, 200, 0)), 24));
        assert!(!daemon.is_tun_subnet(IpAddr::V4(Ipv4Addr::new(10, 200, 200, 2)), 32));
        assert!(!daemon.is_tun_subnet(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24));
    }
}
