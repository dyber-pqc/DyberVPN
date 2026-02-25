//! VPN Daemon - Event loop for tunnel management
//!
//! This module implements the main event loop that:
//! - Reads packets from the TUN device and encrypts them for the network
//! - Reads packets from the UDP socket and decrypts them for the TUN
//! - Handles handshake initiation and response
//! - Manages timer-based events (keepalive, rekey)
//! - Supports peer-to-peer routing through the server
//! - Hot-reloads configuration on SIGHUP
//! - **Enforces per-peer access control policies**
//! - **Checks key revocation status on every handshake**
//! - **Emits structured audit events for compliance**

use crate::audit::{
    AuditConfig, AuditLogger, EventOutcome, EventType,
};
use crate::config::TunnelConfig;
use crate::device::DeviceHandle;
use crate::error::{TunnelError, TunnelResult};
use crate::policy::{self, PolicyAction, PolicyConfig, PolicyEngine};
use crate::revocation::{KeyStatus, RevocationEngine, SecurityConfig};

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
    /// Packets denied by policy
    policy_denied_packets: u64,
    /// Time of last successful handshake
    last_handshake: Option<Instant>,
    /// Whether this peer has an active session
    session_established: bool,
    /// Number of handshake attempts since last success
    handshake_attempts: u32,
    /// Time this peer was first seen (for key age tracking)
    first_seen: Instant,
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

    // ── Enterprise subsystems ────────────────────────────────────────
    /// Access control policy engine
    policy: PolicyEngine,
    /// Key revocation engine
    revocation: RevocationEngine,
    /// Structured audit logger
    audit: AuditLogger,
    /// Last time we ran the revocation/expiry check
    last_revocation_check: Instant,
    /// Last time we ran the FIPS 140-3 CRNGT (continuous entropy health check)
    last_crngt_check: Instant,
}

/// Internal result action type to avoid borrow conflicts in UDP packet handling.
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
            policy: PolicyEngine::disabled(),
            revocation: RevocationEngine::disabled(),
            audit: AuditLogger::disabled(),
            last_revocation_check: Instant::now(),
            last_crngt_check: Instant::now(),
        })
    }

    /// Configure the policy engine from protocol config
    pub fn set_policy(&mut self, config: PolicyConfig) {
        self.policy = PolicyEngine::new(&config);
        if config.enabled {
            tracing::info!("Access control policy engine enabled (default: {})", config.default_action);
        }
    }

    /// Configure the revocation engine from protocol config
    pub fn set_revocation(&mut self, config: SecurityConfig) {
        self.revocation = RevocationEngine::new(config);
    }

    /// Configure the audit logger
    pub fn set_audit(&mut self, config: AuditConfig) {
        self.audit = AuditLogger::new(config);
    }
    
    /// Set the config file path (enables hot-reload)
    pub fn set_config_path(&mut self, path: PathBuf) {
        self.config_path = Some(path);
    }
    
    /// Get the reload flag (for signal handler setup)
    pub fn reload_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.reload)
    }

    /// Get a reference to the audit logger (for enrollment server, etc.)
    pub fn audit_logger(&self) -> &AuditLogger {
        &self.audit
    }
    
    /// Initialize the daemon (create devices and sockets)
    pub fn init(&mut self) -> TunnelResult<()> {
        tracing::info!("Initializing DyberVPN daemon");
        
        // ================================================================
        // FIPS 140-3: Run power-on self-tests BEFORE any crypto operations
        // ================================================================
        let backend = dybervpn_protocol::select_backend();
        let fips_report = dybervpn_protocol::fips::run_power_on_self_tests(backend.as_ref());
        if !fips_report.passed {
            tracing::error!("FIPS 140-3 self-tests FAILED — refusing to start");
            for result in &fips_report.results {
                if !result.passed {
                    tracing::error!("  FAILED: {} — {:?}", result.name, result.error);
                }
            }
            return Err(TunnelError::Config(
                "FIPS 140-3 cryptographic self-tests failed. Module cannot start.".to_string()
            ));
        }
        tracing::info!(
            "FIPS 140-3 self-tests passed ({} tests in {:.2?})",
            fips_report.results.len(), fips_report.duration
        );
        self.audit.log_admin_action(
            EventType::DaemonStarted,
            &format!("FIPS 140-3 POST passed: {} tests in {:.2?}",
                fips_report.results.len(), fips_report.duration),
        );
        
        if self.is_server {
            self.check_ip_forwarding();
        }
        
        let tun = DeviceHandle::create(&self.config.device_name)?;
        tun.configure(self.config.address, self.config.netmask, self.config.mtu)?;
        tracing::info!("TUN device {} configured with {}/{}", 
            tun.name(), self.config.address, self.config.netmask);
        self.tun = Some(tun);
        
        let listen_port = self.config.listen_addr.port();
        let socket = Self::create_udp_socket(listen_port)?;
        tracing::info!("UDP socket bound to port {}", listen_port);
        self.socket = Some(socket);
        
        self.init_peers()?;
        self.setup_routes()?;
        
        // Audit: daemon started
        let mode = format!("{:?}", self.config.mode).to_lowercase();
        self.audit.log_daemon_started(&mode, self.peers.len());
        
        Ok(())
    }
    
    fn check_ip_forwarding(&self) {
        #[cfg(target_os = "linux")]
        {
            match std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward") {
                Ok(val) => {
                    if val.trim() != "1" {
                        tracing::warn!("IP forwarding is disabled. Peer-to-peer routing will not work.");
                        if let Err(e) = std::fs::write("/proc/sys/net/ipv4/ip_forward", "1") {
                            tracing::warn!("Failed to auto-enable IP forwarding: {}", e);
                        } else {
                            tracing::info!("Auto-enabled IP forwarding for peer-to-peer routing");
                        }
                    }
                }
                Err(e) => tracing::warn!("Could not check IP forwarding status: {}", e),
            }
        }
    }
    
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
                    if self.is_tun_subnet(*ip, *prefix) { continue; }
                    let cidr = format!("{}/{}", ip, prefix);
                    let output = std::process::Command::new("ip")
                        .args(["route", "add", &cidr, "dev", &device_name])
                        .output();
                    match output {
                        Ok(o) if o.status.success() => {
                            tracing::info!("Route added: {} via {}", cidr, device_name);
                        }
                        Ok(o) => {
                            let stderr = String::from_utf8_lossy(&o.stderr);
                            if !stderr.contains("File exists") {
                                tracing::warn!("Failed to add route {}: {}", cidr, stderr);
                            }
                        }
                        Err(e) => tracing::warn!("Failed to run ip route: {}", e),
                    }
                }
            }
        }
        Ok(())
    }
    
    fn is_tun_subnet(&self, ip: IpAddr, prefix: u8) -> bool {
        if prefix != self.config.netmask { return false; }
        match (ip, self.config.address) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
                (u32::from_be_bytes(a.octets()) & mask) == (u32::from_be_bytes(b.octets()) & mask)
            }
            _ => false,
        }
    }
    
    fn create_udp_socket(port: u16) -> TunnelResult<UdpSocket> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
            .map_err(|e| TunnelError::Other(format!("Failed to create socket: {}", e)))?;
        socket.set_reuse_address(true)
            .map_err(|e| TunnelError::Other(format!("set reuse_address: {}", e)))?;
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
        socket.bind(&addr.into())
            .map_err(|e| TunnelError::Other(format!("bind: {}", e)))?;
        socket.set_nonblocking(true)
            .map_err(|e| TunnelError::Other(format!("set nonblocking: {}", e)))?;
        Ok(socket.into())
    }
    
    /// Initialize peer tunnels
    fn init_peers(&mut self) -> TunnelResult<()> {
        let our_mldsa_keypair = if let Some(ref key_bytes) = self.config.mldsa_private_key {
            match MlDsaKeyPair::from_secret_key_bytes(key_bytes) {
                Ok(kp) => { tracing::info!("Loaded ML-DSA signing keypair"); Some(kp) }
                Err(e) => { tracing::warn!("Failed to load ML-DSA keypair: {}", e); None }
            }
        } else { None };
        
        for (idx, peer_config) in self.config.peers.iter().enumerate() {
            let peer_public = PublicKey::from(peer_config.public_key);
            
            let peer_mldsa_public = if let Some(ref key_bytes) = peer_config.mldsa_public_key {
                match MlDsaPublicKey::from_bytes(key_bytes) {
                    Ok(pk) => Some(pk),
                    Err(e) => { tracing::warn!("Failed to load peer ML-DSA key: {}", e); None }
                }
            } else { None };
            
            // Check if this peer's key is revoked before even setting up the tunnel
            if self.revocation.is_revoked(&peer_config.public_key) {
                tracing::warn!(
                    "Skipping peer {} — key is revoked",
                    hex::encode(&peer_config.public_key[..4])
                );
                self.audit.log_handshake(
                    &peer_config.public_key, None,
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    EventType::HandshakeRejected, EventOutcome::Denied,
                    "key revoked at init time",
                );
                continue;
            }
            
            let hybrid_state = if self.config.mode.uses_pq_kex() {
                let mut hs = HybridHandshakeState::new(self.config.mode);
                if let Some(ref kp) = our_mldsa_keypair { hs.mldsa_keypair = Some(kp.clone()); }
                if let Some(ref pk) = peer_mldsa_public { hs.peer_mldsa_public_key = Some(pk.clone()); }
                Some(hs)
            } else { None };
            
            let peer_idx = idx as u32;
            let mut tunn = if let Some(hs) = hybrid_state {
                Tunn::new_hybrid(self.private_key.clone(), peer_public, peer_config.preshared_key,
                    peer_config.persistent_keepalive, peer_idx, None, hs)
            } else {
                Tunn::new(self.private_key.clone(), peer_public, peer_config.preshared_key,
                    peer_config.persistent_keepalive, peer_idx, None)
            };
            
            if let Some(ref kp) = our_mldsa_keypair { tunn.set_mldsa_keypair(kp.clone()); }
            if let Some(pk) = peer_mldsa_public { tunn.set_peer_mldsa_public_key(pk); }
            
            // Register peer for key age tracking
            self.revocation.register_peer(&peer_config.public_key);
            
            let peer_state = PeerState {
                tunn,
                endpoint: peer_config.endpoint,
                allowed_ips: peer_config.allowed_ips.clone(),
                last_activity: Instant::now(),
                name: peer_config.name.clone(),
                tx_bytes: 0,
                rx_bytes: 0,
                forwarded_packets: 0,
                policy_denied_packets: 0,
                last_handshake: None,
                session_established: false,
                handshake_attempts: 0,
                first_seen: Instant::now(),
            };
            
            self.peers.insert(peer_config.public_key, peer_state);
            self.index_map.insert(peer_idx, peer_config.public_key);
            self.next_peer_index = peer_idx + 1;
        }
        
        tracing::info!("Initialized {} peers", self.peers.len());
        Ok(())
    }
    
    /// Run the daemon (blocking)
    pub fn run(&mut self) -> TunnelResult<()> {
        if self.tun.is_none() || self.socket.is_none() {
            return Err(TunnelError::NotRunning);
        }
        #[cfg(unix)]
        { self.run_poll_loop() }
        #[cfg(not(unix))]
        { self.run_busy_loop() }
    }
    
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
            "Event loop running: {} peers, policy={}, audit={}, revocation={}",
            self.peers.len(),
            if self.policy.is_enabled() { "on" } else { "off" },
            if self.audit.is_enabled() { "on" } else { "off" },
            if self.revocation.auto_disconnect() { "on" } else { "off" },
        );
        
        while !self.shutdown.load(Ordering::Relaxed) {
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
                if err.kind() == std::io::ErrorKind::Interrupted { continue; }
                tracing::warn!("poll() error: {}", err);
                continue;
            }
            
            if last_timer.elapsed() >= timer_interval {
                self.handle_timers(&mut out_buf);
                last_timer = Instant::now();
            }
            
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
        
        // Audit: daemon stopping
        self.audit.log_daemon_stopped("shutdown signal received");
        tracing::info!("Daemon shutting down");
        self.log_peer_stats();
        Ok(())
    }
    
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
        self.audit.log_daemon_stopped("shutdown signal received");
        tracing::info!("Daemon shutting down");
        Ok(())
    }
    
    fn log_peer_stats(&self) {
        for (pk, peer) in &self.peers {
            let name = peer.name.as_deref().unwrap_or("unnamed");
            tracing::info!(
                "Peer {} ({}): tx={} rx={} fwd={} denied={} endpoint={:?}",
                hex::encode(&pk[..4]), name,
                peer.tx_bytes, peer.rx_bytes,
                peer.forwarded_packets, peer.policy_denied_packets,
                peer.endpoint,
            );
            // Audit: peer disconnect on shutdown
            let duration = Some(peer.first_seen.elapsed().as_secs());
            self.audit.log_peer_disconnected(
                pk, peer.name.as_deref(), "daemon shutdown",
                duration, peer.tx_bytes, peer.rx_bytes,
            );
        }
        let (allowed, denied) = self.policy.stats();
        if self.policy.is_enabled() {
            tracing::info!("Policy stats: {} allowed, {} denied", allowed, denied);
        }
    }
    
    // ─── Config Reload ──────────────────────────────────────────────────
    
    fn handle_reload(&mut self, out_buf: &mut [u8]) {
        let config_path = match &self.config_path {
            Some(p) => p.clone(),
            None => { tracing::warn!("Reload requested but no config path set"); return; }
        };
        
        tracing::info!("Reloading configuration from {}", config_path.display());
        
        let new_config_str = match std::fs::read_to_string(&config_path) {
            Ok(s) => s,
            Err(e) => { tracing::error!("Failed to read config: {}", e); return; }
        };
        
        let new_proto_config: dybervpn_protocol::Config = match toml::from_str(&new_config_str) {
            Ok(c) => c,
            Err(e) => { tracing::error!("Failed to parse config: {}", e); return; }
        };
        
        // Reload CRL
        if let Err(e) = self.revocation.reload() {
            tracing::warn!("CRL reload failed: {}", e);
        }
        
        // Reload policy
        if let Err(e) = self.policy.reload() {
            tracing::warn!("Policy reload failed: {}", e);
        }
        
        // Reload peers
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
        let mut removed = 0;
        for key in &current_keys {
            if !new_peer_keys.contains_key(key) {
                tracing::info!("Removing peer {}", hex::encode(&key[..4]));
                self.peers.remove(key);
                self.index_map.retain(|_, v| v != key);
                removed += 1;
            }
        }
        
        let mut added = 0;
        for (pk, peer_cfg) in &new_peer_keys {
            if !self.peers.contains_key(pk) {
                // Check revocation before adding
                if self.revocation.is_revoked(pk) {
                    tracing::warn!("Skipping peer {} — key revoked", hex::encode(&pk[..4]));
                    continue;
                }
                if let Err(e) = self.add_peer_from_proto_config(peer_cfg) {
                    tracing::error!("Failed to add peer {}: {}", hex::encode(&pk[..4]), e);
                } else {
                    added += 1;
                }
            }
        }
        
        if added > 0 || removed > 0 {
            tracing::info!("Reload: {} added, {} removed, {} total", added, removed, self.peers.len());
            let _ = self.setup_routes();
            if added > 0 { self.initiate_handshakes(out_buf); }
        }
        
        // Audit: config reload
        self.audit.log_config_reload(added, removed, self.peers.len());
    }
    
    fn add_peer_from_proto_config(
        &mut self, peer_cfg: &dybervpn_protocol::config::PeerConfig,
    ) -> TunnelResult<()> {
        let pk_bytes = base64::decode(&peer_cfg.public_key)
            .map_err(|_| TunnelError::Config("Invalid public_key base64".into()))?;
        if pk_bytes.len() != 32 { return Err(TunnelError::Config("Bad key len".into())); }
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&pk_bytes);
        let peer_public = PublicKey::from(public_key);
        
        let endpoint = if let Some(ref ep) = peer_cfg.endpoint {
            Some(ep.parse::<SocketAddr>().map_err(|e| TunnelError::Config(format!("Bad endpoint: {}", e)))?)
        } else { None };
        
        let allowed_ips: Vec<(IpAddr, u8)> = peer_cfg.allowed_ips
            .split(',').map(|s| s.trim()).filter(|s| !s.is_empty())
            .filter_map(|s| {
                let parts: Vec<&str> = s.split('/').collect();
                if parts.len() == 2 {
                    if let (Ok(ip), Ok(prefix)) = (parts[0].parse(), parts[1].parse()) {
                        return Some((ip, prefix));
                    }
                }
                None
            }).collect();
        
        let keepalive = if peer_cfg.persistent_keepalive > 0 { Some(peer_cfg.persistent_keepalive) } else { None };
        let hybrid_state = if self.config.mode.uses_pq_kex() {
            Some(HybridHandshakeState::new(self.config.mode))
        } else { None };
        
        let peer_idx = self.next_peer_index;
        self.next_peer_index += 1;
        
        let tunn = if let Some(hs) = hybrid_state {
            Tunn::new_hybrid(self.private_key.clone(), peer_public, None, keepalive, peer_idx, None, hs)
        } else {
            Tunn::new(self.private_key.clone(), peer_public, None, keepalive, peer_idx, None)
        };
        
        self.revocation.register_peer(&public_key);
        
        let peer_state = PeerState {
            tunn, endpoint, allowed_ips,
            last_activity: Instant::now(), name: peer_cfg.name.clone(),
            tx_bytes: 0, rx_bytes: 0, forwarded_packets: 0, policy_denied_packets: 0,
            last_handshake: None, session_established: false, handshake_attempts: 0,
            first_seen: Instant::now(),
        };
        self.peers.insert(public_key, peer_state);
        self.index_map.insert(peer_idx, public_key);
        
        let name_display = peer_cfg.name.as_deref().unwrap_or("unnamed");
        self.audit.log_admin_action(EventType::PeerAdded,
            &format!("Peer {} ({}) added via config reload", hex::encode(&public_key[..4]), name_display));
        
        Ok(())
    }
    
    fn initiate_handshakes(&mut self, out_buf: &mut [u8]) {
        let peer_endpoints: Vec<([u8; 32], SocketAddr)> = self.peers.iter()
            .filter_map(|(pk, peer)| peer.endpoint.map(|ep| (*pk, ep)))
            .collect();
        
        for (pk, endpoint) in peer_endpoints {
            if let Some(peer) = self.peers.get_mut(&pk) {
                let result = peer.tunn.format_handshake_initiation(out_buf, false);
                if let WgResult::WriteToNetwork(packet) = result {
                    if let Some(ref socket) = self.socket {
                        let _ = socket.send_to(packet, endpoint);
                    }
                    self.audit.log_handshake(&pk, peer.name.as_deref(), endpoint,
                        EventType::HandshakeInitiated, EventOutcome::Success, "initiator");
                }
            }
        }
    }
    
    // ─── Packet Handling with Policy + Audit ─────────────────────────────
    
    /// Handle outgoing TUN packet — encrypt and send to peer
    fn handle_tun_packet(&mut self, packet: &[u8], out_buf: &mut [u8]) {
        let dst_ip = match Self::get_dst_ip(packet) {
            Ok(ip) => ip,
            Err(_) => return,
        };
        
        let peer_key = self.find_peer_for_ip(dst_ip);
        
        if let Some(key) = peer_key {
            // ── Policy check on outgoing traffic ──
            if self.policy.is_enabled() {
                if let Some((_src, dst, dst_port, proto)) = policy::inspect_packet(packet) {
                    let peer_name = self.peers.get(&key).and_then(|p| p.name.as_deref());
                    let (action, rule_name) = self.policy.evaluate(
                        &key, peer_name, dst, dst_port, Some(proto),
                    );
                    if action == PolicyAction::Deny {
                        self.audit.log_policy_decision(
                            &key, peer_name,
                            self.config.address, dst, dst_port, Some(proto),
                            false, &rule_name,
                        );
                        if let Some(peer) = self.peers.get_mut(&key) {
                            peer.policy_denied_packets += 1;
                        }
                        return; // DROP
                    }
                }
            }
            
            let endpoint = self.peers.get(&key).and_then(|p| p.endpoint);
            if let Some(peer) = self.peers.get_mut(&key) {
                if let Some(ep) = endpoint {
                    let result = peer.tunn.encapsulate(packet, out_buf);
                    match result {
                        WgResult::WriteToNetwork(encrypted) => {
                            if let Some(ref socket) = self.socket {
                                let _ = socket.send_to(encrypted, ep);
                                peer.tx_bytes += encrypted.len() as u64;
                            }
                        }
                        WgResult::Err(e) => tracing::debug!("Encap error: {:?}", e),
                        _ => {}
                    }
                }
            }
        }
    }
    
    /// Handle incoming UDP packet — decrypt and forward
    fn handle_udp_packet(&mut self, packet: &[u8], src: SocketAddr, out_buf: &mut [u8]) {
        let parsed = Tunn::parse_incoming_packet(packet);
        
        let peer_key = if let Ok(ref p) = parsed {
            match p {
                Packet::HandshakeInit(_) | Packet::HandshakeInitPq(_) => {
                    self.find_peer_for_handshake_init(packet, src, out_buf)
                }
                Packet::HandshakeResponse(h) => self.index_map.get(&(h.receiver_idx >> 8)).copied(),
                Packet::PacketData(d) => self.index_map.get(&(d.receiver_idx >> 8)).copied(),
                Packet::HandshakeResponsePq(h) => self.index_map.get(&(h.receiver_idx >> 8)).copied(),
                _ => None,
            }
        } else { None };
        
        if let Some(key) = peer_key {
            // ── Revocation check — block packets from revoked peers ──
            if self.revocation.is_revoked(&key) {
                let peer_name = self.peers.get(&key).and_then(|p| p.name.as_deref());
                tracing::warn!("Dropping packet from revoked peer {}", hex::encode(&key[..4]));
                self.audit.log_handshake(&key, peer_name, src,
                    EventType::HandshakeRejected, EventOutcome::Denied, "key revoked");
                return;
            }
            
            let (result_action, is_handshake_complete) = {
                if let Some(peer) = self.peers.get_mut(&key) {
                    // Audit: endpoint change
                    if peer.endpoint != Some(src) {
                        self.audit.log_endpoint_changed(&key, peer.name.as_deref(), peer.endpoint, src);
                        peer.endpoint = Some(src);
                    }
                    peer.last_activity = Instant::now();
                    peer.rx_bytes += packet.len() as u64;
                    
                    let result = peer.tunn.decapsulate(Some(src.ip()), packet, out_buf);
                    match result {
                        WgResult::WriteToTunnelV4(decrypted, _) | WgResult::WriteToTunnelV6(decrypted, _) => {
                            if !peer.session_established {
                                peer.session_established = true;
                                peer.last_handshake = Some(Instant::now());
                                peer.handshake_attempts = 0;
                                // Audit: session established
                                self.audit.log_session_established(&key, peer.name.as_deref(), src);
                            }
                            (ResultAction::TunnelPacket(decrypted.to_vec()), false)
                        }
                        WgResult::WriteToNetwork(response) => {
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
                            tracing::debug!("Tunnel error for {}: {:?}", hex::encode(&key[..4]), e);
                            (ResultAction::Handled, false)
                        }
                    }
                } else { (ResultAction::Handled, false) }
            };
            
            match result_action {
                ResultAction::TunnelPacket(decrypted) => {
                    // ── Policy check on decrypted incoming traffic ──
                    let mut should_forward = true;
                    if self.policy.is_enabled() {
                        if let Some((_src_ip, dst_ip, dst_port, proto)) = policy::inspect_packet(&decrypted) {
                            let peer_name = self.peers.get(&key).and_then(|p| p.name.as_deref());
                            let (action, rule_name) = self.policy.evaluate(
                                &key, peer_name, dst_ip, dst_port, Some(proto),
                            );
                            if action == PolicyAction::Deny {
                                self.audit.log_policy_decision(
                                    &key, peer_name,
                                    _src_ip, dst_ip, dst_port, Some(proto),
                                    false, &rule_name,
                                );
                                if let Some(peer) = self.peers.get_mut(&key) {
                                    peer.policy_denied_packets += 1;
                                }
                                should_forward = false;
                            }
                        }
                    }
                    
                    if should_forward {
                        if !self.try_forward_to_peer(&decrypted, &key, out_buf) {
                            if let Some(ref tun) = self.tun {
                                let _ = tun.write_packet(&decrypted);
                            }
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
                self.audit.log_handshake(&key,
                    self.peers.get(&key).and_then(|p| p.name.as_deref()),
                    src, EventType::HandshakeCompleted, EventOutcome::Success, "responder");
            }
            
            self.process_queued_packets(&key, src, out_buf);
        }
    }
    
    fn find_peer_for_handshake_init(
        &mut self, packet: &[u8], src: SocketAddr, out_buf: &mut [u8],
    ) -> Option<[u8; 32]> {
        let peer_keys: Vec<[u8; 32]> = self.peers.keys().copied().collect();
        for key in peer_keys {
            // Revocation check before processing handshake
            if self.revocation.is_revoked(&key) { continue; }
            
            // Scoped mutable borrow — handle WgResult inline to avoid borrow conflicts.
            // We must consume the result (which borrows out_buf) and extract the peer
            // name before dropping this scope so we can call self methods afterwards.
            let matched_peer_name = if let Some(peer) = self.peers.get_mut(&key) {
                let result = peer.tunn.decapsulate(Some(src.ip()), packet, out_buf);
                match result {
                    WgResult::Err(_) => None,
                    WgResult::WriteToNetwork(response) => {
                        peer.endpoint = Some(src);
                        peer.last_activity = Instant::now();
                        let name = peer.name.clone();
                        if let Some(ref socket) = self.socket {
                            let _ = socket.send_to(response, src);
                        }
                        Some(name)
                    }
                    WgResult::WriteToTunnelV4(pkt, _) | WgResult::WriteToTunnelV6(pkt, _) => {
                        peer.endpoint = Some(src);
                        peer.last_activity = Instant::now();
                        let name = peer.name.clone();
                        if let Some(ref tun) = self.tun {
                            let _ = tun.write_packet(pkt);
                        }
                        Some(name)
                    }
                    WgResult::Done => {
                        peer.endpoint = Some(src);
                        peer.last_activity = Instant::now();
                        Some(peer.name.clone())
                    }
                }
            } else { None };
            // Mutable borrow on self.peers is now dropped
            
            if let Some(peer_name) = matched_peer_name {
                self.process_queued_packets(&key, src, out_buf);
                self.audit.log_handshake(&key, peer_name.as_deref(), src,
                    EventType::HandshakeCompleted, EventOutcome::Success,
                    "responder (matched from init)");
                return None;
            }
        }
        tracing::debug!("No peer matched handshake init from {}", src);
        None
    }
    

    fn try_forward_to_peer(
        &mut self, decrypted_packet: &[u8], source_peer_key: &[u8; 32], out_buf: &mut [u8],
    ) -> bool {
        if !self.is_server { return false; }

        let dst_ip = match Self::get_dst_ip(decrypted_packet) {
            Ok(ip) => ip,
            Err(_) => return false,
        };

        let dest_peer_key = match self.find_peer_for_ip(dst_ip) {
            Some(key) if &key != source_peer_key => key,
            _ => return false,
        };

        // Policy check: does source peer have access to the destination?
        if self.policy.is_enabled() {
            if let Some((_src_ip, dst, dst_port, proto)) = policy::inspect_packet(decrypted_packet) {
                let peer_name = self.peers.get(source_peer_key).and_then(|p| p.name.as_deref());
                let (action, rule_name) = self.policy.evaluate(
                    source_peer_key, peer_name, dst, dst_port, Some(proto),
                );
                if action == PolicyAction::Deny {
                    self.audit.log_policy_decision(
                        source_peer_key, peer_name,
                        _src_ip, dst, dst_port, Some(proto),
                        false, &rule_name,
                    );
                    if let Some(peer) = self.peers.get_mut(source_peer_key) {
                        peer.policy_denied_packets += 1;
                    }
                    return true; // "handled" (dropped)
                }
            }
        }

        let dest_endpoint = match self.peers.get(&dest_peer_key).and_then(|p| p.endpoint) {
            Some(ep) => ep,
            None => return false,
        };

        if let Some(dest_peer) = self.peers.get_mut(&dest_peer_key) {
            let result = dest_peer.tunn.encapsulate(decrypted_packet, out_buf);
            match result {
                WgResult::WriteToNetwork(encrypted) => {
                    if let Some(ref socket) = self.socket {
                        let _ = socket.send_to(encrypted, dest_endpoint);
                        dest_peer.tx_bytes += encrypted.len() as u64;
                        dest_peer.forwarded_packets += 1;
                    }
                    return true;
                }
                WgResult::Err(e) => {
                    tracing::debug!("Forward failed to {}: {:?}", hex::encode(&dest_peer_key[..4]), e);
                    return false;
                }
                _ => return false,
            }
        }
        false
    }
    
    fn process_queued_packets(&mut self, peer_key: &[u8; 32], endpoint: SocketAddr, out_buf: &mut [u8]) {
        loop {
            let result = if let Some(peer) = self.peers.get_mut(peer_key) {
                peer.tunn.decapsulate(None, &[], out_buf)
            } else { return; };
            match result {
                WgResult::WriteToNetwork(packet) => {
                    if let Some(ref socket) = self.socket { let _ = socket.send_to(packet, endpoint); }
                }
                WgResult::WriteToTunnelV4(packet, _) | WgResult::WriteToTunnelV6(packet, _) => {
                    if let Some(ref tun) = self.tun { let _ = tun.write_packet(packet); }
                }
                WgResult::Done | WgResult::Err(_) => break,
            }
        }
    }
    
    // ─── Timers ──────────────────────────────────────────────────────────
    
    fn handle_timers(&mut self, out_buf: &mut [u8]) {
        let now = Instant::now();
        let session_max_age = self.revocation.session_max_age_secs();
        
        // Periodic revocation scan (every check_interval_secs)
        let revocation_interval = Duration::from_secs(self.revocation.check_interval_secs());
        if now.duration_since(self.last_revocation_check) >= revocation_interval {
            self.scan_revoked_peers();
            self.last_revocation_check = now;
        }
        
        // FIPS 140-3 CRNGT: periodic entropy source health check (every 5 minutes)
        const CRNGT_INTERVAL: Duration = Duration::from_secs(300);
        if now.duration_since(self.last_crngt_check) >= CRNGT_INTERVAL {
            let backend = dybervpn_protocol::select_backend();
            if let Err(e) = dybervpn_protocol::fips::crngt_runtime_check(backend.as_ref()) {
                tracing::error!("FIPS 140-3 CRNGT runtime failure: {}. Initiating shutdown.", e);
                self.audit.log_admin_action(
                    EventType::DaemonStopped,
                    &format!("FIPS 140-3 CRNGT failure: {}", e),
                );
                self.shutdown.store(true, Ordering::SeqCst);
            }
            self.last_crngt_check = now;
        }
        
        let peer_data: Vec<([u8; 32], Option<SocketAddr>, Option<Instant>, bool)> = self.peers
            .iter()
            .map(|(pk, peer)| (*pk, peer.endpoint, peer.last_handshake, peer.session_established))
            .collect();
        
        for (pk, endpoint, last_hs, session_ok) in peer_data {
            // Session expiry → forced re-key
            if session_ok {
                if let Some(hs_time) = last_hs {
                    let age = now.duration_since(hs_time).as_secs();
                    if age > session_max_age {
                        let age_hours = age / 3600;
                        tracing::info!("Peer {} session expired after {} hours", hex::encode(&pk[..4]), age_hours);
                        self.audit.log_session_expired(&pk,
                            self.peers.get(&pk).and_then(|p| p.name.as_deref()),
                            age_hours);
                        
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
            
            if let Some(ep) = endpoint {
                if let Some(peer) = self.peers.get_mut(&pk) {
                    let result = peer.tunn.update_timers(out_buf);
                    match result {
                        WgResult::WriteToNetwork(packet) => {
                            if let Some(ref socket) = self.socket { let _ = socket.send_to(packet, ep); }
                        }
                        WgResult::Err(e) => tracing::debug!("Timer error: {:?}", e),
                        _ => {}
                    }
                }
            }
        }
    }
    
    /// Periodic scan: disconnect any peers whose keys have been revoked
    fn scan_revoked_peers(&mut self) {
        if !self.revocation.auto_disconnect() { return; }
        
        let peer_keys: Vec<[u8; 32]> = self.peers.keys().copied().collect();
        let mut revoked_keys = Vec::new();
        
        for pk in &peer_keys {
            let status = self.revocation.check_key(pk, self.peers.get(pk).and_then(|p| p.name.as_deref()));
            match status {
                KeyStatus::Revoked(reason) => {
                    tracing::warn!("Disconnecting peer {} — key revoked: {}", hex::encode(&pk[..4]), reason);
                    self.audit.log_key_revoked(pk,
                        self.peers.get(pk).and_then(|p| p.name.as_deref()),
                        &reason);
                    revoked_keys.push(*pk);
                }
                KeyStatus::Expired(detail) => {
                    tracing::warn!("Disconnecting peer {} — key expired: {}", hex::encode(&pk[..4]), detail);
                    self.audit.log_key_revoked(pk,
                        self.peers.get(pk).and_then(|p| p.name.as_deref()),
                        &format!("expired: {}", detail));
                    revoked_keys.push(*pk);
                }
                KeyStatus::Suspended(detail) => {
                    tracing::warn!("Disconnecting peer {} — suspended: {}", hex::encode(&pk[..4]), detail);
                    revoked_keys.push(*pk);
                }
                KeyStatus::Valid => {}
            }
        }
        
        for pk in &revoked_keys {
            self.peers.remove(pk);
            self.index_map.retain(|_, v| v != pk);
        }
        
        if !revoked_keys.is_empty() {
            tracing::info!("Revocation scan: removed {} peers, {} remaining",
                revoked_keys.len(), self.peers.len());
        }
    }
    
    // ─── Helpers ──────────────────────────────────────────────────────────
    
    fn get_dst_ip(packet: &[u8]) -> TunnelResult<IpAddr> {
        if packet.is_empty() { return Err(TunnelError::InvalidPacket("Empty".into())); }
        let version = packet[0] >> 4;
        match version {
            4 if packet.len() >= 20 => {
                Ok(IpAddr::V4(Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19])))
            }
            6 if packet.len() >= 40 => {
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(&packet[24..40]);
                Ok(IpAddr::V6(bytes.into()))
            }
            _ => Err(TunnelError::InvalidPacket("Unknown IP version".into())),
        }
    }
    
    fn find_peer_for_ip(&self, dst: IpAddr) -> Option<[u8; 32]> {
        let mut best_match: Option<([u8; 32], u8)> = None;
        for (key, peer) in &self.peers {
            for (net, prefix) in &peer.allowed_ips {
                if Self::ip_in_network(dst, *net, *prefix) {
                    match best_match {
                        Some((_, bp)) if *prefix > bp => best_match = Some((*key, *prefix)),
                        None => best_match = Some((*key, *prefix)),
                        _ => {}
                    }
                }
            }
        }
        best_match.map(|(key, _)| key)
    }
    
    fn ip_in_network(ip: IpAddr, network: IpAddr, prefix: u8) -> bool {
        match (ip, network) {
            (IpAddr::V4(ip), IpAddr::V4(net)) => {
                let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
                (u32::from_be_bytes(ip.octets()) & mask) == (u32::from_be_bytes(net.octets()) & mask)
            }
            (IpAddr::V6(ip), IpAddr::V6(net)) => {
                let mask = if prefix == 0 { 0 } else { !0u128 << (128 - prefix) };
                (u128::from_be_bytes(ip.octets()) & mask) == (u128::from_be_bytes(net.octets()) & mask)
            }
            _ => false,
        }
    }
    
    /// Get the number of connected peers
    pub fn peer_count(&self) -> usize { self.peers.len() }
    
    /// Get the number of peers with active endpoints
    pub fn active_peer_count(&self) -> usize {
        self.peers.values().filter(|p| p.endpoint.is_some()).count()
    }
    
    /// Signal shutdown
    pub fn shutdown(&self) { self.shutdown.store(true, Ordering::Relaxed); }
    
    /// Get shutdown flag for external use
    pub fn shutdown_flag(&self) -> Arc<AtomicBool> { Arc::clone(&self.shutdown) }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(ref tun) = self.tun { let _ = tun.shutdown(); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ip_in_network() {
        assert!(Daemon::ip_in_network(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 24));
        assert!(!Daemon::ip_in_network(
            IpAddr::V4(Ipv4Addr::new(10, 0, 1, 5)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 24));
        assert!(Daemon::ip_in_network(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0));
    }
    
    #[test]
    fn test_get_dst_ip() {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[16..20].copy_from_slice(&[192, 168, 1, 1]);
        assert_eq!(Daemon::get_dst_ip(&packet).unwrap(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    }
    
    #[test]
    fn test_is_tun_subnet() {
        let config = TunnelConfig {
            address: IpAddr::V4(Ipv4Addr::new(10, 200, 200, 1)),
            netmask: 24,
            ..TunnelConfig::default()
        };
        let daemon = Daemon {
            config, config_path: None, tun: None, socket: None,
            peers: HashMap::new(), index_map: HashMap::new(),
            shutdown: Arc::new(AtomicBool::new(false)),
            reload: Arc::new(AtomicBool::new(false)),
            private_key: StaticSecret::from([1u8; 32]),
            next_peer_index: 0, is_server: false,
            policy: PolicyEngine::disabled(),
            revocation: RevocationEngine::disabled(),
            audit: AuditLogger::disabled(),
            last_revocation_check: Instant::now(),
        };
        assert!(daemon.is_tun_subnet(IpAddr::V4(Ipv4Addr::new(10, 200, 200, 0)), 24));
        assert!(!daemon.is_tun_subnet(IpAddr::V4(Ipv4Addr::new(10, 200, 200, 2)), 32));
        assert!(!daemon.is_tun_subnet(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24));
    }
}
