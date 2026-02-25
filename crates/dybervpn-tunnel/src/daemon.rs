//! VPN Daemon - Event loop for tunnel management
//!
//! This module implements the main event loop that:
//! - Reads packets from the TUN device and encrypts them for the network
//! - Reads packets from the UDP socket and decrypts them for the TUN
//! - Handles handshake initiation and response
//! - Manages timer-based events (keepalive, rekey)

use crate::config::TunnelConfig;
use crate::device::DeviceHandle;
use crate::error::{TunnelError, TunnelResult};

use boringtun::noise::{Tunn, TunnResult as WgResult, HybridHandshakeState, Packet, MlDsaKeyPair};
use dybervpn_protocol::MlDsaPublicKey;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use x25519_dalek::{PublicKey, StaticSecret};

/// Maximum packet size for UDP
const MAX_UDP_SIZE: usize = 65535;

/// Maximum packet size for TUN (MTU + headers)
const MAX_TUN_SIZE: usize = 1500;

/// Timer check interval
const TIMER_TICK_MS: u64 = 250;

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
}

/// VPN Daemon
pub struct Daemon {
    /// Configuration
    config: TunnelConfig,
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
    /// Our private key
    private_key: StaticSecret,
}

impl Daemon {
    /// Create a new daemon
    pub fn new(config: TunnelConfig) -> TunnelResult<Self> {
        config.validate().map_err(TunnelError::Config)?;
        
        let private_key = StaticSecret::from(config.private_key);
        
        Ok(Self {
            config,
            tun: None,
            socket: None,
            peers: HashMap::new(),
            index_map: HashMap::new(),
            shutdown: Arc::new(AtomicBool::new(false)),
            private_key,
        })
    }
    
    /// Initialize the daemon (create devices and sockets)
    pub fn init(&mut self) -> TunnelResult<()> {
        tracing::info!("Initializing DyberVPN daemon");
        
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
        
        Ok(())
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
        
        // Set non-blocking for async
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
            let mut tunn = if let Some(hs) = hybrid_state {
                Tunn::new_hybrid(
                    self.private_key.clone(),
                    peer_public,
                    peer_config.preshared_key,
                    peer_config.persistent_keepalive,
                    idx as u32,
                    None,
                    hs,
                )
            } else {
                Tunn::new(
                    self.private_key.clone(),
                    peer_public,
                    peer_config.preshared_key,
                    peer_config.persistent_keepalive,
                    idx as u32,
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
            };
            
            // Store peer
            self.peers.insert(peer_config.public_key, peer_state);
            
            // Map index to peer
            self.index_map.insert(idx as u32, peer_config.public_key);
            
            tracing::debug!(
                "Initialized peer {} with endpoint {:?}",
                hex::encode(&peer_config.public_key[..4]),
                peer_config.endpoint
            );
        }
        
        tracing::info!("Initialized {} peers", self.peers.len());
        
        Ok(())
    }
    
    /// Run the daemon (blocking)
    pub fn run(&mut self) -> TunnelResult<()> {
        tracing::info!("Starting DyberVPN event loop");
        
        // Check that we're initialized
        if self.tun.is_none() || self.socket.is_none() {
            return Err(TunnelError::NotRunning);
        }
        
        // Buffers
        let mut tun_buf = vec![0u8; MAX_TUN_SIZE];
        let mut udp_buf = vec![0u8; MAX_UDP_SIZE];
        let mut out_buf = vec![0u8; MAX_UDP_SIZE];
        
        // Timer
        let mut last_timer = Instant::now();
        let timer_interval = Duration::from_millis(TIMER_TICK_MS);
        
        // Initiate handshakes to peers with known endpoints
        self.initiate_handshakes(&mut out_buf);
        
        tracing::info!("Event loop running. Press Ctrl+C to stop.");
        
        while !self.shutdown.load(Ordering::Relaxed) {
            // Check timers
            if last_timer.elapsed() >= timer_interval {
                self.handle_timers(&mut out_buf);
                last_timer = Instant::now();
            }
            
            // Try to read from TUN (non-blocking)
            let tun_result = {
                if let Some(ref tun) = self.tun {
                    tun.read_packet(&mut tun_buf)
                } else {
                    continue;
                }
            };
            
            match tun_result {
                Ok(n) if n > 0 => {
                    self.handle_tun_packet(&tun_buf[..n], &mut out_buf);
                }
                Ok(_) => {}
                Err(TunnelError::Io(ref e)) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    tracing::warn!("TUN read error: {}", e);
                }
            }
            
            // Try to read from UDP (non-blocking)
            let udp_result = {
                if let Some(ref socket) = self.socket {
                    socket.recv_from(&mut udp_buf)
                } else {
                    continue;
                }
            };
            
            match udp_result {
                Ok((n, src)) => {
                    self.handle_udp_packet(&udp_buf[..n], src, &mut out_buf);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    tracing::warn!("UDP read error: {}", e);
                }
            }
            
            // Small sleep to avoid busy-waiting
            std::thread::sleep(Duration::from_micros(100));
        }
        
        tracing::info!("Daemon shutting down");
        
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
    
    /// Handle a packet from the TUN device
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
                            }
                        }
                        WgResult::Err(e) => {
                            tracing::debug!("Encapsulate error: {:?}", e);
                        }
                        _ => {}
                    }
                }
            }
        } else {
            tracing::trace!("No peer found for destination {}", dst_ip);
        }
    }
    
    /// Handle a packet from the UDP socket
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
                
                // Decapsulate the packet
                let result = peer.tunn.decapsulate(Some(src.ip()), packet, out_buf);
                
                // Handle result
                self.handle_wg_result_simple(result, src);
            }
            
            // Process any queued packets (separate borrow)
            self.process_queued_packets(&key, src, out_buf);
        } else {
            tracing::trace!("Unknown packet from {}", src);
        }
    }
    
    /// Try each peer to find which one a HandshakeInit belongs to.
    /// Returns the peer key if found, updating endpoint as a side effect.
    /// For handshake init, we can't know the sender until we try decapsulating
    /// with each peer's Tunn context (which checks the static key inside).
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
                        tracing::debug!(
                            "Handshake init matched peer {}",
                            hex::encode(&key[..4])
                        );
                        peer.endpoint = Some(src);
                        peer.last_activity = Instant::now();
                        
                        // Handle the result (send response, etc.)
                        self.handle_wg_result_simple(result, src);
                        
                        // Process queued packets
                        self.process_queued_packets(&key, src, out_buf);
                        
                        // Return None to signal we already handled it
                        // (prevents double-processing in the caller)
                        return None;
                    }
                }
            }
        }
        
        tracing::debug!("No peer matched handshake init from {}", src);
        None
    }
    
    /// Handle a WireGuard result (simple version without out_buf)
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
            WgResult::WriteToTunnelV4(packet, _src) => {
                if let Some(ref tun) = self.tun {
                    let _ = tun.write_packet(packet);
                }
            }
            WgResult::WriteToTunnelV6(packet, _src) => {
                if let Some(ref tun) = self.tun {
                    let _ = tun.write_packet(packet);
                }
            }
        }
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
    
    /// Handle timer events
    fn handle_timers(&mut self, out_buf: &mut [u8]) {
        // Collect peer keys and endpoints first
        let peer_data: Vec<([u8; 32], Option<SocketAddr>)> = self.peers
            .iter()
            .map(|(pk, peer)| (*pk, peer.endpoint))
            .collect();
        
        for (pk, endpoint) in peer_data {
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
        for (key, peer) in &self.peers {
            for (net, prefix) in &peer.allowed_ips {
                if Self::ip_in_network(dst, *net, *prefix) {
                    return Some(*key);
                }
            }
        }
        None
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
}
