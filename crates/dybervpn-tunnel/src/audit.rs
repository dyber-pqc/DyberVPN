//! Structured Audit Logging for Enterprise Compliance
//!
//! Emits machine-parseable JSON audit events to file and/or syslog.
//! Designed for SOC 2, FedRAMP, HIPAA, and CMMC compliance.
//!
//! Every security-relevant action produces an audit record with:
//! - RFC 3339 timestamp (UTC)
//! - Unique event ID
//! - Event category and type
//! - Peer identity (public key fingerprint + name)
//! - Source/destination IPs
//! - Action and outcome
//! - Session metadata
//!
//! Events are append-only and written atomically (one JSON object per line,
//! newline-delimited JSON / NDJSON format) for safe concurrent reads and
//! SIEM ingestion.
//!
//! # Configuration
//!
//! ```toml
//! [audit]
//! enabled = true
//! path = "/var/log/dybervpn/audit.jsonl"
//! max_size_mb = 100
//! rotate_count = 10
//! log_data_packets = false   # true = log every packet (high volume)
//! events = ["all"]           # or specific: ["connection", "policy_violation"]
//! ```

use serde::Serialize;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

// ─── Event Types ─────────────────────────────────────────────────────────────

/// All audit event categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventCategory {
    /// Peer connection/disconnection lifecycle
    Connection,
    /// Cryptographic handshake events
    Handshake,
    /// Access control policy decisions
    Policy,
    /// Key management (rotation, revocation, generation)
    KeyManagement,
    /// Administrative actions (add/remove peer, config reload)
    Admin,
    /// Enrollment API events
    Enrollment,
    /// Data plane events (packet forwarding — high volume, off by default)
    DataPlane,
    /// System events (startup, shutdown, errors)
    System,
}

/// Specific event types within each category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// A new peer connected to the VPN
    PeerConnected,
    /// A peer disconnected from the VPN
    PeerDisconnected,
    /// An encrypted session was established with a peer
    SessionEstablished,
    /// A session exceeded its maximum age and was expired
    SessionExpired,
    /// A peer's UDP endpoint address changed (NAT traversal / roaming)
    EndpointChanged,

    /// A handshake initiation was sent to a peer
    HandshakeInitiated,
    /// A handshake completed successfully
    HandshakeCompleted,
    /// A handshake failed (timeout, crypto error)
    HandshakeFailed,
    /// A handshake was rejected (revoked key, policy denial)
    HandshakeRejected,

    /// A packet was allowed by the policy engine
    PacketAllowed,
    /// A packet was denied by the policy engine
    PacketDenied,
    /// Access control policy was loaded from file
    PolicyLoaded,
    /// Access control policy was reloaded (SIGHUP)
    PolicyReloaded,
    /// A policy violation was detected
    PolicyViolation,

    /// Key rotation was initiated for a peer
    KeyRotationInitiated,
    /// Key rotation completed successfully
    KeyRotationCompleted,
    /// A peer's key was revoked
    KeyRevoked,
    /// A peer's key expired (exceeded max age)
    KeyExpired,
    /// The certificate revocation list was loaded from disk
    RevocationListLoaded,
    /// The certificate revocation list was updated
    RevocationListUpdated,

    /// A peer was added to the configuration
    PeerAdded,
    /// A peer was removed from the configuration
    PeerRemoved,
    /// The daemon configuration was reloaded (SIGHUP)
    ConfigReloaded,
    /// The DyberVPN daemon started
    DaemonStarted,
    /// The DyberVPN daemon stopped
    DaemonStopped,

    /// A peer enrollment was requested via the enrollment API
    EnrollmentRequested,
    /// A peer enrollment was approved
    EnrollmentApproved,
    /// A peer enrollment was denied
    EnrollmentDenied,

    /// A packet was forwarded between peers (server mode)
    PacketForwarded,

    /// A system-level error occurred
    SystemError,
    /// A system-level warning was raised
    SystemWarning,
}

/// Outcome of the event
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventOutcome {
    /// The action completed successfully
    Success,
    /// The action failed (non-security failure)
    Failure,
    /// The action was denied by policy or revocation
    Denied,
    /// An error occurred during the action
    Error,
}

/// A single audit event record (one line of NDJSON)
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    /// RFC 3339 UTC timestamp
    pub timestamp: String,
    /// Unique event ID (monotonically increasing per process)
    pub event_id: u64,
    /// Event category
    pub category: EventCategory,
    /// Specific event type
    pub event_type: EventType,
    /// Outcome
    pub outcome: EventOutcome,
    /// Peer identity — public key fingerprint (first 8 hex chars)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_id: Option<String>,
    /// Peer human-readable name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_name: Option<String>,
    /// Source IP address (of the peer's UDP endpoint, or packet source)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
    /// Destination IP address (of the packet or connection target)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dest_ip: Option<String>,
    /// Destination port (for policy events)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dest_port: Option<u16>,
    /// IP protocol number (6=TCP, 17=UDP, 1=ICMP)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<u8>,
    /// VPN interface name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// Human-readable description
    pub message: String,
    /// Bytes transferred (for data plane events)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    /// Policy rule that matched (for policy events)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_rule: Option<String>,
    /// Operating mode at time of event
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// Session duration in seconds (for disconnect events)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_duration_secs: Option<u64>,
    /// Reason for failure/denial
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Server hostname
    pub hostname: String,
    /// DyberVPN version
    pub version: String,
}

// ─── Audit Logger ────────────────────────────────────────────────────────────

/// Configuration for the audit logger
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Whether audit logging is enabled
    pub enabled: bool,
    /// Path to the audit log file (NDJSON format)
    pub path: PathBuf,
    /// Maximum size in bytes before rotation
    pub max_size_bytes: u64,
    /// Number of rotated log files to keep
    pub rotate_count: u32,
    /// Whether to log data plane (per-packet) events
    pub log_data_packets: bool,
    /// Which event categories to log (empty = all)
    pub categories: Vec<EventCategory>,
    /// VPN interface name (set at init)
    pub interface_name: String,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: PathBuf::from("/var/log/dybervpn/audit.jsonl"),
            max_size_bytes: 100 * 1024 * 1024, // 100 MB
            rotate_count: 10,
            log_data_packets: false,
            categories: Vec::new(), // empty = all
            interface_name: "dvpn0".to_string(),
        }
    }
}

/// Thread-safe audit logger
///
/// Designed for hot-path use — the `log()` method is cheap when audit is
/// disabled and uses a single mutex on the file handle otherwise.
#[derive(Clone)]
pub struct AuditLogger {
    inner: Arc<AuditLoggerInner>,
}

struct AuditLoggerInner {
    config: AuditConfig,
    file: Mutex<Option<File>>,
    event_counter: std::sync::atomic::AtomicU64,
    hostname: String,
}

impl AuditLogger {
    /// Create a new audit logger
    pub fn new(config: AuditConfig) -> Self {
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        let file = if config.enabled {
            // Ensure parent directory exists
            if let Some(parent) = config.path.parent() {
                let _ = fs::create_dir_all(parent);
            }

            match OpenOptions::new()
                .create(true)
                .append(true)
                .open(&config.path)
            {
                Ok(f) => {
                    tracing::info!("Audit log opened: {}", config.path.display());
                    Some(f)
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to open audit log {}: {} — audit logging disabled",
                        config.path.display(),
                        e
                    );
                    None
                }
            }
        } else {
            None
        };

        Self {
            inner: Arc::new(AuditLoggerInner {
                config,
                file: Mutex::new(file),
                event_counter: std::sync::atomic::AtomicU64::new(1),
                hostname,
            }),
        }
    }

    /// Create a disabled audit logger (no-op)
    pub fn disabled() -> Self {
        Self::new(AuditConfig::default())
    }

    /// Check if audit logging is enabled
    pub fn is_enabled(&self) -> bool {
        self.inner.config.enabled
    }

    /// Log an audit event. Returns immediately if disabled or if the
    /// event category is filtered out.
    pub fn log(&self, event: AuditEvent) {
        if !self.inner.config.enabled {
            return;
        }

        // Check category filter
        if !self.inner.config.categories.is_empty()
            && !self.inner.config.categories.contains(&event.category)
        {
            return;
        }

        // Skip data plane events unless explicitly enabled
        if event.category == EventCategory::DataPlane && !self.inner.config.log_data_packets {
            return;
        }

        // Serialize to NDJSON (one line)
        let json = match serde_json::to_string(&event) {
            Ok(j) => j,
            Err(e) => {
                tracing::warn!("Failed to serialize audit event: {}", e);
                return;
            }
        };

        // Write atomically
        let mut guard = match self.inner.file.lock() {
            Ok(g) => g,
            Err(e) => {
                tracing::warn!("Audit log lock poisoned: {}", e);
                return;
            }
        };

        if let Some(ref mut file) = *guard {
            if writeln!(file, "{}", json).is_err() {
                tracing::warn!("Failed to write audit event");
            }

            // Check for rotation
            if let Ok(meta) = file.metadata() {
                if meta.len() > self.inner.config.max_size_bytes {
                    drop(guard); // release lock before rotating
                    self.rotate_log();
                }
            }
        }

        // Also emit to tracing at debug level for console visibility
        tracing::debug!(
            audit_category = ?event.category,
            audit_type = ?event.event_type,
            audit_outcome = ?event.outcome,
            peer = ?event.peer_id,
            "{}",
            event.message
        );
    }

    /// Build an event with common fields pre-filled
    pub fn build_event(
        &self,
        category: EventCategory,
        event_type: EventType,
        outcome: EventOutcome,
        message: impl Into<String>,
    ) -> AuditEvent {
        let id = self
            .inner
            .event_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let now = SystemTime::now();
        let timestamp = humantime::format_rfc3339_millis(now).to_string();

        AuditEvent {
            timestamp,
            event_id: id,
            category,
            event_type,
            outcome,
            peer_id: None,
            peer_name: None,
            source_ip: None,
            dest_ip: None,
            dest_port: None,
            protocol: None,
            interface: Some(self.inner.config.interface_name.clone()),
            message: message.into(),
            bytes: None,
            policy_rule: None,
            mode: None,
            session_duration_secs: None,
            reason: None,
            hostname: self.inner.hostname.clone(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    // ─── Convenience methods ─────────────────────────────────────────────

    /// Log daemon startup
    pub fn log_daemon_started(&self, mode: &str, peer_count: usize) {
        let mut ev = self.build_event(
            EventCategory::System,
            EventType::DaemonStarted,
            EventOutcome::Success,
            format!(
                "DyberVPN daemon started in {} mode with {} peers",
                mode, peer_count
            ),
        );
        ev.mode = Some(mode.to_string());
        self.log(ev);
    }

    /// Log daemon shutdown
    pub fn log_daemon_stopped(&self, reason: &str) {
        let ev = self.build_event(
            EventCategory::System,
            EventType::DaemonStopped,
            EventOutcome::Success,
            format!("DyberVPN daemon stopped: {}", reason),
        );
        self.log(ev);
    }

    /// Log peer session established
    pub fn log_session_established(
        &self,
        peer_key: &[u8; 32],
        peer_name: Option<&str>,
        endpoint: SocketAddr,
    ) {
        let mut ev = self.build_event(
            EventCategory::Connection,
            EventType::SessionEstablished,
            EventOutcome::Success,
            format!(
                "Session established with peer {} from {}",
                peer_name.unwrap_or(&hex::encode(&peer_key[..4])),
                endpoint
            ),
        );
        ev.peer_id = Some(hex::encode(&peer_key[..8]));
        ev.peer_name = peer_name.map(String::from);
        ev.source_ip = Some(endpoint.ip().to_string());
        self.log(ev);
    }

    /// Log peer disconnected
    pub fn log_peer_disconnected(
        &self,
        peer_key: &[u8; 32],
        peer_name: Option<&str>,
        reason: &str,
        duration_secs: Option<u64>,
        tx_bytes: u64,
        rx_bytes: u64,
    ) {
        let mut ev = self.build_event(
            EventCategory::Connection,
            EventType::PeerDisconnected,
            EventOutcome::Success,
            format!(
                "Peer {} disconnected: {} (tx={}, rx={})",
                peer_name.unwrap_or(&hex::encode(&peer_key[..4])),
                reason,
                tx_bytes,
                rx_bytes,
            ),
        );
        ev.peer_id = Some(hex::encode(&peer_key[..8]));
        ev.peer_name = peer_name.map(String::from);
        ev.session_duration_secs = duration_secs;
        ev.bytes = Some(tx_bytes + rx_bytes);
        ev.reason = Some(reason.to_string());
        self.log(ev);
    }

    /// Log handshake event
    pub fn log_handshake(
        &self,
        peer_key: &[u8; 32],
        peer_name: Option<&str>,
        endpoint: SocketAddr,
        event_type: EventType,
        outcome: EventOutcome,
        detail: &str,
    ) {
        let mut ev = self.build_event(
            EventCategory::Handshake,
            event_type,
            outcome,
            format!(
                "Handshake {} for peer {} from {}: {}",
                match event_type {
                    EventType::HandshakeInitiated => "initiated",
                    EventType::HandshakeCompleted => "completed",
                    EventType::HandshakeFailed => "failed",
                    EventType::HandshakeRejected => "rejected",
                    _ => "event",
                },
                peer_name.unwrap_or(&hex::encode(&peer_key[..4])),
                endpoint,
                detail,
            ),
        );
        ev.peer_id = Some(hex::encode(&peer_key[..8]));
        ev.peer_name = peer_name.map(String::from);
        ev.source_ip = Some(endpoint.ip().to_string());
        self.log(ev);
    }

    /// Log a policy decision (allow/deny)
    #[allow(clippy::too_many_arguments)]
    pub fn log_policy_decision(
        &self,
        peer_key: &[u8; 32],
        peer_name: Option<&str>,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: Option<u16>,
        protocol: Option<u8>,
        allowed: bool,
        rule_name: &str,
    ) {
        let outcome = if allowed {
            EventOutcome::Success
        } else {
            EventOutcome::Denied
        };
        let event_type = if allowed {
            EventType::PacketAllowed
        } else {
            EventType::PacketDenied
        };

        let proto_str = match protocol {
            Some(6) => "TCP",
            Some(17) => "UDP",
            Some(1) => "ICMP",
            Some(n) => &format!("proto:{}", n),
            None => "unknown",
        };

        let mut ev = self.build_event(
            EventCategory::Policy,
            event_type,
            outcome,
            format!(
                "Policy {}: peer {} {} -> {}:{} ({}) rule={}",
                if allowed { "ALLOW" } else { "DENY" },
                peer_name.unwrap_or(&hex::encode(&peer_key[..4])),
                src_ip,
                dst_ip,
                dst_port.map(|p| p.to_string()).unwrap_or_default(),
                proto_str,
                rule_name,
            ),
        );
        ev.peer_id = Some(hex::encode(&peer_key[..8]));
        ev.peer_name = peer_name.map(String::from);
        ev.source_ip = Some(src_ip.to_string());
        ev.dest_ip = Some(dst_ip.to_string());
        ev.dest_port = dst_port;
        ev.protocol = protocol;
        ev.policy_rule = Some(rule_name.to_string());
        self.log(ev);
    }

    /// Log key revocation
    pub fn log_key_revoked(&self, peer_key: &[u8; 32], peer_name: Option<&str>, reason: &str) {
        let mut ev = self.build_event(
            EventCategory::KeyManagement,
            EventType::KeyRevoked,
            EventOutcome::Success,
            format!(
                "Key revoked for peer {}: {}",
                peer_name.unwrap_or(&hex::encode(&peer_key[..4])),
                reason,
            ),
        );
        ev.peer_id = Some(hex::encode(&peer_key[..8]));
        ev.peer_name = peer_name.map(String::from);
        ev.reason = Some(reason.to_string());
        self.log(ev);
    }

    /// Log key rotation event
    pub fn log_key_rotation(
        &self,
        peer_key: &[u8; 32],
        peer_name: Option<&str>,
        event_type: EventType,
    ) {
        let mut ev = self.build_event(
            EventCategory::KeyManagement,
            event_type,
            EventOutcome::Success,
            format!(
                "Key rotation {} for peer {}",
                match event_type {
                    EventType::KeyRotationInitiated => "initiated",
                    EventType::KeyRotationCompleted => "completed",
                    _ => "event",
                },
                peer_name.unwrap_or(&hex::encode(&peer_key[..4])),
            ),
        );
        ev.peer_id = Some(hex::encode(&peer_key[..8]));
        ev.peer_name = peer_name.map(String::from);
        self.log(ev);
    }

    /// Log admin action
    pub fn log_admin_action(&self, event_type: EventType, detail: &str) {
        let ev = self.build_event(
            EventCategory::Admin,
            event_type,
            EventOutcome::Success,
            detail.to_string(),
        );
        self.log(ev);
    }

    /// Log enrollment event
    pub fn log_enrollment(
        &self,
        name: &str,
        source_ip: IpAddr,
        event_type: EventType,
        outcome: EventOutcome,
        detail: &str,
    ) {
        let mut ev = self.build_event(
            EventCategory::Enrollment,
            event_type,
            outcome,
            format!("Enrollment {}: {} from {}", name, detail, source_ip),
        );
        ev.source_ip = Some(source_ip.to_string());
        ev.peer_name = Some(name.to_string());
        self.log(ev);
    }

    /// Log config reload
    pub fn log_config_reload(&self, added: usize, removed: usize, total: usize) {
        let ev = self.build_event(
            EventCategory::Admin,
            EventType::ConfigReloaded,
            EventOutcome::Success,
            format!(
                "Configuration reloaded: {} added, {} removed, {} total peers",
                added, removed, total
            ),
        );
        self.log(ev);
    }

    /// Log session expiry / forced re-key
    pub fn log_session_expired(
        &self,
        peer_key: &[u8; 32],
        peer_name: Option<&str>,
        age_hours: u64,
    ) {
        let mut ev = self.build_event(
            EventCategory::Connection,
            EventType::SessionExpired,
            EventOutcome::Success,
            format!(
                "Session expired for peer {} after {} hours — forcing re-key",
                peer_name.unwrap_or(&hex::encode(&peer_key[..4])),
                age_hours,
            ),
        );
        ev.peer_id = Some(hex::encode(&peer_key[..8]));
        ev.peer_name = peer_name.map(String::from);
        ev.session_duration_secs = Some(age_hours * 3600);
        self.log(ev);
    }

    /// Log endpoint change (potential NAT traversal or IP roaming)
    pub fn log_endpoint_changed(
        &self,
        peer_key: &[u8; 32],
        peer_name: Option<&str>,
        old_endpoint: Option<SocketAddr>,
        new_endpoint: SocketAddr,
    ) {
        let mut ev = self.build_event(
            EventCategory::Connection,
            EventType::EndpointChanged,
            EventOutcome::Success,
            format!(
                "Peer {} endpoint changed: {:?} -> {}",
                peer_name.unwrap_or(&hex::encode(&peer_key[..4])),
                old_endpoint,
                new_endpoint,
            ),
        );
        ev.peer_id = Some(hex::encode(&peer_key[..8]));
        ev.peer_name = peer_name.map(String::from);
        ev.source_ip = Some(new_endpoint.ip().to_string());
        self.log(ev);
    }

    // ─── Log rotation ────────────────────────────────────────────────────

    fn rotate_log(&self) {
        let path = &self.inner.config.path;
        let count = self.inner.config.rotate_count;

        // Rotate: audit.jsonl.9 -> audit.jsonl.10, ... audit.jsonl -> audit.jsonl.1
        for i in (1..count).rev() {
            let from = format!("{}.{}", path.display(), i);
            let to = format!("{}.{}", path.display(), i + 1);
            let _ = fs::rename(&from, &to);
        }

        let rotated = format!("{}.1", path.display());
        let _ = fs::rename(path, &rotated);

        // Re-open
        let mut guard = self.inner.file.lock().unwrap();
        *guard = OpenOptions::new().create(true).append(true).open(path).ok();

        tracing::info!("Audit log rotated: {} -> {}", path.display(), rotated);
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_disabled_logger_is_noop() {
        let logger = AuditLogger::disabled();
        assert!(!logger.is_enabled());
        // This should not panic or do anything
        logger.log_daemon_started("hybrid", 5);
    }

    #[test]
    fn test_event_serialization() {
        let logger = AuditLogger::disabled();
        let mut ev = logger.build_event(
            EventCategory::Connection,
            EventType::SessionEstablished,
            EventOutcome::Success,
            "Test session",
        );
        ev.peer_id = Some("aabbccdd".to_string());
        ev.source_ip = Some("192.168.1.1".to_string());

        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("session_established"));
        assert!(json.contains("aabbccdd"));
        assert!(json.contains("connection"));
    }

    #[test]
    fn test_audit_log_to_file() {
        let dir = std::env::temp_dir().join("dybervpn-audit-test");
        let _ = fs::create_dir_all(&dir);
        let log_path = dir.join("test-audit.jsonl");
        let _ = fs::remove_file(&log_path);

        let config = AuditConfig {
            enabled: true,
            path: log_path.clone(),
            max_size_bytes: 10 * 1024 * 1024,
            rotate_count: 3,
            log_data_packets: false,
            categories: vec![],
            interface_name: "dvpn-test".to_string(),
        };

        let logger = AuditLogger::new(config);
        logger.log_daemon_started("hybrid", 3);
        logger.log_policy_decision(
            &[0xAA; 32],
            Some("alice"),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(10, 100, 0, 5)),
            Some(443),
            Some(6),
            true,
            "engineering-allow-https",
        );
        logger.log_key_revoked(&[0xBB; 32], Some("bob"), "employee departed");

        // Read back and verify
        let contents = fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 3);

        // Each line should be valid JSON
        for line in &lines {
            let _: serde_json::Value = serde_json::from_str(line).unwrap();
        }

        // Verify content
        assert!(contents.contains("daemon_started"));
        assert!(contents.contains("packet_allowed"));
        assert!(contents.contains("key_revoked"));
        assert!(contents.contains("engineering-allow-https"));
        assert!(contents.contains("employee departed"));

        // Cleanup
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_category_filtering() {
        let dir = std::env::temp_dir().join("dybervpn-audit-filter-test");
        let _ = fs::create_dir_all(&dir);
        let log_path = dir.join("filtered-audit.jsonl");
        let _ = fs::remove_file(&log_path);

        let config = AuditConfig {
            enabled: true,
            path: log_path.clone(),
            max_size_bytes: 10 * 1024 * 1024,
            rotate_count: 3,
            log_data_packets: false,
            categories: vec![EventCategory::Policy], // Only policy events
            interface_name: "dvpn-test".to_string(),
        };

        let logger = AuditLogger::new(config);

        // This should be filtered out (System category)
        logger.log_daemon_started("hybrid", 3);

        // This should pass through (Policy category)
        logger.log_policy_decision(
            &[0xAA; 32],
            Some("alice"),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(10, 100, 0, 5)),
            Some(443),
            Some(6),
            false,
            "deny-all",
        );

        let contents = fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = contents.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 1); // Only the policy event
        assert!(contents.contains("packet_denied"));

        let _ = fs::remove_dir_all(&dir);
    }
}
