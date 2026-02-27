//! Configuration parsing for DyberVPN
//!
//! Supports WireGuard-compatible configuration with PQ extensions.

use crate::types::OperatingMode;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::Path;

/// Top-level DyberVPN configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Interface configuration
    pub interface: InterfaceConfig,

    /// Hardware acceleration settings (optional)
    #[serde(default)]
    pub hardware: HardwareConfig,

    /// Entropy source settings (optional)
    #[serde(default)]
    pub entropy: EntropyConfig,

    /// Enrollment API settings (optional, server only)
    #[serde(default)]
    pub enrollment: EnrollmentConfig,

    /// Security / key lifecycle settings (optional)
    #[serde(default)]
    pub security: SecurityConfig,

    /// Access control policy (optional, server only)
    #[serde(default)]
    pub access_control: AccessControlConfig,

    /// Audit logging (optional)
    #[serde(default)]
    pub audit: AuditLogConfig,

    /// Connector mode configuration (ZTNA, optional)
    #[serde(default)]
    pub connector: Option<ConnectorSection>,

    /// Peer configurations
    #[serde(default)]
    pub peer: Vec<PeerConfig>,
}

/// Interface (local) configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceConfig {
    /// Classical WireGuard private key (base64)
    pub private_key: String,

    /// Post-quantum private key (base64, ML-KEM-768) - optional for classic mode
    #[serde(default)]
    pub pq_private_key: Option<String>,

    /// ML-DSA-65 signing private key (base64) - required for pq-only mode
    #[serde(default)]
    pub mldsa_private_key: Option<String>,

    /// UDP port to listen on (server only)
    #[serde(default)]
    pub listen_port: Option<u16>,

    /// VPN interface address (CIDR notation)
    pub address: String,

    /// Operating mode
    #[serde(default)]
    pub mode: OperatingMode,

    /// DNS servers (optional)
    #[serde(default)]
    pub dns: Vec<String>,

    /// MTU (optional, default 1420)
    #[serde(default = "default_mtu")]
    pub mtu: u16,

    /// Interface name (optional, default "dvpn0")
    #[serde(default = "default_interface_name")]
    pub name: String,
}

fn default_mtu() -> u16 {
    1420
}

fn default_interface_name() -> String {
    "dvpn0".to_string()
}

/// Hardware acceleration configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HardwareConfig {
    /// Backend selection: "auto", "software", "quac100"
    #[serde(default = "default_backend")]
    pub backend: String,

    /// QUAC 100 device path (auto-detected if "auto")
    #[serde(default)]
    pub device: Option<String>,
}

fn default_backend() -> String {
    "auto".to_string()
}

/// Entropy source configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EntropyConfig {
    /// Entropy source: "auto", "os", "qrng"
    #[serde(default = "default_entropy_source")]
    pub source: String,
}

fn default_entropy_source() -> String {
    "auto".to_string()
}

/// Enrollment API configuration (server only)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EnrollmentConfig {
    /// Enable enrollment API
    #[serde(default)]
    pub enabled: bool,

    /// Listen address for enrollment API (default: 0.0.0.0:8443)
    #[serde(default = "default_enrollment_listen")]
    pub listen: String,

    /// Pre-shared enrollment token (required if enabled)
    #[serde(default)]
    pub token: Option<String>,

    /// Server endpoint (IP:port) for generated client configs
    #[serde(default)]
    pub server_endpoint: Option<String>,
}

fn default_enrollment_listen() -> String {
    "0.0.0.0:8443".to_string()
}

/// Security / key lifecycle configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Path to CRL (revoked keys) JSON file
    #[serde(default)]
    pub crl_path: Option<String>,

    /// Maximum static key age in hours (0 = no limit, default: 720 = 30 days)
    #[serde(default = "default_key_max_age")]
    pub key_max_age_hours: u64,

    /// Maximum session age in hours before forced re-handshake (default: 24)
    #[serde(default = "default_session_max_age")]
    pub session_max_age_hours: u64,

    /// How often to check for expired/revoked peers in seconds (default: 300)
    #[serde(default = "default_check_interval")]
    pub check_interval_secs: u64,

    /// Automatically disconnect peers with revoked keys (default: true)
    #[serde(default = "default_true")]
    pub auto_disconnect_revoked: bool,
}

fn default_key_max_age() -> u64 {
    720
}
fn default_session_max_age() -> u64 {
    24
}
fn default_check_interval() -> u64 {
    300
}
fn default_true() -> bool {
    true
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            crl_path: None,
            key_max_age_hours: default_key_max_age(),
            session_max_age_hours: default_session_max_age(),
            check_interval_secs: default_check_interval(),
            auto_disconnect_revoked: default_true(),
        }
    }
}

/// Access control policy configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AccessControlConfig {
    /// Enable access control enforcement
    #[serde(default)]
    pub enabled: bool,

    /// Default action: "deny" (Zero Trust) or "allow"
    #[serde(default = "default_deny")]
    pub default_action: String,

    /// Path to external policy JSON file (hot-reloadable)
    #[serde(default)]
    pub policy_path: Option<String>,

    /// Inline role definitions
    #[serde(default)]
    pub role: Vec<AccessRoleConfig>,
}

fn default_deny() -> String {
    "deny".to_string()
}

/// A role in the access control policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRoleConfig {
    /// Role name
    pub name: String,
    /// Peer names assigned to this role
    #[serde(default)]
    pub peers: Vec<String>,
    /// Peer key fingerprints assigned to this role
    #[serde(default)]
    pub peer_keys: Vec<String>,
    /// Access rules for this role
    #[serde(default)]
    pub rule: Vec<AccessRuleConfig>,
}

/// A single access control rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRuleConfig {
    /// "allow" or "deny"
    pub action: String,
    /// Target network in CIDR notation
    pub network: String,
    /// Ports (comma-separated, ranges allowed: "443,8080-8090")
    #[serde(default)]
    pub ports: Option<String>,
    /// Protocol: "tcp", "udp", "icmp", "any"
    #[serde(default = "default_any")]
    pub protocol: String,
    /// Description
    #[serde(default)]
    pub description: Option<String>,
}

fn default_any() -> String {
    "any".to_string()
}

/// Audit logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogConfig {
    /// Enable audit logging
    #[serde(default)]
    pub enabled: bool,

    /// Path to audit log file (NDJSON format)
    #[serde(default = "default_audit_path")]
    pub path: String,

    /// Maximum log file size in MB before rotation (default: 100)
    #[serde(default = "default_audit_max_mb")]
    pub max_size_mb: u64,

    /// Number of rotated files to keep (default: 10)
    #[serde(default = "default_rotate_count")]
    pub rotate_count: u32,

    /// Log per-packet data plane events (high volume, default: false)
    #[serde(default)]
    pub log_data_packets: bool,

    /// Event categories to log (empty = all)
    /// Options: connection, handshake, policy, key_management, admin, enrollment, system
    #[serde(default)]
    pub events: Vec<String>,
}

fn default_audit_path() -> String {
    "/var/log/dybervpn/audit.jsonl".to_string()
}
fn default_audit_max_mb() -> u64 {
    100
}

fn default_rotate_count() -> u32 {
    10
}

impl Default for AuditLogConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: default_audit_path(),
            max_size_mb: default_audit_max_mb(),
            rotate_count: default_rotate_count(),
            log_data_packets: false,
            events: Vec::new(),
        }
    }
}

/// Connector mode configuration (ZTNA)
///
/// When present, the daemon runs as a Connector — it establishes an outbound
/// WireGuard tunnel to a Broker and advertises local network routes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorSection {
    /// Broker's UDP endpoint for data plane (host:port)
    pub broker_endpoint: String,

    /// Broker's TCP endpoint for control plane (host:port)
    pub broker_control: String,

    /// Broker's X25519 public key (base64)
    pub broker_public_key: String,

    /// Broker's ML-KEM-768 public key (base64, for hybrid/pq-only modes)
    #[serde(default)]
    pub broker_pq_public_key: Option<String>,

    /// Broker's ML-DSA-65 public key (base64, for pq-only mode)
    #[serde(default)]
    pub broker_mldsa_public_key: Option<String>,

    /// CIDRs this connector advertises (e.g., ["10.1.0.0/16", "192.168.1.0/24"])
    #[serde(default)]
    pub advertised_routes: Vec<String>,

    /// Human-readable service name
    #[serde(default = "default_service_name")]
    pub service_name: String,

    /// Heartbeat interval in seconds (default: 30)
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval: u64,

    /// Pre-shared enrollment token (for initial registration)
    #[serde(default)]
    pub auth_token: Option<String>,
}

fn default_service_name() -> String {
    "default".to_string()
}
fn default_heartbeat_interval() -> u64 {
    30
}

/// Peer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    /// Human-readable peer name (for policy matching and audit logs)
    #[serde(default)]
    pub name: Option<String>,

    /// Peer's classical public key (base64)
    pub public_key: String,

    /// Peer's post-quantum public key (base64, ML-KEM-768)
    #[serde(default)]
    pub pq_public_key: Option<String>,

    /// Peer's ML-DSA-65 verification public key (base64) - required for pq-only mode
    #[serde(default)]
    pub mldsa_public_key: Option<String>,

    /// Allowed IP ranges for this peer (CIDR notation)
    pub allowed_ips: String,

    /// Peer endpoint (host:port) - optional for server config
    #[serde(default)]
    pub endpoint: Option<String>,

    /// Persistent keepalive interval in seconds (0 = disabled)
    #[serde(default)]
    pub persistent_keepalive: u16,

    /// Pre-shared key (optional, base64)
    #[serde(default)]
    pub preshared_key: Option<String>,
}

/// Configuration errors
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Failed to read configuration file
    #[error("Failed to read config file: {0}")]
    IoError(#[from] std::io::Error),

    /// Failed to parse TOML
    #[error("Failed to parse TOML: {0}")]
    ParseError(#[from] toml::de::Error),

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    ValidationError(String),

    /// Missing required field
    #[error("Missing required field: {0}")]
    MissingField(String),

    /// Invalid key encoding
    #[error("Invalid key encoding: {0}")]
    InvalidKey(String),
}

impl Config {
    /// Load configuration from a TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        Self::from_str(&content)
    }

    /// Parse configuration from a TOML string
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(content: &str) -> Result<Self, ConfigError> {
        let config: Config = toml::from_str(content)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Check that private key is valid base64 and correct length
        let private_bytes = base64::decode(&self.interface.private_key)
            .map_err(|_| ConfigError::InvalidKey("private_key is not valid base64".into()))?;

        if private_bytes.len() != 32 {
            return Err(ConfigError::InvalidKey(format!(
                "private_key has wrong size: {} (expected 32)",
                private_bytes.len()
            )));
        }

        // For hybrid/pq-only modes, PQ key is required
        if self.interface.mode.uses_pq_kex() {
            if self.interface.pq_private_key.is_none() {
                return Err(ConfigError::MissingField(
                    "pq_private_key is required for hybrid/pq-only modes".into(),
                ));
            }

            // Validate PQ private key
            if let Some(ref pq_key) = self.interface.pq_private_key {
                let bytes = base64::decode(pq_key).map_err(|_| {
                    ConfigError::InvalidKey("pq_private_key is not valid base64".into())
                })?;
                if bytes.len() != crate::types::mlkem768::SECRET_KEY_SIZE {
                    return Err(ConfigError::InvalidKey(format!(
                        "pq_private_key has wrong size: {} (expected {})",
                        bytes.len(),
                        crate::types::mlkem768::SECRET_KEY_SIZE
                    )));
                }
            }
        }

        // For pq-only mode, ML-DSA signing key is required
        if self.interface.mode.uses_pq_auth() {
            if self.interface.mldsa_private_key.is_none() {
                return Err(ConfigError::MissingField(
                    "mldsa_private_key is required for pq-only mode".into(),
                ));
            }

            // Validate ML-DSA private key
            if let Some(ref mldsa_key) = self.interface.mldsa_private_key {
                let bytes = base64::decode(mldsa_key).map_err(|_| {
                    ConfigError::InvalidKey("mldsa_private_key is not valid base64".into())
                })?;
                if bytes.len() != crate::types::mldsa65::SECRET_KEY_SIZE {
                    return Err(ConfigError::InvalidKey(format!(
                        "mldsa_private_key has wrong size: {} (expected {})",
                        bytes.len(),
                        crate::types::mldsa65::SECRET_KEY_SIZE
                    )));
                }
            }
        }

        // Validate peers
        for (i, peer) in self.peer.iter().enumerate() {
            let peer_bytes = base64::decode(&peer.public_key).map_err(|_| {
                ConfigError::InvalidKey(format!("peer[{}].public_key is not valid base64", i))
            })?;

            if peer_bytes.len() != 32 {
                return Err(ConfigError::InvalidKey(format!(
                    "peer[{}].public_key has wrong size: {} (expected 32)",
                    i,
                    peer_bytes.len()
                )));
            }

            // For hybrid/pq-only modes, peer PQ key is required
            if self.interface.mode.uses_pq_kex() {
                if peer.pq_public_key.is_none() {
                    return Err(ConfigError::MissingField(format!(
                        "peer[{}].pq_public_key is required for hybrid/pq-only modes",
                        i
                    )));
                }

                if let Some(ref pq_pk) = peer.pq_public_key {
                    let bytes = base64::decode(pq_pk).map_err(|_| {
                        ConfigError::InvalidKey(format!(
                            "peer[{}].pq_public_key is not valid base64",
                            i
                        ))
                    })?;
                    if bytes.len() != crate::types::mlkem768::PUBLIC_KEY_SIZE {
                        return Err(ConfigError::InvalidKey(format!(
                            "peer[{}].pq_public_key has wrong size: {} (expected {})",
                            i,
                            bytes.len(),
                            crate::types::mlkem768::PUBLIC_KEY_SIZE
                        )));
                    }
                }
            }

            // For pq-only mode, peer ML-DSA public key is required
            if self.interface.mode.uses_pq_auth() {
                if peer.mldsa_public_key.is_none() {
                    return Err(ConfigError::MissingField(format!(
                        "peer[{}].mldsa_public_key is required for pq-only mode",
                        i
                    )));
                }

                if let Some(ref mldsa_pk) = peer.mldsa_public_key {
                    let bytes = base64::decode(mldsa_pk).map_err(|_| {
                        ConfigError::InvalidKey(format!(
                            "peer[{}].mldsa_public_key is not valid base64",
                            i
                        ))
                    })?;
                    if bytes.len() != crate::types::mldsa65::PUBLIC_KEY_SIZE {
                        return Err(ConfigError::InvalidKey(format!(
                            "peer[{}].mldsa_public_key has wrong size: {} (expected {})",
                            i,
                            bytes.len(),
                            crate::types::mldsa65::PUBLIC_KEY_SIZE
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    /// Check if this is a server configuration (has listen_port)
    pub fn is_server(&self) -> bool {
        self.interface.listen_port.is_some()
    }

    /// Get the listen address for server mode
    pub fn listen_addr(&self) -> Option<SocketAddr> {
        self.interface
            .listen_port
            .map(|port| SocketAddr::from(([0, 0, 0, 0], port)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Valid 32-byte key encoded as base64
    const TEST_PRIVATE_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const TEST_PUBLIC_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    #[test]
    fn test_parse_server_config_classic() {
        let config_str = format!(
            r#"
[interface]
private_key = "{}"
listen_port = 51820
address = "10.0.0.1/24"
mode = "classic"

[[peer]]
public_key = "{}"
allowed_ips = "10.0.0.2/32"
persistent_keepalive = 25
"#,
            TEST_PRIVATE_KEY, TEST_PUBLIC_KEY
        );

        let config = Config::from_str(&config_str).unwrap();

        assert!(config.is_server());
        assert_eq!(config.interface.listen_port, Some(51820));
        assert_eq!(config.interface.mode, OperatingMode::Classic);
        assert_eq!(config.peer.len(), 1);
        assert_eq!(config.peer[0].persistent_keepalive, 25);
    }

    #[test]
    fn test_default_values_classic() {
        // Use classic mode to avoid needing PQ keys
        let config_str = format!(
            r#"
[interface]
private_key = "{}"
address = "10.0.0.1/24"
mode = "classic"
"#,
            TEST_PRIVATE_KEY
        );

        let config = Config::from_str(&config_str).unwrap();

        assert_eq!(config.interface.mode, OperatingMode::Classic);
        assert_eq!(config.interface.mtu, 1420);
        assert_eq!(config.interface.name, "dvpn0");
        // When [hardware] section is omitted, we get Default which has empty string
        // This is fine - the application treats empty as "auto"
    }

    #[test]
    fn test_hybrid_requires_pq_key() {
        let config_str = format!(
            r#"
[interface]
private_key = "{}"
address = "10.0.0.1/24"
mode = "hybrid"
"#,
            TEST_PRIVATE_KEY
        );

        let result = Config::from_str(&config_str);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(matches!(err, ConfigError::MissingField(_)));
    }

    #[test]
    fn test_invalid_key_length() {
        let config_str = r#"
[interface]
private_key = "dG9vX3Nob3J0"
address = "10.0.0.1/24"
mode = "classic"
"#;

        let result = Config::from_str(config_str);
        assert!(result.is_err());
    }
}
