//! Broker configuration

use dybervpn_protocol::OperatingMode;
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

/// Configuration for the ZTNA Broker
#[derive(Debug, Clone)]
pub struct BrokerConfig {
    /// UDP listen address for data plane (default: 0.0.0.0:51820)
    pub listen_udp: SocketAddr,

    /// TCP listen address for control plane (default: 0.0.0.0:51821)
    pub listen_control: SocketAddr,

    /// Broker's X25519 private key
    pub private_key: [u8; 32],

    /// Broker's ML-KEM-768 private key (for hybrid/pq-only modes)
    pub pq_private_key: Option<Vec<u8>>,

    /// Broker's ML-DSA-65 private key (for pq-only mode signing)
    pub mldsa_private_key: Option<Vec<u8>>,

    /// Operating mode
    pub mode: OperatingMode,

    /// Path to access control policy file
    pub policy_file: Option<PathBuf>,

    /// Path to CRL file
    pub crl_file: Option<PathBuf>,

    /// Path to audit log directory
    pub audit_dir: Option<PathBuf>,

    /// Maximum number of concurrent clients
    pub max_clients: usize,

    /// Session timeout (idle peers are removed)
    pub session_timeout: Duration,

    /// Heartbeat timeout for connectors (remove if no heartbeat)
    pub heartbeat_timeout: Duration,
}

impl Default for BrokerConfig {
    fn default() -> Self {
        Self {
            listen_udp: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 51820),
            listen_control: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 51821),
            private_key: [0u8; 32],
            pq_private_key: None,
            mldsa_private_key: None,
            mode: OperatingMode::Hybrid,
            policy_file: None,
            crl_file: None,
            audit_dir: None,
            max_clients: 1000,
            session_timeout: Duration::from_secs(300),
            heartbeat_timeout: Duration::from_secs(120),
        }
    }
}

/// TOML-deserializable broker configuration file format
#[derive(Debug, Clone, Deserialize)]
pub struct BrokerConfigFile {
    pub broker: BrokerSection,
}

/// The `[broker]` section of the config file
#[derive(Debug, Clone, Deserialize)]
pub struct BrokerSection {
    /// UDP listen address (default: "0.0.0.0:51820")
    #[serde(default = "default_udp_listen")]
    pub listen_udp: String,

    /// TCP listen address for control plane (default: "0.0.0.0:51821")
    #[serde(default = "default_control_listen")]
    pub listen_control: String,

    /// X25519 private key (base64)
    pub private_key: String,

    /// ML-KEM-768 private key (base64, optional)
    #[serde(default)]
    pub pq_private_key: Option<String>,

    /// ML-DSA-65 private key (base64, optional)
    #[serde(default)]
    pub mldsa_private_key: Option<String>,

    /// Operating mode (hybrid, pq-only, classic)
    #[serde(default)]
    pub mode: OperatingMode,

    /// Path to policy file
    #[serde(default)]
    pub policy_file: Option<String>,

    /// Path to CRL file
    #[serde(default)]
    pub crl_file: Option<String>,

    /// Path to audit log directory
    #[serde(default)]
    pub audit_dir: Option<String>,

    /// Max clients (default: 1000)
    #[serde(default = "default_max_clients")]
    pub max_clients: usize,

    /// Session timeout in seconds (default: 300)
    #[serde(default = "default_session_timeout")]
    pub session_timeout: u64,

    /// Heartbeat timeout in seconds (default: 120)
    #[serde(default = "default_heartbeat_timeout")]
    pub heartbeat_timeout: u64,
}

fn default_udp_listen() -> String {
    "0.0.0.0:51820".to_string()
}
fn default_control_listen() -> String {
    "0.0.0.0:51821".to_string()
}
fn default_max_clients() -> usize {
    1000
}
fn default_session_timeout() -> u64 {
    300
}
fn default_heartbeat_timeout() -> u64 {
    120
}
