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

    /// Allowlist of connectors permitted to register (fail-closed).
    ///
    /// If empty, no connector may register — the Broker refuses all connector
    /// registrations until at least one authorized connector is configured.
    /// This closes the pre-auth registration bypass (security audit C3/C4).
    pub authorized_connectors: Vec<AuthorizedConnector>,
}

/// A connector explicitly authorized to register with the Broker.
///
/// Registration is gated on this allowlist: the registering X25519 key must
/// match an entry, its advertised routes must be covered by `allowed_routes`,
/// and — when `mldsa_public_key` is present (required in pq-only mode) — its
/// ML-DSA registration signature must verify.
#[derive(Debug, Clone)]
pub struct AuthorizedConnector {
    /// Connector's X25519 public key
    pub public_key: [u8; 32],
    /// Connector's ML-DSA-65 public key (used to verify the registration
    /// signature). Required in pq-only mode; recommended otherwise.
    pub mldsa_public_key: Option<Vec<u8>>,
    /// CIDRs this connector may advertise. An advertised route is accepted only
    /// if it is equal to or more specific than one of these.
    pub allowed_routes: Vec<(IpAddr, u8)>,
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
            authorized_connectors: Vec::new(),
        }
    }
}

/// Parse a CIDR string like "10.1.0.0/16", validating the prefix length.
///
/// Rejects prefixes greater than 32 (IPv4) / 128 (IPv6), which would otherwise
/// cause shift overflow and let a connector advertise a malformed route
/// (security audit C4/M6).
pub(crate) fn parse_cidr(s: &str) -> Result<(IpAddr, u8), String> {
    let (ip_str, prefix_str) = s
        .split_once('/')
        .ok_or_else(|| format!("invalid CIDR: {}", s))?;
    let ip: IpAddr = ip_str.parse().map_err(|e| format!("invalid IP: {}", e))?;
    let prefix: u8 = prefix_str
        .parse()
        .map_err(|e| format!("invalid prefix: {}", e))?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        return Err(format!("prefix /{} exceeds maximum /{}", prefix, max));
    }
    Ok((ip, prefix))
}

/// Returns true if `ip` falls within the network `net/prefix`.
pub(crate) fn cidr_contains(net: IpAddr, prefix: u8, ip: IpAddr) -> bool {
    match (net, ip) {
        (IpAddr::V4(net), IpAddr::V4(ip)) => {
            if prefix == 0 {
                return true;
            }
            if prefix > 32 {
                return false;
            }
            let mask = !0u32 << (32 - prefix);
            (u32::from_be_bytes(net.octets()) & mask)
                == (u32::from_be_bytes(ip.octets()) & mask)
        }
        (IpAddr::V6(net), IpAddr::V6(ip)) => {
            if prefix == 0 {
                return true;
            }
            if prefix > 128 {
                return false;
            }
            let mask = !0u128 << (128 - prefix);
            (u128::from_be_bytes(net.octets()) & mask)
                == (u128::from_be_bytes(ip.octets()) & mask)
        }
        _ => false,
    }
}

impl AuthorizedConnectorFile {
    /// Resolve a config-file entry into a runtime [`AuthorizedConnector`],
    /// decoding keys and validating CIDRs.
    pub fn resolve(&self) -> Result<AuthorizedConnector, String> {
        let pk_bytes = base64::decode(&self.public_key)
            .map_err(|_| "authorized_connector.public_key is not valid base64".to_string())?;
        if pk_bytes.len() != 32 {
            return Err(format!(
                "authorized_connector.public_key must be 32 bytes, got {}",
                pk_bytes.len()
            ));
        }
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&pk_bytes);

        let mldsa_public_key = match &self.mldsa_public_key {
            Some(s) => Some(base64::decode(s).map_err(|_| {
                "authorized_connector.mldsa_public_key is not valid base64".to_string()
            })?),
            None => None,
        };

        let mut allowed_routes = Vec::with_capacity(self.allowed_routes.len());
        for r in &self.allowed_routes {
            allowed_routes.push(parse_cidr(r)?);
        }

        Ok(AuthorizedConnector {
            public_key,
            mldsa_public_key,
            allowed_routes,
        })
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

    /// Allowlist of connectors permitted to register (`[[authorized_connector]]`).
    /// Registration is fail-closed: if this list is empty, no connector may
    /// register.
    #[serde(default)]
    pub authorized_connector: Vec<AuthorizedConnectorFile>,
}

/// A `[[authorized_connector]]` entry in the broker config file.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthorizedConnectorFile {
    /// Connector's X25519 public key (base64)
    pub public_key: String,

    /// Connector's ML-DSA-65 public key (base64, optional). Required in
    /// pq-only mode to verify the registration signature.
    #[serde(default)]
    pub mldsa_public_key: Option<String>,

    /// CIDRs this connector is permitted to advertise.
    #[serde(default)]
    pub allowed_routes: Vec<String>,
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

#[cfg(test)]
mod tests {
    use super::{cidr_contains, parse_cidr};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn parse_cidr_rejects_out_of_range_prefix() {
        // Security audit C4/M6: prefixes beyond the address width must be
        // rejected rather than causing shift overflow / malformed routes.
        assert!(parse_cidr("10.0.0.0/33").is_err());
        assert!(parse_cidr("10.0.0.0/40").is_err());
        assert!(parse_cidr("::/129").is_err());
        assert!(parse_cidr("10.0.0.0/24").is_ok());
        assert!(parse_cidr("::/0").is_ok());
        assert!(parse_cidr("not-a-cidr").is_err());
    }

    #[test]
    fn cidr_contains_matches_subnets() {
        let net = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0));
        assert!(cidr_contains(net, 16, IpAddr::V4(Ipv4Addr::new(10, 1, 5, 9))));
        assert!(!cidr_contains(net, 16, IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1))));
        // prefix 0 matches everything
        assert!(cidr_contains(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            0,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))
        ));
    }
}
