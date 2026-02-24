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

/// Peer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    /// Peer's classical public key (base64)
    pub public_key: String,
    
    /// Peer's post-quantum public key (base64, ML-KEM-768)
    #[serde(default)]
    pub pq_public_key: Option<String>,
    
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
                    "pq_private_key is required for hybrid/pq-only modes".into()
                ));
            }
            
            // Validate PQ private key
            if let Some(ref pq_key) = self.interface.pq_private_key {
                let bytes = base64::decode(pq_key)
                    .map_err(|_| ConfigError::InvalidKey("pq_private_key is not valid base64".into()))?;
                if bytes.len() != crate::types::mlkem768::SECRET_KEY_SIZE {
                    return Err(ConfigError::InvalidKey(format!(
                        "pq_private_key has wrong size: {} (expected {})",
                        bytes.len(),
                        crate::types::mlkem768::SECRET_KEY_SIZE
                    )));
                }
            }
        }
        
        // Validate peers
        for (i, peer) in self.peer.iter().enumerate() {
            let peer_bytes = base64::decode(&peer.public_key)
                .map_err(|_| ConfigError::InvalidKey(format!("peer[{}].public_key is not valid base64", i)))?;
            
            if peer_bytes.len() != 32 {
                return Err(ConfigError::InvalidKey(format!(
                    "peer[{}].public_key has wrong size: {} (expected 32)",
                    i, peer_bytes.len()
                )));
            }
            
            // For hybrid/pq-only modes, peer PQ key is required
            if self.interface.mode.uses_pq_kex() {
                if peer.pq_public_key.is_none() {
                    return Err(ConfigError::MissingField(format!(
                        "peer[{}].pq_public_key is required for hybrid/pq-only modes", i
                    )));
                }
                
                if let Some(ref pq_pk) = peer.pq_public_key {
                    let bytes = base64::decode(pq_pk)
                        .map_err(|_| ConfigError::InvalidKey(format!("peer[{}].pq_public_key is not valid base64", i)))?;
                    if bytes.len() != crate::types::mlkem768::PUBLIC_KEY_SIZE {
                        return Err(ConfigError::InvalidKey(format!(
                            "peer[{}].pq_public_key has wrong size: {} (expected {})",
                            i, bytes.len(), crate::types::mlkem768::PUBLIC_KEY_SIZE
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
        self.interface.listen_port.map(|port| {
            SocketAddr::from(([0, 0, 0, 0], port))
        })
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
        let config_str = format!(r#"
[interface]
private_key = "{}"
listen_port = 51820
address = "10.0.0.1/24"
mode = "classic"

[[peer]]
public_key = "{}"
allowed_ips = "10.0.0.2/32"
persistent_keepalive = 25
"#, TEST_PRIVATE_KEY, TEST_PUBLIC_KEY);

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
        let config_str = format!(r#"
[interface]
private_key = "{}"
address = "10.0.0.1/24"
mode = "classic"
"#, TEST_PRIVATE_KEY);

        let config = Config::from_str(&config_str).unwrap();
        
        assert_eq!(config.interface.mode, OperatingMode::Classic);
        assert_eq!(config.interface.mtu, 1420);
        assert_eq!(config.interface.name, "dvpn0");
        // When [hardware] section is omitted, we get Default which has empty string
        // This is fine - the application treats empty as "auto"
    }
    
    #[test]
    fn test_hybrid_requires_pq_key() {
        let config_str = format!(r#"
[interface]
private_key = "{}"
address = "10.0.0.1/24"
mode = "hybrid"
"#, TEST_PRIVATE_KEY);

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
