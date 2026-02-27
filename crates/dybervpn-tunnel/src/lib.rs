//! DyberVPN Tunnel Management
//!
//! Cross-platform TUN/TAP device management for DyberVPN.

#![warn(missing_docs)]

pub mod audit;
pub mod config;
pub mod connector;
pub mod daemon;
pub mod device;
pub mod enrollment;
pub mod error;
pub mod policy;
pub mod revocation;
pub mod tunnel;

// Platform-specific modules - only compile on their target
#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "windows")]
pub mod windows;

// Re-exports
pub use audit::{AuditConfig, AuditLogger};
pub use config::{TunnelConfig, PeerConfig, ConnectorConfig};
pub use daemon::Daemon;
pub use device::DeviceHandle;
pub use error::{TunnelError, TunnelResult};
pub use policy::{PolicyConfig, PolicyEngine, PolicyAction};
pub use revocation::{RevocationEngine, RevocationReason, SecurityConfig, KeyStatus};
pub use tunnel::{VpnTunnel, TunnelState, PeerStats};

/// Maximum transmission unit (MTU) for WireGuard
pub const DEFAULT_MTU: u16 = 1420;

/// WireGuard default port
pub const DEFAULT_PORT: u16 = 51820;
