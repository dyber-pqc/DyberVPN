//! Tunnel error types

use std::io;
use thiserror::Error;

/// Result type for tunnel operations
pub type TunnelResult<T> = Result<T, TunnelError>;

/// Errors that can occur during tunnel operations
#[derive(Debug, Error)]
pub enum TunnelError {
    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Device creation failed
    #[error("Failed to create TUN device: {0}")]
    DeviceCreation(String),

    /// Device not found
    #[error("TUN device not found: {0}")]
    DeviceNotFound(String),

    /// Permission denied
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// Invalid address
    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    /// Handshake failed
    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),

    /// Encryption error
    #[error("Encryption error: {0}")]
    Encryption(String),

    /// Decryption error
    #[error("Decryption error: {0}")]
    Decryption(String),

    /// Invalid packet
    #[error("Invalid packet: {0}")]
    InvalidPacket(String),

    /// Peer not found
    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    /// Session expired
    #[error("Session expired")]
    SessionExpired,

    /// Timeout
    #[error("Operation timed out")]
    Timeout,

    /// Already running
    #[error("Tunnel already running")]
    AlreadyRunning,

    /// Not running
    #[error("Tunnel not running")]
    NotRunning,

    /// Platform not supported
    #[error("Platform not supported: {0}")]
    PlatformNotSupported(String),

    /// WireGuard error
    #[error("WireGuard error: {0}")]
    WireGuard(String),

    /// Post-quantum error
    #[error("Post-quantum crypto error: {0}")]
    PostQuantum(String),

    /// Other error
    #[error("{0}")]
    Other(String),
}

impl From<boringtun::noise::errors::WireGuardError> for TunnelError {
    fn from(e: boringtun::noise::errors::WireGuardError) -> Self {
        TunnelError::WireGuard(format!("{:?}", e))
    }
}
