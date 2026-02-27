//! Broker error types

use std::net::IpAddr;

/// Errors that can occur in the Broker
#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    /// Authentication failed (invalid signature, unknown key)
    #[error("authentication failed: {0}")]
    AuthFailed(String),

    /// Peer key is revoked
    #[error("peer revoked: {0}")]
    PeerRevoked(String),

    /// Policy denied the packet
    #[error("policy denied: {0}")]
    PolicyDenied(String),

    /// No Connector serves the destination IP
    #[error("no connector for {0}")]
    NoRoute(IpAddr),

    /// Session timed out
    #[error("session timeout for peer {0}")]
    SessionTimeout(String),

    /// IO error
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Protocol-level error
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Configuration error
    #[error("config error: {0}")]
    Config(String),
}

/// Result type alias for Broker operations
pub type BrokerResult<T> = Result<T, BrokerError>;
