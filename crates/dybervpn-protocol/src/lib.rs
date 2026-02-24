//! DyberVPN Protocol — Post-Quantum Cryptographic Core
//!
//! This crate implements the cryptographic protocol layer for DyberVPN,
//! including hybrid post-quantum key exchange (ML-KEM-768 + X25519).
//!
//! # Features
//!
//! - **Hybrid PQ Key Exchange**: Combines ML-KEM-768 (NIST FIPS 203) with X25519
//!   for defense-in-depth against both classical and quantum attacks.
//! - **Pluggable Backends**: Abstract `CryptoBackend` trait allows swapping
//!   between software and hardware (QUAC 100) implementations.
//! - **CNSA 2.0 Aligned**: Algorithm choices aligned with NSA CNSA 2.0 requirements.
//!
//! # Operating Modes
//!
//! - `Hybrid` (default): ML-KEM-768 + X25519 key exchange, Ed25519 authentication
//! - `PqOnly`: Pure ML-KEM-768 key exchange, ML-DSA-65 authentication (Phase 2)
//! - `Classic`: Standard WireGuard-compatible X25519 + Ed25519
//!
//! # Example
//!
//! ```
//! use dybervpn_protocol::{select_backend, CryptoBackend};
//!
//! let backend = select_backend();
//! println!("Using crypto backend: {}", backend.name());
//!
//! // Generate hybrid key pair
//! let (mlkem_pk, mlkem_sk) = backend.mlkem_keygen().unwrap();
//! let (x25519_pk, x25519_sk) = backend.x25519_keygen().unwrap();
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod config;
pub mod crypto;
pub mod software;
pub mod types;

// Re-exports
pub use config::{Config, ConfigError, InterfaceConfig, PeerConfig};
pub use crypto::{select_backend, CryptoBackend, CryptoError, CryptoResult};
pub use software::SoftwareBackend;
pub use types::{
    KeyError, MlKemCiphertext, MlKemPublicKey, MlKemSecretKey, OperatingMode, SharedSecret,
};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Protocol identifier
pub const PROTOCOL_ID: &[u8] = b"DyberVPN v1";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_select_backend() {
        let backend = select_backend();
        assert_eq!(backend.name(), "software (ml-kem + dalek)");
    }
}
