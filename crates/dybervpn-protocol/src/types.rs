//! Post-quantum cryptographic types for DyberVPN

use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Size constants for ML-KEM-768 (NIST Security Level 3)
pub mod mlkem768 {
    /// Public key size in bytes
    pub const PUBLIC_KEY_SIZE: usize = 1184;
    /// Secret key (decapsulation key) size in bytes
    pub const SECRET_KEY_SIZE: usize = 2400;
    /// Ciphertext size in bytes
    pub const CIPHERTEXT_SIZE: usize = 1088;
    /// Shared secret size in bytes
    pub const SHARED_SECRET_SIZE: usize = 32;
}

/// Size constants for X25519
pub mod x25519 {
    /// Public key size in bytes
    pub const PUBLIC_KEY_SIZE: usize = 32;
    /// Secret key size in bytes
    pub const SECRET_KEY_SIZE: usize = 32;
    /// Shared secret size in bytes
    pub const SHARED_SECRET_SIZE: usize = 32;
}

/// Size constants for Ed25519
pub mod ed25519 {
    /// Public key size in bytes
    pub const PUBLIC_KEY_SIZE: usize = 32;
    /// Secret key size in bytes
    pub const SECRET_KEY_SIZE: usize = 32;
    /// Signature size in bytes
    pub const SIGNATURE_SIZE: usize = 64;
}

// ============================================================================
// ML-KEM (Post-Quantum Key Encapsulation)
// ============================================================================

/// ML-KEM-768 public key (encapsulation key)
#[derive(Clone)]
pub struct MlKemPublicKey(pub Vec<u8>);

impl MlKemPublicKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        if bytes.len() != mlkem768::PUBLIC_KEY_SIZE {
            return Err(KeyError::InvalidLength {
                expected: mlkem768::PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Encode as base64
    pub fn to_base64(&self) -> String {
        base64::encode(&self.0)
    }

    /// Decode from base64
    pub fn from_base64(s: &str) -> Result<Self, KeyError> {
        let bytes = base64::decode(s).map_err(|_| KeyError::InvalidEncoding)?;
        Self::from_bytes(&bytes)
    }
}

impl fmt::Debug for MlKemPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MlKemPublicKey([{}...])", hex::encode(&self.0[..8.min(self.0.len())]))
    }
}

/// ML-KEM-768 secret key (decapsulation key, zeroized on drop)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlKemSecretKey(pub Vec<u8>);

impl MlKemSecretKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        if bytes.len() != mlkem768::SECRET_KEY_SIZE {
            return Err(KeyError::InvalidLength {
                expected: mlkem768::SECRET_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for MlKemSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MlKemSecretKey([REDACTED])")
    }
}

/// ML-KEM-768 ciphertext
#[derive(Clone)]
pub struct MlKemCiphertext(pub Vec<u8>);

impl MlKemCiphertext {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        if bytes.len() != mlkem768::CIPHERTEXT_SIZE {
            return Err(KeyError::InvalidLength {
                expected: mlkem768::CIPHERTEXT_SIZE,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for MlKemCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MlKemCiphertext([{}...])", hex::encode(&self.0[..8.min(self.0.len())]))
    }
}

// ============================================================================
// Shared Secret
// ============================================================================

/// A shared secret derived from key exchange (zeroized on drop)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret(pub [u8; 32]);

impl SharedSecret {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        if bytes.len() != 32 {
            return Err(KeyError::InvalidLength {
                expected: 32,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SharedSecret([REDACTED])")
    }
}

// ============================================================================
// Operating Modes
// ============================================================================

/// DyberVPN operating mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum OperatingMode {
    /// Hybrid ML-KEM-768 + X25519 key exchange, Ed25519 auth
    #[default]
    Hybrid,
    /// Pure post-quantum: ML-KEM-768 key exchange, ML-DSA-65 auth (future)
    PqOnly,
    /// Standard WireGuard: X25519 key exchange, Ed25519 auth
    Classic,
}

impl OperatingMode {
    /// Returns true if post-quantum key exchange is enabled
    pub fn uses_pq_kex(&self) -> bool {
        matches!(self, Self::Hybrid | Self::PqOnly)
    }

    /// Returns true if post-quantum authentication is enabled
    pub fn uses_pq_auth(&self) -> bool {
        matches!(self, Self::PqOnly)
    }
}

impl std::str::FromStr for OperatingMode {
    type Err = KeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "hybrid" => Ok(Self::Hybrid),
            "pq-only" | "pqonly" => Ok(Self::PqOnly),
            "classic" => Ok(Self::Classic),
            _ => Err(KeyError::InvalidEncoding),
        }
    }
}

// ============================================================================
// Errors
// ============================================================================

/// Key-related errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum KeyError {
    /// Invalid key length
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidLength {
        /// Expected length in bytes
        expected: usize,
        /// Actual length in bytes
        actual: usize,
    },

    /// Invalid encoding
    #[error("Invalid key encoding")]
    InvalidEncoding,

    /// Cryptographic operation failed
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operating_mode_default() {
        assert_eq!(OperatingMode::default(), OperatingMode::Hybrid);
    }

    #[test]
    fn test_operating_mode_pq_features() {
        assert!(OperatingMode::Hybrid.uses_pq_kex());
        assert!(!OperatingMode::Hybrid.uses_pq_auth());

        assert!(OperatingMode::PqOnly.uses_pq_kex());
        assert!(OperatingMode::PqOnly.uses_pq_auth());

        assert!(!OperatingMode::Classic.uses_pq_kex());
        assert!(!OperatingMode::Classic.uses_pq_auth());
    }

    #[test]
    fn test_operating_mode_from_str() {
        assert_eq!("hybrid".parse::<OperatingMode>().unwrap(), OperatingMode::Hybrid);
        assert_eq!("pq-only".parse::<OperatingMode>().unwrap(), OperatingMode::PqOnly);
        assert_eq!("classic".parse::<OperatingMode>().unwrap(), OperatingMode::Classic);
    }
}
