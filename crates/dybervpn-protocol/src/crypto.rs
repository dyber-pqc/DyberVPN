//! Cryptographic backend abstraction for DyberVPN
//!
//! This module provides a pluggable interface for cryptographic operations,
//! allowing both software implementations and hardware acceleration (QUAC 100)
//! to be used interchangeably.

use crate::types::{KeyError, MlKemCiphertext, MlKemPublicKey, MlKemSecretKey, SharedSecret};

/// Result type for crypto operations
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Errors that can occur during cryptographic operations
#[derive(Debug, Clone, thiserror::Error)]
pub enum CryptoError {
    /// Key generation failed
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    /// Encapsulation failed
    #[error("Encapsulation failed: {0}")]
    Encapsulation(String),

    /// Decapsulation failed
    #[error("Decapsulation failed: {0}")]
    Decapsulation(String),

    /// Signing failed
    #[error("Signing failed: {0}")]
    Signing(String),

    /// Verification failed
    #[error("Signature verification failed: {0}")]
    Verification(String),

    /// Random number generation failed
    #[error("Random number generation failed: {0}")]
    RandomGeneration(String),

    /// Key error
    #[error("Key error: {0}")]
    Key(#[from] KeyError),

    /// Backend not available
    #[error("Crypto backend not available: {0}")]
    BackendUnavailable(String),

    /// Generic internal error
    #[error("Internal crypto error: {0}")]
    Internal(String),
}

/// Trait for pluggable cryptographic backends
///
/// This trait abstracts all post-quantum and classical cryptographic operations,
/// allowing DyberVPN to switch between software and hardware implementations.
pub trait CryptoBackend: Send + Sync {
    /// Returns the name of this backend
    fn name(&self) -> &'static str;

    // ========================================================================
    // ML-KEM-768 (Post-Quantum Key Encapsulation)
    // ========================================================================

    /// Generate an ML-KEM-768 key pair
    fn mlkem_keygen(&self) -> CryptoResult<(MlKemPublicKey, MlKemSecretKey)>;

    /// Encapsulate a shared secret using an ML-KEM-768 public key
    fn mlkem_encaps(&self, pk: &MlKemPublicKey) -> CryptoResult<(MlKemCiphertext, SharedSecret)>;

    /// Decapsulate a shared secret using an ML-KEM-768 secret key
    fn mlkem_decaps(&self, sk: &MlKemSecretKey, ct: &MlKemCiphertext) -> CryptoResult<SharedSecret>;

    // ========================================================================
    // X25519 (Classical Key Exchange)
    // ========================================================================

    /// Generate an X25519 key pair
    fn x25519_keygen(&self) -> CryptoResult<([u8; 32], [u8; 32])>;

    /// Perform X25519 Diffie-Hellman
    fn x25519_diffie_hellman(
        &self,
        our_secret: &[u8; 32],
        their_public: &[u8; 32],
    ) -> CryptoResult<SharedSecret>;

    // ========================================================================
    // Ed25519 (Classical Signatures)
    // ========================================================================

    /// Generate an Ed25519 key pair
    fn ed25519_keygen(&self) -> CryptoResult<([u8; 32], [u8; 64])>;

    /// Sign a message using Ed25519
    fn ed25519_sign(&self, secret_key: &[u8; 64], msg: &[u8]) -> CryptoResult<[u8; 64]>;

    /// Verify an Ed25519 signature
    fn ed25519_verify(
        &self,
        public_key: &[u8; 32],
        msg: &[u8],
        signature: &[u8; 64],
    ) -> CryptoResult<bool>;

    // ========================================================================
    // Entropy
    // ========================================================================

    /// Fill a buffer with random bytes
    fn random_bytes(&self, buf: &mut [u8]) -> CryptoResult<()>;

    // ========================================================================
    // Key Derivation
    // ========================================================================

    /// HKDF-SHA256 extract and expand
    fn hkdf_sha256(&self, salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) -> CryptoResult<()>;

    // ========================================================================
    // Hybrid Operations
    // ========================================================================

    /// Combine ML-KEM and X25519 shared secrets using HKDF
    fn combine_shared_secrets(
        &self,
        mlkem_ss: &SharedSecret,
        x25519_ss: &SharedSecret,
        context: &[u8],
    ) -> CryptoResult<SharedSecret> {
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(mlkem_ss.as_bytes());
        combined[32..].copy_from_slice(x25519_ss.as_bytes());

        let mut output = [0u8; 32];
        self.hkdf_sha256(b"DyberVPN-Hybrid-KEM", &combined, context, &mut output)?;

        Ok(SharedSecret(output))
    }
}

/// Selects the best available crypto backend
pub fn select_backend() -> Box<dyn CryptoBackend> {
    #[cfg(feature = "software-backend")]
    {
        Box::new(super::software::SoftwareBackend::new())
    }

    #[cfg(not(feature = "software-backend"))]
    {
        compile_error!("At least one crypto backend must be enabled");
    }
}
