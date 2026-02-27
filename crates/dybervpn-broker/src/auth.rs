//! ML-DSA-65 mutual authentication for Broker↔Connector/Client
//!
//! Connectors (and optionally Clients) authenticate to the Broker by signing
//! `SHA-256(public_key || timestamp_be_bytes)` with their ML-DSA-65 private key.
//! The Broker verifies the signature using the peer's known public key.
//!
//! Timestamp must be within `MAX_CLOCK_SKEW` seconds of the Broker's clock
//! to prevent replay attacks.

use crate::error::{BrokerError, BrokerResult};
use dybervpn_protocol::{select_backend, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum allowed clock skew for authentication timestamps (5 minutes)
const MAX_CLOCK_SKEW: u64 = 300;

/// Build the authentication message: SHA-256(public_key || timestamp_be_bytes)
fn build_auth_message(public_key: &[u8; 32], timestamp: u64) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(public_key);
    hasher.update(timestamp.to_be_bytes());
    hasher.finalize().to_vec()
}

/// Check that a timestamp is within acceptable bounds
fn check_timestamp(timestamp: u64) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let skew = now.abs_diff(timestamp);

    skew <= MAX_CLOCK_SKEW
}

/// Verify an ML-DSA-65 signature over (public_key || timestamp)
///
/// Returns `Ok(true)` if the signature is valid and timestamp is fresh.
pub fn verify_mldsa_auth(
    mldsa_public_key_bytes: &[u8],
    public_key: &[u8; 32],
    timestamp: u64,
    signature_bytes: &[u8],
) -> BrokerResult<bool> {
    // Check timestamp freshness (replay protection)
    if !check_timestamp(timestamp) {
        tracing::warn!(
            "Authentication timestamp outside acceptable window (max skew={}s)",
            MAX_CLOCK_SKEW
        );
        return Ok(false);
    }

    // Parse the ML-DSA public key
    let mldsa_pk = MlDsaPublicKey::from_bytes(mldsa_public_key_bytes)
        .map_err(|e| BrokerError::AuthFailed(format!("invalid ML-DSA public key: {}", e)))?;

    // Parse the signature
    let signature = MlDsaSignature::from_bytes(signature_bytes)
        .map_err(|e| BrokerError::AuthFailed(format!("invalid ML-DSA signature: {}", e)))?;

    // Build the message that was signed
    let message = build_auth_message(public_key, timestamp);

    // Verify using the protocol's crypto backend
    let backend = select_backend();
    match backend.mldsa_verify(&mldsa_pk, &message, &signature) {
        Ok(valid) => Ok(valid),
        Err(e) => Err(BrokerError::AuthFailed(format!(
            "ML-DSA verify error: {}",
            e
        ))),
    }
}

/// Create an ML-DSA-65 signature over (public_key || timestamp) for authentication
pub fn sign_mldsa_auth(
    mldsa_secret_key_bytes: &[u8],
    public_key: &[u8; 32],
    timestamp: u64,
) -> BrokerResult<Vec<u8>> {
    let mldsa_sk = MlDsaSecretKey::from_bytes(mldsa_secret_key_bytes)
        .map_err(|e| BrokerError::AuthFailed(format!("invalid ML-DSA secret key: {}", e)))?;

    let message = build_auth_message(public_key, timestamp);

    let backend = select_backend();
    let signature = backend
        .mldsa_sign(&mldsa_sk, &message)
        .map_err(|e| BrokerError::AuthFailed(format!("ML-DSA sign error: {}", e)))?;

    Ok(signature.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_freshness_valid() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(check_timestamp(now));
        assert!(check_timestamp(now - 100));
        assert!(check_timestamp(now + 100));
    }

    #[test]
    fn test_timestamp_freshness_expired() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(!check_timestamp(now - MAX_CLOCK_SKEW - 1));
        assert!(!check_timestamp(now + MAX_CLOCK_SKEW + 1));
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let backend = select_backend();
        let (pk, sk) = backend.mldsa_keygen().expect("keygen");

        let x25519_key = [42u8; 32];
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let sig = sign_mldsa_auth(sk.as_bytes(), &x25519_key, timestamp).expect("sign");

        let valid = verify_mldsa_auth(pk.as_bytes(), &x25519_key, timestamp, &sig).expect("verify");

        assert!(valid, "signature should verify");
    }

    #[test]
    fn test_wrong_key_fails_verification() {
        let backend = select_backend();
        let (_pk1, sk1) = backend.mldsa_keygen().expect("keygen1");
        let (pk2, _sk2) = backend.mldsa_keygen().expect("keygen2");

        let x25519_key = [42u8; 32];
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let sig = sign_mldsa_auth(sk1.as_bytes(), &x25519_key, timestamp).expect("sign");

        let valid =
            verify_mldsa_auth(pk2.as_bytes(), &x25519_key, timestamp, &sig).expect("verify");

        assert!(!valid, "signature should NOT verify with wrong key");
    }
}
