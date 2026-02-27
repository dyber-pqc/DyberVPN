//! Hybrid Post-Quantum Handshake Integration for DyberVPN
//!
//! This module provides the integration layer between the PQ handshake state
//! and the WireGuard Noise protocol handshake.

use super::handshake::{b2s_hmac, b2s_hmac2};
use super::{HybridHandshakeState, MlDsaKeyPair, MLKEM_CIPHERTEXT_SIZE};

#[cfg(test)]
use super::MLDSA_SIGNATURE_SIZE;

#[cfg(test)]
use super::MLKEM_PUBLIC_KEY_SIZE;
use crate::noise::errors::WireGuardError;
use dybervpn_protocol::{MlDsaPublicKey, MlDsaSignature};

/// Extends the chaining key with ML-KEM shared secret
/// This is the core of hybrid key derivation
pub fn derive_hybrid_chaining_key(
    classical_chaining_key: &[u8; 32],
    pq_shared_secret: &[u8; 32],
) -> [u8; 32] {
    // KDF: new_ck = HMAC(HMAC(classical_ck, pq_ss), 0x01)
    let temp = b2s_hmac(classical_chaining_key, pq_shared_secret);
    b2s_hmac(&temp, &[0x01])
}

/// Derive session keys with hybrid PQ contribution
pub fn derive_hybrid_session_keys(
    classical_chaining_key: &[u8; 32],
    pq_shared_secret: Option<&[u8; 32]>,
) -> ([u8; 32], [u8; 32]) {
    // If we have a PQ shared secret, mix it in
    let final_chaining_key = match pq_shared_secret {
        Some(pq_ss) => derive_hybrid_chaining_key(classical_chaining_key, pq_ss),
        None => *classical_chaining_key,
    };

    // Standard WireGuard key derivation from here
    // temp1 = HMAC(chaining_key, [empty])
    // temp2 = HMAC(temp1, 0x1)  -- sending key
    // temp3 = HMAC(temp1, temp2 || 0x2) -- receiving key
    let temp1 = b2s_hmac(&final_chaining_key, &[]);
    let sending_key = b2s_hmac(&temp1, &[0x01]);
    let receiving_key = b2s_hmac2(&temp1, &sending_key, &[0x02]);

    (sending_key, receiving_key)
}

/// State for a hybrid handshake in progress (initiator side)
#[derive(Debug)]
pub struct HybridInitiatorState {
    /// ML-KEM ephemeral public key we sent
    pub pq_ephemeral_pk: Vec<u8>,
    /// Our ephemeral secret key for decapsulation
    pub pq_state: HybridHandshakeState,
    /// Our ML-DSA signature over handshake transcript (for pq-only mode)
    pub mldsa_signature: Option<Vec<u8>>,
}

/// State for a hybrid handshake in progress (responder side)
#[derive(Debug)]
pub struct HybridResponderState {
    /// ML-KEM ciphertext we'll send
    pub pq_ciphertext: [u8; MLKEM_CIPHERTEXT_SIZE],
    /// Shared secret from encapsulation
    pub pq_shared_secret: [u8; 32],
    /// Our ML-DSA signature over handshake transcript (for pq-only mode)
    pub mldsa_signature: Option<Vec<u8>>,
    /// PQ state for transcript management
    pub pq_state: HybridHandshakeState,
}

impl HybridInitiatorState {
    /// Create new initiator state, generating ephemeral PQ keypair
    pub fn new(mode: dybervpn_protocol::OperatingMode) -> Result<Self, WireGuardError> {
        let mut pq_state = HybridHandshakeState::new(mode);

        if pq_state.is_pq_enabled() {
            let pk = pq_state.generate_ephemeral().map_err(|e| {
                tracing::error!("Failed to generate PQ ephemeral key: {}", e);
                WireGuardError::InvalidPacket
            })?;

            let pq_ephemeral_pk = pk.as_bytes().to_vec();

            Ok(Self {
                pq_ephemeral_pk,
                pq_state,
                mldsa_signature: None,
            })
        } else {
            Ok(Self {
                pq_ephemeral_pk: Vec::new(),
                pq_state,
                mldsa_signature: None,
            })
        }
    }

    /// Set the ML-DSA keypair for signing (pq-only mode)
    pub fn set_mldsa_keypair(&mut self, keypair: MlDsaKeyPair) {
        self.pq_state.set_mldsa_keypair(keypair);
    }

    /// Set the peer's ML-DSA public key for verification (pq-only mode)
    pub fn set_peer_mldsa_public_key(&mut self, pk: MlDsaPublicKey) {
        self.pq_state.set_peer_mldsa_public_key(pk);
    }

    /// Add data to the handshake transcript
    pub fn extend_transcript(&mut self, data: &[u8]) {
        self.pq_state.extend_transcript(data);
    }

    /// Sign the current transcript (for pq-only mode)
    pub fn sign_transcript(&mut self) -> Result<Vec<u8>, WireGuardError> {
        if !self.pq_state.is_pq_auth_enabled() {
            return Err(WireGuardError::InvalidPacket);
        }

        let sig = self.pq_state.sign_transcript().map_err(|e| {
            tracing::error!("ML-DSA signing failed: {}", e);
            WireGuardError::InvalidPacket
        })?;

        let sig_bytes = sig.as_bytes().to_vec();
        self.mldsa_signature = Some(sig_bytes.clone());
        Ok(sig_bytes)
    }

    /// Verify peer's signature over transcript (for pq-only mode)
    pub fn verify_peer_signature(&self, signature: &[u8]) -> Result<bool, WireGuardError> {
        if !self.pq_state.is_pq_auth_enabled() {
            return Ok(true); // Not required in non-pq-only modes
        }

        let sig = MlDsaSignature::from_bytes(signature).map_err(|e| {
            tracing::error!("Invalid ML-DSA signature format: {}", e);
            WireGuardError::InvalidPacket
        })?;

        self.pq_state.verify_peer_signature(&sig).map_err(|e| {
            tracing::error!("ML-DSA verification failed: {}", e);
            WireGuardError::InvalidPacket
        })
    }

    /// Process response: decapsulate the ciphertext
    pub fn process_response(&mut self, pq_ciphertext: &[u8]) -> Result<[u8; 32], WireGuardError> {
        self.pq_state.decapsulate(pq_ciphertext).map_err(|e| {
            tracing::error!("PQ decapsulation failed: {}", e);
            WireGuardError::InvalidPacket
        })
    }
}

impl HybridResponderState {
    /// Create responder state from initiator's PQ public key
    pub fn new(
        mode: dybervpn_protocol::OperatingMode,
        initiator_pq_pk: &[u8],
    ) -> Result<Self, WireGuardError> {
        let mut pq_state = HybridHandshakeState::new(mode);

        if pq_state.is_pq_enabled() {
            let (ciphertext, shared_secret) =
                pq_state.encapsulate_to_peer(initiator_pq_pk).map_err(|e| {
                    tracing::error!("PQ encapsulation failed: {}", e);
                    WireGuardError::InvalidPacket
                })?;

            Ok(Self {
                pq_ciphertext: ciphertext,
                pq_shared_secret: shared_secret,
                mldsa_signature: None,
                pq_state,
            })
        } else {
            Err(WireGuardError::InvalidPacket)
        }
    }

    /// Set the ML-DSA keypair for signing (pq-only mode)
    pub fn set_mldsa_keypair(&mut self, keypair: MlDsaKeyPair) {
        self.pq_state.set_mldsa_keypair(keypair);
    }

    /// Set the peer's ML-DSA public key for verification (pq-only mode)
    pub fn set_peer_mldsa_public_key(&mut self, pk: MlDsaPublicKey) {
        self.pq_state.set_peer_mldsa_public_key(pk);
    }

    /// Add data to the handshake transcript
    pub fn extend_transcript(&mut self, data: &[u8]) {
        self.pq_state.extend_transcript(data);
    }

    /// Sign the current transcript (for pq-only mode)
    pub fn sign_transcript(&mut self) -> Result<Vec<u8>, WireGuardError> {
        if !self.pq_state.is_pq_auth_enabled() {
            return Err(WireGuardError::InvalidPacket);
        }

        let sig = self.pq_state.sign_transcript().map_err(|e| {
            tracing::error!("ML-DSA signing failed: {}", e);
            WireGuardError::InvalidPacket
        })?;

        let sig_bytes = sig.as_bytes().to_vec();
        self.mldsa_signature = Some(sig_bytes.clone());
        Ok(sig_bytes)
    }

    /// Verify peer's signature over transcript (for pq-only mode)
    pub fn verify_peer_signature(&self, signature: &[u8]) -> Result<bool, WireGuardError> {
        if !self.pq_state.is_pq_auth_enabled() {
            return Ok(true); // Not required in non-pq-only modes
        }

        let sig = MlDsaSignature::from_bytes(signature).map_err(|e| {
            tracing::error!("Invalid ML-DSA signature format: {}", e);
            WireGuardError::InvalidPacket
        })?;

        self.pq_state.verify_peer_signature(&sig).map_err(|e| {
            tracing::error!("ML-DSA verification failed: {}", e);
            WireGuardError::InvalidPacket
        })
    }

    /// Check if PQ authentication is enabled
    pub fn is_pq_auth_enabled(&self) -> bool {
        self.pq_state.is_pq_auth_enabled()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dybervpn_protocol::OperatingMode;

    #[test]
    fn test_hybrid_key_derivation() {
        let classical_ck = [1u8; 32];
        let pq_ss = [2u8; 32];

        let hybrid_ck = derive_hybrid_chaining_key(&classical_ck, &pq_ss);

        // Should be deterministic
        let hybrid_ck2 = derive_hybrid_chaining_key(&classical_ck, &pq_ss);
        assert_eq!(hybrid_ck, hybrid_ck2);

        // Different input should produce different output
        let different = derive_hybrid_chaining_key(&[3u8; 32], &pq_ss);
        assert_ne!(hybrid_ck, different);
    }

    #[test]
    fn test_hybrid_session_keys() {
        let ck = [1u8; 32];
        let pq_ss = [2u8; 32];

        // With PQ
        let (send_key1, recv_key1) = derive_hybrid_session_keys(&ck, Some(&pq_ss));

        // Without PQ
        let (send_key2, recv_key2) = derive_hybrid_session_keys(&ck, None);

        // Should be different
        assert_ne!(send_key1, send_key2);
        assert_ne!(recv_key1, recv_key2);

        // Sending and receiving keys should be different
        assert_ne!(send_key1, recv_key1);
    }

    #[test]
    fn test_initiator_responder_flow() {
        // Initiator generates ephemeral PQ keypair
        let initiator = HybridInitiatorState::new(OperatingMode::Hybrid).unwrap();
        assert!(!initiator.pq_ephemeral_pk.is_empty());
        assert_eq!(initiator.pq_ephemeral_pk.len(), MLKEM_PUBLIC_KEY_SIZE);

        // Responder encapsulates to initiator's public key
        let responder =
            HybridResponderState::new(OperatingMode::Hybrid, &initiator.pq_ephemeral_pk).unwrap();
        assert_eq!(responder.pq_ciphertext.len(), MLKEM_CIPHERTEXT_SIZE);

        // Initiator decapsulates
        let mut initiator = initiator;
        let initiator_ss = initiator
            .process_response(&responder.pq_ciphertext)
            .unwrap();

        // Shared secrets should match
        assert_eq!(initiator_ss, responder.pq_shared_secret);
    }

    #[test]
    fn test_classic_mode() {
        let initiator = HybridInitiatorState::new(OperatingMode::Classic).unwrap();
        // In classic mode, no PQ key should be generated
        assert!(initiator.pq_ephemeral_pk.is_empty());
    }

    #[test]
    fn test_pq_only_mode_with_mldsa_signing() {
        // Generate ML-DSA keypairs for both parties
        let initiator_keypair = MlDsaKeyPair::generate().unwrap();
        let responder_keypair = MlDsaKeyPair::generate().unwrap();

        // Initiator generates ephemeral PQ keypair
        let mut initiator = HybridInitiatorState::new(OperatingMode::PqOnly).unwrap();
        assert!(!initiator.pq_ephemeral_pk.is_empty());

        // Set up ML-DSA keys
        initiator.set_mldsa_keypair(initiator_keypair.clone());
        initiator.set_peer_mldsa_public_key(responder_keypair.public_key().clone());

        // Responder encapsulates
        let mut responder =
            HybridResponderState::new(OperatingMode::PqOnly, &initiator.pq_ephemeral_pk).unwrap();

        responder.set_mldsa_keypair(responder_keypair.clone());
        responder.set_peer_mldsa_public_key(initiator_keypair.public_key().clone());

        // Simulate transcript: both parties record the same handshake data
        let handshake_data = b"handshake_initiation_data_here";
        initiator.extend_transcript(handshake_data);
        responder.extend_transcript(handshake_data);

        // Initiator signs the transcript
        let initiator_sig = initiator.sign_transcript().unwrap();
        assert_eq!(initiator_sig.len(), MLDSA_SIGNATURE_SIZE);

        // Responder verifies initiator's signature
        let valid = responder.verify_peer_signature(&initiator_sig).unwrap();
        assert!(valid, "Initiator signature should be valid");

        // Add response to transcript
        let response_data = b"handshake_response_data_here";
        initiator.extend_transcript(response_data);
        responder.extend_transcript(response_data);

        // Responder signs the transcript
        let responder_sig = responder.sign_transcript().unwrap();
        assert_eq!(responder_sig.len(), MLDSA_SIGNATURE_SIZE);

        // Initiator verifies responder's signature
        let valid = initiator.verify_peer_signature(&responder_sig).unwrap();
        assert!(valid, "Responder signature should be valid");

        // Verify key exchange still works
        // Re-create for clean decapsulation test
        let fresh_initiator = HybridInitiatorState::new(OperatingMode::PqOnly).unwrap();
        let fresh_responder =
            HybridResponderState::new(OperatingMode::PqOnly, &fresh_initiator.pq_ephemeral_pk)
                .unwrap();

        let mut fresh_initiator = fresh_initiator;
        let initiator_ss = fresh_initiator
            .process_response(&fresh_responder.pq_ciphertext)
            .unwrap();
        assert_eq!(initiator_ss, fresh_responder.pq_shared_secret);
    }

    #[test]
    fn test_mldsa_signature_verification_fails_with_wrong_key() {
        let initiator_keypair = MlDsaKeyPair::generate().unwrap();
        let responder_keypair = MlDsaKeyPair::generate().unwrap();
        let wrong_keypair = MlDsaKeyPair::generate().unwrap();

        let mut initiator = HybridInitiatorState::new(OperatingMode::PqOnly).unwrap();
        initiator.set_mldsa_keypair(initiator_keypair.clone());
        initiator.set_peer_mldsa_public_key(wrong_keypair.public_key().clone()); // Wrong key!

        let mut responder =
            HybridResponderState::new(OperatingMode::PqOnly, &initiator.pq_ephemeral_pk).unwrap();
        responder.set_mldsa_keypair(responder_keypair.clone());
        responder.set_peer_mldsa_public_key(initiator_keypair.public_key().clone());

        // Add same transcript
        let data = b"test_transcript";
        initiator.extend_transcript(data);
        responder.extend_transcript(data);

        // Responder signs
        let responder_sig = responder.sign_transcript().unwrap();

        // Initiator tries to verify with wrong public key - should fail
        let result = initiator.verify_peer_signature(&responder_sig);
        assert!(
            result.is_err() || !result.unwrap(),
            "Verification should fail with wrong public key"
        );
    }
}
