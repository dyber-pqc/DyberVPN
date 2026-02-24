//! Hybrid Post-Quantum Handshake for DyberVPN
//!
//! This module extends the WireGuard Noise IK handshake with ML-KEM-768
//! for post-quantum key exchange. The hybrid approach combines:
//! - X25519 (classical ECDH) - existing WireGuard
//! - ML-KEM-768 (post-quantum KEM) - NIST FIPS 203
//!
//! Both shared secrets are combined via HKDF to derive the final keys.
//! If either algorithm is broken, the other still provides security.

use std::convert::TryInto;

use dybervpn_protocol::{
    select_backend, MlKemCiphertext, MlKemPublicKey, MlKemSecretKey,
    OperatingMode,
};

/// ML-KEM-768 key sizes
pub const MLKEM_PUBLIC_KEY_SIZE: usize = 1184;
pub const MLKEM_SECRET_KEY_SIZE: usize = 2400;
pub const MLKEM_CIPHERTEXT_SIZE: usize = 1088;
pub const MLKEM_SHARED_SECRET_SIZE: usize = 32;

/// Extended handshake message types for DyberVPN
/// These use message type 5+ to avoid conflicts with standard WireGuard (1-4)
pub const HANDSHAKE_INIT_PQ: u32 = 5;
pub const HANDSHAKE_RESP_PQ: u32 = 6;

/// Size of PQ handshake init message
/// Standard WireGuard init (148) + ML-KEM public key (1184) = 1332 bytes
pub const HANDSHAKE_INIT_PQ_SZ: usize = 148 + MLKEM_PUBLIC_KEY_SIZE;

/// Size of PQ handshake response message
/// Standard WireGuard response (92) + ML-KEM ciphertext (1088) = 1180 bytes
pub const HANDSHAKE_RESP_PQ_SZ: usize = 92 + MLKEM_CIPHERTEXT_SIZE;

/// Post-quantum key material for a peer
#[derive(Clone)]
pub struct PqKeyPair {
    /// ML-KEM public key (encapsulation key)
    pub public_key: MlKemPublicKey,
    /// ML-KEM secret key (decapsulation key)
    pub secret_key: MlKemSecretKey,
}

impl PqKeyPair {
    /// Generate a new ML-KEM-768 key pair
    pub fn generate() -> Result<Self, String> {
        let backend = select_backend();
        let (public_key, secret_key) = backend
            .mlkem_keygen()
            .map_err(|e| format!("ML-KEM keygen failed: {}", e))?;
        Ok(Self {
            public_key,
            secret_key,
        })
    }
}

impl std::fmt::Debug for PqKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqKeyPair")
            .field("public_key", &"[ML-KEM-768 public key]")
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

/// Hybrid handshake state extension for PQ
#[derive(Debug)]
pub struct HybridHandshakeState {
    /// Operating mode
    pub mode: OperatingMode,
    /// Our static PQ key pair (for hybrid/pq-only modes)
    pub static_pq_keypair: Option<PqKeyPair>,
    /// Peer's static PQ public key
    pub peer_pq_public_key: Option<MlKemPublicKey>,
    /// Ephemeral PQ key pair for current handshake
    pub ephemeral_pq_keypair: Option<PqKeyPair>,
    /// ML-KEM ciphertext from peer (during handshake)
    pub pq_ciphertext: Option<MlKemCiphertext>,
    /// ML-KEM shared secret (derived during handshake)
    pub pq_shared_secret: Option<[u8; 32]>,
}

impl HybridHandshakeState {
    /// Create a new hybrid handshake state
    pub fn new(mode: OperatingMode) -> Self {
        Self {
            mode,
            static_pq_keypair: None,
            peer_pq_public_key: None,
            ephemeral_pq_keypair: None,
            pq_ciphertext: None,
            pq_shared_secret: None,
        }
    }

    /// Set our static PQ key pair
    pub fn set_static_keypair(&mut self, keypair: PqKeyPair) {
        self.static_pq_keypair = Some(keypair);
    }

    /// Set peer's PQ public key
    pub fn set_peer_public_key(&mut self, public_key: MlKemPublicKey) {
        self.peer_pq_public_key = Some(public_key);
    }

    /// Check if PQ is enabled for this handshake
    pub fn is_pq_enabled(&self) -> bool {
        self.mode.uses_pq_kex()
    }

    /// Generate ephemeral PQ keypair for initiator
    pub fn generate_ephemeral(&mut self) -> Result<&MlKemPublicKey, String> {
        if !self.is_pq_enabled() {
            return Err("PQ not enabled".into());
        }

        let keypair = PqKeyPair::generate()?;
        self.ephemeral_pq_keypair = Some(keypair);

        Ok(&self.ephemeral_pq_keypair.as_ref().unwrap().public_key)
    }

    /// Encapsulate to peer's ephemeral PQ public key (responder side)
    pub fn encapsulate_to_peer(
        &mut self,
        peer_ephemeral_pk: &[u8],
    ) -> Result<([u8; MLKEM_CIPHERTEXT_SIZE], [u8; 32]), String> {
        if !self.is_pq_enabled() {
            return Err("PQ not enabled".into());
        }

        let backend = select_backend();

        // Parse peer's ephemeral PQ public key
        let peer_pk = MlKemPublicKey::from_bytes(peer_ephemeral_pk)
            .map_err(|e| format!("Invalid peer PQ public key: {}", e))?;

        // Encapsulate
        let (ciphertext, shared_secret) = backend
            .mlkem_encaps(&peer_pk)
            .map_err(|e| format!("ML-KEM encapsulation failed: {}", e))?;

        // Store shared secret
        let mut ss = [0u8; 32];
        ss.copy_from_slice(shared_secret.as_bytes());
        self.pq_shared_secret = Some(ss);

        // Convert ciphertext to fixed-size array
        let ct_bytes = ciphertext.as_bytes();
        let mut ct_arr = [0u8; MLKEM_CIPHERTEXT_SIZE];
        ct_arr.copy_from_slice(ct_bytes);

        Ok((ct_arr, ss))
    }

    /// Decapsulate ciphertext using our ephemeral secret key (initiator side)
    pub fn decapsulate(&mut self, ciphertext: &[u8]) -> Result<[u8; 32], String> {
        if !self.is_pq_enabled() {
            return Err("PQ not enabled".into());
        }

        let backend = select_backend();

        let ephemeral_sk = self
            .ephemeral_pq_keypair
            .as_ref()
            .ok_or("No ephemeral PQ keypair")?;

        let ct = MlKemCiphertext::from_bytes(ciphertext)
            .map_err(|e| format!("Invalid ciphertext: {}", e))?;

        let shared_secret = backend
            .mlkem_decaps(&ephemeral_sk.secret_key, &ct)
            .map_err(|e| format!("ML-KEM decapsulation failed: {}", e))?;

        let mut ss = [0u8; 32];
        ss.copy_from_slice(shared_secret.as_bytes());
        self.pq_shared_secret = Some(ss);

        Ok(ss)
    }

    /// Combine X25519 and ML-KEM shared secrets
    pub fn combine_secrets(
        x25519_ss: &[u8; 32],
        mlkem_ss: &[u8; 32],
        chaining_key: &[u8; 32],
    ) -> [u8; 32] {
        use blake2::{Blake2s256, Digest};

        // Combine: HASH(chaining_key || x25519_ss || mlkem_ss)
        let mut hasher = Blake2s256::new();
        hasher.update(chaining_key);
        hasher.update(x25519_ss);
        hasher.update(mlkem_ss);
        hasher.finalize().into()
    }

    /// Clear ephemeral state after handshake completes
    pub fn clear_ephemeral(&mut self) {
        self.ephemeral_pq_keypair = None;
        self.pq_ciphertext = None;
        // Note: pq_shared_secret is intentionally kept for session key derivation
    }
}

/// Parse a PQ handshake init message
#[derive(Debug)]
pub struct HandshakeInitPq<'a> {
    /// Standard WireGuard handshake init fields
    pub sender_idx: u32,
    pub unencrypted_ephemeral: &'a [u8; 32],
    pub encrypted_static: &'a [u8],
    pub encrypted_timestamp: &'a [u8],
    /// PQ extension: initiator's ephemeral ML-KEM public key
    pub pq_ephemeral_public: &'a [u8],
}

/// Parse a PQ handshake response message
#[derive(Debug)]
pub struct HandshakeResponsePq<'a> {
    /// Standard WireGuard handshake response fields
    pub sender_idx: u32,
    pub receiver_idx: u32,
    pub unencrypted_ephemeral: &'a [u8; 32],
    pub encrypted_nothing: &'a [u8],
    /// PQ extension: ML-KEM ciphertext
    pub pq_ciphertext: &'a [u8],
}

impl<'a> HandshakeInitPq<'a> {
    /// Parse a PQ handshake init from bytes
    pub fn parse(src: &'a [u8]) -> Result<Self, &'static str> {
        if src.len() != HANDSHAKE_INIT_PQ_SZ {
            return Err("Invalid PQ handshake init size");
        }

        let msg_type = u32::from_le_bytes(src[0..4].try_into().unwrap());
        if msg_type != HANDSHAKE_INIT_PQ {
            return Err("Not a PQ handshake init");
        }

        Ok(Self {
            sender_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
            unencrypted_ephemeral: src[8..40].try_into().unwrap(),
            encrypted_static: &src[40..88],
            encrypted_timestamp: &src[88..116],
            // Skip MAC fields (116..148), then PQ public key
            pq_ephemeral_public: &src[148..148 + MLKEM_PUBLIC_KEY_SIZE],
        })
    }
}

impl<'a> HandshakeResponsePq<'a> {
    /// Parse a PQ handshake response from bytes
    pub fn parse(src: &'a [u8]) -> Result<Self, &'static str> {
        if src.len() != HANDSHAKE_RESP_PQ_SZ {
            return Err("Invalid PQ handshake response size");
        }

        let msg_type = u32::from_le_bytes(src[0..4].try_into().unwrap());
        if msg_type != HANDSHAKE_RESP_PQ {
            return Err("Not a PQ handshake response");
        }

        Ok(Self {
            sender_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
            receiver_idx: u32::from_le_bytes(src[8..12].try_into().unwrap()),
            unencrypted_ephemeral: src[12..44].try_into().unwrap(),
            encrypted_nothing: &src[44..60],
            // Skip MAC fields (60..92), then PQ ciphertext
            pq_ciphertext: &src[92..92 + MLKEM_CIPHERTEXT_SIZE],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pq_keypair_generation() {
        let keypair = PqKeyPair::generate().unwrap();
        assert_eq!(keypair.public_key.as_bytes().len(), MLKEM_PUBLIC_KEY_SIZE);
        assert_eq!(keypair.secret_key.as_bytes().len(), MLKEM_SECRET_KEY_SIZE);
    }

    #[test]
    fn test_hybrid_handshake_state() {
        let mut state = HybridHandshakeState::new(OperatingMode::Hybrid);
        assert!(state.is_pq_enabled());

        // Generate ephemeral
        let pk = state.generate_ephemeral().unwrap();
        assert_eq!(pk.as_bytes().len(), MLKEM_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_hybrid_encaps_decaps() {
        // Simulate initiator
        let mut initiator_state = HybridHandshakeState::new(OperatingMode::Hybrid);
        let initiator_pk = initiator_state.generate_ephemeral().unwrap();
        let initiator_pk_bytes = initiator_pk.as_bytes().to_vec();

        // Simulate responder
        let mut responder_state = HybridHandshakeState::new(OperatingMode::Hybrid);
        let (ciphertext, responder_ss) = responder_state
            .encapsulate_to_peer(&initiator_pk_bytes)
            .unwrap();

        // Initiator decapsulates
        let initiator_ss = initiator_state.decapsulate(&ciphertext).unwrap();

        // Shared secrets should match
        assert_eq!(initiator_ss, responder_ss);
    }

    #[test]
    fn test_classic_mode_no_pq() {
        let state = HybridHandshakeState::new(OperatingMode::Classic);
        assert!(!state.is_pq_enabled());
    }

    #[test]
    fn test_combine_secrets() {
        let x25519_ss = [1u8; 32];
        let mlkem_ss = [2u8; 32];
        let chaining_key = [3u8; 32];

        let combined = HybridHandshakeState::combine_secrets(&x25519_ss, &mlkem_ss, &chaining_key);

        // Should be deterministic
        let combined2 = HybridHandshakeState::combine_secrets(&x25519_ss, &mlkem_ss, &chaining_key);
        assert_eq!(combined, combined2);

        // Different inputs should produce different outputs
        let different =
            HybridHandshakeState::combine_secrets(&[4u8; 32], &mlkem_ss, &chaining_key);
        assert_ne!(combined, different);
    }

    #[test]
    fn test_message_sizes() {
        // Verify our calculations
        assert_eq!(HANDSHAKE_INIT_PQ_SZ, 148 + 1184); // 1332
        assert_eq!(HANDSHAKE_RESP_PQ_SZ, 92 + 1088); // 1180
    }
}
