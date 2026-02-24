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
    select_backend, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature,
    MlKemCiphertext, MlKemPublicKey, MlKemSecretKey, OperatingMode,
};

/// ML-KEM-768 key sizes (NIST FIPS 203)
pub const MLKEM_PUBLIC_KEY_SIZE: usize = 1184;
pub const MLKEM_SECRET_KEY_SIZE: usize = 2400;
pub const MLKEM_CIPHERTEXT_SIZE: usize = 1088;
pub const MLKEM_SHARED_SECRET_SIZE: usize = 32;

/// ML-DSA-65 key/signature sizes (NIST FIPS 204)
pub const MLDSA_PUBLIC_KEY_SIZE: usize = 1952;
pub const MLDSA_SECRET_KEY_SIZE: usize = 4032;
pub const MLDSA_SIGNATURE_SIZE: usize = 3309;

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

    /// Create from raw bytes
    pub fn from_bytes(public_key: &[u8], secret_key: &[u8]) -> Result<Self, String> {
        let public_key = MlKemPublicKey::from_bytes(public_key)
            .map_err(|e| format!("Invalid public key: {}", e))?;
        let secret_key = MlKemSecretKey::from_bytes(secret_key)
            .map_err(|e| format!("Invalid secret key: {}", e))?;
        Ok(Self { public_key, secret_key })
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

/// ML-DSA-65 signing key pair for post-quantum authentication
#[derive(Clone)]
pub struct MlDsaKeyPair {
    /// ML-DSA public key (verification key)
    pub public_key: MlDsaPublicKey,
    /// ML-DSA secret key (signing key)
    pub secret_key: MlDsaSecretKey,
}

impl MlDsaKeyPair {
    /// Generate a new ML-DSA-65 key pair
    pub fn generate() -> Result<Self, String> {
        let backend = select_backend();
        let (public_key, secret_key) = backend
            .mldsa_keygen()
            .map_err(|e| format!("ML-DSA keygen failed: {}", e))?;
        Ok(Self {
            public_key,
            secret_key,
        })
    }

    /// Create from raw bytes
    pub fn from_bytes(public_key: &[u8], secret_key: &[u8]) -> Result<Self, String> {
        let public_key = MlDsaPublicKey::from_bytes(public_key)
            .map_err(|e| format!("Invalid ML-DSA public key: {}", e))?;
        let secret_key = MlDsaSecretKey::from_bytes(secret_key)
            .map_err(|e| format!("Invalid ML-DSA secret key: {}", e))?;
        Ok(Self { public_key, secret_key })
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Result<MlDsaSignature, String> {
        let backend = select_backend();
        backend
            .mldsa_sign(&self.secret_key, message)
            .map_err(|e| format!("ML-DSA sign failed: {}", e))
    }

    /// Verify a signature with our public key
    pub fn verify(&self, message: &[u8], signature: &MlDsaSignature) -> Result<bool, String> {
        let backend = select_backend();
        backend
            .mldsa_verify(&self.public_key, message, signature)
            .map_err(|e| format!("ML-DSA verify failed: {}", e))
    }
}

impl std::fmt::Debug for MlDsaKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlDsaKeyPair")
            .field("public_key", &"[ML-DSA-65 public key]")
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

/// Verify an ML-DSA signature using a public key
pub fn mldsa_verify(
    public_key: &MlDsaPublicKey,
    message: &[u8],
    signature: &MlDsaSignature,
) -> Result<bool, String> {
    let backend = select_backend();
    backend
        .mldsa_verify(public_key, message, signature)
        .map_err(|e| format!("ML-DSA verify failed: {}", e))
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
    
    // ML-DSA-65 authentication (for pq-only mode)
    /// Our ML-DSA signing key pair
    pub mldsa_keypair: Option<MlDsaKeyPair>,
    /// Peer's ML-DSA public key
    pub peer_mldsa_public_key: Option<MlDsaPublicKey>,
    /// Handshake transcript for signing (accumulates handshake messages)
    pub handshake_transcript: Vec<u8>,
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
            mldsa_keypair: None,
            peer_mldsa_public_key: None,
            handshake_transcript: Vec::new(),
        }
    }

    /// Create with static keys
    pub fn with_keys(
        mode: OperatingMode,
        static_keypair: Option<PqKeyPair>,
        peer_public_key: Option<MlKemPublicKey>,
    ) -> Self {
        Self {
            mode,
            static_pq_keypair: static_keypair,
            peer_pq_public_key: peer_public_key,
            ephemeral_pq_keypair: None,
            pq_ciphertext: None,
            pq_shared_secret: None,
            mldsa_keypair: None,
            peer_mldsa_public_key: None,
            handshake_transcript: Vec::new(),
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
    
    /// Set our ML-DSA signing key pair (for pq-only mode)
    pub fn set_mldsa_keypair(&mut self, keypair: MlDsaKeyPair) {
        self.mldsa_keypair = Some(keypair);
    }
    
    /// Set peer's ML-DSA public key (for pq-only mode)
    pub fn set_peer_mldsa_public_key(&mut self, public_key: MlDsaPublicKey) {
        self.peer_mldsa_public_key = Some(public_key);
    }

    /// Check if PQ is enabled for this handshake
    pub fn is_pq_enabled(&self) -> bool {
        self.mode.uses_pq_kex()
    }
    
    /// Check if PQ authentication (ML-DSA) is enabled
    pub fn is_pq_auth_enabled(&self) -> bool {
        self.mode.uses_pq_auth()
    }
    
    /// Add data to the handshake transcript (for signing)
    pub fn extend_transcript(&mut self, data: &[u8]) {
        self.handshake_transcript.extend_from_slice(data);
    }
    
    /// Sign the handshake transcript with our ML-DSA key
    pub fn sign_transcript(&self) -> Result<MlDsaSignature, String> {
        if !self.is_pq_auth_enabled() {
            return Err("PQ auth not enabled".into());
        }
        
        let keypair = self.mldsa_keypair.as_ref()
            .ok_or("No ML-DSA keypair configured")?;
        
        keypair.sign(&self.handshake_transcript)
    }
    
    /// Verify peer's signature over the transcript
    pub fn verify_peer_signature(&self, signature: &MlDsaSignature) -> Result<bool, String> {
        if !self.is_pq_auth_enabled() {
            return Err("PQ auth not enabled".into());
        }
        
        let peer_pk = self.peer_mldsa_public_key.as_ref()
            .ok_or("No peer ML-DSA public key configured")?;
        
        mldsa_verify(peer_pk, &self.handshake_transcript, signature)
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

    /// Get the PQ shared secret if available
    pub fn get_pq_shared_secret(&self) -> Option<&[u8; 32]> {
        self.pq_shared_secret.as_ref()
    }

    /// Combine X25519 and ML-KEM shared secrets using BLAKE2s
    /// Returns combined chaining key for the Noise protocol
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
        self.handshake_transcript.clear();
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

/// Format a PQ handshake init message
/// This appends the ML-KEM public key to a standard WireGuard init
pub fn format_handshake_init_pq(
    classic_init: &[u8],     // 148 bytes
    pq_ephemeral_pk: &[u8],  // 1184 bytes
    dst: &mut [u8],          // Must be at least HANDSHAKE_INIT_PQ_SZ
) -> Result<usize, &'static str> {
    if classic_init.len() != 148 {
        return Err("Invalid classic init size");
    }
    if pq_ephemeral_pk.len() != MLKEM_PUBLIC_KEY_SIZE {
        return Err("Invalid PQ public key size");
    }
    if dst.len() < HANDSHAKE_INIT_PQ_SZ {
        return Err("Destination buffer too small");
    }

    // Copy classic init
    dst[..148].copy_from_slice(classic_init);
    
    // Change message type to PQ variant
    dst[0..4].copy_from_slice(&HANDSHAKE_INIT_PQ.to_le_bytes());
    
    // Append PQ public key
    dst[148..HANDSHAKE_INIT_PQ_SZ].copy_from_slice(pq_ephemeral_pk);

    Ok(HANDSHAKE_INIT_PQ_SZ)
}

/// Format a PQ handshake response message
/// This appends the ML-KEM ciphertext to a standard WireGuard response
pub fn format_handshake_response_pq(
    classic_resp: &[u8],    // 92 bytes
    pq_ciphertext: &[u8],   // 1088 bytes
    dst: &mut [u8],         // Must be at least HANDSHAKE_RESP_PQ_SZ
) -> Result<usize, &'static str> {
    if classic_resp.len() != 92 {
        return Err("Invalid classic response size");
    }
    if pq_ciphertext.len() != MLKEM_CIPHERTEXT_SIZE {
        return Err("Invalid PQ ciphertext size");
    }
    if dst.len() < HANDSHAKE_RESP_PQ_SZ {
        return Err("Destination buffer too small");
    }

    // Copy classic response
    dst[..92].copy_from_slice(classic_resp);
    
    // Change message type to PQ variant
    dst[0..4].copy_from_slice(&HANDSHAKE_RESP_PQ.to_le_bytes());
    
    // Append PQ ciphertext
    dst[92..HANDSHAKE_RESP_PQ_SZ].copy_from_slice(pq_ciphertext);

    Ok(HANDSHAKE_RESP_PQ_SZ)
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

    #[test]
    fn test_format_handshake_init_pq() {
        let classic_init = vec![0u8; 148];
        let pq_pk = vec![0xABu8; MLKEM_PUBLIC_KEY_SIZE];
        let mut dst = vec![0u8; HANDSHAKE_INIT_PQ_SZ];

        let size = format_handshake_init_pq(&classic_init, &pq_pk, &mut dst).unwrap();
        assert_eq!(size, HANDSHAKE_INIT_PQ_SZ);
        
        // Check message type was updated
        let msg_type = u32::from_le_bytes(dst[0..4].try_into().unwrap());
        assert_eq!(msg_type, HANDSHAKE_INIT_PQ);
        
        // Check PQ key was appended
        assert_eq!(&dst[148..], &pq_pk[..]);
    }

    #[test]
    fn test_format_handshake_response_pq() {
        let classic_resp = vec![0u8; 92];
        let pq_ct = vec![0xCDu8; MLKEM_CIPHERTEXT_SIZE];
        let mut dst = vec![0u8; HANDSHAKE_RESP_PQ_SZ];

        let size = format_handshake_response_pq(&classic_resp, &pq_ct, &mut dst).unwrap();
        assert_eq!(size, HANDSHAKE_RESP_PQ_SZ);
        
        // Check message type was updated
        let msg_type = u32::from_le_bytes(dst[0..4].try_into().unwrap());
        assert_eq!(msg_type, HANDSHAKE_RESP_PQ);
        
        // Check ciphertext was appended
        assert_eq!(&dst[92..], &pq_ct[..]);
    }

    #[test]
    fn test_mldsa_keypair_generation() {
        let keypair = MlDsaKeyPair::generate().unwrap();
        assert_eq!(keypair.public_key.as_bytes().len(), MLDSA_PUBLIC_KEY_SIZE);
        assert_eq!(keypair.secret_key.as_bytes().len(), MLDSA_SECRET_KEY_SIZE);
    }

    #[test]
    fn test_mldsa_sign_verify() {
        let keypair = MlDsaKeyPair::generate().unwrap();
        let message = b"test handshake transcript";
        
        let signature = keypair.sign(message).unwrap();
        assert_eq!(signature.as_bytes().len(), MLDSA_SIGNATURE_SIZE);
        
        let valid = keypair.verify(message, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_pq_only_mode_auth() {
        let mut state = HybridHandshakeState::new(OperatingMode::PqOnly);
        assert!(state.is_pq_enabled());
        assert!(state.is_pq_auth_enabled());
        
        // Set up ML-DSA keys
        let keypair = MlDsaKeyPair::generate().unwrap();
        state.set_mldsa_keypair(keypair);
        
        // Simulate handshake transcript
        state.extend_transcript(b"init message");
        state.extend_transcript(b"response message");
        
        // Sign transcript
        let signature = state.sign_transcript().unwrap();
        
        // Create peer state to verify
        let mut peer_state = HybridHandshakeState::new(OperatingMode::PqOnly);
        peer_state.set_peer_mldsa_public_key(
            state.mldsa_keypair.as_ref().unwrap().public_key.clone()
        );
        peer_state.extend_transcript(b"init message");
        peer_state.extend_transcript(b"response message");
        
        let valid = peer_state.verify_peer_signature(&signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_full_pq_handshake_flow() {
        // This simulates the complete PQ handshake flow
        
        // 1. Initiator generates ephemeral PQ keypair
        let mut initiator = HybridHandshakeState::new(OperatingMode::Hybrid);
        let initiator_pk = initiator.generate_ephemeral().unwrap();
        let initiator_pk_bytes = initiator_pk.as_bytes().to_vec();
        
        // 2. Responder receives init, encapsulates to initiator's ephemeral PQ key
        let mut responder = HybridHandshakeState::new(OperatingMode::Hybrid);
        let (ciphertext, responder_pq_ss) = responder
            .encapsulate_to_peer(&initiator_pk_bytes)
            .unwrap();
        
        // 3. Initiator receives response, decapsulates
        let initiator_pq_ss = initiator.decapsulate(&ciphertext).unwrap();
        
        // 4. Both sides now have matching PQ shared secrets
        assert_eq!(initiator_pq_ss, responder_pq_ss);
        
        // 5. Combine with X25519 shared secret (simulated)
        let x25519_ss = [0x42u8; 32];
        let chaining_key = [0x00u8; 32];
        
        let initiator_combined = HybridHandshakeState::combine_secrets(
            &x25519_ss,
            &initiator_pq_ss,
            &chaining_key,
        );
        let responder_combined = HybridHandshakeState::combine_secrets(
            &x25519_ss,
            &responder_pq_ss,
            &chaining_key,
        );
        
        assert_eq!(initiator_combined, responder_combined);
    }
}
