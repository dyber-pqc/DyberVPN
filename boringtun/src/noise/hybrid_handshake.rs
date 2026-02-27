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
    select_backend, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature, MlKemCiphertext,
    MlKemPublicKey, MlKemSecretKey, OperatingMode,
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
pub const HANDSHAKE_INIT_PQ: u32 = 5; // Hybrid mode (ML-KEM only, Ed25519 auth)
pub const HANDSHAKE_RESP_PQ: u32 = 6; // Hybrid mode response
pub const HANDSHAKE_INIT_PQ_AUTH: u32 = 7; // PQ-only mode (ML-KEM + ML-DSA auth)
pub const HANDSHAKE_RESP_PQ_AUTH: u32 = 8; // PQ-only mode response

/// Size of PQ handshake init message (hybrid mode - no PQ signature)
/// Standard WireGuard init (148) + ML-KEM public key (1184) = 1332 bytes
pub const HANDSHAKE_INIT_PQ_SZ: usize = 148 + MLKEM_PUBLIC_KEY_SIZE;

/// Size of PQ handshake response message (hybrid mode - no PQ signature)
/// Standard WireGuard response (92) + ML-KEM ciphertext (1088) = 1180 bytes
pub const HANDSHAKE_RESP_PQ_SZ: usize = 92 + MLKEM_CIPHERTEXT_SIZE;

/// Size of PQ-only handshake init message (with ML-DSA signature)
/// Standard WireGuard init (148) + ML-KEM public key (1184) + ML-DSA signature (3309) = 4641 bytes
pub const HANDSHAKE_INIT_PQ_AUTH_SZ: usize = 148 + MLKEM_PUBLIC_KEY_SIZE + MLDSA_SIGNATURE_SIZE;

/// Size of PQ-only handshake response message (with ML-DSA signature)
/// Standard WireGuard response (92) + ML-KEM ciphertext (1088) + ML-DSA signature (3309) = 4489 bytes
pub const HANDSHAKE_RESP_PQ_AUTH_SZ: usize = 92 + MLKEM_CIPHERTEXT_SIZE + MLDSA_SIGNATURE_SIZE;

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

    /// Create from raw bytes (both public and secret key)
    pub fn from_bytes(public_key: &[u8], secret_key: &[u8]) -> Result<Self, String> {
        let public_key = MlDsaPublicKey::from_bytes(public_key)
            .map_err(|e| format!("Invalid ML-DSA public key: {}", e))?;
        let secret_key = MlDsaSecretKey::from_bytes(secret_key)
            .map_err(|e| format!("Invalid ML-DSA secret key: {}", e))?;
        Ok(Self {
            public_key,
            secret_key,
        })
    }

    /// Create from secret key bytes only (derives public key)
    ///
    /// Note: ML-DSA secret keys contain the public key, so we can extract it.
    /// The ml-dsa crate's SecretKey includes the public key bytes.
    pub fn from_secret_key_bytes(secret_key_bytes: &[u8]) -> Result<Self, String> {
        let secret_key = MlDsaSecretKey::from_bytes(secret_key_bytes)
            .map_err(|e| format!("Invalid ML-DSA secret key: {}", e))?;

        // ML-DSA-65 secret key format includes the public key
        // The public key is the last 1952 bytes of the 4032-byte secret key
        if secret_key_bytes.len() != MLDSA_SECRET_KEY_SIZE {
            return Err(format!(
                "Invalid secret key size: {} (expected {})",
                secret_key_bytes.len(),
                MLDSA_SECRET_KEY_SIZE
            ));
        }

        // Extract public key from the end of the secret key
        // In ML-DSA, the secret key structure embeds the public key
        // The ml-dsa crate's SecretKey includes the public key bytes at the end
        let pk_offset = MLDSA_SECRET_KEY_SIZE - MLDSA_PUBLIC_KEY_SIZE;
        let pk_bytes = &secret_key_bytes[pk_offset..];

        let public_key = MlDsaPublicKey::from_bytes(pk_bytes)
            .map_err(|e| format!("Failed to extract ML-DSA public key from secret key: {}", e))?;

        Ok(Self {
            public_key,
            secret_key,
        })
    }

    /// Get the public key
    pub fn public_key(&self) -> &MlDsaPublicKey {
        &self.public_key
    }

    /// Get the secret key
    pub fn secret_key(&self) -> &MlDsaSecretKey {
        &self.secret_key
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

        let keypair = self
            .mldsa_keypair
            .as_ref()
            .ok_or("No ML-DSA keypair configured")?;

        keypair.sign(&self.handshake_transcript)
    }

    /// Verify peer's signature over the transcript
    pub fn verify_peer_signature(&self, signature: &MlDsaSignature) -> Result<bool, String> {
        if !self.is_pq_auth_enabled() {
            return Err("PQ auth not enabled".into());
        }

        let peer_pk = self
            .peer_mldsa_public_key
            .as_ref()
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
    classic_init: &[u8],    // 148 bytes
    pq_ephemeral_pk: &[u8], // 1184 bytes
    dst: &mut [u8],         // Must be at least HANDSHAKE_INIT_PQ_SZ
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
    classic_resp: &[u8],  // 92 bytes
    pq_ciphertext: &[u8], // 1088 bytes
    dst: &mut [u8],       // Must be at least HANDSHAKE_RESP_PQ_SZ
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

// =============================================================================
// PQ-Only Mode Messages (with ML-DSA signatures)
// =============================================================================

/// Parse a PQ-only handshake init message (with ML-DSA signature)
#[derive(Debug)]
pub struct HandshakeInitPqAuth<'a> {
    /// Standard WireGuard handshake init fields
    pub sender_idx: u32,
    pub unencrypted_ephemeral: &'a [u8; 32],
    pub encrypted_static: &'a [u8],
    pub encrypted_timestamp: &'a [u8],
    /// PQ extension: initiator's ephemeral ML-KEM public key
    pub pq_ephemeral_public: &'a [u8],
    /// ML-DSA signature over the handshake transcript
    pub mldsa_signature: &'a [u8],
}

/// Parse a PQ-only handshake response message (with ML-DSA signature)
#[derive(Debug)]
pub struct HandshakeResponsePqAuth<'a> {
    /// Standard WireGuard handshake response fields
    pub sender_idx: u32,
    pub receiver_idx: u32,
    pub unencrypted_ephemeral: &'a [u8; 32],
    pub encrypted_nothing: &'a [u8],
    /// PQ extension: ML-KEM ciphertext
    pub pq_ciphertext: &'a [u8],
    /// ML-DSA signature over the handshake transcript
    pub mldsa_signature: &'a [u8],
}

impl<'a> HandshakeInitPqAuth<'a> {
    /// Parse a PQ-only handshake init from bytes
    pub fn parse(src: &'a [u8]) -> Result<Self, &'static str> {
        if src.len() != HANDSHAKE_INIT_PQ_AUTH_SZ {
            return Err("Invalid PQ-auth handshake init size");
        }

        let msg_type = u32::from_le_bytes(src[0..4].try_into().unwrap());
        if msg_type != HANDSHAKE_INIT_PQ_AUTH {
            return Err("Not a PQ-auth handshake init");
        }

        let pq_pk_end = 148 + MLKEM_PUBLIC_KEY_SIZE;
        let sig_end = pq_pk_end + MLDSA_SIGNATURE_SIZE;

        Ok(Self {
            sender_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
            unencrypted_ephemeral: src[8..40].try_into().unwrap(),
            encrypted_static: &src[40..88],
            encrypted_timestamp: &src[88..116],
            pq_ephemeral_public: &src[148..pq_pk_end],
            mldsa_signature: &src[pq_pk_end..sig_end],
        })
    }
}

impl<'a> HandshakeResponsePqAuth<'a> {
    /// Parse a PQ-only handshake response from bytes
    pub fn parse(src: &'a [u8]) -> Result<Self, &'static str> {
        if src.len() != HANDSHAKE_RESP_PQ_AUTH_SZ {
            return Err("Invalid PQ-auth handshake response size");
        }

        let msg_type = u32::from_le_bytes(src[0..4].try_into().unwrap());
        if msg_type != HANDSHAKE_RESP_PQ_AUTH {
            return Err("Not a PQ-auth handshake response");
        }

        let ct_end = 92 + MLKEM_CIPHERTEXT_SIZE;
        let sig_end = ct_end + MLDSA_SIGNATURE_SIZE;

        Ok(Self {
            sender_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
            receiver_idx: u32::from_le_bytes(src[8..12].try_into().unwrap()),
            unencrypted_ephemeral: src[12..44].try_into().unwrap(),
            encrypted_nothing: &src[44..60],
            pq_ciphertext: &src[92..ct_end],
            mldsa_signature: &src[ct_end..sig_end],
        })
    }
}

/// Format a PQ-only handshake init message (with ML-DSA signature)
pub fn format_handshake_init_pq_auth(
    classic_init: &[u8],    // 148 bytes
    pq_ephemeral_pk: &[u8], // 1184 bytes
    mldsa_signature: &[u8], // 3309 bytes
    dst: &mut [u8],         // Must be at least HANDSHAKE_INIT_PQ_AUTH_SZ
) -> Result<usize, &'static str> {
    if classic_init.len() != 148 {
        return Err("Invalid classic init size");
    }
    if pq_ephemeral_pk.len() != MLKEM_PUBLIC_KEY_SIZE {
        return Err("Invalid PQ public key size");
    }
    if mldsa_signature.len() != MLDSA_SIGNATURE_SIZE {
        return Err("Invalid ML-DSA signature size");
    }
    if dst.len() < HANDSHAKE_INIT_PQ_AUTH_SZ {
        return Err("Destination buffer too small");
    }

    // Copy classic init
    dst[..148].copy_from_slice(classic_init);

    // Change message type to PQ-auth variant
    dst[0..4].copy_from_slice(&HANDSHAKE_INIT_PQ_AUTH.to_le_bytes());

    // Append PQ public key
    let pq_pk_end = 148 + MLKEM_PUBLIC_KEY_SIZE;
    dst[148..pq_pk_end].copy_from_slice(pq_ephemeral_pk);

    // Append ML-DSA signature
    dst[pq_pk_end..HANDSHAKE_INIT_PQ_AUTH_SZ].copy_from_slice(mldsa_signature);

    Ok(HANDSHAKE_INIT_PQ_AUTH_SZ)
}

/// Format a PQ-only handshake response message (with ML-DSA signature)
pub fn format_handshake_response_pq_auth(
    classic_resp: &[u8],    // 92 bytes
    pq_ciphertext: &[u8],   // 1088 bytes
    mldsa_signature: &[u8], // 3309 bytes
    dst: &mut [u8],         // Must be at least HANDSHAKE_RESP_PQ_AUTH_SZ
) -> Result<usize, &'static str> {
    if classic_resp.len() != 92 {
        return Err("Invalid classic response size");
    }
    if pq_ciphertext.len() != MLKEM_CIPHERTEXT_SIZE {
        return Err("Invalid PQ ciphertext size");
    }
    if mldsa_signature.len() != MLDSA_SIGNATURE_SIZE {
        return Err("Invalid ML-DSA signature size");
    }
    if dst.len() < HANDSHAKE_RESP_PQ_AUTH_SZ {
        return Err("Destination buffer too small");
    }

    // Copy classic response
    dst[..92].copy_from_slice(classic_resp);

    // Change message type to PQ-auth variant
    dst[0..4].copy_from_slice(&HANDSHAKE_RESP_PQ_AUTH.to_le_bytes());

    // Append PQ ciphertext
    let ct_end = 92 + MLKEM_CIPHERTEXT_SIZE;
    dst[92..ct_end].copy_from_slice(pq_ciphertext);

    // Append ML-DSA signature
    dst[ct_end..HANDSHAKE_RESP_PQ_AUTH_SZ].copy_from_slice(mldsa_signature);

    Ok(HANDSHAKE_RESP_PQ_AUTH_SZ)
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
        let different = HybridHandshakeState::combine_secrets(&[4u8; 32], &mlkem_ss, &chaining_key);
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
        peer_state
            .set_peer_mldsa_public_key(state.mldsa_keypair.as_ref().unwrap().public_key.clone());
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
        let (ciphertext, responder_pq_ss) =
            responder.encapsulate_to_peer(&initiator_pk_bytes).unwrap();

        // 3. Initiator receives response, decapsulates
        let initiator_pq_ss = initiator.decapsulate(&ciphertext).unwrap();

        // 4. Both sides now have matching PQ shared secrets
        assert_eq!(initiator_pq_ss, responder_pq_ss);

        // 5. Combine with X25519 shared secret (simulated)
        let x25519_ss = [0x42u8; 32];
        let chaining_key = [0x00u8; 32];

        let initiator_combined =
            HybridHandshakeState::combine_secrets(&x25519_ss, &initiator_pq_ss, &chaining_key);
        let responder_combined =
            HybridHandshakeState::combine_secrets(&x25519_ss, &responder_pq_ss, &chaining_key);

        assert_eq!(initiator_combined, responder_combined);
    }

    // =========================================================================
    // Serialization round-trip tests
    // =========================================================================

    #[test]
    fn test_init_pq_format_parse_roundtrip() {
        // Build a realistic classic init with known field values
        let mut classic_init = [0u8; 148];
        // Type = 1 (HANDSHAKE_INIT), will be overwritten to 5 by format_handshake_init_pq
        classic_init[0..4].copy_from_slice(&1u32.to_le_bytes());
        // Sender index = 0xDEADBEEF
        let sender_idx: u32 = 0xDEADBEEF;
        classic_init[4..8].copy_from_slice(&sender_idx.to_le_bytes());
        // Unencrypted ephemeral (32 bytes at offset 8)
        let ephemeral = [0x42u8; 32];
        classic_init[8..40].copy_from_slice(&ephemeral);
        // Encrypted static (48 bytes at offset 40)
        let enc_static = [0xAA; 48];
        classic_init[40..88].copy_from_slice(&enc_static);
        // Encrypted timestamp (28 bytes at offset 88)
        let enc_timestamp = [0xBB; 28];
        classic_init[88..116].copy_from_slice(&enc_timestamp);
        // MACs at 116..148 (32 bytes) — set to non-zero to verify they're preserved
        let macs = [0xCC; 32];
        classic_init[116..148].copy_from_slice(&macs);

        // PQ ephemeral public key
        let pq_pk = vec![0x77u8; MLKEM_PUBLIC_KEY_SIZE];

        // Format
        let mut dst = vec![0u8; HANDSHAKE_INIT_PQ_SZ];
        let size = format_handshake_init_pq(&classic_init, &pq_pk, &mut dst).unwrap();
        assert_eq!(size, HANDSHAKE_INIT_PQ_SZ);

        // Parse back
        let parsed = HandshakeInitPq::parse(&dst).unwrap();

        // Verify all fields survived the round-trip
        assert_eq!(parsed.sender_idx, sender_idx);
        assert_eq!(parsed.unencrypted_ephemeral, &ephemeral);
        assert_eq!(parsed.encrypted_static, &enc_static[..]);
        assert_eq!(parsed.encrypted_timestamp, &enc_timestamp[..]);
        assert_eq!(parsed.pq_ephemeral_public, &pq_pk[..]);
    }

    #[test]
    fn test_resp_pq_format_parse_roundtrip() {
        // Build a realistic classic response with known field values
        let mut classic_resp = [0u8; 92];
        // Type = 2, will be overwritten to 6
        classic_resp[0..4].copy_from_slice(&2u32.to_le_bytes());
        // Sender index
        let sender_idx: u32 = 0x12345678;
        classic_resp[4..8].copy_from_slice(&sender_idx.to_le_bytes());
        // Receiver index
        let receiver_idx: u32 = 0x87654321;
        classic_resp[8..12].copy_from_slice(&receiver_idx.to_le_bytes());
        // Unencrypted ephemeral
        let ephemeral = [0x55u8; 32];
        classic_resp[12..44].copy_from_slice(&ephemeral);
        // Encrypted nothing (16 bytes)
        let enc_nothing = [0xDD; 16];
        classic_resp[44..60].copy_from_slice(&enc_nothing);
        // MACs at 60..92
        classic_resp[60..92].copy_from_slice(&[0xEE; 32]);

        // PQ ciphertext
        let pq_ct = vec![0x99u8; MLKEM_CIPHERTEXT_SIZE];

        // Format
        let mut dst = vec![0u8; HANDSHAKE_RESP_PQ_SZ];
        let size = format_handshake_response_pq(&classic_resp, &pq_ct, &mut dst).unwrap();
        assert_eq!(size, HANDSHAKE_RESP_PQ_SZ);

        // Parse back
        let parsed = HandshakeResponsePq::parse(&dst).unwrap();

        // Verify all fields
        assert_eq!(parsed.sender_idx, sender_idx);
        assert_eq!(parsed.receiver_idx, receiver_idx);
        assert_eq!(parsed.unencrypted_ephemeral, &ephemeral);
        assert_eq!(parsed.encrypted_nothing, &enc_nothing[..]);
        assert_eq!(parsed.pq_ciphertext, &pq_ct[..]);
    }

    #[test]
    fn test_init_pq_auth_format_parse_roundtrip() {
        let mut classic_init = [0u8; 148];
        classic_init[0..4].copy_from_slice(&1u32.to_le_bytes());
        let sender_idx: u32 = 0xCAFEBABE;
        classic_init[4..8].copy_from_slice(&sender_idx.to_le_bytes());
        let ephemeral = [0x11u8; 32];
        classic_init[8..40].copy_from_slice(&ephemeral);
        let enc_static = [0x22; 48];
        classic_init[40..88].copy_from_slice(&enc_static);
        let enc_timestamp = [0x33; 28];
        classic_init[88..116].copy_from_slice(&enc_timestamp);

        let pq_pk = vec![0x44u8; MLKEM_PUBLIC_KEY_SIZE];
        let signature = vec![0x55u8; MLDSA_SIGNATURE_SIZE];

        let mut dst = vec![0u8; HANDSHAKE_INIT_PQ_AUTH_SZ];
        let size =
            format_handshake_init_pq_auth(&classic_init, &pq_pk, &signature, &mut dst).unwrap();
        assert_eq!(size, HANDSHAKE_INIT_PQ_AUTH_SZ);

        let parsed = HandshakeInitPqAuth::parse(&dst).unwrap();
        assert_eq!(parsed.sender_idx, sender_idx);
        assert_eq!(parsed.unencrypted_ephemeral, &ephemeral);
        assert_eq!(parsed.encrypted_static, &enc_static[..]);
        assert_eq!(parsed.encrypted_timestamp, &enc_timestamp[..]);
        assert_eq!(parsed.pq_ephemeral_public, &pq_pk[..]);
        assert_eq!(parsed.mldsa_signature, &signature[..]);
    }

    #[test]
    fn test_resp_pq_auth_format_parse_roundtrip() {
        let mut classic_resp = [0u8; 92];
        classic_resp[0..4].copy_from_slice(&2u32.to_le_bytes());
        let sender_idx: u32 = 0xFEEDFACE;
        classic_resp[4..8].copy_from_slice(&sender_idx.to_le_bytes());
        let receiver_idx: u32 = 0xDECAF000;
        classic_resp[8..12].copy_from_slice(&receiver_idx.to_le_bytes());
        let ephemeral = [0x66u8; 32];
        classic_resp[12..44].copy_from_slice(&ephemeral);
        let enc_nothing = [0x77; 16];
        classic_resp[44..60].copy_from_slice(&enc_nothing);

        let pq_ct = vec![0x88u8; MLKEM_CIPHERTEXT_SIZE];
        let signature = vec![0x99u8; MLDSA_SIGNATURE_SIZE];

        let mut dst = vec![0u8; HANDSHAKE_RESP_PQ_AUTH_SZ];
        let size =
            format_handshake_response_pq_auth(&classic_resp, &pq_ct, &signature, &mut dst).unwrap();
        assert_eq!(size, HANDSHAKE_RESP_PQ_AUTH_SZ);

        let parsed = HandshakeResponsePqAuth::parse(&dst).unwrap();
        assert_eq!(parsed.sender_idx, sender_idx);
        assert_eq!(parsed.receiver_idx, receiver_idx);
        assert_eq!(parsed.unencrypted_ephemeral, &ephemeral);
        assert_eq!(parsed.encrypted_nothing, &enc_nothing[..]);
        assert_eq!(parsed.pq_ciphertext, &pq_ct[..]);
        assert_eq!(parsed.mldsa_signature, &signature[..]);
    }

    // =========================================================================
    // MAC zeroing + transcript signing verification
    // =========================================================================

    #[test]
    fn test_pq_auth_transcript_mac_zeroing() {
        // Verify that both initiator and responder produce identical transcripts
        // when MAC bytes are zeroed, regardless of what actual MACs were computed.
        //
        // This is the protocol invariant: transcript = fields + zero_MACs + PQ_data

        // Simulate an init with non-zero MACs
        let mut classic_init = [0u8; 148];
        classic_init[0..4].copy_from_slice(&1u32.to_le_bytes()); // type
        classic_init[4..8].copy_from_slice(&42u32.to_le_bytes()); // sender_idx
        let ephemeral = [0xAA; 32];
        classic_init[8..40].copy_from_slice(&ephemeral);
        let enc_static = [0xBB; 48];
        classic_init[40..88].copy_from_slice(&enc_static);
        let enc_timestamp = [0xCC; 28];
        classic_init[88..116].copy_from_slice(&enc_timestamp);
        // Actual MACs would be computed by WireGuard — use different values
        classic_init[116..132].copy_from_slice(&[0xDD; 16]); // mac1
        classic_init[132..148].copy_from_slice(&[0xEE; 16]); // mac2

        let pq_pk = vec![0xFF; MLKEM_PUBLIC_KEY_SIZE];

        // Build initiator transcript (as done in format_handshake_initiation)
        let mut initiator_transcript = Vec::with_capacity(148 + MLKEM_PUBLIC_KEY_SIZE);
        initiator_transcript.extend_from_slice(&classic_init[..116]); // before MACs
        initiator_transcript.extend_from_slice(&[0u8; 32]); // zero MACs
        initiator_transcript.extend_from_slice(&pq_pk);

        // Build responder transcript (as done in handle_handshake_init_pq_auth)
        // Responder only has parsed fields, NOT the raw MAC bytes
        let mut responder_transcript = Vec::with_capacity(148 + MLKEM_PUBLIC_KEY_SIZE);
        responder_transcript.extend_from_slice(&1u32.to_le_bytes()); // type
        responder_transcript.extend_from_slice(&42u32.to_le_bytes()); // sender_idx
        responder_transcript.extend_from_slice(&ephemeral);
        responder_transcript.extend_from_slice(&enc_static);
        responder_transcript.extend_from_slice(&enc_timestamp);
        responder_transcript.extend_from_slice(&[0u8; 32]); // zero MACs
        responder_transcript.extend_from_slice(&pq_pk);

        // Both transcripts must be byte-identical
        assert_eq!(
            initiator_transcript, responder_transcript,
            "Initiator and responder must produce identical transcripts with zeroed MACs"
        );
        assert_eq!(initiator_transcript.len(), 148 + MLKEM_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_transcript_sign_verify_with_zeroed_macs() {
        // End-to-end: sign a transcript on one side, verify on the other,
        // using the exact MAC-zeroing protocol from the handshake code.

        let initiator_kp = MlDsaKeyPair::generate().unwrap();
        let responder_kp = MlDsaKeyPair::generate().unwrap();

        // Simulate init fields
        let sender_idx: u32 = 1234;
        let ephemeral = [0x42u8; 32];
        let enc_static = [0xAA; 48];
        let enc_timestamp = [0xBB; 28];
        let pq_pk = PqKeyPair::generate()
            .unwrap()
            .public_key
            .as_bytes()
            .to_vec();

        // Initiator builds and signs transcript
        let mut transcript = Vec::new();
        transcript.extend_from_slice(&1u32.to_le_bytes());
        transcript.extend_from_slice(&sender_idx.to_le_bytes());
        transcript.extend_from_slice(&ephemeral);
        transcript.extend_from_slice(&enc_static);
        transcript.extend_from_slice(&enc_timestamp);
        transcript.extend_from_slice(&[0u8; 32]); // zero MACs
        transcript.extend_from_slice(&pq_pk);

        let signature = initiator_kp.sign(&transcript).unwrap();

        // Responder reconstructs transcript from parsed fields (NOT raw bytes)
        // and verifies — this is exactly what handle_handshake_init_pq_auth does
        let mut responder_transcript = Vec::new();
        responder_transcript.extend_from_slice(&1u32.to_le_bytes());
        responder_transcript.extend_from_slice(&sender_idx.to_le_bytes());
        responder_transcript.extend_from_slice(&ephemeral);
        responder_transcript.extend_from_slice(&enc_static);
        responder_transcript.extend_from_slice(&enc_timestamp);
        responder_transcript.extend_from_slice(&[0u8; 32]); // zero MACs
        responder_transcript.extend_from_slice(&pq_pk);

        // Verify using initiator's public key
        let valid =
            mldsa_verify(initiator_kp.public_key(), &responder_transcript, &signature).unwrap();
        assert!(
            valid,
            "Responder must be able to verify initiator's signature"
        );

        // Also verify that a wrong transcript fails
        let mut wrong_transcript = responder_transcript.clone();
        wrong_transcript[10] ^= 0xFF; // flip a byte
        let invalid =
            mldsa_verify(initiator_kp.public_key(), &wrong_transcript, &signature).unwrap();
        assert!(!invalid, "Modified transcript must fail verification");

        // Verify that wrong key fails
        let wrong_valid = mldsa_verify(
            responder_kp.public_key(), // wrong key
            &responder_transcript,
            &signature,
        )
        .unwrap();
        assert!(!wrong_valid, "Wrong key must fail verification");
    }

    #[test]
    fn test_response_transcript_initiator_responder_agreement() {
        // Test the full response transcript: both sides must agree on the
        // combined init+response transcript for ML-DSA verification.

        let responder_kp = MlDsaKeyPair::generate().unwrap();

        // Init fields
        let init_sender_idx: u32 = 100;
        let init_ephemeral = [0x11; 32];
        let init_enc_static = [0x22; 48];
        let init_enc_timestamp = [0x33; 28];
        let pq_pk = vec![0x44; MLKEM_PUBLIC_KEY_SIZE];

        // Response fields
        let resp_sender_idx: u32 = 200;
        let resp_receiver_idx: u32 = 100;
        let resp_ephemeral = [0x55; 32];
        let resp_enc_nothing = [0x66; 16];
        let pq_ct = vec![0x77; MLKEM_CIPHERTEXT_SIZE];

        // Responder builds full transcript and signs
        let mut resp_transcript = Vec::new();
        // init part (with zero MACs)
        resp_transcript.extend_from_slice(&1u32.to_le_bytes());
        resp_transcript.extend_from_slice(&init_sender_idx.to_le_bytes());
        resp_transcript.extend_from_slice(&init_ephemeral);
        resp_transcript.extend_from_slice(&init_enc_static);
        resp_transcript.extend_from_slice(&init_enc_timestamp);
        resp_transcript.extend_from_slice(&[0u8; 32]); // zero MACs
        resp_transcript.extend_from_slice(&pq_pk);
        // response part (with zero MACs)
        resp_transcript.extend_from_slice(&2u32.to_le_bytes()); // response type
        resp_transcript.extend_from_slice(&resp_sender_idx.to_le_bytes());
        resp_transcript.extend_from_slice(&resp_receiver_idx.to_le_bytes());
        resp_transcript.extend_from_slice(&resp_ephemeral);
        resp_transcript.extend_from_slice(&resp_enc_nothing);
        resp_transcript.extend_from_slice(&[0u8; 32]); // zero MACs
        resp_transcript.extend_from_slice(&pq_ct);

        let signature = responder_kp.sign(&resp_transcript).unwrap();

        // Initiator rebuilds the same transcript from its stored init + parsed response
        let mut init_transcript = Vec::new();
        // Initiator has the raw init bytes (116 before MACs)
        let mut raw_init = [0u8; 148];
        raw_init[0..4].copy_from_slice(&1u32.to_le_bytes());
        raw_init[4..8].copy_from_slice(&init_sender_idx.to_le_bytes());
        raw_init[8..40].copy_from_slice(&init_ephemeral);
        raw_init[40..88].copy_from_slice(&init_enc_static);
        raw_init[88..116].copy_from_slice(&init_enc_timestamp);
        // Non-zero MACs in the actual packet (doesn't matter — we zero them)
        raw_init[116..148].copy_from_slice(&[0xFF; 32]);

        init_transcript.extend_from_slice(&raw_init[..116]); // before MACs
        init_transcript.extend_from_slice(&[0u8; 32]); // zero MACs
        init_transcript.extend_from_slice(&pq_pk);
        // response part
        init_transcript.extend_from_slice(&2u32.to_le_bytes());
        init_transcript.extend_from_slice(&resp_sender_idx.to_le_bytes());
        init_transcript.extend_from_slice(&resp_receiver_idx.to_le_bytes());
        init_transcript.extend_from_slice(&resp_ephemeral);
        init_transcript.extend_from_slice(&resp_enc_nothing);
        init_transcript.extend_from_slice(&[0u8; 32]); // zero MACs
        init_transcript.extend_from_slice(&pq_ct);

        // Both transcripts must match
        assert_eq!(
            resp_transcript, init_transcript,
            "Responder and initiator must produce identical response transcripts"
        );

        // Initiator verifies responder's signature
        let valid = mldsa_verify(responder_kp.public_key(), &init_transcript, &signature).unwrap();
        assert!(
            valid,
            "Initiator must verify responder's response signature"
        );
    }
}
