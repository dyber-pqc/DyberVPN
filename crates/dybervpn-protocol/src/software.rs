//! Software cryptographic backend using ml-kem and dalek

use crate::crypto::{CryptoBackend, CryptoError, CryptoResult};
use crate::types::{
    mldsa65, mlkem768, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature, MlKemCiphertext,
    MlKemPublicKey, MlKemSecretKey, SharedSecret,
};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use ml_dsa::MlDsa65;
use ml_kem::kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768, MlKem768Params};
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

/// Software cryptographic backend
#[derive(Debug, Default)]
pub struct SoftwareBackend;

impl SoftwareBackend {
    /// Create a new software backend
    pub fn new() -> Self {
        Self
    }
}

impl CryptoBackend for SoftwareBackend {
    fn name(&self) -> &'static str {
        "software (ml-kem + dalek)"
    }

    // ========================================================================
    // ML-KEM-768
    // ========================================================================

    fn mlkem_keygen(&self) -> CryptoResult<(MlKemPublicKey, MlKemSecretKey)> {
        // Generate keypair - returns (DecapsulationKey, EncapsulationKey)
        let (dk, ek) = MlKem768::generate(&mut OsRng);

        // Get encoded bytes using EncodedSizeUser trait
        let ek_encoded = ek.as_bytes();
        let dk_encoded = dk.as_bytes();

        let ek_bytes: &[u8] = ek_encoded.as_ref();
        let dk_bytes: &[u8] = dk_encoded.as_ref();

        if ek_bytes.len() != mlkem768::PUBLIC_KEY_SIZE {
            return Err(CryptoError::KeyGeneration(format!(
                "Unexpected ML-KEM encapsulation key size: {} (expected {})",
                ek_bytes.len(),
                mlkem768::PUBLIC_KEY_SIZE
            )));
        }

        if dk_bytes.len() != mlkem768::SECRET_KEY_SIZE {
            return Err(CryptoError::KeyGeneration(format!(
                "Unexpected ML-KEM decapsulation key size: {} (expected {})",
                dk_bytes.len(),
                mlkem768::SECRET_KEY_SIZE
            )));
        }

        Ok((
            MlKemPublicKey(ek_bytes.to_vec()),
            MlKemSecretKey(dk_bytes.to_vec()),
        ))
    }

    fn mlkem_encaps(&self, pk: &MlKemPublicKey) -> CryptoResult<(MlKemCiphertext, SharedSecret)> {
        let ek_bytes = pk.as_bytes();
        if ek_bytes.len() != mlkem768::PUBLIC_KEY_SIZE {
            return Err(CryptoError::Encapsulation("Invalid public key size".into()));
        }

        // Convert to the Array type ml-kem expects
        let ek_array = ml_kem::Encoded::<EncapsulationKey<MlKem768Params>>::try_from(ek_bytes)
            .map_err(|_| CryptoError::Encapsulation("Failed to parse encapsulation key".into()))?;

        let ek = EncapsulationKey::<MlKem768Params>::from_bytes(&ek_array);

        // Encapsulate returns Result<(Ciphertext, SharedKey), ()>
        let (ct, ss) = ek
            .encapsulate(&mut OsRng)
            .map_err(|_| CryptoError::Encapsulation("Encapsulation failed".into()))?;

        let ct_bytes: &[u8] = ct.as_ref();

        if ct_bytes.len() != mlkem768::CIPHERTEXT_SIZE {
            return Err(CryptoError::Encapsulation(format!(
                "Unexpected ciphertext size: {} (expected {})",
                ct_bytes.len(),
                mlkem768::CIPHERTEXT_SIZE
            )));
        }

        let ss_bytes: &[u8] = ss.as_ref();
        let mut ss_arr = [0u8; 32];
        ss_arr.copy_from_slice(ss_bytes);

        Ok((MlKemCiphertext(ct_bytes.to_vec()), SharedSecret(ss_arr)))
    }

    fn mlkem_decaps(
        &self,
        sk: &MlKemSecretKey,
        ct: &MlKemCiphertext,
    ) -> CryptoResult<SharedSecret> {
        let dk_bytes = sk.as_bytes();
        if dk_bytes.len() != mlkem768::SECRET_KEY_SIZE {
            return Err(CryptoError::Decapsulation("Invalid secret key size".into()));
        }

        let ct_bytes = ct.as_bytes();
        if ct_bytes.len() != mlkem768::CIPHERTEXT_SIZE {
            return Err(CryptoError::Decapsulation("Invalid ciphertext size".into()));
        }

        // Convert to Array types
        let dk_array = ml_kem::Encoded::<DecapsulationKey<MlKem768Params>>::try_from(dk_bytes)
            .map_err(|_| CryptoError::Decapsulation("Failed to parse decapsulation key".into()))?;

        let ct_array = ml_kem::Ciphertext::<MlKem768>::try_from(ct_bytes)
            .map_err(|_| CryptoError::Decapsulation("Failed to parse ciphertext".into()))?;

        let dk = DecapsulationKey::<MlKem768Params>::from_bytes(&dk_array);

        // Decapsulate returns Result<SharedKey, ()>
        let ss = dk
            .decapsulate(&ct_array)
            .map_err(|_| CryptoError::Decapsulation("Decapsulation failed".into()))?;

        let ss_bytes: &[u8] = ss.as_ref();
        let mut ss_arr = [0u8; 32];
        ss_arr.copy_from_slice(ss_bytes);

        Ok(SharedSecret(ss_arr))
    }

    // ========================================================================
    // X25519
    // ========================================================================

    fn x25519_keygen(&self) -> CryptoResult<([u8; 32], [u8; 32])> {
        let secret = X25519Secret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);

        Ok((*public.as_bytes(), secret.to_bytes()))
    }

    fn x25519_diffie_hellman(
        &self,
        our_secret: &[u8; 32],
        their_public: &[u8; 32],
    ) -> CryptoResult<SharedSecret> {
        let secret = X25519Secret::from(*our_secret);
        let public = X25519PublicKey::from(*their_public);
        let shared = secret.diffie_hellman(&public);

        Ok(SharedSecret(*shared.as_bytes()))
    }

    // ========================================================================
    // Ed25519
    // ========================================================================

    fn ed25519_keygen(&self) -> CryptoResult<([u8; 32], [u8; 64])> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let public: [u8; 32] = verifying_key.to_bytes();

        // 64-byte secret key = seed || public
        let mut secret = [0u8; 64];
        secret[..32].copy_from_slice(signing_key.as_bytes());
        secret[32..].copy_from_slice(&public);

        Ok((public, secret))
    }

    fn ed25519_sign(&self, secret_key: &[u8; 64], msg: &[u8]) -> CryptoResult<[u8; 64]> {
        let seed: [u8; 32] = secret_key[..32].try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&seed);

        let signature: Signature = signing_key.sign(msg);
        Ok(signature.to_bytes())
    }

    fn ed25519_verify(
        &self,
        public_key: &[u8; 32],
        msg: &[u8],
        signature: &[u8; 64],
    ) -> CryptoResult<bool> {
        let verifying_key = VerifyingKey::from_bytes(public_key)
            .map_err(|e| CryptoError::Verification(format!("Invalid public key: {}", e)))?;

        let sig = Signature::from_bytes(signature);

        match verifying_key.verify(msg, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    // ========================================================================
    // ML-DSA-65 (Post-Quantum Signatures)
    // ========================================================================

    fn mldsa_keygen(&self) -> CryptoResult<(MlDsaPublicKey, MlDsaSecretKey)> {
        // Generate a 32-byte seed for key generation
        let mut seed = [0u8; 32];
        self.random_bytes(&mut seed)?;

        // Create signing key from seed
        let signing_key = ml_dsa::SigningKey::<MlDsa65>::from_seed(&seed.into());
        let verifying_key = signing_key.verifying_key();

        // Get expanded signing key bytes (this is what we store)
        // Note: to_expanded is deprecated, but we need it for key serialization
        #[allow(deprecated)]
        let sk_expanded = signing_key.to_expanded();
        let sk_bytes: &[u8] = sk_expanded.as_ref();

        // Get verifying key bytes
        let pk_encoded = verifying_key.encode();
        let pk_bytes: &[u8] = pk_encoded.as_ref();

        if pk_bytes.len() != mldsa65::PUBLIC_KEY_SIZE {
            return Err(CryptoError::KeyGeneration(format!(
                "Unexpected ML-DSA public key size: {} (expected {})",
                pk_bytes.len(),
                mldsa65::PUBLIC_KEY_SIZE
            )));
        }

        if sk_bytes.len() != mldsa65::SECRET_KEY_SIZE {
            return Err(CryptoError::KeyGeneration(format!(
                "Unexpected ML-DSA secret key size: {} (expected {})",
                sk_bytes.len(),
                mldsa65::SECRET_KEY_SIZE
            )));
        }

        Ok((
            MlDsaPublicKey(pk_bytes.to_vec()),
            MlDsaSecretKey(sk_bytes.to_vec()),
        ))
    }

    fn mldsa_sign(&self, secret_key: &MlDsaSecretKey, msg: &[u8]) -> CryptoResult<MlDsaSignature> {
        use ml_dsa::signature::Signer;

        let sk_bytes = secret_key.as_bytes();
        if sk_bytes.len() != mldsa65::SECRET_KEY_SIZE {
            return Err(CryptoError::Signing("Invalid secret key size".into()));
        }

        // Convert bytes to ExpandedSigningKey and create SigningKey
        let sk_array: ml_dsa::ExpandedSigningKey<MlDsa65> = sk_bytes
            .try_into()
            .map_err(|_| CryptoError::Signing("Failed to convert secret key".into()))?;

        // Note: from_expanded is deprecated, but we need it to reconstruct from stored bytes
        #[allow(deprecated)]
        let signing_key = ml_dsa::SigningKey::<MlDsa65>::from_expanded(&sk_array);
        let signature = signing_key.sign(msg);
        let sig_encoded = signature.encode();
        let sig_bytes: &[u8] = sig_encoded.as_ref();

        Ok(MlDsaSignature(sig_bytes.to_vec()))
    }

    fn mldsa_verify(
        &self,
        public_key: &MlDsaPublicKey,
        msg: &[u8],
        signature: &MlDsaSignature,
    ) -> CryptoResult<bool> {
        use ml_dsa::signature::Verifier;

        let pk_bytes = public_key.as_bytes();
        if pk_bytes.len() != mldsa65::PUBLIC_KEY_SIZE {
            return Err(CryptoError::Verification("Invalid public key size".into()));
        }

        let sig_bytes = signature.as_bytes();
        if sig_bytes.len() != mldsa65::SIGNATURE_SIZE {
            return Err(CryptoError::Verification("Invalid signature size".into()));
        }

        // Convert bytes to EncodedVerifyingKey and decode
        let pk_array: ml_dsa::EncodedVerifyingKey<MlDsa65> = pk_bytes
            .try_into()
            .map_err(|_| CryptoError::Verification("Failed to convert public key".into()))?;

        let verifying_key = ml_dsa::VerifyingKey::<MlDsa65>::decode(&pk_array);

        // Convert bytes to EncodedSignature and decode
        let sig_array: ml_dsa::EncodedSignature<MlDsa65> = sig_bytes
            .try_into()
            .map_err(|_| CryptoError::Verification("Failed to convert signature".into()))?;

        let sig = ml_dsa::Signature::<MlDsa65>::decode(&sig_array)
            .ok_or_else(|| CryptoError::Verification("Invalid signature encoding".into()))?;

        match verifying_key.verify(msg, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    // ========================================================================
    // Entropy
    // ========================================================================

    fn random_bytes(&self, buf: &mut [u8]) -> CryptoResult<()> {
        use rand_core::RngCore;
        OsRng.fill_bytes(buf);
        Ok(())
    }

    // ========================================================================
    // Key Derivation
    // ========================================================================

    fn hkdf_sha256(
        &self,
        salt: &[u8],
        ikm: &[u8],
        info: &[u8],
        okm: &mut [u8],
    ) -> CryptoResult<()> {
        let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
        hk.expand(info, okm)
            .map_err(|e| CryptoError::Internal(format!("HKDF expand failed: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend() -> SoftwareBackend {
        SoftwareBackend::new()
    }

    #[test]
    fn test_mlkem_roundtrip() {
        let b = backend();

        let (pk, sk) = b.mlkem_keygen().expect("keygen failed");
        let (ct, ss1) = b.mlkem_encaps(&pk).expect("encaps failed");
        let ss2 = b.mlkem_decaps(&sk, &ct).expect("decaps failed");

        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn test_x25519_roundtrip() {
        let b = backend();

        let (pk_a, sk_a) = b.x25519_keygen().expect("keygen A failed");
        let (pk_b, sk_b) = b.x25519_keygen().expect("keygen B failed");

        let ss_a = b.x25519_diffie_hellman(&sk_a, &pk_b).expect("DH A failed");
        let ss_b = b.x25519_diffie_hellman(&sk_b, &pk_a).expect("DH B failed");

        assert_eq!(ss_a.as_bytes(), ss_b.as_bytes());
    }

    #[test]
    fn test_ed25519_sign_verify() {
        let b = backend();

        let (pk, sk) = b.ed25519_keygen().expect("keygen failed");
        let msg = b"test message for signing";

        let sig = b.ed25519_sign(&sk, msg).expect("sign failed");
        let valid = b.ed25519_verify(&pk, msg, &sig).expect("verify failed");

        assert!(valid);

        // Wrong message should fail
        let invalid = b
            .ed25519_verify(&pk, b"wrong message", &sig)
            .expect("verify failed");
        assert!(!invalid);
    }

    #[test]
    fn test_mldsa_sign_verify() {
        let b = backend();

        let (pk, sk) = b.mldsa_keygen().expect("keygen failed");
        let msg = b"test message for ML-DSA signing";

        let sig = b.mldsa_sign(&sk, msg).expect("sign failed");
        let valid = b.mldsa_verify(&pk, msg, &sig).expect("verify failed");

        assert!(valid);

        // Wrong message should fail
        let invalid = b
            .mldsa_verify(&pk, b"wrong message", &sig)
            .expect("verify failed");
        assert!(!invalid);
    }

    #[test]
    fn test_hybrid_key_exchange() {
        let b = backend();

        // Initiator
        let (mlkem_pk_i, mlkem_sk_i) = b.mlkem_keygen().expect("mlkem keygen failed");
        let (x25519_pk_i, x25519_sk_i) = b.x25519_keygen().expect("x25519 keygen failed");

        // Responder
        let (x25519_pk_r, x25519_sk_r) = b.x25519_keygen().expect("x25519 keygen failed");

        // Responder encapsulates
        let (mlkem_ct, mlkem_ss_r) = b.mlkem_encaps(&mlkem_pk_i).expect("encaps failed");
        let x25519_ss_r = b
            .x25519_diffie_hellman(&x25519_sk_r, &x25519_pk_i)
            .expect("DH failed");
        let combined_r = b
            .combine_shared_secrets(&mlkem_ss_r, &x25519_ss_r, b"test")
            .expect("combine failed");

        // Initiator decapsulates
        let mlkem_ss_i = b
            .mlkem_decaps(&mlkem_sk_i, &mlkem_ct)
            .expect("decaps failed");
        let x25519_ss_i = b
            .x25519_diffie_hellman(&x25519_sk_i, &x25519_pk_r)
            .expect("DH failed");
        let combined_i = b
            .combine_shared_secrets(&mlkem_ss_i, &x25519_ss_i, b"test")
            .expect("combine failed");

        assert_eq!(combined_i.as_bytes(), combined_r.as_bytes());
    }
}
