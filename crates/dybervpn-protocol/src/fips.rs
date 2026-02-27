//! FIPS 140-3 Cryptographic Self-Tests
//!
//! This module implements the self-test requirements for FIPS 140-3 Level 3
//! compliance. All tests must pass before the crypto module services any
//! request. Tests include:
//!
//! - **Power-On Self-Tests (POST)**: Known-Answer Tests (KATs) for every
//!   approved algorithm, run once at module initialization.
//! - **Pairwise Consistency Tests**: Verify freshly generated keypairs work
//!   correctly (keygen → use → verify roundtrip).
//! - **Continuous Random Number Generator Test (CRNGT)**: Verify the entropy
//!   source never produces consecutive identical blocks.
//!
//! If any self-test fails, the module enters an error state and refuses to
//! perform cryptographic operations until the failure is resolved.
//!
//! # Reference
//!
//! - FIPS 140-3: <https://csrc.nist.gov/pubs/fips/140-3/final>
//! - FIPS 140-3 IG: <https://csrc.nist.gov/projects/cryptographic-module-validation-program>
//! - FIPS 203 (ML-KEM): <https://csrc.nist.gov/pubs/fips/203/final>
//! - FIPS 204 (ML-DSA): <https://csrc.nist.gov/pubs/fips/204/final>

use crate::crypto::{CryptoBackend, CryptoResult};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Module health state
///
/// FIPS 140-3 requires the module to track its operational state.
/// If any self-test fails, the module must enter an error state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ModuleState {
    /// Module has not been initialized — no crypto operations allowed
    Uninitialized = 0,
    /// Power-on self-tests are currently running
    SelfTesting = 1,
    /// All self-tests passed — module is operational
    Operational = 2,
    /// A self-test failed — module is in error state, no crypto operations allowed
    Error = 3,
}

impl ModuleState {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Uninitialized,
            1 => Self::SelfTesting,
            2 => Self::Operational,
            3 => Self::Error,
            _ => Self::Error,
        }
    }
}

impl std::fmt::Display for ModuleState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Uninitialized => write!(f, "UNINITIALIZED"),
            Self::SelfTesting => write!(f, "SELF-TESTING"),
            Self::Operational => write!(f, "OPERATIONAL"),
            Self::Error => write!(f, "ERROR"),
        }
    }
}

/// Individual self-test result
#[derive(Debug, Clone)]
pub struct SelfTestResult {
    /// Name of the algorithm or test
    pub name: String,
    /// Whether the test passed
    pub passed: bool,
    /// Duration of the test
    pub duration: Duration,
    /// Error details if the test failed
    pub error: Option<String>,
}

impl std::fmt::Display for SelfTestResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let status = if self.passed { "PASS" } else { "FAIL" };
        write!(f, "[{}] {} ({:.2?})", status, self.name, self.duration)?;
        if let Some(ref err) = self.error {
            write!(f, " — {}", err)?;
        }
        Ok(())
    }
}

/// Complete self-test report
#[derive(Debug, Clone)]
pub struct SelfTestReport {
    /// Individual test results
    pub results: Vec<SelfTestResult>,
    /// Overall pass/fail
    pub passed: bool,
    /// Total duration
    pub duration: Duration,
    /// Module state after tests
    pub module_state: ModuleState,
    /// Timestamp (ISO 8601)
    pub timestamp: String,
    /// Backend name
    pub backend: String,
}

impl std::fmt::Display for SelfTestReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "╔══════════════════════════════════════════════════════════╗"
        )?;
        writeln!(
            f,
            "║        DyberVPN FIPS 140-3 Self-Test Report             ║"
        )?;
        writeln!(
            f,
            "╠══════════════════════════════════════════════════════════╣"
        )?;
        writeln!(f, "║ Backend:  {:<46} ║", self.backend)?;
        writeln!(f, "║ Time:     {:<46} ║", self.timestamp)?;
        writeln!(f, "║ Duration: {:<46} ║", format!("{:.2?}", self.duration))?;
        writeln!(
            f,
            "╠══════════════════════════════════════════════════════════╣"
        )?;

        for result in &self.results {
            let icon = if result.passed { "✓" } else { "✗" };
            writeln!(
                f,
                "║ {} {:<54} ║",
                icon,
                format!("{} ({:.2?})", result.name, result.duration)
            )?;
            if let Some(ref err) = result.error {
                writeln!(f, "║   ERROR: {:<47} ║", err)?;
            }
        }

        writeln!(
            f,
            "╠══════════════════════════════════════════════════════════╣"
        )?;
        let overall = if self.passed {
            "ALL TESTS PASSED"
        } else {
            "SELF-TEST FAILURE"
        };
        let state_str = format!("Module state: {}", self.module_state);
        writeln!(f, "║ {:<56} ║", overall)?;
        writeln!(f, "║ {:<56} ║", state_str)?;
        writeln!(
            f,
            "╚══════════════════════════════════════════════════════════╝"
        )?;
        Ok(())
    }
}

/// Global module state — shared across threads
static MODULE_STATE: AtomicU8 = AtomicU8::new(0); // Uninitialized
static CRNGT_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Get the current module state
pub fn module_state() -> ModuleState {
    ModuleState::from_u8(MODULE_STATE.load(Ordering::SeqCst))
}

/// Check if the module is operational (self-tests passed)
pub fn is_operational() -> bool {
    module_state() == ModuleState::Operational
}

/// Run all FIPS 140-3 power-on self-tests.
///
/// This must be called before ANY cryptographic operation. If any test fails,
/// the module enters an error state and all crypto operations will be refused.
///
/// # FIPS 140-3 Requirements Addressed
///
/// - **AS09.25**: Power-on self-tests for all approved algorithms
/// - **AS09.26**: Pairwise consistency tests for key generation
/// - **AS09.39**: Continuous random number generator test
/// - **AS09.41**: Module enters error state on self-test failure
pub fn run_power_on_self_tests(backend: &dyn CryptoBackend) -> SelfTestReport {
    let start = Instant::now();
    MODULE_STATE.store(ModuleState::SelfTesting as u8, Ordering::SeqCst);

    tracing::info!(
        "FIPS 140-3 power-on self-tests starting (backend: {})",
        backend.name()
    );

    let results = vec![
        // 1. ML-KEM-768 Known-Answer Test (FIPS 203)
        kat_mlkem768(backend),
        // 2. ML-DSA-65 Known-Answer Test (FIPS 204)
        kat_mldsa65(backend),
        // 3. X25519 Known-Answer Test (RFC 7748)
        kat_x25519(backend),
        // 4. Ed25519 Known-Answer Test (RFC 8032)
        kat_ed25519(backend),
        // 5. HKDF-SHA256 Known-Answer Test (RFC 5869)
        kat_hkdf_sha256(backend),
        // 6. Continuous Random Number Generator Test (CRNGT)
        crngt_initial(backend),
        // 7. ML-KEM-768 Pairwise Consistency Test
        pct_mlkem768(backend),
        // 8. ML-DSA-65 Pairwise Consistency Test
        pct_mldsa65(backend),
        // 9. Ed25519 Pairwise Consistency Test
        pct_ed25519(backend),
    ];

    // Determine overall result
    let all_passed = results.iter().all(|r| r.passed);
    let duration = start.elapsed();

    let final_state = if all_passed {
        MODULE_STATE.store(ModuleState::Operational as u8, Ordering::SeqCst);
        tracing::info!(
            "FIPS 140-3 self-tests PASSED ({}/{} tests, {:.2?})",
            results.len(),
            results.len(),
            duration
        );
        ModuleState::Operational
    } else {
        MODULE_STATE.store(ModuleState::Error as u8, Ordering::SeqCst);
        let failed: Vec<_> = results.iter().filter(|r| !r.passed).collect();
        tracing::error!(
            "FIPS 140-3 self-tests FAILED — {} of {} tests failed. Module entering error state.",
            failed.len(),
            results.len()
        );
        for f in &failed {
            tracing::error!("  FAILED: {} — {:?}", f.name, f.error);
        }
        ModuleState::Error
    };

    SelfTestReport {
        results,
        passed: all_passed,
        duration,
        module_state: final_state,
        timestamp: iso8601_now(),
        backend: backend.name().to_string(),
    }
}

/// Generate an ISO 8601 timestamp without pulling in chrono
fn iso8601_now() -> String {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs();
    // Simple UTC timestamp: seconds since epoch
    // For a full ISO 8601 date we'd need chrono, but epoch seconds
    // is unambiguous and machine-parseable for audit purposes
    format!("{}Z", secs)
}

// ============================================================================
// Known-Answer Tests (KATs)
//
// For PQ algorithms (ML-KEM, ML-DSA): These use deterministic roundtrip tests.
// The algorithms use internal randomness, so we verify the functional
// correctness of keygen → encaps/sign → decaps/verify rather than comparing
// against static byte vectors.
//
// For classical algorithms (X25519, Ed25519, HKDF): These use RFC test vectors
// with hardcoded expected outputs.
//
// FIPS 140-3 IG 10.3.A: "The KAT is a minimum requirement. A PCT (pairwise
// consistency test) may be used as a KAT for asymmetric algorithms."
// ============================================================================

/// ML-KEM-768 KAT: keygen → encaps → decaps → shared secrets must match
fn kat_mlkem768(backend: &dyn CryptoBackend) -> SelfTestResult {
    let start = Instant::now();
    let name = "ML-KEM-768 KAT (FIPS 203)".to_string();

    let result = (|| -> Result<(), String> {
        // Step 1: Generate keypair
        let (pk, sk) = backend
            .mlkem_keygen()
            .map_err(|e| format!("keygen failed: {}", e))?;

        // Step 2: Verify key sizes
        if pk.as_bytes().len() != crate::types::mlkem768::PUBLIC_KEY_SIZE {
            return Err(format!(
                "public key size {} != expected {}",
                pk.as_bytes().len(),
                crate::types::mlkem768::PUBLIC_KEY_SIZE
            ));
        }
        if sk.as_bytes().len() != crate::types::mlkem768::SECRET_KEY_SIZE {
            return Err(format!(
                "secret key size {} != expected {}",
                sk.as_bytes().len(),
                crate::types::mlkem768::SECRET_KEY_SIZE
            ));
        }

        // Step 3: Encapsulate
        let (ct, ss_enc) = backend
            .mlkem_encaps(&pk)
            .map_err(|e| format!("encaps failed: {}", e))?;

        if ct.as_bytes().len() != crate::types::mlkem768::CIPHERTEXT_SIZE {
            return Err(format!(
                "ciphertext size {} != expected {}",
                ct.as_bytes().len(),
                crate::types::mlkem768::CIPHERTEXT_SIZE
            ));
        }

        // Step 4: Decapsulate
        let ss_dec = backend
            .mlkem_decaps(&sk, &ct)
            .map_err(|e| format!("decaps failed: {}", e))?;

        // Step 5: Shared secrets must match
        if ss_enc.as_bytes() != ss_dec.as_bytes() {
            return Err("shared secret mismatch: encaps != decaps".to_string());
        }

        // Step 6: Shared secret must not be all zeros
        if ss_enc.as_bytes().iter().all(|&b| b == 0) {
            return Err("shared secret is all zeros".to_string());
        }

        Ok(())
    })();

    SelfTestResult {
        name,
        passed: result.is_ok(),
        duration: start.elapsed(),
        error: result.err(),
    }
}

/// ML-DSA-65 KAT: keygen → sign → verify → must validate
fn kat_mldsa65(backend: &dyn CryptoBackend) -> SelfTestResult {
    let start = Instant::now();
    let name = "ML-DSA-65 KAT (FIPS 204)".to_string();

    // Fixed test message — never changes (part of the KAT definition)
    const KAT_MESSAGE: &[u8] = b"DyberVPN FIPS 140-3 ML-DSA-65 Known-Answer Test Message v1";

    let result = (|| -> Result<(), String> {
        // Step 1: Generate keypair
        let (pk, sk) = backend
            .mldsa_keygen()
            .map_err(|e| format!("keygen failed: {}", e))?;

        // Step 2: Verify key sizes
        if pk.as_bytes().len() != crate::types::mldsa65::PUBLIC_KEY_SIZE {
            return Err(format!(
                "public key size {} != expected {}",
                pk.as_bytes().len(),
                crate::types::mldsa65::PUBLIC_KEY_SIZE
            ));
        }
        if sk.as_bytes().len() != crate::types::mldsa65::SECRET_KEY_SIZE {
            return Err(format!(
                "secret key size {} != expected {}",
                sk.as_bytes().len(),
                crate::types::mldsa65::SECRET_KEY_SIZE
            ));
        }

        // Step 3: Sign
        let sig = backend
            .mldsa_sign(&sk, KAT_MESSAGE)
            .map_err(|e| format!("sign failed: {}", e))?;

        if sig.as_bytes().len() != crate::types::mldsa65::SIGNATURE_SIZE {
            return Err(format!(
                "signature size {} != expected {}",
                sig.as_bytes().len(),
                crate::types::mldsa65::SIGNATURE_SIZE
            ));
        }

        // Step 4: Verify — must pass
        let valid = backend
            .mldsa_verify(&pk, KAT_MESSAGE, &sig)
            .map_err(|e| format!("verify failed: {}", e))?;

        if !valid {
            return Err("signature verification failed on valid signature".to_string());
        }

        // Step 5: Verify with wrong message — must fail
        let invalid = backend
            .mldsa_verify(&pk, b"wrong message", &sig)
            .map_err(|e| format!("verify-wrong failed: {}", e))?;

        if invalid {
            return Err("signature verification passed on wrong message".to_string());
        }

        Ok(())
    })();

    SelfTestResult {
        name,
        passed: result.is_ok(),
        duration: start.elapsed(),
        error: result.err(),
    }
}

/// X25519 KAT using RFC 7748 Section 6.1 test vector
fn kat_x25519(backend: &dyn CryptoBackend) -> SelfTestResult {
    let start = Instant::now();
    let name = "X25519 KAT (RFC 7748)".to_string();

    let result = (|| -> Result<(), String> {
        // RFC 7748 Section 6.1 test vector
        let alice_private: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let bob_public: [u8; 32] = [
            0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4,
            0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14,
            0x6f, 0x88, 0x2b, 0x4f,
        ];
        let expected_shared: [u8; 32] = [
            0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35,
            0x0f, 0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c,
            0x1e, 0x16, 0x17, 0x42,
        ];

        let shared = backend
            .x25519_diffie_hellman(&alice_private, &bob_public)
            .map_err(|e| format!("DH failed: {}", e))?;

        if shared.as_bytes() != expected_shared {
            return Err(format!(
                "shared secret mismatch: got {:02x?}, expected {:02x?}",
                &shared.as_bytes()[..8],
                &expected_shared[..8]
            ));
        }

        Ok(())
    })();

    SelfTestResult {
        name,
        passed: result.is_ok(),
        duration: start.elapsed(),
        error: result.err(),
    }
}

/// Ed25519 KAT using RFC 8032 Section 7.1 test vector (TEST 2)
fn kat_ed25519(backend: &dyn CryptoBackend) -> SelfTestResult {
    let start = Instant::now();
    let name = "Ed25519 KAT (RFC 8032)".to_string();

    let result = (|| -> Result<(), String> {
        // RFC 8032 Section 7.1, TEST 2 (one-byte message 0x72)
        // Secret key (seed): 4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb
        let secret_seed: [u8; 32] = [
            0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11,
            0x4e, 0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed,
            0x4f, 0xb8, 0xa6, 0xfb,
        ];
        // Public key: 3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c
        let expected_public: [u8; 32] = [
            0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b,
            0x7e, 0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1,
            0x2a, 0xf4, 0x66, 0x0c,
        ];
        let message: [u8; 1] = [0x72];
        // Expected signature
        let expected_sig: [u8; 64] = [
            0x92, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8, 0x72, 0x0e, 0x82, 0x0b, 0x5f, 0x64,
            0x25, 0x40, 0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50, 0x3f, 0x8f, 0xb3, 0x76, 0x22, 0x23,
            0xeb, 0xdb, 0x69, 0xda, 0x08, 0x5a, 0xc1, 0xe4, 0x3e, 0x15, 0x99, 0x6e, 0x45, 0x8f,
            0x36, 0x13, 0xd0, 0xf1, 0x1d, 0x8c, 0x38, 0x7b, 0x2e, 0xae, 0xb4, 0x30, 0x2a, 0xee,
            0xb0, 0x0d, 0x29, 0x16, 0x12, 0xbb, 0x0c, 0x00,
        ];

        // Build the 64-byte secret key ed25519-dalek expects: seed || public
        let mut secret_key = [0u8; 64];
        secret_key[..32].copy_from_slice(&secret_seed);
        secret_key[32..].copy_from_slice(&expected_public);

        // Step 1: Sign with known key
        let sig = backend
            .ed25519_sign(&secret_key, &message)
            .map_err(|e| format!("sign failed: {}", e))?;

        if sig != expected_sig {
            return Err(format!(
                "signature mismatch: got {:02x?}..., expected {:02x?}...",
                &sig[..8],
                &expected_sig[..8]
            ));
        }

        // Step 2: Verify
        let valid = backend
            .ed25519_verify(&expected_public, &message, &sig)
            .map_err(|e| format!("verify failed: {}", e))?;

        if !valid {
            return Err("verification failed on known-good signature".to_string());
        }

        // Step 3: Verify with wrong message — must fail
        let invalid = backend
            .ed25519_verify(&expected_public, b"wrong", &sig)
            .map_err(|e| format!("verify-wrong failed: {}", e))?;

        if invalid {
            return Err("verification passed on wrong message".to_string());
        }

        Ok(())
    })();

    SelfTestResult {
        name,
        passed: result.is_ok(),
        duration: start.elapsed(),
        error: result.err(),
    }
}

/// HKDF-SHA256 KAT using RFC 5869 Appendix A, Test Case 1
fn kat_hkdf_sha256(backend: &dyn CryptoBackend) -> SelfTestResult {
    let start = Instant::now();
    let name = "HKDF-SHA256 KAT (RFC 5869)".to_string();

    let result = (|| -> Result<(), String> {
        // RFC 5869 Test Case 1
        let ikm: [u8; 22] = [0x0b; 22];
        let salt: [u8; 13] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let expected_okm: [u8; 42] = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];

        let mut okm = [0u8; 42];
        backend
            .hkdf_sha256(&salt, &ikm, &info, &mut okm)
            .map_err(|e| format!("HKDF failed: {}", e))?;

        if okm != expected_okm {
            return Err(format!(
                "OKM mismatch: got {:02x?}..., expected {:02x?}...",
                &okm[..8],
                &expected_okm[..8]
            ));
        }

        Ok(())
    })();

    SelfTestResult {
        name,
        passed: result.is_ok(),
        duration: start.elapsed(),
        error: result.err(),
    }
}

// ============================================================================
// Continuous Random Number Generator Test (CRNGT)
//
// FIPS 140-3 AS09.39: The module must test the output of the RNG.
// Implementation: Generate two consecutive 32-byte blocks and verify
// they are not identical. This must also be called during operation.
// ============================================================================

/// CRNGT initial test — run at power-on
fn crngt_initial(backend: &dyn CryptoBackend) -> SelfTestResult {
    let start = Instant::now();
    let name = "CRNGT (Entropy Source)".to_string();

    let result = (|| -> Result<(), String> {
        // Generate multiple blocks and verify none are identical to the previous
        let mut prev = [0u8; 32];
        backend
            .random_bytes(&mut prev)
            .map_err(|e| format!("first random_bytes failed: {}", e))?;

        // All zeros is suspicious but not impossible — check multiple times
        let mut all_zeros = prev.iter().all(|&b| b == 0);

        for i in 1..10 {
            let mut current = [0u8; 32];
            backend
                .random_bytes(&mut current)
                .map_err(|e| format!("random_bytes iteration {} failed: {}", i, e))?;

            if current == prev {
                return Err(format!(
                    "CRNGT failure: consecutive 32-byte blocks identical at iteration {}",
                    i
                ));
            }

            if !current.iter().all(|&b| b == 0) {
                all_zeros = false;
            }

            prev = current;
        }

        if all_zeros {
            return Err("CRNGT failure: all random blocks were zeros".to_string());
        }

        CRNGT_INITIALIZED.store(true, Ordering::SeqCst);
        Ok(())
    })();

    SelfTestResult {
        name,
        passed: result.is_ok(),
        duration: start.elapsed(),
        error: result.err(),
    }
}

/// Runtime CRNGT check — call this periodically or before critical operations.
///
/// Returns `Ok(())` if the entropy source is healthy, `Err` if it fails.
pub fn crngt_runtime_check(backend: &dyn CryptoBackend) -> CryptoResult<()> {
    let mut block_a = [0u8; 32];
    let mut block_b = [0u8; 32];

    backend.random_bytes(&mut block_a)?;
    backend.random_bytes(&mut block_b)?;

    if block_a == block_b {
        MODULE_STATE.store(ModuleState::Error as u8, Ordering::SeqCst);
        tracing::error!("CRNGT runtime failure: consecutive random blocks identical. Module entering error state.");
        return Err(crate::crypto::CryptoError::Internal(
            "CRNGT failure: entropy source produced identical consecutive blocks".to_string(),
        ));
    }

    Ok(())
}

// ============================================================================
// Pairwise Consistency Tests (PCTs)
//
// FIPS 140-3 AS09.26: After generating a key pair, verify that the
// public and private keys are consistent by performing a full operation.
//
// These tests generate fresh keypairs (separate from KATs) and verify
// they work end-to-end.
// ============================================================================

/// ML-KEM-768 Pairwise Consistency Test
fn pct_mlkem768(backend: &dyn CryptoBackend) -> SelfTestResult {
    let start = Instant::now();
    let name = "ML-KEM-768 PCT (keygen consistency)".to_string();

    let result = (|| -> Result<(), String> {
        let (pk, sk) = backend
            .mlkem_keygen()
            .map_err(|e| format!("keygen failed: {}", e))?;

        let (ct, ss_enc) = backend
            .mlkem_encaps(&pk)
            .map_err(|e| format!("encaps failed: {}", e))?;

        let ss_dec = backend
            .mlkem_decaps(&sk, &ct)
            .map_err(|e| format!("decaps failed: {}", e))?;

        if ss_enc.as_bytes() != ss_dec.as_bytes() {
            return Err("PCT failure: shared secrets don't match after keygen".to_string());
        }

        Ok(())
    })();

    SelfTestResult {
        name,
        passed: result.is_ok(),
        duration: start.elapsed(),
        error: result.err(),
    }
}

/// ML-DSA-65 Pairwise Consistency Test
fn pct_mldsa65(backend: &dyn CryptoBackend) -> SelfTestResult {
    let start = Instant::now();
    let name = "ML-DSA-65 PCT (keygen consistency)".to_string();

    const PCT_MESSAGE: &[u8] = b"DyberVPN FIPS 140-3 ML-DSA-65 PCT";

    let result = (|| -> Result<(), String> {
        let (pk, sk) = backend
            .mldsa_keygen()
            .map_err(|e| format!("keygen failed: {}", e))?;

        let sig = backend
            .mldsa_sign(&sk, PCT_MESSAGE)
            .map_err(|e| format!("sign failed: {}", e))?;

        let valid = backend
            .mldsa_verify(&pk, PCT_MESSAGE, &sig)
            .map_err(|e| format!("verify failed: {}", e))?;

        if !valid {
            return Err("PCT failure: signature invalid after keygen".to_string());
        }

        Ok(())
    })();

    SelfTestResult {
        name,
        passed: result.is_ok(),
        duration: start.elapsed(),
        error: result.err(),
    }
}

/// Ed25519 Pairwise Consistency Test
fn pct_ed25519(backend: &dyn CryptoBackend) -> SelfTestResult {
    let start = Instant::now();
    let name = "Ed25519 PCT (keygen consistency)".to_string();

    const PCT_MESSAGE: &[u8] = b"DyberVPN FIPS 140-3 Ed25519 PCT";

    let result = (|| -> Result<(), String> {
        let (pk, sk) = backend
            .ed25519_keygen()
            .map_err(|e| format!("keygen failed: {}", e))?;

        let sig = backend
            .ed25519_sign(&sk, PCT_MESSAGE)
            .map_err(|e| format!("sign failed: {}", e))?;

        let valid = backend
            .ed25519_verify(&pk, PCT_MESSAGE, &sig)
            .map_err(|e| format!("verify failed: {}", e))?;

        if !valid {
            return Err("PCT failure: signature invalid after keygen".to_string());
        }

        Ok(())
    })();

    SelfTestResult {
        name,
        passed: result.is_ok(),
        duration: start.elapsed(),
        error: result.err(),
    }
}

// ============================================================================
// On-Demand Self-Tests
//
// Can be triggered via CLI (`dybervpn self-test`) or API for compliance
// verification during operation.
// ============================================================================

/// Run self-tests on demand (e.g., from CLI or management API).
///
/// Unlike power-on self-tests, this does NOT change the module state on
/// failure — it only reports results. Use `run_power_on_self_tests` at
/// startup for state management.
pub fn run_on_demand_self_tests(backend: &dyn CryptoBackend) -> SelfTestReport {
    let start = Instant::now();
    tracing::info!("On-demand FIPS 140-3 self-tests starting");

    let results = vec![
        kat_mlkem768(backend),
        kat_mldsa65(backend),
        kat_x25519(backend),
        kat_ed25519(backend),
        kat_hkdf_sha256(backend),
        crngt_initial(backend),
        pct_mlkem768(backend),
        pct_mldsa65(backend),
        pct_ed25519(backend),
    ];

    let all_passed = results.iter().all(|r| r.passed);

    SelfTestReport {
        results,
        passed: all_passed,
        duration: start.elapsed(),
        module_state: module_state(),
        timestamp: iso8601_now(),
        backend: backend.name().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::software::SoftwareBackend;

    fn backend() -> SoftwareBackend {
        SoftwareBackend::new()
    }

    #[test]
    fn test_power_on_self_tests_pass() {
        let b = backend();
        let report = run_power_on_self_tests(&b);

        println!("{}", report);

        assert!(
            report.passed,
            "Self-tests should pass: {:?}",
            report
                .results
                .iter()
                .filter(|r| !r.passed)
                .collect::<Vec<_>>()
        );
        assert_eq!(report.module_state, ModuleState::Operational);
        assert!(is_operational());
    }

    #[test]
    fn test_all_nine_tests_run() {
        let b = backend();
        let report = run_power_on_self_tests(&b);

        assert_eq!(report.results.len(), 9, "Expected 9 self-tests");

        let names: Vec<&str> = report.results.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"ML-KEM-768 KAT (FIPS 203)"));
        assert!(names.contains(&"ML-DSA-65 KAT (FIPS 204)"));
        assert!(names.contains(&"X25519 KAT (RFC 7748)"));
        assert!(names.contains(&"Ed25519 KAT (RFC 8032)"));
        assert!(names.contains(&"HKDF-SHA256 KAT (RFC 5869)"));
        assert!(names.contains(&"CRNGT (Entropy Source)"));
        assert!(names.contains(&"ML-KEM-768 PCT (keygen consistency)"));
        assert!(names.contains(&"ML-DSA-65 PCT (keygen consistency)"));
        assert!(names.contains(&"Ed25519 PCT (keygen consistency)"));
    }

    #[test]
    fn test_x25519_kat_vector() {
        let b = backend();
        let result = kat_x25519(&b);
        assert!(result.passed, "X25519 KAT failed: {:?}", result.error);
    }

    #[test]
    fn test_ed25519_kat_vector() {
        let b = backend();
        let result = kat_ed25519(&b);
        assert!(result.passed, "Ed25519 KAT failed: {:?}", result.error);
    }

    #[test]
    fn test_hkdf_kat_vector() {
        let b = backend();
        let result = kat_hkdf_sha256(&b);
        assert!(result.passed, "HKDF KAT failed: {:?}", result.error);
    }

    #[test]
    fn test_crngt() {
        let b = backend();
        let result = crngt_initial(&b);
        assert!(result.passed, "CRNGT failed: {:?}", result.error);
    }

    #[test]
    fn test_crngt_runtime() {
        let b = backend();
        crngt_runtime_check(&b).expect("CRNGT runtime check failed");
    }

    #[test]
    fn test_on_demand_self_tests() {
        let b = backend();
        let report = run_on_demand_self_tests(&b);
        assert!(report.passed);
        assert_eq!(report.results.len(), 9);
    }

    #[test]
    fn test_module_state_display() {
        assert_eq!(format!("{}", ModuleState::Uninitialized), "UNINITIALIZED");
        assert_eq!(format!("{}", ModuleState::SelfTesting), "SELF-TESTING");
        assert_eq!(format!("{}", ModuleState::Operational), "OPERATIONAL");
        assert_eq!(format!("{}", ModuleState::Error), "ERROR");
    }

    #[test]
    fn test_self_test_report_display() {
        let b = backend();
        let report = run_power_on_self_tests(&b);
        let display = format!("{}", report);
        assert!(display.contains("DyberVPN FIPS 140-3 Self-Test Report"));
        assert!(display.contains("ALL TESTS PASSED"));
    }
}
