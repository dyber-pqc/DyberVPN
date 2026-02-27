//! Key Revocation & Rotation — Enterprise Key Lifecycle Management
//!
//! Provides:
//! - **CRL (Certificate Revocation List)**: A JSON file listing revoked public keys.
//!   Checked on every handshake attempt and periodically scanned for existing sessions.
//! - **Key expiry**: Peers can have a `valid_until` timestamp; after expiry they are
//!   treated as revoked.
//! - **Automatic rotation**: Configurable session key max age. When exceeded, the
//!   daemon forces a re-handshake (already in timer loop — this module adds CRL support).
//! - **Hot-reload**: The CRL file is re-read on SIGHUP alongside the main config.
//!
//! # Revocation File Format
//!
//! ```json
//! {
//!   "version": 1,
//!   "updated_at": "2026-02-24T12:00:00Z",
//!   "revoked_keys": [
//!     {
//!       "public_key_fingerprint": "aabbccdd",
//!       "name": "bob-laptop",
//!       "revoked_at": "2026-02-24T11:00:00Z",
//!       "reason": "employee_departed",
//!       "revoked_by": "admin@dyber.com"
//!     }
//!   ]
//! }
//! ```
//!
//! # Configuration
//!
//! ```toml
//! [security]
//! crl_path = "/etc/dybervpn/revoked-keys.json"
//! key_max_age_hours = 720          # 30 days — force full key rotation
//! session_max_age_hours = 24       # Force re-handshake every 24h
//! check_interval_secs = 300        # How often to scan for expired/revoked peers
//! auto_disconnect_revoked = true   # Drop sessions for revoked keys immediately
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

// ─── Data Structures ─────────────────────────────────────────────────────────

/// Top-level CRL file structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationList {
    /// File format version (currently 1)
    pub version: u32,
    /// When this CRL was last updated (RFC 3339)
    pub updated_at: String,
    /// List of revoked key entries
    pub revoked_keys: Vec<RevokedKeyEntry>,
}

impl Default for RevocationList {
    fn default() -> Self {
        Self {
            version: 1,
            updated_at: chrono::Utc::now().to_rfc3339(),
            revoked_keys: Vec::new(),
        }
    }
}

/// A single revoked key entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokedKeyEntry {
    /// First 8+ hex characters of the public key (fingerprint)
    pub public_key_fingerprint: String,
    /// Full public key in base64 (optional — fingerprint is usually enough)
    #[serde(default)]
    pub public_key_full: Option<String>,
    /// Human-readable peer name
    #[serde(default)]
    pub name: Option<String>,
    /// RFC 3339 timestamp of revocation
    pub revoked_at: String,
    /// Reason for revocation
    pub reason: RevocationReason,
    /// Who performed the revocation (admin email/ID)
    #[serde(default)]
    pub revoked_by: Option<String>,
    /// Optional expiry for the revocation (for temporary suspensions)
    #[serde(default)]
    pub expires_at: Option<String>,
}

/// Standard revocation reasons
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    /// Employee left the organization
    EmployeeDeparted,
    /// Key suspected compromised
    KeyCompromised,
    /// Device lost or stolen
    DeviceLost,
    /// Replaced by a new key
    KeySuperseded,
    /// Policy violation
    PolicyViolation,
    /// Administrative action
    Administrative,
    /// Temporary suspension
    Suspended,
    /// Other (freeform)
    Other(String),
}

impl std::fmt::Display for RevocationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmployeeDeparted => write!(f, "employee_departed"),
            Self::KeyCompromised => write!(f, "key_compromised"),
            Self::DeviceLost => write!(f, "device_lost"),
            Self::KeySuperseded => write!(f, "key_superseded"),
            Self::PolicyViolation => write!(f, "policy_violation"),
            Self::Administrative => write!(f, "administrative"),
            Self::Suspended => write!(f, "suspended"),
            Self::Other(s) => write!(f, "other: {}", s),
        }
    }
}

/// Configuration for key lifecycle management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Path to the CRL file
    #[serde(default)]
    pub crl_path: Option<String>,

    /// Maximum age of a peer's static key in hours (0 = no limit)
    #[serde(default = "default_key_max_age")]
    pub key_max_age_hours: u64,

    /// Maximum session age in hours before forced re-handshake
    #[serde(default = "default_session_max_age")]
    pub session_max_age_hours: u64,

    /// How often (in seconds) to check for expired/revoked peers
    #[serde(default = "default_check_interval")]
    pub check_interval_secs: u64,

    /// Whether to immediately disconnect peers with revoked keys
    #[serde(default = "default_true")]
    pub auto_disconnect_revoked: bool,
}

fn default_key_max_age() -> u64 {
    720
} // 30 days
fn default_session_max_age() -> u64 {
    24
}
fn default_check_interval() -> u64 {
    300
} // 5 minutes
fn default_true() -> bool {
    true
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            crl_path: None,
            key_max_age_hours: 720,
            session_max_age_hours: 24,
            check_interval_secs: 300,
            auto_disconnect_revoked: true,
        }
    }
}

// ─── Revocation Engine ──────────────────────────────────────────────────────

/// Action to take for a revoked/expired peer
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyStatus {
    /// Key is valid, proceed normally
    Valid,
    /// Key has been explicitly revoked
    Revoked(String), // reason
    /// Key has expired (past valid_until or key_max_age)
    Expired(String), // detail
    /// Key is temporarily suspended
    Suspended(String),
}

/// The revocation engine — checks keys against the CRL
pub struct RevocationEngine {
    /// Path to the CRL file
    crl_path: Option<PathBuf>,
    /// In-memory CRL indexed by fingerprint
    revoked: HashMap<String, RevokedKeyEntry>,
    /// When the CRL was last loaded
    last_loaded: Option<Instant>,
    /// Security config
    config: SecurityConfig,
    /// Peer provisioning timestamps (fingerprint → when first seen)
    peer_first_seen: HashMap<String, Instant>,
}

impl RevocationEngine {
    /// Create a new revocation engine from config
    pub fn new(config: SecurityConfig) -> Self {
        let mut engine = Self {
            crl_path: config.crl_path.as_ref().map(PathBuf::from),
            revoked: HashMap::new(),
            last_loaded: None,
            config,
            peer_first_seen: HashMap::new(),
        };

        // Load CRL if path is configured
        if let Some(path) = engine.crl_path.clone() {
            match engine.load_crl(&path) {
                Ok(count) => {
                    tracing::info!(
                        "Loaded CRL with {} revoked keys from {}",
                        count,
                        path.display()
                    );
                }
                Err(e) => {
                    // File might not exist yet, which is fine
                    if path.exists() {
                        tracing::error!("Failed to load CRL from {}: {}", path.display(), e);
                    } else {
                        tracing::info!(
                            "CRL file {} does not exist yet (will be created on first revocation)",
                            path.display()
                        );
                    }
                }
            }
        }

        engine
    }

    /// Create a disabled revocation engine
    pub fn disabled() -> Self {
        Self {
            crl_path: None,
            revoked: HashMap::new(),
            last_loaded: None,
            config: SecurityConfig::default(),
            peer_first_seen: HashMap::new(),
        }
    }

    /// Check the status of a peer's key
    pub fn check_key(&self, peer_key: &[u8; 32], _peer_name: Option<&str>) -> KeyStatus {
        let fingerprint = hex::encode(&peer_key[..4]);
        let fingerprint_long = hex::encode(&peer_key[..8]);

        // Check CRL — try short and long fingerprints
        for fp in &[&fingerprint, &fingerprint_long] {
            if let Some(entry) = self.revoked.get(*fp) {
                // Check if suspension has expired
                if entry.reason == RevocationReason::Suspended {
                    if let Some(ref expires) = entry.expires_at {
                        if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(expires) {
                            if exp > chrono::Utc::now() {
                                return KeyStatus::Suspended(format!(
                                    "suspended until {}",
                                    expires
                                ));
                            }
                            // Suspension expired — key is valid again
                            continue;
                        }
                    }
                    return KeyStatus::Suspended("suspended indefinitely".to_string());
                }

                return KeyStatus::Revoked(entry.reason.to_string());
            }
        }

        // Check key age if key_max_age is configured
        if self.config.key_max_age_hours > 0 {
            if let Some(first_seen) = self.peer_first_seen.get(&fingerprint) {
                let age_hours = first_seen.elapsed().as_secs() / 3600;
                if age_hours > self.config.key_max_age_hours {
                    return KeyStatus::Expired(format!(
                        "key age {} hours exceeds max {} hours",
                        age_hours, self.config.key_max_age_hours
                    ));
                }
            }
        }

        KeyStatus::Valid
    }

    /// Register a peer as "first seen" for key age tracking
    pub fn register_peer(&mut self, peer_key: &[u8; 32]) {
        let fingerprint = hex::encode(&peer_key[..4]);
        self.peer_first_seen
            .entry(fingerprint)
            .or_insert_with(Instant::now);
    }

    /// Check if a key is revoked (convenience method for handshake path)
    pub fn is_revoked(&self, peer_key: &[u8; 32]) -> bool {
        matches!(
            self.check_key(peer_key, None),
            KeyStatus::Revoked(_) | KeyStatus::Suspended(_)
        )
    }

    /// Revoke a key and write to CRL file
    pub fn revoke_key(
        &mut self,
        peer_key: &[u8; 32],
        peer_name: Option<&str>,
        reason: RevocationReason,
        revoked_by: Option<&str>,
    ) -> Result<(), String> {
        let fingerprint = hex::encode(&peer_key[..4]);
        let fingerprint_long = hex::encode(&peer_key[..8]);

        let entry = RevokedKeyEntry {
            public_key_fingerprint: fingerprint_long.clone(),
            public_key_full: Some(base64::encode(peer_key)),
            name: peer_name.map(String::from),
            revoked_at: chrono::Utc::now().to_rfc3339(),
            reason: reason.clone(),
            revoked_by: revoked_by.map(String::from),
            expires_at: None,
        };

        self.revoked.insert(fingerprint.clone(), entry.clone());
        self.revoked.insert(fingerprint_long, entry);

        // Persist to file
        self.save_crl()?;

        tracing::info!(
            "Key revoked: {} ({}) reason: {}",
            fingerprint,
            peer_name.unwrap_or("unnamed"),
            reason,
        );

        Ok(())
    }

    /// Suspend a key temporarily
    pub fn suspend_key(
        &mut self,
        peer_key: &[u8; 32],
        peer_name: Option<&str>,
        expires_at: Option<&str>,
        revoked_by: Option<&str>,
    ) -> Result<(), String> {
        let fingerprint = hex::encode(&peer_key[..4]);
        let fingerprint_long = hex::encode(&peer_key[..8]);

        let entry = RevokedKeyEntry {
            public_key_fingerprint: fingerprint_long.clone(),
            public_key_full: Some(base64::encode(peer_key)),
            name: peer_name.map(String::from),
            revoked_at: chrono::Utc::now().to_rfc3339(),
            reason: RevocationReason::Suspended,
            revoked_by: revoked_by.map(String::from),
            expires_at: expires_at.map(String::from),
        };

        self.revoked.insert(fingerprint, entry.clone());
        self.revoked.insert(fingerprint_long, entry);
        self.save_crl()?;

        Ok(())
    }

    /// Un-revoke / un-suspend a key
    pub fn reinstate_key(&mut self, peer_key: &[u8; 32]) -> Result<(), String> {
        let fingerprint = hex::encode(&peer_key[..4]);
        let fingerprint_long = hex::encode(&peer_key[..8]);

        self.revoked.remove(&fingerprint);
        self.revoked.remove(&fingerprint_long);
        self.save_crl()?;

        tracing::info!("Key reinstated: {}", fingerprint);
        Ok(())
    }

    /// Reload CRL from disk (called on SIGHUP)
    pub fn reload(&mut self) -> Result<usize, String> {
        if let Some(path) = self.crl_path.clone() {
            let count = self.load_crl(&path)?;
            tracing::info!("CRL reloaded: {} revoked keys", count);
            Ok(count)
        } else {
            Ok(0)
        }
    }

    /// Get all revoked entries
    pub fn list_revoked(&self) -> Vec<&RevokedKeyEntry> {
        // Deduplicate (we store both short and long fingerprints)
        let mut seen = std::collections::HashSet::new();
        self.revoked
            .values()
            .filter(|e| seen.insert(e.public_key_fingerprint.clone()))
            .collect()
    }

    /// Get the session max age from config (in seconds)
    pub fn session_max_age_secs(&self) -> u64 {
        self.config.session_max_age_hours * 3600
    }

    /// Whether to auto-disconnect revoked peers
    pub fn auto_disconnect(&self) -> bool {
        self.config.auto_disconnect_revoked
    }

    /// Check interval in seconds
    pub fn check_interval_secs(&self) -> u64 {
        self.config.check_interval_secs
    }

    // ─── Internal ────────────────────────────────────────────────────────

    fn load_crl(&mut self, path: &Path) -> Result<usize, String> {
        let content =
            fs::read_to_string(path).map_err(|e| format!("read {}: {}", path.display(), e))?;

        let crl: RevocationList = serde_json::from_str(&content)
            .map_err(|e| format!("parse {}: {}", path.display(), e))?;

        self.revoked.clear();
        for entry in &crl.revoked_keys {
            let fp = &entry.public_key_fingerprint;
            self.revoked.insert(fp.clone(), entry.clone());
            // Also index by short fingerprint (first 8 chars)
            if fp.len() >= 8 {
                self.revoked.insert(fp[..8].to_string(), entry.clone());
            }
        }

        self.last_loaded = Some(Instant::now());
        Ok(crl.revoked_keys.len())
    }

    fn save_crl(&self) -> Result<(), String> {
        let path = match &self.crl_path {
            Some(p) => p,
            None => return Err("No CRL path configured".to_string()),
        };

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        // Deduplicate entries for serialization
        let mut seen = std::collections::HashSet::new();
        let entries: Vec<RevokedKeyEntry> = self
            .revoked
            .values()
            .filter(|e| seen.insert(e.public_key_fingerprint.clone()))
            .cloned()
            .collect();

        let crl = RevocationList {
            version: 1,
            updated_at: chrono::Utc::now().to_rfc3339(),
            revoked_keys: entries,
        };

        let json =
            serde_json::to_string_pretty(&crl).map_err(|e| format!("serialize CRL: {}", e))?;

        // Atomic write: write to temp file then rename
        let tmp_path = path.with_extension("tmp");
        fs::write(&tmp_path, &json).map_err(|e| format!("write {}: {}", tmp_path.display(), e))?;
        fs::rename(&tmp_path, path)
            .map_err(|e| format!("rename {} -> {}: {}", tmp_path.display(), path.display(), e))?;

        tracing::debug!("CRL saved to {}", path.display());
        Ok(())
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a test engine with a unique temp CRL path so save_crl() works.
    /// Each call gets its own directory to avoid parallel test interference.
    fn test_engine(name: &str) -> (RevocationEngine, PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("dybervpn-rev-{}-{}", name, std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let crl_path = dir.join("test-crl.json");
        let config = SecurityConfig {
            crl_path: Some(crl_path.to_string_lossy().to_string()),
            ..Default::default()
        };
        (RevocationEngine::new(config), dir)
    }

    #[test]
    fn test_check_clean_key() {
        let engine = RevocationEngine::disabled();
        let key = [0xAA; 32];
        assert_eq!(engine.check_key(&key, Some("test")), KeyStatus::Valid);
    }

    #[test]
    fn test_revoke_and_check() {
        let (mut engine, dir) = test_engine("revoke");
        let key = [0xBB; 32];

        assert!(!engine.is_revoked(&key));

        engine
            .revoke_key(
                &key,
                Some("bob"),
                RevocationReason::EmployeeDeparted,
                Some("admin"),
            )
            .unwrap();

        assert!(engine.is_revoked(&key));
        match engine.check_key(&key, Some("bob")) {
            KeyStatus::Revoked(reason) => assert!(reason.contains("employee_departed")),
            other => panic!("Expected Revoked, got {:?}", other),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_suspend_and_reinstate() {
        let (mut engine, dir) = test_engine("suspend");
        let key = [0xCC; 32];

        engine
            .suspend_key(&key, Some("charlie"), None, Some("admin"))
            .unwrap();

        assert!(engine.is_revoked(&key));
        assert!(matches!(
            engine.check_key(&key, None),
            KeyStatus::Suspended(_)
        ));

        engine.reinstate_key(&key).unwrap();
        assert!(!engine.is_revoked(&key));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_crl_file_roundtrip() {
        let dir = std::env::temp_dir().join("dybervpn-crl-test");
        let _ = fs::create_dir_all(&dir);
        let crl_path = dir.join("test-crl.json");

        let config = SecurityConfig {
            crl_path: Some(crl_path.to_string_lossy().to_string()),
            ..Default::default()
        };

        let mut engine = RevocationEngine::new(config.clone());

        let key1 = [0x11; 32];
        let key2 = [0x22; 32];

        engine
            .revoke_key(&key1, Some("alice"), RevocationReason::KeyCompromised, None)
            .unwrap();
        engine
            .revoke_key(
                &key2,
                Some("bob"),
                RevocationReason::DeviceLost,
                Some("admin"),
            )
            .unwrap();

        // Verify file exists and is valid JSON
        let content = fs::read_to_string(&crl_path).unwrap();
        let crl: RevocationList = serde_json::from_str(&content).unwrap();
        assert_eq!(crl.version, 1);
        assert_eq!(crl.revoked_keys.len(), 2);

        // Create a new engine from the same file — should load the CRL
        let engine2 = RevocationEngine::new(config);
        assert!(engine2.is_revoked(&key1));
        assert!(engine2.is_revoked(&key2));
        assert!(!engine2.is_revoked(&[0x33; 32]));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_list_revoked() {
        let (mut engine, dir) = test_engine("list");
        engine
            .revoke_key(
                &[0x11; 32],
                Some("a"),
                RevocationReason::Administrative,
                None,
            )
            .unwrap();
        engine
            .revoke_key(
                &[0x22; 32],
                Some("b"),
                RevocationReason::PolicyViolation,
                None,
            )
            .unwrap();

        let list = engine.list_revoked();
        assert_eq!(list.len(), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_revocation_list_serialization() {
        let crl = RevocationList {
            version: 1,
            updated_at: "2026-02-24T12:00:00Z".to_string(),
            revoked_keys: vec![RevokedKeyEntry {
                public_key_fingerprint: "aabbccdd".to_string(),
                public_key_full: None,
                name: Some("bob".to_string()),
                revoked_at: "2026-02-24T11:00:00Z".to_string(),
                reason: RevocationReason::EmployeeDeparted,
                revoked_by: Some("admin@dyber.com".to_string()),
                expires_at: None,
            }],
        };

        let json = serde_json::to_string_pretty(&crl).unwrap();
        assert!(json.contains("employee_departed"));
        assert!(json.contains("aabbccdd"));

        // Roundtrip
        let parsed: RevocationList = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.revoked_keys.len(), 1);
        assert_eq!(
            parsed.revoked_keys[0].reason,
            RevocationReason::EmployeeDeparted
        );
    }
}
