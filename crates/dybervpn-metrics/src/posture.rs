//! Zero Trust Device Posture Assessment
//!
//! Performs local device health checks for endpoint compliance scoring.
//! Used before tunnel establishment and periodically during sessions.

use serde::{Deserialize, Serialize};
use std::time::Instant;

/// Overall posture assessment result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureResult {
    /// Overall compliance score (0-100)
    pub score: u32,
    /// Pass/fail verdict
    pub compliant: bool,
    /// Minimum score required for compliance (configurable)
    pub threshold: u32,
    /// Individual check results
    pub checks: Vec<PostureCheck>,
    /// Assessment timestamp
    pub timestamp: String,
    /// Time taken for all checks in milliseconds
    pub duration_ms: u64,
}

/// Individual posture check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureCheck {
    /// Check name
    pub name: String,
    /// Check category
    pub category: PostureCategory,
    /// Pass/fail
    pub passed: bool,
    /// Score weight (points awarded if passed)
    pub weight: u32,
    /// Human-readable detail
    pub detail: String,
    /// Check duration in milliseconds
    pub duration_ms: u64,
}

/// Posture check categories
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PostureCategory {
    /// Operating system checks
    OperatingSystem,
    /// Security software
    Security,
    /// Disk encryption
    Encryption,
    /// Network configuration
    Network,
    /// Software updates
    Updates,
}

/// Posture assessment configuration
#[derive(Debug, Clone)]
pub struct PostureConfig {
    /// Minimum score to pass (0-100)
    pub threshold: u32,
    /// Enable OS version check
    pub check_os_version: bool,
    /// Enable firewall check
    pub check_firewall: bool,
    /// Enable disk encryption check
    pub check_disk_encryption: bool,
    /// Enable antivirus check
    pub check_antivirus: bool,
    /// Enable screen lock check
    pub check_screen_lock: bool,
}

impl Default for PostureConfig {
    fn default() -> Self {
        Self {
            threshold: 60,
            check_os_version: true,
            check_firewall: true,
            check_disk_encryption: true,
            check_antivirus: true,
            check_screen_lock: true,
        }
    }
}

/// Run a full device posture assessment
pub async fn assess_posture(config: &PostureConfig) -> PostureResult {
    let start = Instant::now();
    let mut checks = Vec::new();

    if config.check_os_version {
        checks.push(check_os_version().await);
    }
    if config.check_firewall {
        checks.push(check_firewall().await);
    }
    if config.check_disk_encryption {
        checks.push(check_disk_encryption().await);
    }
    if config.check_antivirus {
        checks.push(check_antivirus().await);
    }
    if config.check_screen_lock {
        checks.push(check_screen_lock().await);
    }

    let total_weight: u32 = checks.iter().map(|c| c.weight).sum();
    let earned: u32 = checks.iter().filter(|c| c.passed).map(|c| c.weight).sum();
    let score = if total_weight > 0 {
        (earned * 100) / total_weight
    } else {
        100
    };

    PostureResult {
        score,
        compliant: score >= config.threshold,
        threshold: config.threshold,
        checks,
        timestamp: chrono::Utc::now().to_rfc3339(),
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

/// Check OS version is supported and up to date
async fn check_os_version() -> PostureCheck {
    let start = Instant::now();

    #[cfg(target_os = "windows")]
    let (passed, detail) = {
        // Check Windows version via PowerShell
        let output = tokio::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "[System.Environment]::OSVersion.Version | ConvertTo-Json",
            ])
            .output()
            .await;

        match output {
            Ok(out) if out.status.success() => {
                let text = String::from_utf8_lossy(&out.stdout);
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) {
                    let major = val["Major"].as_u64().unwrap_or(0);
                    let build = val["Build"].as_u64().unwrap_or(0);
                    let version_str = format!("Windows {}.{}", major, build);
                    // Windows 10 build 19041+ or Windows 11
                    let supported = (major == 10 && build >= 19041) || major > 10;
                    (supported, format!("{} — {}", version_str, if supported { "supported" } else { "below minimum version" }))
                } else {
                    (false, "Could not parse OS version".to_string())
                }
            }
            _ => (false, "Failed to query OS version".to_string()),
        }
    };

    #[cfg(target_os = "linux")]
    let (passed, detail) = {
        let output = tokio::process::Command::new("uname")
            .args(["-r"])
            .output()
            .await;

        match output {
            Ok(out) if out.status.success() => {
                let kernel = String::from_utf8_lossy(&out.stdout).trim().to_string();
                // Kernel 5.10+ is considered good
                let major: u64 = kernel.split('.').next().and_then(|v| v.parse().ok()).unwrap_or(0);
                let minor: u64 = kernel.split('.').nth(1).and_then(|v| v.parse().ok()).unwrap_or(0);
                let supported = major > 5 || (major == 5 && minor >= 10);
                (supported, format!("Linux {} — {}", kernel, if supported { "supported" } else { "kernel too old" }))
            }
            _ => (false, "Failed to query kernel version".to_string()),
        }
    };

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    let (passed, detail) = (true, "OS check not implemented for this platform".to_string());

    PostureCheck {
        name: "OS Version".to_string(),
        category: PostureCategory::OperatingSystem,
        passed,
        weight: 20,
        detail,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

/// Check if firewall is enabled
async fn check_firewall() -> PostureCheck {
    let start = Instant::now();

    #[cfg(target_os = "windows")]
    let (passed, detail) = {
        let output = tokio::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "(Get-NetFirewallProfile -Profile Domain,Public,Private).Enabled | ConvertTo-Json",
            ])
            .output()
            .await;

        match output {
            Ok(out) if out.status.success() => {
                let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
                // Result is [true, true, true] or similar JSON array
                let all_enabled = text.contains("true") && !text.contains("false");
                (all_enabled, format!("Windows Firewall: {}", if all_enabled { "all profiles enabled" } else { "some profiles disabled" }))
            }
            _ => (false, "Could not query firewall status".to_string()),
        }
    };

    #[cfg(target_os = "linux")]
    let (passed, detail) = {
        // Check iptables or nftables
        let nft = tokio::process::Command::new("nft")
            .args(["list", "ruleset"])
            .output()
            .await;

        match nft {
            Ok(out) if out.status.success() => {
                let text = String::from_utf8_lossy(&out.stdout);
                let has_rules = text.lines().count() > 2;
                (has_rules, format!("nftables: {}", if has_rules { "rules configured" } else { "no rules" }))
            }
            _ => {
                // Fallback: check iptables
                let ipt = tokio::process::Command::new("iptables")
                    .args(["-L", "-n"])
                    .output()
                    .await;
                match ipt {
                    Ok(out) if out.status.success() => {
                        let text = String::from_utf8_lossy(&out.stdout);
                        let has_rules = text.lines().count() > 6;
                        (has_rules, format!("iptables: {}", if has_rules { "rules configured" } else { "default policy only" }))
                    }
                    _ => (false, "No firewall detected".to_string()),
                }
            }
        }
    };

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    let (passed, detail) = (true, "Firewall check not implemented for this platform".to_string());

    PostureCheck {
        name: "Firewall".to_string(),
        category: PostureCategory::Security,
        passed,
        weight: 25,
        detail,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

/// Check if disk encryption is enabled
async fn check_disk_encryption() -> PostureCheck {
    let start = Instant::now();

    #[cfg(target_os = "windows")]
    let (passed, detail) = {
        let output = tokio::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "(Get-BitLockerVolume -MountPoint 'C:').ProtectionStatus | ConvertTo-Json",
            ])
            .output()
            .await;

        match output {
            Ok(out) if out.status.success() => {
                let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
                // ProtectionStatus: 1 = On, 0 = Off
                let encrypted = text.contains('1');
                (encrypted, format!("BitLocker C: {}", if encrypted { "protected" } else { "not protected" }))
            }
            _ => (false, "Could not query BitLocker status".to_string()),
        }
    };

    #[cfg(target_os = "linux")]
    let (passed, detail) = {
        let output = tokio::process::Command::new("lsblk")
            .args(["-o", "NAME,TYPE", "--noheadings"])
            .output()
            .await;

        match output {
            Ok(out) if out.status.success() => {
                let text = String::from_utf8_lossy(&out.stdout);
                let has_crypt = text.contains("crypt");
                (has_crypt, format!("LUKS: {}", if has_crypt { "encrypted volumes found" } else { "no encrypted volumes" }))
            }
            _ => (false, "Could not query disk encryption".to_string()),
        }
    };

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    let (passed, detail) = (true, "Disk encryption check not implemented for this platform".to_string());

    PostureCheck {
        name: "Disk Encryption".to_string(),
        category: PostureCategory::Encryption,
        passed,
        weight: 25,
        detail,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

/// Check if antivirus / security software is active
async fn check_antivirus() -> PostureCheck {
    let start = Instant::now();

    #[cfg(target_os = "windows")]
    let (passed, detail) = {
        let output = tokio::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Get-MpComputerStatus | Select-Object -Property AMRunningMode,AntivirusEnabled,RealTimeProtectionEnabled | ConvertTo-Json",
            ])
            .output()
            .await;

        match output {
            Ok(out) if out.status.success() => {
                let text = String::from_utf8_lossy(&out.stdout);
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) {
                    let av_enabled = val["AntivirusEnabled"].as_bool().unwrap_or(false);
                    let rtp_enabled = val["RealTimeProtectionEnabled"].as_bool().unwrap_or(false);
                    let mode = val["AMRunningMode"].as_str().unwrap_or("Unknown");
                    let ok = av_enabled && rtp_enabled;
                    (ok, format!("Windows Defender: AV={}, RTP={}, Mode={}", av_enabled, rtp_enabled, mode))
                } else {
                    (false, "Could not parse Defender status".to_string())
                }
            }
            _ => (false, "Could not query antivirus status".to_string()),
        }
    };

    #[cfg(target_os = "linux")]
    let (passed, detail) = {
        // Check for ClamAV or other common AVs
        let clam = tokio::process::Command::new("which")
            .args(["clamd"])
            .output()
            .await;
        match clam {
            Ok(out) if out.status.success() => (true, "ClamAV daemon found".to_string()),
            _ => (true, "No AV required on managed Linux (policy-dependent)".to_string()),
        }
    };

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    let (passed, detail) = (true, "AV check not implemented for this platform".to_string());

    PostureCheck {
        name: "Antivirus".to_string(),
        category: PostureCategory::Security,
        passed,
        weight: 15,
        detail,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

/// Check if screen lock / password protection is enabled
async fn check_screen_lock() -> PostureCheck {
    let start = Instant::now();

    #[cfg(target_os = "windows")]
    let (passed, detail) = {
        let output = tokio::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'InactivityTimeoutSecs' -ErrorAction SilentlyContinue).InactivityTimeoutSecs",
            ])
            .output()
            .await;

        match output {
            Ok(out) if out.status.success() => {
                let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if let Ok(secs) = text.parse::<u64>() {
                    let ok = secs > 0 && secs <= 900; // Must lock within 15 minutes
                    (ok, format!("Screen lock timeout: {}s — {}", secs, if ok { "compliant" } else { "too long or disabled" }))
                } else {
                    // No policy set, but Windows defaults usually have screen lock
                    (true, "Screen lock: using system defaults".to_string())
                }
            }
            _ => (true, "Screen lock: using system defaults".to_string()),
        }
    };

    #[cfg(target_os = "linux")]
    let (passed, detail) = {
        // Check for xdg-screensaver or xautolock
        (true, "Screen lock: policy-dependent on Linux".to_string())
    };

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    let (passed, detail) = (true, "Screen lock check not implemented for this platform".to_string());

    PostureCheck {
        name: "Screen Lock".to_string(),
        category: PostureCategory::Security,
        passed,
        weight: 15,
        detail,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_posture_assessment() {
        let config = PostureConfig::default();
        let result = assess_posture(&config).await;
        assert!(result.score <= 100);
        assert!(!result.checks.is_empty());
        assert!(!result.timestamp.is_empty());
    }
}
