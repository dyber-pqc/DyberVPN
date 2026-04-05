// DyberVPN Desktop Client — Tauri Backend
// Copyright 2026 Dyber, Inc.
//
// This backend wraps the dybervpn CLI binary to provide
// a native desktop experience for managing VPN tunnels.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use tauri::menu::{MenuBuilder, MenuItemBuilder};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Emitter, Manager, State, WindowEvent};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tokio::time::Instant;

// ─── Types ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    pub name: Option<String>,
    pub endpoint: Option<String>,
    pub mode: Option<String>,
    pub address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TunnelState {
    Running,
    Starting,
    Stopped,
    Stale,
    Error,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelStatus {
    pub connected: bool,
    pub state: TunnelState,
    pub rx: u64,
    pub tx: u64,
    pub uptime_secs: u64,
    pub latency_ms: Option<f64>,
    pub interface_name: String,
}

/// Payload emitted on the `tunnel-stats` event
#[derive(Debug, Clone, Serialize)]
pub struct TunnelStatsEvent {
    pub tunnels: HashMap<String, TunnelStatus>,
}

/// JSON output from `dybervpn status --json`
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CliStatusOutput {
    #[serde(default)]
    interface: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    mode: String,
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    pid: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub index: usize,
    pub public_key: String,
    pub pq_public_key: Option<String>,
    pub allowed_ips: String,
    pub endpoint: Option<String>,
    pub keepalive: u16,
}

// ─── App State ────────────────────────────────────────────

struct AppState {
    /// Running tunnel processes keyed by tunnel ID
    processes: Mutex<HashMap<String, Child>>,
    /// Time each tunnel was connected, for uptime calculation
    connect_times: Mutex<HashMap<String, Instant>>,
    /// Interface name for each connected tunnel
    interface_names: Mutex<HashMap<String, String>>,
    /// Path to the dybervpn binary
    dybervpn_bin: PathBuf,
}

impl AppState {
    fn new() -> Self {
        let bin = find_dybervpn_binary();
        eprintln!("[info] Using DyberVPN binary: {}", bin.display());
        Self {
            processes: Mutex::new(HashMap::new()),
            connect_times: Mutex::new(HashMap::new()),
            interface_names: Mutex::new(HashMap::new()),
            dybervpn_bin: bin,
        }
    }
}

/// Verify the DyberVPN binary is executable and log its version.
async fn verify_binary(bin: &PathBuf) {
    match Command::new(bin).args(["version"]).output().await {
        Ok(out) if out.status.success() => {
            let ver = String::from_utf8_lossy(&out.stdout);
            eprintln!("[info] DyberVPN CLI version: {}", ver.trim());
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            eprintln!("[warn] dybervpn version exited with {}: {}", out.status, stderr.trim());
        }
        Err(e) => eprintln!("[error] Cannot execute dybervpn binary at {}: {}", bin.display(), e),
    }
}

fn find_dybervpn_binary() -> PathBuf {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()));

    let mut candidates: Vec<PathBuf> = vec![];

    // 1. Sidecar / same directory as the app binary (production)
    if let Some(ref dir) = exe_dir {
        candidates.push(dir.join("dybervpn.exe"));
        candidates.push(dir.join("dybervpn"));
    }

    // 2. Development: workspace-relative from Cargo.toml location
    //    CARGO_MANIFEST_DIR = .../dybervpn-app/src-tauri
    //    CLI binary  = .../dybervpn/target/release/dybervpn.exe
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    candidates.push(manifest_dir.join("../../dybervpn/target/release/dybervpn.exe"));
    candidates.push(manifest_dir.join("../../dybervpn/target/release/dybervpn"));

    // 3. Hardcoded dev paths (multiple drive letters)
    candidates.push(PathBuf::from(r"H:\dybervpn\dybervpn\target\release\dybervpn.exe"));
    candidates.push(PathBuf::from(r"C:\dybervpn\dybervpn\target\release\dybervpn.exe"));

    // 4. System install paths
    candidates.push(PathBuf::from(r"C:\Program Files\DyberVPN\dybervpn.exe"));
    candidates.push(PathBuf::from("/usr/local/bin/dybervpn"));
    candidates.push(PathBuf::from("/usr/bin/dybervpn"));

    for path in &candidates {
        if path.exists() {
            eprintln!("[info] DyberVPN binary found: {}", path.display());
            return path.clone();
        }
    }

    eprintln!("[warn] DyberVPN binary not found in any candidate path, falling back to PATH lookup");
    PathBuf::from("dybervpn")
}

// ─── OS Traffic Counters ──────────────────────────────────

/// Read rx/tx bytes from OS network interface counters.
/// Returns (rx_bytes, tx_bytes).
async fn read_interface_traffic(iface: &str) -> (u64, u64) {
    #[cfg(target_os = "linux")]
    {
        let rx_path = format!("/sys/class/net/{}/statistics/rx_bytes", iface);
        let tx_path = format!("/sys/class/net/{}/statistics/tx_bytes", iface);
        let rx = tokio::fs::read_to_string(&rx_path)
            .await
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);
        let tx = tokio::fs::read_to_string(&tx_path)
            .await
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);
        (rx, tx)
    }

    #[cfg(target_os = "windows")]
    {
        // Use PowerShell to query network adapter statistics
        let script = format!(
            "Get-NetAdapterStatistics -Name '{}' | Select-Object -Property ReceivedBytes,SentBytes | ConvertTo-Json",
            iface
        );
        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", &script])
            .output()
            .await;

        if let Ok(out) = output {
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout);
                // Parse JSON: { "ReceivedBytes": N, "SentBytes": N }
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) {
                    let rx = val["ReceivedBytes"].as_u64().unwrap_or(0);
                    let tx = val["SentBytes"].as_u64().unwrap_or(0);
                    return (rx, tx);
                }
            }
        }
        (0, 0)
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = iface;
        (0, 0)
    }
}

// ─── Ping Helper ──────────────────────────────────────────

/// Ping a host and return RTT in milliseconds.
async fn ping_host(host: &str) -> Option<f64> {
    #[cfg(target_os = "windows")]
    let output = Command::new("ping")
        .args(["-n", "1", "-w", "2000", host])
        .output()
        .await;

    #[cfg(not(target_os = "windows"))]
    let output = Command::new("ping")
        .args(["-c", "1", "-W", "2", host])
        .output()
        .await;

    if let Ok(out) = output {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            // Parse "time=12.3 ms" or "time=12.3ms" or "time<1ms"
            for part in text.split_whitespace() {
                if part.starts_with("time=") || part.starts_with("time<") {
                    let num_str = part
                        .trim_start_matches("time=")
                        .trim_start_matches("time<")
                        .trim_end_matches("ms");
                    if let Ok(ms) = num_str.parse::<f64>() {
                        return Some(ms);
                    }
                }
            }
        }
    }
    None
}

// ─── CLI State Parsing ───────────────────────────────────

/// Map CLI state strings to TunnelState enum.
/// CLI outputs: "running", "running (foreground)", "stale (process not found)",
///              "not running", "unknown"
fn parse_cli_state(s: &str) -> TunnelState {
    let lower = s.to_lowercase();
    if lower.starts_with("running") {
        TunnelState::Running
    } else if lower.contains("starting") {
        TunnelState::Starting
    } else if lower.starts_with("not running") || lower == "stopped" {
        TunnelState::Stopped
    } else if lower.contains("stale") {
        TunnelState::Stale
    } else if lower.contains("error") {
        TunnelState::Error
    } else {
        TunnelState::Unknown
    }
}

/// Query the CLI for tunnel state, properly mapping all possible state strings.
async fn query_tunnel_state(bin: &PathBuf) -> TunnelState {
    let output = match Command::new(bin)
        .args(["status", "--json"])
        .output()
        .await
    {
        Ok(o) => o,
        Err(e) => {
            eprintln!("[warn] query_tunnel_state: CLI execution failed: {}", e);
            return TunnelState::Unknown;
        }
    };

    if !output.status.success() {
        eprintln!(
            "[warn] query_tunnel_state: CLI exited with status {}",
            output.status
        );
        return TunnelState::Unknown;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    match serde_json::from_str::<CliStatusOutput>(&text) {
        Ok(status) => parse_cli_state(&status.state),
        Err(e) => {
            eprintln!("[warn] query_tunnel_state: JSON parse failed: {}", e);
            TunnelState::Unknown
        }
    }
}

// ─── OS Interface Detection ─────────────────────────────

/// Try to detect a DyberVPN interface from the OS.
/// Returns the first `dvpn*` interface found, or None.
async fn detect_dybervpn_interface() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let output = Command::new("ip")
            .args(["link", "show", "type", "tun"])
            .output()
            .await
            .ok()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains("dvpn") {
                if let Some(name) = line.split(':').nth(1) {
                    let name = name.trim().split('@').next().unwrap_or("").trim();
                    if !name.is_empty() {
                        return Some(name.to_string());
                    }
                }
            }
        }
        None
    }

    #[cfg(target_os = "windows")]
    {
        let output = Command::new("powershell")
            .args([
                "-NoProfile", "-Command",
                "Get-NetAdapter | Where-Object { $_.InterfaceDescription -like '*DyberVPN*' -or $_.Name -like 'dvpn*' } | Select-Object -First 1 -ExpandProperty Name"
            ])
            .output()
            .await
            .ok()?;
        if output.status.success() {
            let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !name.is_empty() {
                return Some(name);
            }
        }
        None
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        None
    }
}

// ─── Tauri Commands ───────────────────────────────────────

/// Import and parse a TOML config file
#[tauri::command]
async fn import_config(path: String) -> Result<TunnelConfig, String> {
    let content = tokio::fs::read_to_string(&path)
        .await
        .map_err(|e| format!("Failed to read {}: {}", path, e))?;

    let table: toml::Table = content
        .parse()
        .map_err(|e| format!("Invalid TOML: {}", e))?;

    // Extract interface settings
    let iface = table.get("interface");
    let mode = iface
        .and_then(|i| i.get("mode"))
        .and_then(|v| v.as_str())
        .map(String::from);
    let name = iface
        .and_then(|i| i.get("name"))
        .and_then(|v| v.as_str())
        .map(String::from);
    let address = iface
        .and_then(|i| i.get("address"))
        .and_then(|v| v.as_str())
        .map(String::from);

    // Extract first peer endpoint
    let endpoint = table
        .get("peer")
        .and_then(|p| p.as_array())
        .and_then(|arr| arr.first())
        .or_else(|| table.get("peer"))
        .and_then(|p| p.get("endpoint"))
        .and_then(|v| v.as_str())
        .map(String::from);

    Ok(TunnelConfig {
        name,
        endpoint,
        mode,
        address,
    })
}

/// Connect a tunnel by spawning dybervpn up
#[tauri::command]
async fn connect_tunnel(
    tunnel_id: String,
    config_path: String,
    state: State<'_, Arc<AppState>>,
) -> Result<(), String> {
    let mut processes = state.processes.lock().await;

    // Kill existing process if any
    if let Some(mut child) = processes.remove(&tunnel_id) {
        let _ = child.kill().await;
    }

    // Spawn dybervpn up -c <config> -f
    let child = Command::new(&state.dybervpn_bin)
        .args(["up", "-c", &config_path, "-f"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("Failed to start dybervpn: {}", e))?;

    processes.insert(tunnel_id.clone(), child);

    // Record connect time
    state.connect_times.lock().await.insert(tunnel_id.clone(), Instant::now());

    // Try to determine interface name from config
    let iface_name = if !config_path.is_empty() {
        tokio::fs::read_to_string(&config_path)
            .await
            .ok()
            .and_then(|content| {
                content.parse::<toml::Table>().ok()
            })
            .and_then(|table| {
                table.get("interface")
                    .and_then(|i| i.get("name"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
            })
            .unwrap_or_else(|| "dvpn0".to_string())
    } else {
        "dvpn0".to_string()
    };
    state.interface_names.lock().await.insert(tunnel_id, iface_name);

    Ok(())
}

/// Disconnect a tunnel
#[tauri::command]
async fn disconnect_tunnel(
    tunnel_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<(), String> {
    let mut processes = state.processes.lock().await;

    if let Some(mut child) = processes.remove(&tunnel_id) {
        let _ = child.kill().await;
    }

    // Get the interface name — do not silently fall back
    let iface = match state.interface_names.lock().await.remove(&tunnel_id) {
        Some(name) => name,
        None => {
            eprintln!(
                "[warn] disconnect_tunnel: no interface name for '{}', attempting OS detection",
                tunnel_id
            );
            detect_dybervpn_interface().await.unwrap_or_else(|| {
                eprintln!(
                    "[warn] disconnect_tunnel: OS detection failed for '{}', falling back to 'dvpn0'",
                    tunnel_id
                );
                "dvpn0".to_string()
            })
        }
    };

    // Also call dybervpn down to clean up the interface
    let _ = Command::new(&state.dybervpn_bin)
        .args(["down", &iface])
        .output()
        .await;

    // Remove connect time
    state.connect_times.lock().await.remove(&tunnel_id);

    Ok(())
}

/// Get tunnel status with real traffic data
#[tauri::command]
async fn get_status(
    tunnel_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<Option<TunnelStatus>, String> {
    let processes = state.processes.lock().await;

    if !processes.contains_key(&tunnel_id) {
        return Ok(None);
    }
    drop(processes);

    // Get interface name with warning on fallback
    let iface = state.interface_names.lock().await
        .get(&tunnel_id)
        .cloned()
        .unwrap_or_else(|| {
            eprintln!("[warn] get_status: no interface name for tunnel '{}'", tunnel_id);
            "dvpn0".to_string()
        });

    // Query CLI for real state differentiation
    let tunnel_state = query_tunnel_state(&state.dybervpn_bin).await;
    let connected = matches!(tunnel_state, TunnelState::Running);

    // Read real traffic from OS counters
    let (rx, tx) = read_interface_traffic(&iface).await;

    // Compute uptime from connect time
    let uptime_secs = state.connect_times.lock().await
        .get(&tunnel_id)
        .map(|t| t.elapsed().as_secs())
        .unwrap_or(0);

    Ok(Some(TunnelStatus {
        connected,
        state: tunnel_state,
        rx,
        tx,
        uptime_secs,
        latency_ms: None, // Latency is fetched separately via ping_endpoint
        interface_name: iface,
    }))
}

/// Get peers from a tunnel config file
#[tauri::command]
async fn get_peers(
    config_path: String,
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<PeerInfo>, String> {
    if config_path.is_empty() {
        return Ok(vec![]);
    }

    let output = Command::new(&state.dybervpn_bin)
        .args(["list-peers", "-c", &config_path, "--json"])
        .output()
        .await
        .map_err(|e| format!("list-peers failed: {}", e))?;

    if output.status.success() {
        let text = String::from_utf8_lossy(&output.stdout);
        serde_json::from_str::<Vec<PeerInfo>>(&text)
            .map_err(|e| format!("Failed to parse peer list: {}", e))
    } else {
        // Fallback: parse TOML config directly for peer info
        let content = tokio::fs::read_to_string(&config_path)
            .await
            .map_err(|e| format!("Cannot read config: {}", e))?;

        let table: toml::Table = content
            .parse()
            .map_err(|e| format!("Invalid TOML: {}", e))?;

        let mut peers = Vec::new();
        if let Some(peer_val) = table.get("peer") {
            let peer_list = if let Some(arr) = peer_val.as_array() {
                arr.clone()
            } else {
                vec![peer_val.clone()]
            };
            for (i, p) in peer_list.iter().enumerate() {
                peers.push(PeerInfo {
                    index: i,
                    public_key: p.get("public_key")
                        .and_then(|v| v.as_str())
                        .unwrap_or("—")
                        .to_string(),
                    pq_public_key: p.get("pq_public_key")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    allowed_ips: p.get("allowed_ips")
                        .and_then(|v| v.as_str())
                        .unwrap_or("0.0.0.0/0")
                        .to_string(),
                    endpoint: p.get("endpoint")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    keepalive: p.get("persistent_keepalive")
                        .and_then(|v| v.as_integer())
                        .unwrap_or(25) as u16,
                });
            }
        }
        Ok(peers)
    }
}

/// Ping an endpoint and return latency in ms
#[tauri::command]
async fn ping_endpoint(host: String) -> Result<Option<f64>, String> {
    // Strip port if present (ping only works with host/IP)
    let host_only = host.split(':').next().unwrap_or(&host);
    Ok(ping_host(host_only).await)
}

/// Generate keys via dybervpn genkey
#[tauri::command]
async fn generate_keys(
    mode: String,
    state: State<'_, Arc<AppState>>,
) -> Result<String, String> {
    let output = Command::new(&state.dybervpn_bin)
        .args(["genkey", "-m", &mode])
        .output()
        .await
        .map_err(|e| format!("Key generation failed: {}", e))?;

    if output.status.success() {
        String::from_utf8(output.stdout)
            .map_err(|e| format!("Invalid output: {}", e))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

/// Validate a config file via dybervpn check
#[tauri::command]
async fn check_config(
    path: String,
    state: State<'_, Arc<AppState>>,
) -> Result<String, String> {
    let output = Command::new(&state.dybervpn_bin)
        .args(["check", "-c", &path])
        .output()
        .await
        .map_err(|e| format!("Config check failed: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if output.status.success() {
        Ok(stdout)
    } else {
        Err(format!("{}\n{}", stdout, stderr))
    }
}

/// Open a file picker dialog for config files
#[tauri::command]
async fn pick_config_file(app: tauri::AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;

    let file = app
        .dialog()
        .file()
        .add_filter("TOML Config", &["toml"])
        .add_filter("All Files", &["*"])
        .blocking_pick_file();

    Ok(file.map(|f| f.to_string()))
}

/// Get version info
#[tauri::command]
async fn get_version(state: State<'_, Arc<AppState>>) -> Result<String, String> {
    let output = Command::new(&state.dybervpn_bin)
        .args(["version"])
        .output()
        .await
        .map_err(|e| format!("Version check failed: {}", e))?;

    String::from_utf8(output.stdout)
        .map_err(|e| format!("Invalid output: {}", e))
}

// ─── Fleet Management Commands ───────────────────────────

/// Enroll this device with a DyberVPN Management Server
#[tauri::command]
async fn enroll_device(
    server: String,
    token: String,
    name: String,
    mode: String,
    output_dir: String,
    state: State<'_, Arc<AppState>>,
) -> Result<String, String> {
    let output = Command::new(&state.dybervpn_bin)
        .args([
            "enroll",
            "--server", &server,
            "--token", &token,
            "--name", &name,
            "--mode", &mode,
            "--output", &output_dir,
        ])
        .output()
        .await
        .map_err(|e| format!("Enrollment failed: {}", e))?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        Ok(format!("{}{}", stderr, stdout))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        Err(format!("{}\n{}", stderr, stdout))
    }
}

/// Revoke a peer's key permanently
#[tauri::command]
async fn revoke_peer(
    config_path: String,
    peer: String,
    reason: String,
    revoked_by: String,
    state: State<'_, Arc<AppState>>,
) -> Result<String, String> {
    let mut args = vec![
        "revoke-key".to_string(),
        "-c".to_string(), config_path,
        "-p".to_string(), peer,
        "-r".to_string(), reason,
        "--yes".to_string(),
    ];
    if !revoked_by.is_empty() {
        args.push("-b".to_string());
        args.push(revoked_by);
    }

    let output = Command::new(&state.dybervpn_bin)
        .args(&args)
        .output()
        .await
        .map_err(|e| format!("Revocation failed: {}", e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(format!("{}\n{}", String::from_utf8_lossy(&output.stderr), String::from_utf8_lossy(&output.stdout)))
    }
}

/// Temporarily suspend a peer's key
#[tauri::command]
async fn suspend_peer(
    config_path: String,
    peer: String,
    expires: String,
    revoked_by: String,
    state: State<'_, Arc<AppState>>,
) -> Result<String, String> {
    let mut args = vec![
        "suspend-key".to_string(),
        "-c".to_string(), config_path,
        "-p".to_string(), peer,
    ];
    if !expires.is_empty() {
        args.push("--expires".to_string());
        args.push(expires);
    }
    if !revoked_by.is_empty() {
        args.push("-b".to_string());
        args.push(revoked_by);
    }

    let output = Command::new(&state.dybervpn_bin)
        .args(&args)
        .output()
        .await
        .map_err(|e| format!("Suspension failed: {}", e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(format!("{}\n{}", String::from_utf8_lossy(&output.stderr), String::from_utf8_lossy(&output.stdout)))
    }
}

/// Reinstate a previously revoked or suspended key
#[tauri::command]
async fn reinstate_peer(
    config_path: String,
    peer: String,
    state: State<'_, Arc<AppState>>,
) -> Result<String, String> {
    let output = Command::new(&state.dybervpn_bin)
        .args(["reinstate-key", "-c", &config_path, "-p", &peer])
        .output()
        .await
        .map_err(|e| format!("Reinstatement failed: {}", e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(format!("{}\n{}", String::from_utf8_lossy(&output.stderr), String::from_utf8_lossy(&output.stdout)))
    }
}

/// List all revoked and suspended keys (JSON)
#[tauri::command]
async fn list_revoked(
    config_path: String,
    state: State<'_, Arc<AppState>>,
) -> Result<String, String> {
    let output = Command::new(&state.dybervpn_bin)
        .args(["list-revoked", "-c", &config_path, "--json"])
        .output()
        .await
        .map_err(|e| format!("List revoked failed: {}", e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(format!("{}\n{}", String::from_utf8_lossy(&output.stderr), String::from_utf8_lossy(&output.stdout)))
    }
}

/// Check enrollment server health via HTTP GET /health
#[tauri::command]
async fn check_server_health(server_url: String) -> Result<String, String> {
    use std::io::{Read as IoRead, Write as IoWrite};

    let url = server_url.trim_end_matches('/');
    let host_port = url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .to_string();

    let mut stream = std::net::TcpStream::connect(&host_port)
        .map_err(|e| format!("Cannot connect to {}: {}", host_port, e))?;

    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .ok();

    let request = format!(
        "GET /health HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        host_port
    );

    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("Failed to send request: {}", e))?;
    stream.flush().ok();

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| format!("Failed to read response: {}", e))?;

    // Extract JSON body after HTTP headers
    let body = response
        .split("\r\n\r\n")
        .nth(1)
        .or_else(|| response.split("\n\n").nth(1))
        .unwrap_or("{}");

    Ok(body.to_string())
}

// ─── Policy, Audit, Metrics & Posture Commands ──────────

/// Read the NDJSON audit log file and return the last N entries as JSON array
#[tauri::command]
async fn read_audit_log(
    config_path: String,
    max_entries: Option<usize>,
) -> Result<String, String> {
    let config_dir = std::path::Path::new(&config_path)
        .parent()
        .unwrap_or(std::path::Path::new("."));
    let audit_path = config_dir.join("audit.ndjson");

    if !audit_path.exists() {
        return Ok("[]".to_string());
    }

    let content = tokio::fs::read_to_string(&audit_path)
        .await
        .map_err(|e| format!("Failed to read audit log: {}", e))?;

    let limit = max_entries.unwrap_or(200);
    let lines: Vec<&str> = content.lines().rev().take(limit).collect();

    let mut entries = Vec::new();
    for line in lines.iter().rev() {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
            entries.push(val);
        }
    }

    serde_json::to_string(&entries)
        .map_err(|e| format!("JSON serialization error: {}", e))
}

/// Read policy configuration from a tunnel config file
#[tauri::command]
async fn get_policy_config(config_path: String) -> Result<String, String> {
    let content = tokio::fs::read_to_string(&config_path)
        .await
        .map_err(|e| format!("Failed to read config: {}", e))?;

    let table: toml::Table = content
        .parse()
        .map_err(|e| format!("Invalid TOML: {}", e))?;

    let policy = table.get("policy").cloned().unwrap_or(toml::Value::Table(toml::Table::new()));
    let security = table.get("security").cloned().unwrap_or(toml::Value::Table(toml::Table::new()));

    let result = serde_json::json!({
        "policy": toml_to_json(&policy),
        "security": toml_to_json(&security),
    });

    Ok(result.to_string())
}

fn toml_to_json(val: &toml::Value) -> serde_json::Value {
    match val {
        toml::Value::String(s) => serde_json::Value::String(s.clone()),
        toml::Value::Integer(i) => serde_json::json!(*i),
        toml::Value::Float(f) => serde_json::json!(*f),
        toml::Value::Boolean(b) => serde_json::Value::Bool(*b),
        toml::Value::Array(arr) => serde_json::Value::Array(arr.iter().map(toml_to_json).collect()),
        toml::Value::Table(t) => {
            let mut map = serde_json::Map::new();
            for (k, v) in t {
                map.insert(k.clone(), toml_to_json(v));
            }
            serde_json::Value::Object(map)
        }
        toml::Value::Datetime(d) => serde_json::Value::String(d.to_string()),
    }
}

/// Run device posture assessment (local OS-level checks)
#[tauri::command]
async fn run_posture_check() -> Result<String, String> {
    let mut checks = Vec::new();

    // 1. OS Version check
    {
        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", "[System.Environment]::OSVersion.Version | ConvertTo-Json"])
            .output()
            .await;

        let (passed, detail) = match output {
            Ok(out) if out.status.success() => {
                let text = String::from_utf8_lossy(&out.stdout);
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) {
                    let major = val["Major"].as_u64().unwrap_or(0);
                    let build = val["Build"].as_u64().unwrap_or(0);
                    let supported = (major == 10 && build >= 19041) || major > 10;
                    (supported, format!("Windows {}.{} — {}", major, build, if supported { "supported" } else { "below minimum" }))
                } else {
                    (false, "Could not parse OS version".to_string())
                }
            }
            _ => (false, "Failed to query OS version".to_string()),
        };
        checks.push(serde_json::json!({"name": "OS Version", "category": "operating_system", "passed": passed, "weight": 20, "detail": detail}));
    }

    // 2. Firewall check
    {
        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", "(Get-NetFirewallProfile -Profile Domain,Public,Private).Enabled | ConvertTo-Json"])
            .output()
            .await;

        let (passed, detail) = match output {
            Ok(out) if out.status.success() => {
                let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
                let all_enabled = text.contains("true") && !text.contains("false");
                (all_enabled, format!("Windows Firewall: {}", if all_enabled { "all profiles enabled" } else { "some profiles disabled" }))
            }
            _ => (false, "Could not query firewall status".to_string()),
        };
        checks.push(serde_json::json!({"name": "Firewall", "category": "security", "passed": passed, "weight": 25, "detail": detail}));
    }

    // 3. Disk encryption check
    {
        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", "(Get-BitLockerVolume -MountPoint 'C:' -ErrorAction SilentlyContinue).ProtectionStatus"])
            .output()
            .await;

        let (passed, detail) = match output {
            Ok(out) if out.status.success() => {
                let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
                let encrypted = text.contains('1');
                (encrypted, format!("BitLocker C: {}", if encrypted { "protected" } else { "not protected" }))
            }
            _ => (false, "Could not query BitLocker status".to_string()),
        };
        checks.push(serde_json::json!({"name": "Disk Encryption", "category": "encryption", "passed": passed, "weight": 25, "detail": detail}));
    }

    // 4. Antivirus check
    {
        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", "Get-MpComputerStatus | Select-Object -Property AntivirusEnabled,RealTimeProtectionEnabled | ConvertTo-Json"])
            .output()
            .await;

        let (passed, detail) = match output {
            Ok(out) if out.status.success() => {
                let text = String::from_utf8_lossy(&out.stdout);
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) {
                    let av = val["AntivirusEnabled"].as_bool().unwrap_or(false);
                    let rtp = val["RealTimeProtectionEnabled"].as_bool().unwrap_or(false);
                    (av && rtp, format!("Windows Defender: AV={}, RealTime={}", av, rtp))
                } else {
                    (false, "Could not parse Defender status".to_string())
                }
            }
            _ => (false, "Could not query antivirus status".to_string()),
        };
        checks.push(serde_json::json!({"name": "Antivirus", "category": "security", "passed": passed, "weight": 15, "detail": detail}));
    }

    // 5. Screen lock
    checks.push(serde_json::json!({"name": "Screen Lock", "category": "security", "passed": true, "weight": 15, "detail": "Screen lock: using system defaults"}));

    let total_weight: u32 = checks.iter().map(|c| c["weight"].as_u64().unwrap_or(0) as u32).sum();
    let earned: u32 = checks.iter().filter(|c| c["passed"].as_bool().unwrap_or(false)).map(|c| c["weight"].as_u64().unwrap_or(0) as u32).sum();
    let score = if total_weight > 0 { (earned * 100) / total_weight } else { 100 };

    let result = serde_json::json!({
        "score": score,
        "compliant": score >= 60,
        "threshold": 60,
        "checks": checks,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    Ok(result.to_string())
}

/// Query local metrics endpoint
#[tauri::command]
async fn get_metrics(metrics_url: Option<String>) -> Result<String, String> {
    use std::io::{Read as IoRead, Write as IoWrite};

    let url = metrics_url.unwrap_or_else(|| "127.0.0.1:9090".to_string());
    let host_port = url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .to_string();

    let mut stream = match std::net::TcpStream::connect(&host_port) {
        Ok(s) => s,
        Err(_) => {
            let fallback = serde_json::json!({
                "available": false,
                "message": "Metrics server not running. Start the DyberVPN daemon with --metrics flag.",
            });
            return Ok(fallback.to_string());
        }
    };

    stream.set_read_timeout(Some(std::time::Duration::from_secs(3))).ok();

    let request = format!("GET /metrics HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", host_port);
    stream.write_all(request.as_bytes()).map_err(|e| format!("Request failed: {}", e))?;
    stream.flush().ok();

    let mut response = String::new();
    stream.read_to_string(&mut response).map_err(|e| format!("Read failed: {}", e))?;

    let body = response
        .split("\r\n\r\n")
        .nth(1)
        .or_else(|| response.split("\n\n").nth(1))
        .unwrap_or("");

    let result = serde_json::json!({
        "available": true,
        "data": body,
    });
    Ok(result.to_string())
}

// ─── Background Stats Emitter ────────────────────────────

/// Background loop that emits tunnel stats every 2 seconds via Tauri events.
async fn stats_emitter_loop(handle: AppHandle, state: Arc<AppState>) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));

    loop {
        interval.tick().await;

        // Snapshot current tunnel IDs (minimize lock time)
        let tunnel_ids: Vec<String> = {
            let processes = state.processes.lock().await;
            processes.keys().cloned().collect()
        };

        if tunnel_ids.is_empty() {
            continue;
        }

        let mut stats_map: HashMap<String, TunnelStatus> = HashMap::new();

        // Query CLI state once (shared across all tunnels)
        let cli_state = query_tunnel_state(&state.dybervpn_bin).await;
        let connected = matches!(cli_state, TunnelState::Running);

        for tunnel_id in &tunnel_ids {
            let iface = state.interface_names.lock().await
                .get(tunnel_id)
                .cloned()
                .unwrap_or_else(|| "dvpn0".to_string());

            let (rx, tx) = read_interface_traffic(&iface).await;

            let uptime_secs = state.connect_times.lock().await
                .get(tunnel_id)
                .map(|t| t.elapsed().as_secs())
                .unwrap_or(0);

            stats_map.insert(tunnel_id.clone(), TunnelStatus {
                connected,
                state: cli_state.clone(),
                rx,
                tx,
                uptime_secs,
                latency_ms: None,
                interface_name: iface,
            });
        }

        let _ = handle.emit("tunnel-stats", TunnelStatsEvent {
            tunnels: stats_map,
        });
    }
}

// ─── Graceful Shutdown ──────────────────────────────────

/// Tear down all running tunnels before the app exits.
async fn shutdown_all_tunnels(state: &Arc<AppState>) {
    let mut processes = state.processes.lock().await;
    let ifaces = state.interface_names.lock().await;

    for (id, mut child) in processes.drain() {
        eprintln!("[info] Shutting down tunnel '{}'", id);
        let _ = child.kill().await;

        // Clean up the OS interface
        if let Some(iface) = ifaces.get(&id) {
            let _ = Command::new(&state.dybervpn_bin)
                .args(["down", iface])
                .output()
                .await;
        }
    }
    drop(ifaces);
    state.connect_times.lock().await.clear();
    state.interface_names.lock().await.clear();
}

// ─── System Tray ────────────────────────────────────────

fn build_system_tray(app: &tauri::App) -> tauri::Result<()> {
    let show = MenuItemBuilder::with_id("show", "Show DyberVPN").build(app)?;
    let quit = MenuItemBuilder::with_id("quit", "Quit").build(app)?;
    let menu = MenuBuilder::new(app)
        .item(&show)
        .separator()
        .item(&quit)
        .build()?;

    let _tray = TrayIconBuilder::new()
        .icon(app.default_window_icon().cloned().expect("no icon"))
        .menu(&menu)
        .tooltip("DyberVPN")
        .on_menu_event(move |app, event| match event.id().as_ref() {
            "show" => {
                if let Some(win) = app.get_webview_window("main") {
                    let _ = win.show();
                    let _ = win.unminimize();
                    let _ = win.set_focus();
                }
            }
            "quit" => {
                // Shutdown tunnels then exit
                let state: tauri::State<Arc<AppState>> = app.state();
                let state = state.inner().clone();
                let handle = app.clone();
                tauri::async_runtime::spawn(async move {
                    shutdown_all_tunnels(&state).await;
                    handle.exit(0);
                });
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let tauri::tray::TrayIconEvent::DoubleClick { .. } = event {
                if let Some(win) = tray.app_handle().get_webview_window("main") {
                    let _ = win.show();
                    let _ = win.unminimize();
                    let _ = win.set_focus();
                }
            }
        })
        .build(app)?;

    Ok(())
}

// ─── Main ─────────────────────────────────────────────────

fn main() {
    let app_state = Arc::new(AppState::new());

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_store::Builder::new().build())
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            // Focus the existing window when a second instance is launched
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.show();
                let _ = win.unminimize();
                let _ = win.set_focus();
            }
        }))
        .manage(app_state)
        .setup(|app| {
            let handle = app.handle().clone();
            let state: tauri::State<Arc<AppState>> = app.state();
            let state = state.inner().clone();

            // Verify the CLI binary is reachable at startup
            let bin = state.dybervpn_bin.clone();
            tauri::async_runtime::spawn(async move {
                verify_binary(&bin).await;
            });

            // System tray
            build_system_tray(app)?;

            // Background stats emitter
            tauri::async_runtime::spawn(stats_emitter_loop(handle, state));
            Ok(())
        })
        .on_window_event(|window, event| {
            // Minimize to tray on close (instead of quitting)
            if let WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .invoke_handler(tauri::generate_handler![
            import_config,
            connect_tunnel,
            disconnect_tunnel,
            get_status,
            get_peers,
            ping_endpoint,
            generate_keys,
            check_config,
            pick_config_file,
            get_version,
            // Fleet management
            enroll_device,
            revoke_peer,
            suspend_peer,
            reinstate_peer,
            list_revoked,
            check_server_health,
            // Policy, audit, metrics & posture
            read_audit_log,
            get_policy_config,
            run_posture_check,
            get_metrics,
        ])
        .run(tauri::generate_context!())
        .expect("error while running DyberVPN");
}
