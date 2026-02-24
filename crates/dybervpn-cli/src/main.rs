//! DyberVPN CLI — Post-Quantum VPN Command Line Interface

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use dybervpn_protocol::{select_backend, Config, OperatingMode};
use dybervpn_tunnel::{Daemon, TunnelConfig, PeerConfig};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::Ordering;

/// DyberVPN — Post-Quantum VPN for Infrastructure You Control
#[derive(Parser)]
#[command(name = "dybervpn")]
#[command(author = "Dyber, Inc.")]
#[command(version)]
#[command(about = "A WireGuard-compatible post-quantum VPN", long_about = None)]
struct Cli {
    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new key pair (classical + post-quantum)
    Genkey {
        /// Operating mode (hybrid, pq-only, classic)
        #[arg(short, long, default_value = "hybrid")]
        mode: String,
        
        /// Output format (toml, wg)
        #[arg(short, long, default_value = "toml")]
        format: String,
    },

    /// Derive public key from private key (reads from stdin)
    Pubkey,

    /// Start the VPN tunnel
    Up {
        /// Configuration file path
        #[arg(short, long)]
        config: PathBuf,
        
        /// Run in foreground (don't daemonize)
        #[arg(short, long)]
        foreground: bool,
    },

    /// Stop the VPN tunnel
    Down {
        /// Interface name (e.g., dvpn0)
        interface: String,
    },

    /// Show tunnel status
    Status {
        /// Interface name (optional, shows all if not specified)
        interface: Option<String>,
        
        /// Output as JSON
        #[arg(short, long)]
        json: bool,
    },

    /// Validate configuration file
    Check {
        /// Configuration file path
        #[arg(short, long)]
        config: PathBuf,
    },

    /// Interactive setup wizard
    Init {
        /// Initialize as server
        #[arg(long)]
        server: bool,
        
        /// Initialize as client (specify server IP)
        #[arg(long)]
        client: Option<String>,
        
        /// Output directory
        #[arg(short, long, default_value = ".")]
        output: PathBuf,
    },

    /// Show version and crypto backend info
    Version,
    
    /// Show benchmark information
    Benchmark {
        /// Number of iterations
        #[arg(short, long, default_value = "1000")]
        iterations: usize,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("info")
    };

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(filter)
        .init();

    match cli.command {
        Commands::Genkey { mode, format } => cmd_genkey(&mode, &format),
        Commands::Pubkey => cmd_pubkey(),
        Commands::Up { config, foreground } => cmd_up(&config, foreground),
        Commands::Down { interface } => cmd_down(&interface),
        Commands::Status { interface, json } => cmd_status(interface.as_deref(), json),
        Commands::Check { config } => cmd_check(&config),
        Commands::Init { server, client, output } => cmd_init(server, client.as_deref(), &output),
        Commands::Version => cmd_version(),
        Commands::Benchmark { iterations } => cmd_benchmark(iterations),
    }
}

/// Generate a new key pair
fn cmd_genkey(mode: &str, format: &str) -> Result<()> {
    let mode: OperatingMode = mode.parse().context("Invalid mode")?;
    let backend = select_backend();

    // Generate classical X25519 key
    let (x25519_pub, x25519_priv) = backend
        .x25519_keygen()
        .context("Failed to generate X25519 key")?;

    // Generate Ed25519 signing key
    let (ed25519_pub, ed25519_priv) = backend
        .ed25519_keygen()
        .context("Failed to generate Ed25519 key")?;

    match format {
        "toml" => {
            println!("# DyberVPN Key Pair");
            println!("# Mode: {:?}", mode);
            println!("# Generated: {}", chrono::Utc::now().to_rfc3339());
            println!();
            println!("[interface]");
            println!("private_key = \"{}\"", base64::encode(x25519_priv));
            println!("# public_key = \"{}\"", base64::encode(x25519_pub));
            println!();
            println!("# Signing Keys");
            println!("signing_private_key = \"{}\"", base64::encode(ed25519_priv));
            println!("# signing_public_key = \"{}\"", base64::encode(ed25519_pub));
        }
        "wg" => {
            // WireGuard-compatible format
            println!("{}", base64::encode(x25519_priv));
        }
        _ => {
            anyhow::bail!("Unknown format: {}. Use 'toml' or 'wg'", format);
        }
    }

    // Generate PQ keys if needed
    if mode.uses_pq_kex() && format == "toml" {
        println!();
        println!("# Post-Quantum Keys (ML-KEM-768)");

        let (mlkem_pub, mlkem_priv) = backend
            .mlkem_keygen()
            .context("Failed to generate ML-KEM key")?;

        println!("pq_private_key = \"{}\"", base64::encode(mlkem_priv.as_bytes()));
        println!("# pq_public_key = \"{}\"", base64::encode(mlkem_pub.as_bytes()));
    }

    // Generate ML-DSA keys if in pq-only mode (for authentication)
    if mode.uses_pq_auth() && format == "toml" {
        println!();
        println!("# Post-Quantum Signing Keys (ML-DSA-65)");

        let (mldsa_pub, mldsa_priv) = backend
            .mldsa_keygen()
            .context("Failed to generate ML-DSA key")?;

        println!("mldsa_private_key = \"{}\"", base64::encode(mldsa_priv.as_bytes()));
        println!("# mldsa_public_key = \"{}\"", base64::encode(mldsa_pub.as_bytes()));
    }

    eprintln!();
    eprintln!("Keys generated successfully.");
    eprintln!("Save the private keys securely and share only the public keys.");

    Ok(())
}

/// Derive public key from private key
fn cmd_pubkey() -> Result<()> {
    use std::io::{self, Read};
    use x25519_dalek::{PublicKey, StaticSecret};

    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let input = input.trim();

    let private_bytes = base64::decode(input).context("Invalid base64")?;

    match private_bytes.len() {
        32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&private_bytes);
            let secret = StaticSecret::from(arr);
            let public = PublicKey::from(&secret);
            println!("{}", base64::encode(public.as_bytes()));
        }
        _ => {
            anyhow::bail!("Unknown key format (length: {})", private_bytes.len());
        }
    }

    Ok(())
}

/// Start the VPN tunnel
fn cmd_up(config_path: &PathBuf, foreground: bool) -> Result<()> {
    let config_str = std::fs::read_to_string(config_path)
        .context("Failed to read config file")?;
    
    let config: Config = toml::from_str(&config_str)
        .context("Failed to parse config file")?;
    
    config.validate().context("Invalid configuration")?;
    
    tracing::info!(
        "Starting DyberVPN tunnel: {}",
        config.interface.name
    );
    tracing::info!("Mode: {:?}", config.interface.mode);
    
    if !foreground {
        eprintln!("Note: Daemonization not yet implemented. Running in foreground.");
    }
    
    // Convert config to TunnelConfig
    let tunnel_config = convert_config(&config)?;
    
    // Create and run daemon
    let mut daemon = Daemon::new(tunnel_config)
        .context("Failed to create daemon")?;
    
    // Get shutdown flag for signal handling
    let shutdown_flag = daemon.shutdown_flag();
    
    // Set up Ctrl+C handler
    let shutdown_flag_clone = shutdown_flag.clone();
    ctrlc::set_handler(move || {
        tracing::info!("Received shutdown signal");
        shutdown_flag_clone.store(true, Ordering::Relaxed);
    }).context("Failed to set Ctrl+C handler")?;
    
    // Initialize the daemon
    daemon.init().context("Failed to initialize daemon")?;
    
    // Run the event loop
    daemon.run().context("Daemon error")?;
    
    tracing::info!("Tunnel stopped");
    
    Ok(())
}

/// Convert protocol Config to tunnel TunnelConfig
fn convert_config(config: &Config) -> Result<TunnelConfig> {
    // Decode private key
    let private_key_bytes = base64::decode(&config.interface.private_key)
        .context("Invalid private_key base64")?;
    let mut private_key = [0u8; 32];
    if private_key_bytes.len() != 32 {
        anyhow::bail!("Private key must be 32 bytes");
    }
    private_key.copy_from_slice(&private_key_bytes);
    
    // Parse address
    let (address, netmask) = parse_cidr(&config.interface.address)?;
    
    // Decode PQ private key if present
    let pq_private_key = if let Some(ref pq_key) = config.interface.pq_private_key {
        Some(base64::decode(pq_key).context("Invalid pq_private_key base64")?)
    } else {
        None
    };
    
    let listen_port = config.interface.listen_port.unwrap_or(51820);
    
    let mut tunnel_config = TunnelConfig {
        device_name: config.interface.name.clone(),
        private_key,
        pq_private_key,
        listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), listen_port),
        address,
        netmask,
        mtu: config.interface.mtu,
        mode: config.interface.mode,
        peers: Vec::new(),
        dns: Vec::new(),
        keepalive_interval: Some(std::time::Duration::from_secs(25)),
        handshake_timeout: std::time::Duration::from_secs(5),
        verbose: false,
    };
    
    // Convert peers
    for peer_config in &config.peer {
        let public_key_bytes = base64::decode(&peer_config.public_key)
            .context("Invalid peer public_key base64")?;
        let mut public_key = [0u8; 32];
        if public_key_bytes.len() != 32 {
            anyhow::bail!("Peer public key must be 32 bytes");
        }
        public_key.copy_from_slice(&public_key_bytes);
        
        let pq_public_key = if let Some(ref pq_key) = peer_config.pq_public_key {
            Some(base64::decode(pq_key).context("Invalid peer pq_public_key base64")?)
        } else {
            None
        };
        
        let endpoint = peer_config.endpoint.as_ref()
            .map(|e| e.parse::<SocketAddr>())
            .transpose()
            .context("Invalid peer endpoint")?;
        
        // allowed_ips is a comma-separated string like "10.0.0.0/24, 192.168.1.0/24"
        let allowed_ips: Vec<(IpAddr, u8)> = peer_config.allowed_ips
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .filter_map(|s| parse_cidr(s).ok())
            .collect();
        
        let preshared_key = if let Some(ref psk) = peer_config.preshared_key {
            let psk_bytes = base64::decode(psk).context("Invalid preshared_key base64")?;
            let mut arr = [0u8; 32];
            if psk_bytes.len() != 32 {
                anyhow::bail!("Preshared key must be 32 bytes");
            }
            arr.copy_from_slice(&psk_bytes);
            Some(arr)
        } else {
            None
        };
        
        let peer = PeerConfig {
            public_key,
            pq_public_key,
            endpoint,
            allowed_ips,
            persistent_keepalive: if peer_config.persistent_keepalive > 0 {
                Some(peer_config.persistent_keepalive)
            } else {
                None
            },
            preshared_key,
        };
        
        tunnel_config.peers.push(peer);
    }
    
    Ok(tunnel_config)
}

/// Parse CIDR notation
fn parse_cidr(s: &str) -> Result<(IpAddr, u8)> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid CIDR format: {}", s);
    }
    let ip: IpAddr = parts[0].parse().context("Invalid IP address")?;
    let prefix: u8 = parts[1].parse().context("Invalid prefix length")?;
    Ok((ip, prefix))
}

/// Stop the VPN tunnel
fn cmd_down(interface: &str) -> Result<()> {
    use std::process::Command;
    
    let pid_file = format!("/var/run/dybervpn/{}.pid", interface);
    
    // Check if PID file exists
    if !std::path::Path::new(&pid_file).exists() {
        // Try alternative location
        let alt_pid_file = format!("/tmp/dybervpn-{}.pid", interface);
        if !std::path::Path::new(&alt_pid_file).exists() {
            eprintln!("No PID file found for interface '{}'", interface);
            eprintln!("The tunnel may not be running, or was started in foreground mode.");
            eprintln!();
            eprintln!("To stop a foreground tunnel, use Ctrl+C in the terminal where it's running.");
            
            // Try to check if interface exists
            #[cfg(target_os = "linux")]
            {
                let output = Command::new("ip")
                    .args(["link", "show", interface])
                    .output();
                
                if let Ok(output) = output {
                    if output.status.success() {
                        eprintln!();
                        eprintln!("Note: Interface '{}' exists. You may need to remove it manually:", interface);
                        eprintln!("  sudo ip link delete {}", interface);
                    }
                }
            }
            
            return Ok(());
        }
        return stop_tunnel_from_pid(&alt_pid_file, interface);
    }
    
    stop_tunnel_from_pid(&pid_file, interface)
}

fn stop_tunnel_from_pid(pid_file: &str, interface: &str) -> Result<()> {
    use std::fs;
    
    let pid_str = fs::read_to_string(pid_file)
        .context("Failed to read PID file")?;
    let pid: i32 = pid_str.trim().parse()
        .context("Invalid PID in file")?;
    
    println!("Stopping DyberVPN tunnel '{}' (PID: {})", interface, pid);
    
    // Send SIGTERM to the process
    #[cfg(unix)]
    {
        // Check if process exists
        let exists = unsafe { libc::kill(pid, 0) } == 0;
        if !exists {
            eprintln!("Process {} is not running. Cleaning up PID file.", pid);
            let _ = fs::remove_file(pid_file);
            return Ok(());
        }
        
        // Send SIGTERM
        let result = unsafe { libc::kill(pid, libc::SIGTERM) };
        if result != 0 {
            anyhow::bail!("Failed to send SIGTERM to process {}", pid);
        }
        
        println!("Sent SIGTERM to process {}", pid);
        
        // Wait for process to exit (up to 5 seconds)
        for i in 0..50 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            let exists = unsafe { libc::kill(pid, 0) } == 0;
            if !exists {
                println!("Tunnel '{}' stopped successfully", interface);
                let _ = fs::remove_file(pid_file);
                return Ok(());
            }
            if i == 20 {
                println!("Waiting for tunnel to stop...");
            }
        }
        
        // Process didn't exit, try SIGKILL
        eprintln!("Process didn't exit gracefully, sending SIGKILL");
        let result = unsafe { libc::kill(pid, libc::SIGKILL) };
        if result != 0 {
            anyhow::bail!("Failed to send SIGKILL to process {}", pid);
        }
        
        let _ = fs::remove_file(pid_file);
        println!("Tunnel '{}' killed", interface);
    }
    
    #[cfg(not(unix))]
    {
        eprintln!("Process management not supported on this platform");
    }
    
    Ok(())
}

/// Show tunnel status
fn cmd_status(interface: Option<&str>, json: bool) -> Result<()> {
    use std::fs;
    
    #[cfg(target_os = "linux")]
    use std::process::Command;
    
    // If no interface specified, look for all running tunnels
    if interface.is_none() {
        println!("DyberVPN Status");
        println!("===============");
        println!();
        
        // Check for running tunnels
        let mut found_any = false;
        
        // Check /var/run/dybervpn/ for PID files
        if let Ok(entries) = fs::read_dir("/var/run/dybervpn") {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if name.ends_with(".pid") {
                        let iface = name.trim_end_matches(".pid");
                        show_interface_status(iface, json)?;
                        found_any = true;
                    }
                }
            }
        }
        
        // Check /tmp for PID files
        if let Ok(entries) = fs::read_dir("/tmp") {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if name.starts_with("dybervpn-") && name.ends_with(".pid") {
                        let iface = name.trim_start_matches("dybervpn-").trim_end_matches(".pid");
                        show_interface_status(iface, json)?;
                        found_any = true;
                    }
                }
            }
        }
        
        // Check for interfaces without PID files (foreground mode)
        #[cfg(target_os = "linux")]
        {
            let output = Command::new("ip")
                .args(["link", "show", "type", "tun"])
                .output();
            
            if let Ok(output) = output {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if line.contains("dvpn") {
                        // Extract interface name
                        if let Some(name) = line.split(':').nth(1) {
                            let name = name.trim().split('@').next().unwrap_or("").trim();
                            if !name.is_empty() {
                                show_interface_status(name, json)?;
                                found_any = true;
                            }
                        }
                    }
                }
            }
        }
        
        if !found_any {
            println!("No DyberVPN tunnels found.");
            println!();
            println!("To start a tunnel:");
            println!("  dybervpn up -c /path/to/config.toml");
        }
        
        return Ok(());
    }
    
    let iface = interface.unwrap();
    show_interface_status(iface, json)
}

fn show_interface_status(interface: &str, json: bool) -> Result<()> {
    use std::fs;
    use std::process::Command;
    
    #[derive(serde::Serialize)]
    struct StatusOutput {
        interface: String,
        state: String,
        mode: String,
        address: Option<String>,
        pid: Option<i32>,
    }
    
    let mut state = "unknown";
    let mut pid: Option<i32> = None;
    let mut address: Option<String> = None;
    
    // Check for PID file
    let pid_file = format!("/var/run/dybervpn/{}.pid", interface);
    let alt_pid_file = format!("/tmp/dybervpn-{}.pid", interface);
    
    for pf in [&pid_file, &alt_pid_file] {
        if let Ok(pid_str) = fs::read_to_string(pf) {
            if let Ok(p) = pid_str.trim().parse::<i32>() {
                // Check if process is actually running
                #[cfg(unix)]
                {
                    let exists = unsafe { libc::kill(p, 0) } == 0;
                    if exists {
                        pid = Some(p);
                        state = "running";
                    } else {
                        state = "stale (process not found)";
                    }
                }
                #[cfg(not(unix))]
                {
                    pid = Some(p);
                    state = "running (unverified)";
                }
            }
            break;
        }
    }
    
    // Check if interface exists and get address
    #[cfg(target_os = "linux")]
    {
        let output = Command::new("ip")
            .args(["-4", "addr", "show", interface])
            .output();
        
        if let Ok(output) = output {
            if output.status.success() {
                if state == "unknown" {
                    state = "running (foreground)";
                }
                let stdout = String::from_utf8_lossy(&output.stdout);
                // Parse inet line
                for line in stdout.lines() {
                    let line = line.trim();
                    if line.starts_with("inet ") {
                        if let Some(addr) = line.split_whitespace().nth(1) {
                            address = Some(addr.to_string());
                        }
                    }
                }
            } else if state == "unknown" {
                state = "not running";
            }
        }
    }
    
    let status = StatusOutput {
        interface: interface.to_string(),
        state: state.to_string(),
        mode: "hybrid".to_string(), // TODO: Read from config
        address,
        pid,
    };
    
    if json {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        println!("interface: {}", status.interface);
        println!("  state: {}", status.state);
        if let Some(p) = status.pid {
            println!("  pid: {}", p);
        }
        if let Some(addr) = &status.address {
            println!("  address: {}", addr);
        }
        println!("  mode: {}", status.mode);
        println!();
    }
    
    Ok(())
}

/// Validate configuration file
fn cmd_check(config_path: &PathBuf) -> Result<()> {
    let config_str = std::fs::read_to_string(config_path)
        .context("Failed to read config file")?;
    
    let config: Config = toml::from_str(&config_str)
        .context("Failed to parse config file")?;
    
    config.validate().context("Configuration validation failed")?;
    
    println!("✓ Configuration is valid");
    println!();
    println!("Summary:");
    println!("  Device: {}", config.interface.name);
    println!("  Mode: {:?}", config.interface.mode);
    println!("  Address: {}", config.interface.address);
    if let Some(port) = config.interface.listen_port {
        println!("  Listen Port: {}", port);
    }
    println!("  Peers: {}", config.peer.len());
    
    Ok(())
}

/// Interactive setup wizard
fn cmd_init(server: bool, client: Option<&str>, output: &PathBuf) -> Result<()> {
    let backend = select_backend();
    
    // Generate keys
    let (x25519_pub, x25519_priv) = backend.x25519_keygen()?;
    let (_ed25519_pub, _ed25519_priv) = backend.ed25519_keygen()?;
    let (mlkem_pub, mlkem_priv) = backend.mlkem_keygen()?;
    
    let config_name = if server { "server.toml" } else { "client.toml" };
    let config_path = output.join(config_name);
    
    let config = if server {
        format!(r#"# DyberVPN Server Configuration
# Generated: {}

[interface]
name = "dvpn0"
private_key = "{}"
pq_private_key = "{}"
listen_port = 51820
address = "10.0.0.1/24"
mode = "hybrid"

# Add peers below:
# [[peer]]
# public_key = "..."
# pq_public_key = "..."
# allowed_ips = ["10.0.0.2/32"]
"#,
            chrono::Utc::now().to_rfc3339(),
            base64::encode(x25519_priv),
            base64::encode(mlkem_priv.as_bytes()),
        )
    } else {
        let server_addr = client.unwrap_or("SERVER_IP");
        format!(r#"# DyberVPN Client Configuration
# Generated: {}

[interface]
name = "dvpn0"
private_key = "{}"
pq_private_key = "{}"
address = "10.0.0.2/24"
mode = "hybrid"

[[peer]]
# Replace with server's public keys
public_key = "SERVER_PUBLIC_KEY"
pq_public_key = "SERVER_PQ_PUBLIC_KEY"
endpoint = "{}:51820"
allowed_ips = ["0.0.0.0/0"]
persistent_keepalive = 25
"#,
            chrono::Utc::now().to_rfc3339(),
            base64::encode(x25519_priv),
            base64::encode(mlkem_priv.as_bytes()),
            server_addr,
        )
    };
    
    std::fs::write(&config_path, &config)?;
    
    println!("Created: {}", config_path.display());
    println!();
    println!("Your public keys (share these with peers):");
    println!("  X25519:    {}", base64::encode(x25519_pub));
    println!("  ML-KEM:    {}...", &base64::encode(mlkem_pub.as_bytes())[..40]);
    println!();
    
    if server {
        println!("Next steps:");
        println!("  1. Add peer configurations to {}", config_path.display());
        println!("  2. Start the server: dybervpn up -c {}", config_path.display());
    } else {
        println!("Next steps:");
        println!("  1. Replace SERVER_PUBLIC_KEY with the server's X25519 public key");
        println!("  2. Replace SERVER_PQ_PUBLIC_KEY with the server's ML-KEM public key");
        println!("  3. Replace SERVER_IP with the server's IP address");
        println!("  4. Connect: dybervpn up -c {}", config_path.display());
    }
    
    Ok(())
}

/// Show version info
fn cmd_version() -> Result<()> {
    let backend = select_backend();

    println!("DyberVPN {}", env!("CARGO_PKG_VERSION"));
    println!();
    println!("Protocol: DyberVPN v1 (WireGuard-compatible)");
    println!("Crypto Backend: {}", backend.name());
    println!();
    println!("Algorithms:");
    println!("  Key Exchange: ML-KEM-768 + X25519 (hybrid)");
    println!("  Authentication: Ed25519 (Phase 1), ML-DSA-65 (pq-only)");
    println!("  AEAD: ChaCha20-Poly1305");
    println!("  Hash: BLAKE2s, SHA-256");
    println!();
    println!("Compliance:");
    println!("  NIST FIPS 203 (ML-KEM)");
    println!("  NIST FIPS 204 (ML-DSA) - pq-only mode");
    println!("  CNSA 2.0 Aligned");
    println!();
    println!("License: Apache-2.0 (new code), BSD-3-Clause (BoringTun-derived)");

    Ok(())
}

/// Run benchmarks
fn cmd_benchmark(iterations: usize) -> Result<()> {
    use std::time::Instant;
    
    let backend = select_backend();
    
    println!("DyberVPN Cryptographic Benchmarks");
    println!("==================================");
    println!("Backend: {}", backend.name());
    println!("Iterations: {}", iterations);
    println!();
    
    // ML-KEM keygen
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = backend.mlkem_keygen().unwrap();
    }
    let elapsed = start.elapsed();
    println!("ML-KEM-768 keygen:  {:>8.2} µs/op", 
        elapsed.as_micros() as f64 / iterations as f64);
    
    // ML-KEM encaps
    let (pk, _sk) = backend.mlkem_keygen().unwrap();
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = backend.mlkem_encaps(&pk).unwrap();
    }
    let elapsed = start.elapsed();
    println!("ML-KEM-768 encaps:  {:>8.2} µs/op",
        elapsed.as_micros() as f64 / iterations as f64);
    
    // ML-KEM decaps
    let (pk, sk) = backend.mlkem_keygen().unwrap();
    let (ct, _) = backend.mlkem_encaps(&pk).unwrap();
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = backend.mlkem_decaps(&sk, &ct).unwrap();
    }
    let elapsed = start.elapsed();
    println!("ML-KEM-768 decaps:  {:>8.2} µs/op",
        elapsed.as_micros() as f64 / iterations as f64);
    
    // X25519 keygen
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = backend.x25519_keygen().unwrap();
    }
    let elapsed = start.elapsed();
    println!("X25519 keygen:      {:>8.2} µs/op",
        elapsed.as_micros() as f64 / iterations as f64);
    
    // X25519 DH
    let (pk, sk) = backend.x25519_keygen().unwrap();
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = backend.x25519_diffie_hellman(&sk, &pk).unwrap();
    }
    let elapsed = start.elapsed();
    println!("X25519 DH:          {:>8.2} µs/op",
        elapsed.as_micros() as f64 / iterations as f64);
    
    // Ed25519 sign
    let (_, sk) = backend.ed25519_keygen().unwrap();
    let msg = b"benchmark message for signing";
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = backend.ed25519_sign(&sk, msg).unwrap();
    }
    let elapsed = start.elapsed();
    println!("Ed25519 sign:       {:>8.2} µs/op",
        elapsed.as_micros() as f64 / iterations as f64);
    
    // Ed25519 verify
    let (pk, sk) = backend.ed25519_keygen().unwrap();
    let sig = backend.ed25519_sign(&sk, msg).unwrap();
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = backend.ed25519_verify(&pk, msg, &sig).unwrap();
    }
    let elapsed = start.elapsed();
    println!("Ed25519 verify:     {:>8.2} µs/op",
        elapsed.as_micros() as f64 / iterations as f64);
    
    println!();
    println!("Post-Quantum Signatures (ML-DSA-65):");
    
    // ML-DSA keygen
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = backend.mldsa_keygen().unwrap();
    }
    let elapsed = start.elapsed();
    println!("ML-DSA-65 keygen:   {:>8.2} µs/op",
        elapsed.as_micros() as f64 / iterations as f64);
    
    // ML-DSA sign
    let (_, mldsa_sk) = backend.mldsa_keygen().unwrap();
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = backend.mldsa_sign(&mldsa_sk, msg).unwrap();
    }
    let elapsed = start.elapsed();
    println!("ML-DSA-65 sign:     {:>8.2} µs/op",
        elapsed.as_micros() as f64 / iterations as f64);
    
    // ML-DSA verify
    let (mldsa_pk, mldsa_sk) = backend.mldsa_keygen().unwrap();
    let mldsa_sig = backend.mldsa_sign(&mldsa_sk, msg).unwrap();
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = backend.mldsa_verify(&mldsa_pk, msg, &mldsa_sig).unwrap();
    }
    let elapsed = start.elapsed();
    println!("ML-DSA-65 verify:   {:>8.2} µs/op",
        elapsed.as_micros() as f64 / iterations as f64);
    
    println!();
    println!("Full hybrid handshake estimate: ~250-300 µs");
    println!("Full PQ-only handshake estimate: ~2-3 ms (includes ML-DSA)");
    
    Ok(())
}
