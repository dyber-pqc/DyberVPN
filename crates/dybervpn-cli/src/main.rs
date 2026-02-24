//! DyberVPN CLI — Post-Quantum VPN Command Line Interface

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use dybervpn_protocol::{select_backend, Config, OperatingMode};
use dybervpn_tunnel::{Daemon, TunnelConfig, PeerConfig};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::fs;
use std::io::Write;

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

    /// Generate an ML-DSA-65 signing keypair for release/artifact signing
    SignKeygen {
        /// Output directory for the keypair files
        #[arg(short, long, default_value = ".")]
        output: PathBuf,

        /// Key name prefix (creates <name>.mldsa.key and <name>.mldsa.pub)
        #[arg(short, long, default_value = "release-signing")]
        name: String,
    },

    /// Sign a file with ML-DSA-65 (post-quantum digital signature)
    Sign {
        /// File to sign
        file: PathBuf,

        /// Path to ML-DSA-65 private key (.mldsa.key)
        #[arg(short, long)]
        key: PathBuf,

        /// Output signature file path (default: <file>.sig.mldsa)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Verify an ML-DSA-65 signature on a file
    Verify {
        /// File to verify
        file: PathBuf,

        /// Path to ML-DSA-65 public key (.mldsa.pub)
        #[arg(short, long)]
        key: PathBuf,

        /// Signature file path (default: <file>.sig.mldsa)
        #[arg(short, long)]
        sig: Option<PathBuf>,
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
        Commands::SignKeygen { output, name } => cmd_sign_keygen(&output, &name),
        Commands::Sign { file, key, output } => cmd_sign(&file, &key, output.as_deref()),
        Commands::Verify { file, key, sig } => cmd_verify(&file, &key, sig.as_deref()),
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

/// PID file locations (in order of preference)
const PID_DIR_PRIMARY: &str = "/var/run/dybervpn";
const PID_DIR_FALLBACK: &str = "/tmp";

/// Get the PID file path for an interface
fn get_pid_path(interface: &str) -> PathBuf {
    // Try primary location first
    let primary_dir = Path::new(PID_DIR_PRIMARY);
    if primary_dir.exists() || fs::create_dir_all(primary_dir).is_ok() {
        return primary_dir.join(format!("{}.pid", interface));
    }
    // Fall back to /tmp
    PathBuf::from(format!("{}/dybervpn-{}.pid", PID_DIR_FALLBACK, interface))
}

/// Write PID file
fn write_pid_file(path: &Path, pid: u32) -> Result<()> {
    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).ok(); // Best effort
    }
    
    let mut file = fs::File::create(path)
        .with_context(|| format!("Failed to create PID file: {}", path.display()))?;
    
    writeln!(file, "{}", pid)
        .with_context(|| format!("Failed to write PID file: {}", path.display()))?;
    
    // Set restrictive permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o644);
        fs::set_permissions(path, perms).ok();
    }
    
    Ok(())
}

/// Remove PID file
fn remove_pid_file(path: &Path) {
    if let Err(e) = fs::remove_file(path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!("Failed to remove PID file {}: {}", path.display(), e);
        }
    }
}

/// Check if a process is running
/// Uses multiple methods to check, works regardless of permissions
#[cfg(unix)]
fn is_process_running(pid: i32) -> bool {
    // Method 1: Try to read /proc/PID/stat (world-readable)
    // This is more reliable than exists() which can fail due to permission checks
    let proc_stat = format!("/proc/{}/stat", pid);
    if fs::metadata(&proc_stat).is_ok() {
        return true;
    }
    
    // Method 2: Try to read /proc/PID/cmdline (also world-readable)
    let proc_cmdline = format!("/proc/{}/cmdline", pid);
    if fs::read(&proc_cmdline).is_ok() {
        return true;
    }
    
    // Method 3: Check /proc/PID directory using metadata
    let proc_dir = format!("/proc/{}", pid);
    if fs::metadata(&proc_dir).is_ok() {
        return true;
    }
    
    // Method 4: Fall back to kill(0) - works if we have permission
    let result = unsafe { libc::kill(pid, 0) };
    if result == 0 {
        return true;
    }
    
    // Method 5: Check errno for EPERM (process exists but no permission)
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    errno == libc::EPERM
}

#[cfg(not(unix))]
fn is_process_running(_pid: i32) -> bool {
    true // Assume running on non-Unix
}

/// Check if tunnel is already running
fn check_already_running(interface: &str) -> Result<()> {
    let pid_path = get_pid_path(interface);
    
    if pid_path.exists() {
        if let Ok(pid_str) = fs::read_to_string(&pid_path) {
            if let Ok(pid) = pid_str.trim().parse::<i32>() {
                if is_process_running(pid) {
                    anyhow::bail!(
                        "Tunnel '{}' is already running (PID {}). \
                         Use 'dybervpn down {}' to stop it first.",
                        interface, pid, interface
                    );
                } else {
                    // Stale PID file, remove it
                    tracing::warn!("Removing stale PID file for '{}'", interface);
                    remove_pid_file(&pid_path);
                }
            }
        }
    }
    
    Ok(())
}

/// Daemonize the process (Unix only)
#[cfg(unix)]
fn daemonize() -> Result<bool> {
    use nix::unistd::{fork, setsid, ForkResult};
    use nix::sys::stat::umask;
    use nix::sys::stat::Mode;
    
    // First fork
    match unsafe { fork() } {
        Ok(ForkResult::Parent { .. }) => {
            // Parent exits successfully
            return Ok(false); // Signal parent to exit
        }
        Ok(ForkResult::Child) => {
            // Child continues
        }
        Err(e) => {
            anyhow::bail!("First fork failed: {}", e);
        }
    }
    
    // Create new session (detach from terminal)
    setsid().context("Failed to create new session")?;
    
    // Set umask
    umask(Mode::from_bits_truncate(0o022));
    
    // Second fork (prevent acquiring a controlling terminal)
    match unsafe { fork() } {
        Ok(ForkResult::Parent { .. }) => {
            // Intermediate parent exits
            std::process::exit(0);
        }
        Ok(ForkResult::Child) => {
            // Grandchild continues as daemon
        }
        Err(e) => {
            anyhow::bail!("Second fork failed: {}", e);
        }
    }
    
    // Change to root directory to avoid holding directory handles
    std::env::set_current_dir("/").ok();
    
    // Redirect standard file descriptors to /dev/null
    use std::os::unix::io::AsRawFd;
    let dev_null = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .context("Failed to open /dev/null")?;
    
    let null_fd = dev_null.as_raw_fd();
    unsafe {
        libc::dup2(null_fd, libc::STDIN_FILENO);
        libc::dup2(null_fd, libc::STDOUT_FILENO);
        libc::dup2(null_fd, libc::STDERR_FILENO);
    }
    
    Ok(true) // Signal daemon to continue
}

#[cfg(not(unix))]
fn daemonize() -> Result<bool> {
    anyhow::bail!("Daemonization is not supported on this platform. Use -f/--foreground.");
}

/// Start the VPN tunnel
fn cmd_up(config_path: &PathBuf, foreground: bool) -> Result<()> {
    let config_str = std::fs::read_to_string(config_path)
        .context("Failed to read config file")?;
    
    let config: Config = toml::from_str(&config_str)
        .context("Failed to parse config file")?;
    
    config.validate().context("Invalid configuration")?;
    
    let interface_name = config.interface.name.clone();
    
    // Check if already running
    check_already_running(&interface_name)?;
    
    // Get PID file path before potential daemonization
    let pid_path = get_pid_path(&interface_name);
    
    if !foreground {
        // Daemonize before initializing the tunnel
        println!("Starting DyberVPN tunnel '{}' in background...", interface_name);
        println!("PID file: {}", pid_path.display());
        println!("Use 'dybervpn status' to check tunnel status");
        println!("Use 'dybervpn down {}' to stop the tunnel", interface_name);
        
        if !daemonize()? {
            // Parent process - exit successfully
            // The child will continue and write the PID file
            std::process::exit(0);
        }
        
        // We're now the daemon process
        // Re-initialize logging for daemon mode (log to syslog or file)
        // For now, we'll just continue with the existing setup
        // In production, you'd configure file-based logging here
    } else {
        tracing::info!("Starting DyberVPN tunnel '{}' in foreground", interface_name);
    }
    
    tracing::info!("Mode: {:?}", config.interface.mode);
    
    // Write PID file
    let current_pid = std::process::id();
    write_pid_file(&pid_path, current_pid)?;
    tracing::info!("PID {} written to {}", current_pid, pid_path.display());
    
    // Set up cleanup on exit
    let pid_path_clone = pid_path.clone();
    
    // Convert config to TunnelConfig
    let tunnel_config = convert_config(&config)?;
    
    // Create and run daemon
    let mut daemon = Daemon::new(tunnel_config)
        .context("Failed to create daemon")?;
    
    // Get shutdown flag for signal handling
    let shutdown_flag = daemon.shutdown_flag();
    
    // Set up Ctrl+C handler (and SIGTERM in daemon mode)
    let shutdown_flag_clone = shutdown_flag.clone();
    ctrlc::set_handler(move || {
        tracing::info!("Received shutdown signal");
        shutdown_flag_clone.store(true, Ordering::Relaxed);
    }).context("Failed to set signal handler")?;
    
    // Initialize the daemon
    match daemon.init() {
        Ok(_) => {}
        Err(e) => {
            remove_pid_file(&pid_path_clone);
            return Err(e).context("Failed to initialize daemon");
        }
    }
    
    // Run the event loop
    let result = daemon.run();
    
    // Clean up PID file
    remove_pid_file(&pid_path);
    tracing::info!("PID file removed");
    
    result.context("Daemon error")?;
    tracing::info!("Tunnel '{}' stopped", interface_name);
    
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
    
    // Decode ML-DSA private key if present (for pq-only mode)
    let mldsa_private_key = if let Some(ref mldsa_key) = config.interface.mldsa_private_key {
        Some(base64::decode(mldsa_key).context("Invalid mldsa_private_key base64")?)
    } else {
        None
    };
    
    let listen_port = config.interface.listen_port.unwrap_or(51820);
    
    let mut tunnel_config = TunnelConfig {
        device_name: config.interface.name.clone(),
        private_key,
        pq_private_key,
        mldsa_private_key,
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
        
        // Decode peer's ML-DSA public key if present (for pq-only mode)
        let mldsa_public_key = if let Some(ref mldsa_key) = peer_config.mldsa_public_key {
            Some(base64::decode(mldsa_key).context("Invalid peer mldsa_public_key base64")?)
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
            mldsa_public_key,
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
    let pid_path = get_pid_path(interface);
    
    // Also check alternate location if primary doesn't exist
    let pid_file_to_use = if pid_path.exists() {
        pid_path
    } else {
        // Try both locations
        let primary = PathBuf::from(format!("{}/{}.pid", PID_DIR_PRIMARY, interface));
        let fallback = PathBuf::from(format!("{}/dybervpn-{}.pid", PID_DIR_FALLBACK, interface));
        
        if primary.exists() {
            primary
        } else if fallback.exists() {
            fallback
        } else {
            eprintln!("No PID file found for interface '{}'", interface);
            eprintln!("The tunnel may not be running, or was started in foreground mode.");
            eprintln!();
            eprintln!("To stop a foreground tunnel, use Ctrl+C in the terminal where it's running.");
            
            // Try to check if interface exists
            #[cfg(target_os = "linux")]
            {
                use std::process::Command;
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
    };
    
    stop_tunnel_from_pid(&pid_file_to_use, interface)
}

fn stop_tunnel_from_pid(pid_file: &Path, interface: &str) -> Result<()> {
    
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
    use std::collections::HashSet;
    
    #[cfg(target_os = "linux")]
    use std::process::Command;
    
    // If no interface specified, look for all running tunnels
    if interface.is_none() {
        println!("DyberVPN Status");
        println!("===============");
        println!();
        
        // Track interfaces we've already shown to avoid duplicates
        let mut shown_interfaces: HashSet<String> = HashSet::new();
        
        // Check /var/run/dybervpn/ for PID files
        if let Ok(entries) = fs::read_dir("/var/run/dybervpn") {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if name.ends_with(".pid") {
                        let iface = name.trim_end_matches(".pid");
                        if shown_interfaces.insert(iface.to_string()) {
                            show_interface_status(iface, json)?;
                        }
                    }
                }
            }
        }
        
        // Check /tmp for PID files (only if not already shown)
        if let Ok(entries) = fs::read_dir("/tmp") {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if name.starts_with("dybervpn-") && name.ends_with(".pid") {
                        let iface = name.trim_start_matches("dybervpn-").trim_end_matches(".pid");
                        if shown_interfaces.insert(iface.to_string()) {
                            show_interface_status(iface, json)?;
                        }
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
                            if !name.is_empty() && shown_interfaces.insert(name.to_string()) {
                                show_interface_status(name, json)?;
                            }
                        }
                    }
                }
            }
        }
        
        if shown_interfaces.is_empty() {
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
                // Check if process is actually running using our robust function
                if is_process_running(p) {
                    pid = Some(p);
                    state = "running";
                } else {
                    state = "stale (process not found)";
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

// ════════════════════════════════════════════════════════════════════════════
// ML-DSA-65 Artifact Signing — Post-Quantum Code Signing
// ════════════════════════════════════════════════════════════════════════════
//
// Signature file format (.sig.mldsa):
//   Bytes 0..9:    Magic "DYBERSIG\x01" (version 1)
//   Bytes 9..41:   SHA-256 hash of the signed file
//   Bytes 41..49:  Timestamp (Unix epoch, big-endian u64)
//   Bytes 49..3358: ML-DSA-65 signature (3309 bytes) over bytes 0..49
//
// Total signature file size: 3358 bytes
// ════════════════════════════════════════════════════════════════════════════

const SIG_MAGIC: &[u8; 9] = b"DYBERSIG\x01";
const SIG_FILE_SIZE: usize = 9 + 32 + 8 + 3309; // 3358 bytes

/// Generate an ML-DSA-65 signing keypair
fn cmd_sign_keygen(output: &Path, name: &str) -> Result<()> {
    use dybervpn_protocol::types::mldsa65;
    
    let backend = select_backend();
    
    println!("Generating ML-DSA-65 signing keypair...");
    println!("Algorithm: FIPS 204 (ML-DSA-65, Security Level 3)");
    println!();
    
    let (pk, sk) = backend.mldsa_keygen()
        .context("ML-DSA-65 key generation failed")?;
    
    // Validate sizes
    assert_eq!(pk.as_bytes().len(), mldsa65::PUBLIC_KEY_SIZE);
    assert_eq!(sk.as_bytes().len(), mldsa65::SECRET_KEY_SIZE);
    
    let sk_path = output.join(format!("{}.mldsa.key", name));
    let pk_path = output.join(format!("{}.mldsa.pub", name));
    
    // Write private key (raw bytes)
    fs::write(&sk_path, sk.as_bytes())
        .with_context(|| format!("Failed to write private key to {}", sk_path.display()))?;
    
    // Set restrictive permissions on private key
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&sk_path, fs::Permissions::from_mode(0o600))?;
    }
    
    // Write public key (raw bytes)
    fs::write(&pk_path, pk.as_bytes())
        .with_context(|| format!("Failed to write public key to {}", pk_path.display()))?;
    
    println!("Private key: {} ({} bytes)", sk_path.display(), mldsa65::SECRET_KEY_SIZE);
    println!("Public key:  {} ({} bytes)", pk_path.display(), mldsa65::PUBLIC_KEY_SIZE);
    println!();
    println!("Public key fingerprint (SHA-256):");
    
    use sha2::{Sha256, Digest};
    let fingerprint = Sha256::digest(pk.as_bytes());
    let fp_hex = hex::encode(&fingerprint);
    println!("  {}:{}", &fp_hex[..32], &fp_hex[32..]);
    println!();
    println!("\x1b[1;33m⚠  KEEP THE PRIVATE KEY SECURE.\x1b[0m");
    println!("   Store it offline or in a hardware security module.");
    println!("   The public key should be distributed with your releases.");
    println!();
    println!("Usage:");
    println!("  Sign:   dybervpn sign <file> --key {}", sk_path.display());
    println!("  Verify: dybervpn verify <file> --key {}", pk_path.display());
    
    Ok(())
}

/// Sign a file with ML-DSA-65
fn cmd_sign(file: &Path, key_path: &Path, output: Option<&Path>) -> Result<()> {
    use sha2::{Sha256, Digest};
    use dybervpn_protocol::types::mldsa65;
    use dybervpn_protocol::MlDsaSecretKey;
    
    let backend = select_backend();
    
    // Read private key
    let sk_bytes = fs::read(key_path)
        .with_context(|| format!("Failed to read private key: {}", key_path.display()))?;
    
    if sk_bytes.len() != mldsa65::SECRET_KEY_SIZE {
        anyhow::bail!(
            "Invalid private key size: {} bytes (expected {} for ML-DSA-65).\n\
             Use 'dybervpn sign-keygen' to generate a valid signing keypair.",
            sk_bytes.len(), mldsa65::SECRET_KEY_SIZE
        );
    }
    
    let sk = MlDsaSecretKey::from_bytes(&sk_bytes)
        .context("Invalid ML-DSA-65 private key")?;
    
    // Read file to sign
    let file_data = fs::read(file)
        .with_context(|| format!("Failed to read file: {}", file.display()))?;
    
    let file_size = file_data.len();
    
    // Hash the file
    let file_hash = Sha256::digest(&file_data);
    
    // Get timestamp
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    // Build the message to sign: magic + hash + timestamp
    let mut sign_message = Vec::with_capacity(9 + 32 + 8);
    sign_message.extend_from_slice(SIG_MAGIC);
    sign_message.extend_from_slice(&file_hash);
    sign_message.extend_from_slice(&timestamp.to_be_bytes());
    
    assert_eq!(sign_message.len(), 49);
    
    // Sign with ML-DSA-65
    eprintln!("Signing {} ({} bytes) with ML-DSA-65...", file.display(), file_size);
    
    let signature = backend.mldsa_sign(&sk, &sign_message)
        .context("ML-DSA-65 signing failed")?;
    
    assert_eq!(signature.as_bytes().len(), mldsa65::SIGNATURE_SIZE);
    
    // Build signature file: message + signature
    let mut sig_file = Vec::with_capacity(SIG_FILE_SIZE);
    sig_file.extend_from_slice(&sign_message);     // 49 bytes
    sig_file.extend_from_slice(signature.as_bytes()); // 3309 bytes
    
    assert_eq!(sig_file.len(), SIG_FILE_SIZE);
    
    // Write signature file
    let sig_path = match output {
        Some(p) => p.to_path_buf(),
        None => {
            let mut p = file.as_os_str().to_owned();
            p.push(".sig.mldsa");
            PathBuf::from(p)
        }
    };
    
    fs::write(&sig_path, &sig_file)
        .with_context(|| format!("Failed to write signature: {}", sig_path.display()))?;
    
    println!("\x1b[1;32m✓ Signed successfully\x1b[0m");
    println!();
    println!("  File:       {}", file.display());
    println!("  Size:       {} bytes", file_size);
    println!("  SHA-256:    {}", hex::encode(&file_hash));
    println!("  Algorithm:  ML-DSA-65 (FIPS 204)");
    println!("  Timestamp:  {}", chrono::DateTime::from_timestamp(timestamp as i64, 0)
        .map(|dt| dt.to_rfc3339()).unwrap_or_else(|| timestamp.to_string()));
    println!("  Signature:  {} ({} bytes)", sig_path.display(), SIG_FILE_SIZE);
    println!();
    println!("Verify with:");
    println!("  dybervpn verify {} --key <public_key>.mldsa.pub", file.display());
    
    Ok(())
}

/// Verify an ML-DSA-65 signature on a file
fn cmd_verify(file: &Path, key_path: &Path, sig_path: Option<&Path>) -> Result<()> {
    use sha2::{Sha256, Digest};
    use dybervpn_protocol::types::mldsa65;
    use dybervpn_protocol::{MlDsaPublicKey, MlDsaSignature};
    
    let backend = select_backend();
    
    // Read public key
    let pk_bytes = fs::read(key_path)
        .with_context(|| format!("Failed to read public key: {}", key_path.display()))?;
    
    if pk_bytes.len() != mldsa65::PUBLIC_KEY_SIZE {
        anyhow::bail!(
            "Invalid public key size: {} bytes (expected {} for ML-DSA-65).\n\
             Make sure you're using the .mldsa.pub file, not the private key.",
            pk_bytes.len(), mldsa65::PUBLIC_KEY_SIZE
        );
    }
    
    let pk = MlDsaPublicKey::from_bytes(&pk_bytes)
        .context("Invalid ML-DSA-65 public key")?;
    
    // Read signature file
    let sig_file_path = match sig_path {
        Some(p) => p.to_path_buf(),
        None => {
            let mut p = file.as_os_str().to_owned();
            p.push(".sig.mldsa");
            PathBuf::from(p)
        }
    };
    
    let sig_data = fs::read(&sig_file_path)
        .with_context(|| format!("Failed to read signature file: {}\n\
            Looked for: {}\n\
            Specify manually with --sig <path>", sig_file_path.display(), sig_file_path.display()))?;
    
    if sig_data.len() != SIG_FILE_SIZE {
        anyhow::bail!(
            "Invalid signature file size: {} bytes (expected {}).\n\
             The file may be corrupted or not a DyberVPN signature.",
            sig_data.len(), SIG_FILE_SIZE
        );
    }
    
    // Parse signature file
    let magic = &sig_data[0..9];
    if magic != SIG_MAGIC {
        anyhow::bail!("Invalid signature file: bad magic bytes. Not a DyberVPN ML-DSA signature.");
    }
    
    let stored_hash = &sig_data[9..41];
    let timestamp_bytes: [u8; 8] = sig_data[41..49].try_into().unwrap();
    let timestamp = u64::from_be_bytes(timestamp_bytes);
    let sig_bytes = &sig_data[49..SIG_FILE_SIZE];
    
    let signature = MlDsaSignature::from_bytes(sig_bytes)
        .context("Invalid ML-DSA-65 signature in file")?;
    
    // Read and hash the original file
    let file_data = fs::read(file)
        .with_context(|| format!("Failed to read file: {}", file.display()))?;
    
    let file_hash = Sha256::digest(&file_data);
    
    // Check hash matches
    if file_hash.as_slice() != stored_hash {
        println!("\x1b[1;31m✗ VERIFICATION FAILED — file has been modified\x1b[0m");
        println!();
        println!("  Expected SHA-256: {}", hex::encode(stored_hash));
        println!("  Actual SHA-256:   {}", hex::encode(&file_hash));
        println!();
        println!("  The file content does not match the signed hash.");
        println!("  This file may have been tampered with.");
        std::process::exit(1);
    }
    
    // Verify ML-DSA-65 signature
    let sign_message = &sig_data[0..49]; // magic + hash + timestamp
    
    let valid = backend.mldsa_verify(&pk, sign_message, &signature)
        .context("ML-DSA-65 verification error")?;
    
    if valid {
        println!("\x1b[1;32m✓ Signature verified — file is authentic\x1b[0m");
        println!();
        println!("  File:       {}", file.display());
        println!("  Size:       {} bytes", file_data.len());
        println!("  SHA-256:    {}", hex::encode(&file_hash));
        println!("  Algorithm:  ML-DSA-65 (FIPS 204, NIST Security Level 3)");
        println!("  Signed at:  {}", chrono::DateTime::from_timestamp(timestamp as i64, 0)
            .map(|dt| dt.to_rfc3339()).unwrap_or_else(|| timestamp.to_string()));
        println!("  Signer key: {}", key_path.display());
        
        // Show public key fingerprint
        let fingerprint = Sha256::digest(&pk_bytes);
        let fp_hex = hex::encode(&fingerprint);
        println!("  Key SHA-256: {}:{}", &fp_hex[..32], &fp_hex[32..]);
        println!();
        println!("  This file was signed with a valid ML-DSA-65 post-quantum");
        println!("  digital signature and has not been modified since signing.");
    } else {
        println!("\x1b[1;31m✗ VERIFICATION FAILED — invalid signature\x1b[0m");
        println!();
        println!("  The SHA-256 hash matches, but the ML-DSA-65 signature is invalid.");
        println!("  This could mean:");
        println!("    - The file was signed with a different key");
        println!("    - The signature file is corrupted");
        println!("    - The public key does not match the signer");
        std::process::exit(1);
    }
    
    Ok(())
}
