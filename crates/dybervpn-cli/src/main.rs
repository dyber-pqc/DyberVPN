//! DyberVPN CLI — Post-Quantum VPN Command Line Interface

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use dybervpn_protocol::{select_backend, Config, OperatingMode};
use dybervpn_tunnel::{Daemon, TunnelConfig, PeerConfig};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
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

    /// Add a new peer to a server config and generate client config
    AddPeer {
        /// Server configuration file path
        #[arg(short, long)]
        config: PathBuf,

        /// Client name (used for output filename)
        #[arg(short, long)]
        name: String,

        /// Server endpoint (IP:port) for client config
        #[arg(short, long)]
        endpoint: String,

        /// Output directory for client config
        #[arg(short, long, default_value = ".")]
        output: PathBuf,
    },

    /// Remove a peer from a server config
    RemovePeer {
        /// Server configuration file path
        #[arg(short, long)]
        config: PathBuf,

        /// Peer to remove (name, public key prefix, or VPN IP)
        #[arg(short, long)]
        peer: String,

        /// Skip confirmation prompt
        #[arg(short = 'y', long)]
        yes: bool,
    },

    /// List all peers in a server config
    ListPeers {
        /// Configuration file path
        #[arg(short, long)]
        config: PathBuf,

        /// Output as JSON
        #[arg(short, long)]
        json: bool,
    },

    /// Send SIGHUP to a running tunnel to reload its config
    Reload {
        /// Interface name (e.g., dvpn0)
        interface: String,
    },

    /// Enroll this client with a DyberVPN server's enrollment API
    Enroll {
        /// Server enrollment URL (e.g., http://server:8443)
        #[arg(short, long)]
        server: String,

        /// Enrollment token
        #[arg(short, long)]
        token: String,

        /// Client name
        #[arg(short, long)]
        name: String,

        /// Operating mode (hybrid, pq-only, classic)
        #[arg(short, long, default_value = "hybrid")]
        mode: String,

        /// Output directory for client config
        #[arg(short, long, default_value = ".")]
        output: PathBuf,
    },

    /// Revoke a peer's key (add to CRL, optionally disconnect immediately)
    RevokeKey {
        /// Server configuration file path (to locate CRL path)
        #[arg(short, long)]
        config: PathBuf,

        /// Peer to revoke (name, public key prefix, or VPN IP)
        #[arg(short, long)]
        peer: String,

        /// Reason for revocation
        #[arg(short, long, default_value = "administrative")]
        reason: String,

        /// Your identifier (admin email/name for audit trail)
        #[arg(short = 'b', long)]
        revoked_by: Option<String>,

        /// Skip confirmation prompt
        #[arg(short = 'y', long)]
        yes: bool,
    },

    /// Temporarily suspend a peer's key
    SuspendKey {
        /// Server configuration file path
        #[arg(short, long)]
        config: PathBuf,

        /// Peer to suspend (name, public key prefix, or VPN IP)
        #[arg(short, long)]
        peer: String,

        /// Suspension expiry (RFC 3339 timestamp, or duration like "24h", "7d")
        #[arg(short, long)]
        expires: Option<String>,

        /// Your identifier (admin email/name)
        #[arg(short = 'b', long)]
        revoked_by: Option<String>,
    },

    /// Reinstate a previously revoked or suspended key
    ReinstateKey {
        /// Server configuration file path
        #[arg(short, long)]
        config: PathBuf,

        /// Peer to reinstate (name, public key prefix, or VPN IP)
        #[arg(short, long)]
        peer: String,
    },

    /// List all revoked and suspended keys
    ListRevoked {
        /// Server configuration file path
        #[arg(short, long)]
        config: PathBuf,

        /// Output as JSON
        #[arg(short, long)]
        json: bool,
    },

    /// Run FIPS 140-3 cryptographic self-tests
    SelfTest {
        /// Output as JSON
        #[arg(short, long)]
        json: bool,
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
        Commands::AddPeer { config, name, endpoint, output } => cmd_add_peer(&config, &name, &endpoint, &output),
        Commands::RemovePeer { config, peer, yes } => cmd_remove_peer(&config, &peer, yes),
        Commands::ListPeers { config, json } => cmd_list_peers(&config, json),
        Commands::Reload { interface } => cmd_reload(&interface),
        Commands::Enroll { server, token, name, mode, output } => cmd_enroll(&server, &token, &name, &mode, &output),
        Commands::RevokeKey { config, peer, reason, revoked_by, yes } => cmd_revoke_key(&config, &peer, &reason, revoked_by.as_deref(), yes),
        Commands::SuspendKey { config, peer, expires, revoked_by } => cmd_suspend_key(&config, &peer, expires.as_deref(), revoked_by.as_deref()),
        Commands::ReinstateKey { config, peer } => cmd_reinstate_key(&config, &peer),
        Commands::ListRevoked { config, json } => cmd_list_revoked(&config, json),
        Commands::SelfTest { json } => cmd_self_test(json),
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

/// Add a new peer to server config and generate client config
fn cmd_add_peer(server_config_path: &Path, client_name: &str, endpoint: &str, output_dir: &Path) -> Result<()> {
    let backend = select_backend();
    
    // Read and parse server config
    let server_config_str = fs::read_to_string(server_config_path)
        .with_context(|| format!("Failed to read server config: {}", server_config_path.display()))?;
    
    let server_config: Config = toml::from_str(&server_config_str)
        .context("Failed to parse server config")?;
    
    // Extract server's public keys from private keys
    let server_priv_bytes = base64::decode(&server_config.interface.private_key)
        .context("Invalid server private_key base64")?;
    let mut server_priv_arr = [0u8; 32];
    server_priv_arr.copy_from_slice(&server_priv_bytes);
    let server_secret = x25519_dalek::StaticSecret::from(server_priv_arr);
    let server_public = x25519_dalek::PublicKey::from(&server_secret);
    let server_public_b64 = base64::encode(server_public.as_bytes());
    
    let server_pq_public_b64 = if let Some(ref pq_priv) = server_config.interface.pq_private_key {
        // For ML-KEM, we need the public key from the private key
        // The PQ public key isn't derivable from private key alone in ML-KEM
        // So we need to look for it in comments or ask the user
        // Workaround: extract from the private key bytes (ML-KEM-768 sk contains pk)
        let pq_priv_bytes = base64::decode(pq_priv)
            .context("Invalid server pq_private_key base64")?;
        // ML-KEM-768 secret key is 2400 bytes; last 1184 bytes are the public key
        if pq_priv_bytes.len() >= 2400 {
            let pk_bytes = &pq_priv_bytes[pq_priv_bytes.len() - 1184..];
            base64::encode(pk_bytes)
        } else {
            anyhow::bail!("Cannot derive PQ public key from server config. \
                Please provide server's pq_public_key manually.");
        }
    } else {
        String::new()
    };
    
    // Determine next available IP
    let (server_ip, prefix) = parse_cidr(&server_config.interface.address)?;
    let existing_ips: Vec<u8> = server_config.peer.iter()
        .filter_map(|p| {
            parse_cidr(&p.allowed_ips).ok()
                .and_then(|(ip, _)| match ip {
                    IpAddr::V4(v4) => Some(v4.octets()[3]),
                    _ => None,
                })
        })
        .collect();
    
    let server_last_octet = match server_ip {
        IpAddr::V4(v4) => v4.octets()[3],
        _ => anyhow::bail!("Only IPv4 supported for auto-IP assignment"),
    };
    
    let base_octets = match server_ip {
        IpAddr::V4(v4) => v4.octets(),
        _ => anyhow::bail!("Only IPv4 supported"),
    };
    
    // Find next free IP (start from server+1, skip existing)
    let mut next_octet = server_last_octet + 1;
    while existing_ips.contains(&next_octet) || next_octet == 0 || next_octet == 255 {
        next_octet += 1;
        if next_octet >= 255 {
            anyhow::bail!("No free IP addresses in subnet");
        }
    }
    
    let client_ip = format!("{}.{}.{}.{}", base_octets[0], base_octets[1], base_octets[2], next_octet);
    let client_cidr = format!("{}/{}", client_ip, prefix);
    let subnet = format!("{}.{}.{}.0/{}", base_octets[0], base_octets[1], base_octets[2], prefix);
    
    // Generate client keys
    let (client_x25519_pub, client_x25519_priv) = backend.x25519_keygen()
        .context("Failed to generate X25519 key")?;
    let (_client_ed25519_pub, _client_ed25519_priv) = backend.ed25519_keygen()
        .context("Failed to generate Ed25519 key")?;
    
    let mut client_pq_pub_b64 = String::new();
    let mut client_pq_priv_b64 = String::new();
    
    if server_config.interface.mode.uses_pq_kex() {
        let (mlkem_pub, mlkem_priv) = backend.mlkem_keygen()
            .context("Failed to generate ML-KEM key")?;
        client_pq_pub_b64 = base64::encode(mlkem_pub.as_bytes());
        client_pq_priv_b64 = base64::encode(mlkem_priv.as_bytes());
    }
    
    // Build the [[peer]] block to append to server config
    let mut peer_block = format!(
        "\n# Peer: {} (added {})\n[[peer]]\npublic_key = \"{}\"\n",
        client_name,
        chrono::Utc::now().format("%Y-%m-%d %H:%M"),
        base64::encode(&client_x25519_pub),
    );
    
    if !client_pq_pub_b64.is_empty() {
        peer_block.push_str(&format!("pq_public_key = \"{}\"\n", client_pq_pub_b64));
    }
    
    peer_block.push_str(&format!("allowed_ips = \"{}/32\"\n", client_ip));
    peer_block.push_str("persistent_keepalive = 25\n");
    
    // Append to server config
    let mut server_file = fs::OpenOptions::new()
        .append(true)
        .open(server_config_path)
        .with_context(|| format!("Failed to open server config for writing: {}", server_config_path.display()))?;
    
    server_file.write_all(peer_block.as_bytes())
        .context("Failed to append peer to server config")?;
    
    // Build client config
    let mode_str = format!("{:?}", server_config.interface.mode).to_lowercase();
    let mut client_config = format!(
        "# DyberVPN Client Configuration — {}\n\
         # Generated: {}\n\
         # Server: {}\n\n\
         [interface]\n\
         name = \"dvpn0\"\n\
         address = \"{}\"\n\
         mode = \"{}\"\n\
         private_key = \"{}\"\n",
        client_name,
        chrono::Utc::now().to_rfc3339(),
        endpoint,
        client_cidr,
        mode_str,
        base64::encode(&client_x25519_priv),
    );
    
    if !client_pq_priv_b64.is_empty() {
        client_config.push_str(&format!("pq_private_key = \"{}\"\n", client_pq_priv_b64));
    }
    
    client_config.push_str(&format!(
        "\n[[peer]]\n\
         public_key = \"{}\"\n",
        server_public_b64,
    ));
    
    if !server_pq_public_b64.is_empty() {
        client_config.push_str(&format!("pq_public_key = \"{}\"\n", server_pq_public_b64));
    }
    
    client_config.push_str(&format!(
        "allowed_ips = \"{}\"\n\
         endpoint = \"{}\"\n\
         persistent_keepalive = 25\n",
        subnet,
        endpoint,
    ));
    
    // Write client config
    let client_config_path = output_dir.join(format!("{}.toml", client_name));
    fs::write(&client_config_path, &client_config)
        .with_context(|| format!("Failed to write client config: {}", client_config_path.display()))?;
    
    // Summary
    println!("\x1b[1;32m✓ Peer '{}' added successfully\x1b[0m", client_name);
    println!();
    println!("  Client IP:     {}", client_ip);
    println!("  Client config: {}", client_config_path.display());
    println!("  Server config: {} (updated)", server_config_path.display());
    println!("  Mode:          {}", mode_str);
    println!();
    println!("  Peers in server config: {}", server_config.peer.len() + 1);
    println!();
    println!("Next steps:");
    println!("  1. Copy {} to the client machine", client_config_path.display());
    println!("  2. On the client: sudo dybervpn up -c {} -f", client_config_path.file_name().unwrap().to_string_lossy());
    println!("  3. Apply changes to a running server (no restart needed):");
    println!("     dybervpn reload dvpn0");
    println!("     — or restart: sudo dybervpn down dvpn0 && sudo dybervpn up -c {} -f", server_config_path.display());
    
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
    
    // Set config path for hot-reload via SIGHUP
    daemon.set_config_path(config_path.to_path_buf());
    
    // ── Enterprise: Policy Engine ──────────────────────────────────────
    if config.access_control.enabled {
        use dybervpn_tunnel::policy::{PolicyConfig, RoleConfig, RuleConfig};
        let policy_cfg = PolicyConfig {
            enabled: true,
            default_action: config.access_control.default_action.clone(),
            policy_path: config.access_control.policy_path.clone(),
            role: config.access_control.role.iter().map(|r| RoleConfig {
                name: r.name.clone(),
                peers: r.peers.clone(),
                peer_keys: r.peer_keys.clone(),
                rule: r.rule.iter().map(|ru| RuleConfig {
                    action: ru.action.clone(),
                    network: ru.network.clone(),
                    ports: ru.ports.clone(),
                    protocol: ru.protocol.clone(),
                    description: ru.description.clone(),
                }).collect(),
            }).collect(),
        };
        daemon.set_policy(policy_cfg);
        tracing::info!("Access control policy engine enabled");
    }
    
    // ── Enterprise: Revocation Engine ──────────────────────────────────
    {
        use dybervpn_tunnel::revocation::SecurityConfig as RevSecConfig;
        let rev_cfg = RevSecConfig {
            crl_path: config.security.crl_path.clone(),
            key_max_age_hours: config.security.key_max_age_hours,
            session_max_age_hours: config.security.session_max_age_hours,
            check_interval_secs: config.security.check_interval_secs,
            auto_disconnect_revoked: config.security.auto_disconnect_revoked,
        };
        daemon.set_revocation(rev_cfg);
        if config.security.crl_path.is_some() {
            tracing::info!("Key revocation engine enabled (CRL: {})",
                config.security.crl_path.as_deref().unwrap_or("none"));
        }
    }
    
    // ── Enterprise: Audit Logger ───────────────────────────────────────
    if config.audit.enabled {
        use dybervpn_tunnel::audit::{AuditConfig, EventCategory};
        let categories: Vec<EventCategory> = config.audit.events.iter().filter_map(|s| {
            match s.to_lowercase().as_str() {
                "connection" => Some(EventCategory::Connection),
                "handshake" => Some(EventCategory::Handshake),
                "policy" => Some(EventCategory::Policy),
                "key_management" => Some(EventCategory::KeyManagement),
                "admin" => Some(EventCategory::Admin),
                "enrollment" => Some(EventCategory::Enrollment),
                "data_plane" | "dataplane" => Some(EventCategory::DataPlane),
                "system" => Some(EventCategory::System),
                "all" => None, // empty vec = all categories
                _ => { tracing::warn!("Unknown audit event category: {}", s); None }
            }
        }).collect();
        
        let audit_cfg = AuditConfig {
            enabled: true,
            path: std::path::PathBuf::from(&config.audit.path),
            max_size_bytes: config.audit.max_size_mb * 1024 * 1024,
            rotate_count: config.audit.rotate_count,
            log_data_packets: config.audit.log_data_packets,
            categories,
            interface_name: config.interface.name.clone(),
        };
        daemon.set_audit(audit_cfg);
        tracing::info!("Audit logging enabled: {}", config.audit.path);
    }
    
    // Get shutdown flag for signal handling
    let shutdown_flag = daemon.shutdown_flag();
    let reload_flag = daemon.reload_flag();
    
    // Set up Ctrl+C handler (and SIGTERM in daemon mode)
    let shutdown_flag_clone = shutdown_flag.clone();
    ctrlc::set_handler(move || {
        tracing::info!("Received shutdown signal");
        shutdown_flag_clone.store(true, Ordering::Relaxed);
    }).context("Failed to set signal handler")?;
    
    // Set up SIGHUP handler for config reload
    #[cfg(unix)]
    {
        let reload_flag_clone = reload_flag.clone();
        unsafe {
            libc::signal(libc::SIGHUP, sighup_handler as libc::sighandler_t);
        }
        // Store the reload flag in a static so the signal handler can access it
        RELOAD_FLAG.store(Box::into_raw(Box::new(reload_flag_clone)) as usize, Ordering::SeqCst);
    }
    
    // Initialize the daemon
    match daemon.init() {
        Ok(_) => {}
        Err(e) => {
            remove_pid_file(&pid_path_clone);
            return Err(e).context("Failed to initialize daemon");
        }
    }
    
    // Start enrollment API if enabled
    if config.enrollment.enabled {
        let enrollment_token = config.enrollment.token.clone()
            .unwrap_or_else(|| {
                tracing::warn!("Enrollment API enabled but no token set — generating random token");
                let mut buf = [0u8; 32];
                use std::io::Read;
                if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
                    let _ = f.read_exact(&mut buf);
                }
                hex::encode(&buf[..16])
            });
        
        let enrollment_listen: SocketAddr = config.enrollment.listen
            .parse()
            .unwrap_or_else(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8443));
        
        let server_endpoint = config.enrollment.server_endpoint.clone()
            .unwrap_or_else(|| format!("0.0.0.0:{}", config.interface.listen_port.unwrap_or(51820)));
        
        let enrollment_config = dybervpn_tunnel::enrollment::EnrollmentConfig {
            listen_addr: enrollment_listen,
            token: enrollment_token.clone(),
            server_config_path: config_path.to_path_buf(),
            server_endpoint,
            reload_flag: reload_flag.clone(),
        };
        
        let enrollment_shutdown = shutdown_flag.clone();
        std::thread::spawn(move || {
            let mut server = dybervpn_tunnel::enrollment::EnrollmentServer::new(
                enrollment_config,
                enrollment_shutdown,
            );
            server.run();
        });
        
        tracing::info!("Enrollment API started on {}", enrollment_listen);
        tracing::info!("Enrollment token: {}", enrollment_token);
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
            name: peer_config.name.clone(),
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

// ════════════════════════════════════════════════════════════════════════════
// SIGHUP Hot-Reload Support
// ════════════════════════════════════════════════════════════════════════════

/// Global atomic to pass the reload flag to the signal handler
static RELOAD_FLAG: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// SIGHUP signal handler — sets the reload flag
#[cfg(unix)]
extern "C" fn sighup_handler(_sig: libc::c_int) {
    let ptr = RELOAD_FLAG.load(Ordering::SeqCst);
    if ptr != 0 {
        let flag = unsafe { &*(ptr as *const Arc<AtomicBool>) };
        flag.store(true, Ordering::Relaxed);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Peer Management Commands
// ════════════════════════════════════════════════════════════════════════════

/// Remove a peer from server config
fn cmd_remove_peer(config_path: &Path, peer_identifier: &str, skip_confirm: bool) -> Result<()> {
    let config_str = fs::read_to_string(config_path)
        .with_context(|| format!("Failed to read config: {}", config_path.display()))?;
    
    // Find the peer to remove by matching:
    // 1. Comment name (# Peer: <name>)
    // 2. Public key prefix
    // 3. VPN IP in allowed_ips
    let lines: Vec<&str> = config_str.lines().collect();
    
    // Find [[peer]] block boundaries
    let mut peer_blocks: Vec<(usize, usize, String, String, String)> = Vec::new(); // (start, end, name, pub_key, allowed_ips)
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim() == "[[peer]]" {
            let block_start = {
                // Include preceding comment lines (# Peer: ...)
                let mut s = i;
                while s > 0 && lines[s - 1].trim().starts_with('#') {
                    s -= 1;
                }
                // Also include blank line before comment
                if s > 0 && lines[s - 1].trim().is_empty() {
                    s -= 1;
                }
                s
            };
            
            // Find end of block (next [[peer]] or EOF)
            let mut block_end = i + 1;
            while block_end < lines.len() {
                if lines[block_end].trim() == "[[peer]]" {
                    break;
                }
                // Also check for preceding comment of next block
                if block_end + 1 < lines.len() && lines[block_end + 1].trim() == "[[peer]]" {
                    if lines[block_end].trim().starts_with('#') {
                        break;
                    }
                }
                block_end += 1;
            }
            
            // Extract fields from this block
            let mut name = String::new();
            let mut pub_key = String::new();
            let mut allowed_ips = String::new();
            
            for j in block_start..block_end {
                let line = lines[j].trim();
                if line.starts_with("# Peer:") {
                    name = line.trim_start_matches("# Peer:").trim()
                        .split('(').next().unwrap_or("").trim().to_string();
                }
                if line.starts_with("public_key") {
                    pub_key = line.split('"').nth(1).unwrap_or("").to_string();
                }
                if line.starts_with("allowed_ips") {
                    allowed_ips = line.split('"').nth(1).unwrap_or("").to_string();
                }
            }
            
            peer_blocks.push((block_start, block_end, name, pub_key, allowed_ips));
            i = block_end;
        } else {
            i += 1;
        }
    }
    
    if peer_blocks.is_empty() {
        println!("No peers found in config.");
        return Ok(());
    }
    
    // Find matching peer
    let identifier_lower = peer_identifier.to_lowercase();
    let matched: Vec<_> = peer_blocks.iter().enumerate().filter(|(_, (_, _, name, pub_key, allowed_ips))| {
        name.to_lowercase().contains(&identifier_lower)
        || pub_key.to_lowercase().starts_with(&identifier_lower)
        || allowed_ips.contains(peer_identifier)
    }).collect();
    
    if matched.is_empty() {
        anyhow::bail!(
            "No peer found matching '{}'. Use 'dybervpn list-peers -c {}' to see all peers.",
            peer_identifier,
            config_path.display()
        );
    }
    
    if matched.len() > 1 {
        println!("Multiple peers match '{}':", peer_identifier);
        for (_, (_, _, name, pub_key, allowed_ips)) in &matched {
            let display_name = if name.is_empty() { "unnamed" } else { name };
            println!("  - {} (key: {}..., ips: {})", display_name, &pub_key[..16.min(pub_key.len())], allowed_ips);
        }
        anyhow::bail!("Be more specific to match a single peer.");
    }
    
    let (_, (start, end, name, pub_key, allowed_ips)) = matched[0];
    let display_name = if name.is_empty() { "unnamed" } else { name };
    
    // Confirm removal
    if !skip_confirm {
        println!("Removing peer:");
        println!("  Name:        {}", display_name);
        println!("  Public key:  {}...", &pub_key[..16.min(pub_key.len())]);
        println!("  Allowed IPs: {}", allowed_ips);
        println!();
        print!("Confirm removal? [y/N] ");
        std::io::stdout().flush()?;
        
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Cancelled.");
            return Ok(());
        }
    }
    
    // Remove the peer block from the config
    let mut new_lines: Vec<&str> = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        if idx >= *start && idx < *end {
            continue;
        }
        new_lines.push(line);
    }
    
    // Remove trailing blank lines from the result
    while new_lines.last().map(|l| l.trim().is_empty()).unwrap_or(false) {
        new_lines.pop();
    }
    
    let new_config = new_lines.join("\n") + "\n";
    
    fs::write(config_path, &new_config)
        .with_context(|| format!("Failed to write config: {}", config_path.display()))?;
    
    let remaining = peer_blocks.len() - 1;
    
    println!("\x1b[1;32m✓ Peer '{}' removed\x1b[0m", display_name);
    println!();
    println!("  Config: {} (updated)", config_path.display());
    println!("  Remaining peers: {}", remaining);
    println!();
    println!("To apply changes to a running tunnel:");
    println!("  sudo kill -HUP $(cat /var/run/dybervpn/dvpn0.pid)");
    println!("  — or —");
    println!("  dybervpn reload dvpn0");
    
    Ok(())
}

/// List all peers in a config
fn cmd_list_peers(config_path: &Path, json: bool) -> Result<()> {
    let config_str = fs::read_to_string(config_path)
        .with_context(|| format!("Failed to read config: {}", config_path.display()))?;
    
    let config: Config = toml::from_str(&config_str)
        .context("Failed to parse config file")?;
    
    if json {
        #[derive(serde::Serialize)]
        struct PeerInfo {
            index: usize,
            public_key: String,
            pq_public_key: Option<String>,
            allowed_ips: String,
            endpoint: Option<String>,
            keepalive: u16,
        }
        
        let peers: Vec<PeerInfo> = config.peer.iter().enumerate().map(|(i, p)| {
            PeerInfo {
                index: i,
                public_key: p.public_key.clone(),
                pq_public_key: p.pq_public_key.as_ref().map(|k| format!("{}...", &k[..20.min(k.len())])),
                allowed_ips: p.allowed_ips.clone(),
                endpoint: p.endpoint.clone(),
                keepalive: p.persistent_keepalive,
            }
        }).collect();
        
        println!("{}", serde_json::to_string_pretty(&peers)?);
        return Ok(());
    }
    
    println!("Peers in {} (mode: {:?}):", config_path.display(), config.interface.mode);
    println!();
    
    if config.peer.is_empty() {
        println!("  (no peers configured)");
        return Ok(());
    }
    
    // Also scan for comment names
    let lines: Vec<&str> = config_str.lines().collect();
    let mut peer_names: Vec<String> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if line.trim() == "[[peer]]" {
            // Look back for # Peer: comment
            let mut name = String::new();
            if i > 0 {
                for j in (0..i).rev() {
                    let l = lines[j].trim();
                    if l.starts_with("# Peer:") {
                        name = l.trim_start_matches("# Peer:").trim()
                            .split('(').next().unwrap_or("").trim().to_string();
                        break;
                    }
                    if !l.starts_with('#') && !l.is_empty() {
                        break;
                    }
                }
            }
            peer_names.push(name);
        }
    }
    
    for (i, peer) in config.peer.iter().enumerate() {
        let name = peer_names.get(i).and_then(|n| if n.is_empty() { None } else { Some(n.as_str()) });
        let display_name = name.unwrap_or("unnamed");
        
        println!("  [{}] {}", i + 1, display_name);
        println!("      Public key:  {}...", &peer.public_key[..20.min(peer.public_key.len())]);
        if let Some(ref pq) = peer.pq_public_key {
            println!("      PQ key:      {}... ({} chars)", &pq[..20.min(pq.len())], pq.len());
        }
        println!("      Allowed IPs: {}", peer.allowed_ips);
        if let Some(ref ep) = peer.endpoint {
            println!("      Endpoint:    {}", ep);
        }
        if peer.persistent_keepalive > 0 {
            println!("      Keepalive:   {} sec", peer.persistent_keepalive);
        }
        println!();
    }
    
    println!("Total: {} peers", config.peer.len());
    
    Ok(())
}

/// Send SIGHUP to a running tunnel to reload config
fn cmd_reload(interface: &str) -> Result<()> {
    let pid_path = get_pid_path(interface);
    
    // Also check fallback locations
    let pid_file = if pid_path.exists() {
        pid_path
    } else {
        let primary = PathBuf::from(format!("{}/{}.pid", PID_DIR_PRIMARY, interface));
        let fallback = PathBuf::from(format!("{}/dybervpn-{}.pid", PID_DIR_FALLBACK, interface));
        if primary.exists() {
            primary
        } else if fallback.exists() {
            fallback
        } else {
            anyhow::bail!(
                "No PID file found for '{}'. Is the tunnel running?",
                interface
            );
        }
    };
    
    let pid_str = fs::read_to_string(&pid_file)
        .context("Failed to read PID file")?;
    let pid: i32 = pid_str.trim().parse()
        .context("Invalid PID in file")?;
    
    #[cfg(unix)]
    {
        // Check process exists
        if !is_process_running(pid) {
            anyhow::bail!("Process {} is not running. The tunnel may have stopped.", pid);
        }
        
        // Send SIGHUP
        let result = unsafe { libc::kill(pid, libc::SIGHUP) };
        if result != 0 {
            let err = std::io::Error::last_os_error();
            anyhow::bail!("Failed to send SIGHUP to process {}: {}", pid, err);
        }
        
        println!("\x1b[1;32m✓ Sent reload signal to '{}' (PID {})\x1b[0m", interface, pid);
        println!();
        println!("The tunnel will re-read its config file and add/remove peers.");
        println!("Active sessions for unchanged peers are preserved.");
    }
    
    #[cfg(not(unix))]
    {
        anyhow::bail!("Config reload via signal is only supported on Unix.");
    }
    
    Ok(())
}

/// Enroll with a DyberVPN server's enrollment API
fn cmd_enroll(server_url: &str, token: &str, name: &str, mode: &str, output: &Path) -> Result<()> {
    let mode: OperatingMode = mode.parse().context("Invalid mode")?;
    let backend = select_backend();

    // Generate client keys
    eprintln!("Generating client keys...");
    let (x25519_pub, x25519_priv) = backend.x25519_keygen()
        .context("X25519 keygen failed")?;

    let mut pq_pub_b64: Option<String> = None;
    let mut pq_priv_b64: Option<String> = None;

    if mode.uses_pq_kex() {
        let (pk, sk) = backend.mlkem_keygen().context("ML-KEM keygen failed")?;
        pq_pub_b64 = Some(base64::encode(pk.as_bytes()));
        pq_priv_b64 = Some(base64::encode(sk.as_bytes()));
    }

    let mut mldsa_pub_b64: Option<String> = None;
    let mut _mldsa_priv_b64: Option<String> = None;

    if mode.uses_pq_auth() {
        let (pk, sk) = backend.mldsa_keygen().context("ML-DSA keygen failed")?;
        mldsa_pub_b64 = Some(base64::encode(pk.as_bytes()));
        _mldsa_priv_b64 = Some(base64::encode(sk.as_bytes()));
    }

    // Build enrollment request JSON
    let mut request_body = format!(
        r#"{{"name":"{}","public_key":"{}""#,
        name,
        base64::encode(&x25519_pub)
    );
    if let Some(ref pq_pk) = pq_pub_b64 {
        request_body.push_str(&format!(r#","pq_public_key":"{}""#, pq_pk));
    }
    if let Some(ref mldsa_pk) = mldsa_pub_b64 {
        request_body.push_str(&format!(r#","mldsa_public_key":"{}""#, mldsa_pk));
    }
    request_body.push('}');

    // Parse server URL
    let url = server_url.trim_end_matches('/');
    let url = if url.starts_with("http://") || url.starts_with("https://") {
        url.to_string()
    } else {
        format!("http://{}", url)
    };

    // Extract host:port
    let host_port = url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .to_string();

    eprintln!("Enrolling '{}' with server {}...", name, host_port);

    // Connect and send HTTP request
    use std::io::{Read, Write as IoWrite};
    use std::net::TcpStream;

    let mut stream = TcpStream::connect(&host_port)
        .with_context(|| format!("Failed to connect to enrollment server at {}", host_port))?;

    stream.set_read_timeout(Some(std::time::Duration::from_secs(10))).ok();

    let http_request = format!(
        "POST /enroll HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        host_port, token, request_body.len(), request_body
    );

    stream.write_all(http_request.as_bytes())
        .context("Failed to send enrollment request")?;
    stream.flush().context("flush")?;

    // Read response
    let mut response = String::new();
    stream.read_to_string(&mut response)
        .context("Failed to read enrollment response")?;

    // Parse HTTP response (find the JSON body after headers)
    let body = response.split("\r\n\r\n").nth(1)
        .or_else(|| response.split("\n\n").nth(1))
        .unwrap_or(&response);

    let enroll_response: serde_json::Value = serde_json::from_str(body)
        .with_context(|| format!("Invalid enrollment response: {}", body))?;

    if !enroll_response["success"].as_bool().unwrap_or(false) {
        let err = enroll_response["error"].as_str().unwrap_or("unknown error");
        anyhow::bail!("Enrollment failed: {}", err);
    }

    let assigned_ip = enroll_response["assigned_ip"].as_str().unwrap_or("?");
    let client_config_template = enroll_response["client_config"].as_str()
        .context("Missing client_config in response")?;

    // Insert our private keys into the config
    let final_config = client_config_template
        .replace(
            "# IMPORTANT: Add your private keys below\n# private_key = \"YOUR_X25519_PRIVATE_KEY\"",
            &format!("private_key = \"{}\"", base64::encode(&x25519_priv)),
        )
        .replace(
            "# pq_private_key = \"YOUR_MLKEM_PRIVATE_KEY\"",
            &match pq_priv_b64 {
                Some(ref k) => format!("pq_private_key = \"{}\"", k),
                None => String::new(),
            },
        );

    // Write config
    let config_path = output.join(format!("{}.toml", name));
    fs::write(&config_path, &final_config)
        .with_context(|| format!("Failed to write config: {}", config_path.display()))?;

    println!("\x1b[1;32m\u{2713} Enrolled successfully!\x1b[0m");
    println!();
    println!("  Name:        {}", name);
    println!("  Assigned IP: {}", assigned_ip);
    println!("  Config:      {}", config_path.display());
    println!("  Mode:        {:?}", mode);
    println!();
    println!("Next steps:");
    println!("  sudo dybervpn up -c {} -f", config_path.display());

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

// ════════════════════════════════════════════════════════════════════════════
// Enterprise Key Lifecycle Commands
// ════════════════════════════════════════════════════════════════════════════

/// Resolve a peer identifier (name, key prefix, or IP) to a (public_key_bytes, display_name) pair.
/// Reads the server config and scans [[peer]] blocks + comment names.
fn resolve_peer_from_config(config_path: &Path, identifier: &str) -> Result<([u8; 32], String)> {
    let config_str = fs::read_to_string(config_path)
        .with_context(|| format!("Failed to read config: {}", config_path.display()))?;

    let config: Config = toml::from_str(&config_str)
        .context("Failed to parse config file")?;

    // Also extract comment names by scanning raw lines
    let lines: Vec<&str> = config_str.lines().collect();
    let mut peer_names: Vec<String> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if line.trim() == "[[peer]]" {
            let mut name = String::new();
            if i > 0 {
                for j in (0..i).rev() {
                    let l = lines[j].trim();
                    if l.starts_with("# Peer:") {
                        name = l.trim_start_matches("# Peer:").trim()
                            .split('(').next().unwrap_or("").trim().to_string();
                        break;
                    }
                    if !l.starts_with('#') && !l.is_empty() {
                        break;
                    }
                }
            }
            peer_names.push(name);
        }
    }

    let id_lower = identifier.to_lowercase();
    let mut matches: Vec<([u8; 32], String)> = Vec::new();

    for (i, peer) in config.peer.iter().enumerate() {
        // Prefer the structured `name` field; fall back to comment-based name
        let name = peer.name.as_deref()
            .or_else(|| peer_names.get(i)
                .and_then(|n| if n.is_empty() { None } else { Some(n.as_str()) })
            );

        let pk_bytes = base64::decode(&peer.public_key)
            .ok()
            .filter(|b| b.len() == 32);
        let pk_hex = pk_bytes.as_ref()
            .map(|b| hex::encode(&b[..4]))
            .unwrap_or_default();

        let matches_name = name.map(|n| n.to_lowercase().contains(&id_lower)).unwrap_or(false);
        let matches_key = peer.public_key.to_lowercase().starts_with(&id_lower)
            || pk_hex.starts_with(&id_lower);
        let matches_ip = peer.allowed_ips.contains(identifier);

        if matches_name || matches_key || matches_ip {
            if let Some(ref bytes) = pk_bytes {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(bytes);
                let display = name.unwrap_or("unnamed").to_string();
                matches.push((arr, display));
            }
        }
    }

    match matches.len() {
        0 => anyhow::bail!(
            "No peer found matching '{}'. Use 'dybervpn list-peers -c {}' to see all peers.",
            identifier, config_path.display()
        ),
        1 => Ok(matches.into_iter().next().unwrap()),
        n => {
            eprintln!("Multiple peers ({}) match '{}'. Be more specific.", n, identifier);
            for (pk, name) in &matches {
                eprintln!("  - {} (key: {}...)", name, hex::encode(&pk[..4]));
            }
            anyhow::bail!("Ambiguous peer identifier");
        }
    }
}

/// Parse a revocation reason string into the enum
fn parse_revocation_reason(s: &str) -> dybervpn_tunnel::revocation::RevocationReason {
    use dybervpn_tunnel::revocation::RevocationReason;
    match s.to_lowercase().as_str() {
        "employee_departed" | "departed" | "left" => RevocationReason::EmployeeDeparted,
        "key_compromised" | "compromised" => RevocationReason::KeyCompromised,
        "device_lost" | "lost" | "stolen" => RevocationReason::DeviceLost,
        "key_superseded" | "superseded" | "rotated" => RevocationReason::KeySuperseded,
        "policy_violation" | "violation" => RevocationReason::PolicyViolation,
        "administrative" | "admin" => RevocationReason::Administrative,
        "suspended" | "suspend" => RevocationReason::Suspended,
        other => RevocationReason::Other(other.to_string()),
    }
}

/// Get the CRL path from config, with a sensible default
fn get_crl_path(config_path: &Path) -> Result<PathBuf> {
    let config_str = fs::read_to_string(config_path)
        .with_context(|| format!("Failed to read config: {}", config_path.display()))?;
    let config: Config = toml::from_str(&config_str)
        .context("Failed to parse config file")?;

    if let Some(ref crl) = config.security.crl_path {
        Ok(PathBuf::from(crl))
    } else {
        // Default: same directory as the config file
        let dir = config_path.parent().unwrap_or(Path::new("."));
        Ok(dir.join("revoked-keys.json"))
    }
}

/// Revoke a peer's key — adds to CRL, optionally triggers live disconnect via reload
fn cmd_revoke_key(
    config_path: &Path,
    peer_identifier: &str,
    reason: &str,
    revoked_by: Option<&str>,
    skip_confirm: bool,
) -> Result<()> {
    use dybervpn_tunnel::revocation::{RevocationEngine, SecurityConfig as RevSecConfig};

    let (peer_key, peer_name) = resolve_peer_from_config(config_path, peer_identifier)?;
    let crl_path = get_crl_path(config_path)?;
    let reason_enum = parse_revocation_reason(reason);

    if !skip_confirm {
        println!("Revoking key for peer:");
        println!("  Name:        {}", peer_name);
        println!("  Public key:  {}...", hex::encode(&peer_key[..8]));
        println!("  Reason:      {}", reason);
        println!("  CRL file:    {}", crl_path.display());
        if let Some(by) = revoked_by {
            println!("  Revoked by:  {}", by);
        }
        println!();
        print!("Confirm revocation? [y/N] ");
        std::io::stdout().flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Cancelled.");
            return Ok(());
        }
    }

    // Create engine pointing at CRL file
    let rev_cfg = RevSecConfig {
        crl_path: Some(crl_path.to_string_lossy().to_string()),
        ..RevSecConfig::default()
    };
    let mut engine = RevocationEngine::new(rev_cfg);

    engine.revoke_key(&peer_key, Some(&peer_name), reason_enum, revoked_by)
        .map_err(|e| anyhow::anyhow!("Revocation failed: {}", e))?;

    println!("\x1b[1;32m✓ Key revoked for peer '{}'\x1b[0m", peer_name);
    println!();
    println!("  Fingerprint: {}", hex::encode(&peer_key[..8]));
    println!("  Reason:      {}", reason);
    println!("  CRL file:    {}", crl_path.display());
    println!();
    println!("The revocation takes effect:");
    println!("  • Immediately for new handshake attempts (if daemon has [security] crl_path set)");
    println!("  • On next CRL check for existing sessions (default: every 5 minutes)");
    println!("  • Immediately if you send a config reload:");
    println!("      dybervpn reload dvpn0");
    println!();
    println!("To also remove the peer from the config entirely:");
    println!("  dybervpn remove-peer -c {} -p {}", config_path.display(), peer_identifier);

    Ok(())
}

/// Temporarily suspend a peer's key
fn cmd_suspend_key(
    config_path: &Path,
    peer_identifier: &str,
    expires: Option<&str>,
    revoked_by: Option<&str>,
) -> Result<()> {
    use dybervpn_tunnel::revocation::{RevocationEngine, SecurityConfig as RevSecConfig};

    let (peer_key, peer_name) = resolve_peer_from_config(config_path, peer_identifier)?;
    let crl_path = get_crl_path(config_path)?;

    // Parse expiry: accept RFC 3339 or durations like "24h", "7d", "1w"
    let expires_rfc3339 = expires.map(|e| {
        // Try RFC 3339 first
        if chrono::DateTime::parse_from_rfc3339(e).is_ok() {
            return e.to_string();
        }
        // Parse duration shortcuts
        let now = chrono::Utc::now();
        let e_lower = e.to_lowercase();
        let duration = if let Some(h) = e_lower.strip_suffix('h') {
            h.parse::<i64>().ok().and_then(|n| chrono::TimeDelta::try_hours(n))
        } else if let Some(d) = e_lower.strip_suffix('d') {
            d.parse::<i64>().ok().and_then(|n| chrono::TimeDelta::try_days(n))
        } else if let Some(w) = e_lower.strip_suffix('w') {
            w.parse::<i64>().ok().and_then(|n| chrono::TimeDelta::try_weeks(n))
        } else {
            None
        };
        match duration {
            Some(d) => (now + d).to_rfc3339(),
            None => {
                eprintln!("Warning: could not parse expiry '{}', suspension will be indefinite", e);
                String::new()
            }
        }
    });

    let expires_str = expires_rfc3339.as_deref().filter(|s| !s.is_empty());

    let rev_cfg = RevSecConfig {
        crl_path: Some(crl_path.to_string_lossy().to_string()),
        ..RevSecConfig::default()
    };
    let mut engine = RevocationEngine::new(rev_cfg);

    engine.suspend_key(&peer_key, Some(&peer_name), expires_str, revoked_by)
        .map_err(|e| anyhow::anyhow!("Suspension failed: {}", e))?;

    println!("\x1b[1;33m⏸ Key suspended for peer '{}'\x1b[0m", peer_name);
    println!();
    println!("  Fingerprint: {}", hex::encode(&peer_key[..8]));
    if let Some(exp) = expires_str {
        println!("  Expires:     {}", exp);
    } else {
        println!("  Expires:     indefinite (manual reinstatement required)");
    }
    println!("  CRL file:    {}", crl_path.display());
    println!();
    println!("To reinstate:");
    println!("  dybervpn reinstate-key -c {} -p {}", config_path.display(), peer_identifier);

    Ok(())
}

/// Reinstate a previously revoked or suspended key
fn cmd_reinstate_key(config_path: &Path, peer_identifier: &str) -> Result<()> {
    use dybervpn_tunnel::revocation::{RevocationEngine, SecurityConfig as RevSecConfig};

    let (peer_key, peer_name) = resolve_peer_from_config(config_path, peer_identifier)?;
    let crl_path = get_crl_path(config_path)?;

    let rev_cfg = RevSecConfig {
        crl_path: Some(crl_path.to_string_lossy().to_string()),
        ..RevSecConfig::default()
    };
    let mut engine = RevocationEngine::new(rev_cfg);

    if !engine.is_revoked(&peer_key) {
        println!("Peer '{}' ({}) is not currently revoked or suspended.",
            peer_name, hex::encode(&peer_key[..4]));
        return Ok(());
    }

    engine.reinstate_key(&peer_key)
        .map_err(|e| anyhow::anyhow!("Reinstatement failed: {}", e))?;

    println!("\x1b[1;32m✓ Key reinstated for peer '{}'\x1b[0m", peer_name);
    println!();
    println!("  Fingerprint: {}", hex::encode(&peer_key[..8]));
    println!("  CRL file:    {} (updated)", crl_path.display());
    println!();
    println!("The peer can now reconnect. To force immediate effect:");
    println!("  dybervpn reload dvpn0");

    Ok(())
}

/// List all revoked and suspended keys
fn cmd_list_revoked(config_path: &Path, json: bool) -> Result<()> {
    use dybervpn_tunnel::revocation::{RevocationEngine, SecurityConfig as RevSecConfig};

    let crl_path = get_crl_path(config_path)?;

    if !crl_path.exists() {
        if json {
            println!("[]");
        } else {
            println!("No CRL file found at {}", crl_path.display());
            println!("No keys have been revoked yet.");
        }
        return Ok(());
    }

    let rev_cfg = RevSecConfig {
        crl_path: Some(crl_path.to_string_lossy().to_string()),
        ..RevSecConfig::default()
    };
    let engine = RevocationEngine::new(rev_cfg);
    let revoked = engine.list_revoked();

    if json {
        let entries: Vec<serde_json::Value> = revoked.iter().map(|e| {
            serde_json::json!({
                "fingerprint": e.public_key_fingerprint,
                "name": e.name,
                "reason": format!("{}", e.reason),
                "revoked_at": e.revoked_at,
                "revoked_by": e.revoked_by,
                "expires_at": e.expires_at,
            })
        }).collect();
        println!("{}", serde_json::to_string_pretty(&entries)?);
        return Ok(());
    }

    println!("Revoked/Suspended Keys (CRL: {})", crl_path.display());
    println!();

    if revoked.is_empty() {
        println!("  (no revoked keys)");
        return Ok(());
    }

    for (i, entry) in revoked.iter().enumerate() {
        let status_icon = match entry.reason {
            dybervpn_tunnel::revocation::RevocationReason::Suspended => "⏸",
            _ => "✗",
        };
        let name_display = entry.name.as_deref().unwrap_or("unnamed");

        println!("  {} [{}] {}", status_icon, i + 1, name_display);
        println!("      Fingerprint: {}", entry.public_key_fingerprint);
        println!("      Reason:      {}", entry.reason);
        println!("      Revoked at:  {}", entry.revoked_at);
        if let Some(ref by) = entry.revoked_by {
            println!("      Revoked by:  {}", by);
        }
        if let Some(ref exp) = entry.expires_at {
            println!("      Expires:     {}", exp);
        }
        println!();
    }

    println!("Total: {} entries", revoked.len());

    Ok(())
}

/// Run FIPS 140-3 cryptographic self-tests
fn cmd_self_test(json: bool) -> Result<()> {
    let backend = dybervpn_protocol::select_backend();
    
    if !json {
        println!("Running FIPS 140-3 cryptographic self-tests...");
        println!("Backend: {}\n", backend.name());
    }
    
    let report = dybervpn_protocol::fips::run_on_demand_self_tests(backend.as_ref());
    
    if json {
        // Machine-readable output for CI/CD and compliance tooling
        let json_results: Vec<serde_json::Value> = report.results.iter().map(|r| {
            serde_json::json!({
                "name": r.name,
                "passed": r.passed,
                "duration_us": r.duration.as_micros(),
                "error": r.error,
            })
        }).collect();
        
        let output = serde_json::json!({
            "fips_self_test": {
                "passed": report.passed,
                "module_state": format!("{}", report.module_state),
                "backend": report.backend,
                "timestamp": report.timestamp,
                "duration_us": report.duration.as_micros() as u64,
                "tests": json_results,
            }
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        // Human-readable report
        println!("{}", report);
    }
    
    if report.passed {
        Ok(())
    } else {
        anyhow::bail!("FIPS 140-3 self-tests FAILED")
    }
}
