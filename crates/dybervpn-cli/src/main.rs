//! DyberVPN CLI — Post-Quantum VPN Command Line Interface

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use dybervpn_protocol::{select_backend, Config, OperatingMode};
use std::path::PathBuf;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

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
    },

    /// Derive public key from private key (reads from stdin)
    Pubkey,

    /// Start a VPN tunnel
    Up {
        /// Path to configuration file
        #[arg(value_name = "CONFIG")]
        config: PathBuf,
        
        /// Run in foreground (don't daemonize)
        #[arg(short, long)]
        foreground: bool,
    },

    /// Stop a VPN tunnel
    Down {
        /// Interface name (e.g., dvpn0)
        #[arg(value_name = "INTERFACE")]
        interface: String,
    },

    /// Show tunnel status
    Status {
        /// Interface name (optional, shows all if not specified)
        #[arg(value_name = "INTERFACE")]
        interface: Option<String>,
    },

    /// Validate a configuration file
    Check {
        /// Path to configuration file
        #[arg(value_name = "CONFIG")]
        config: PathBuf,
    },

    /// Interactive setup wizard
    Init {
        /// Generate server configuration
        #[arg(long, conflicts_with = "client")]
        server: bool,
        
        /// Generate client configuration pointing to server
        #[arg(long, value_name = "SERVER_IP")]
        client: Option<String>,
        
        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Show version and crypto backend info
    Version,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("warn")
    };

    tracing_subscriber::registry()
        .with(fmt::layer().with_target(false))
        .with(filter)
        .init();

    match cli.command {
        Commands::Genkey { mode } => cmd_genkey(&mode),
        Commands::Pubkey => cmd_pubkey(),
        Commands::Up { config, foreground } => cmd_up(&config, foreground),
        Commands::Down { interface } => cmd_down(&interface),
        Commands::Status { interface } => cmd_status(interface.as_deref()),
        Commands::Check { config } => cmd_check(&config),
        Commands::Init { server, client, output } => cmd_init(server, client, output),
        Commands::Version => cmd_version(),
    }
}

/// Generate a new key pair
fn cmd_genkey(mode: &str) -> Result<()> {
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

    println!("# DyberVPN Key Pair");
    println!("# Mode: {:?}", mode);
    println!();

    // Output classical keys (WireGuard-compatible format)
    println!("# Classical Keys (WireGuard-compatible)");
    println!("PrivateKey = {}", base64::encode(x25519_priv));
    println!("PublicKey = {}", base64::encode(x25519_pub));
    println!();

    // Output signing keys
    println!("# Signing Keys (Ed25519)");
    println!("SigningPrivateKey = {}", base64::encode(ed25519_priv));
    println!("SigningPublicKey = {}", base64::encode(ed25519_pub));

    // Generate PQ keys if needed
    if mode.uses_pq_kex() {
        println!();
        println!("# Post-Quantum Keys (ML-KEM-768)");

        let (mlkem_pub, mlkem_priv) = backend
            .mlkem_keygen()
            .context("Failed to generate ML-KEM key")?;

        println!("PQPrivateKey = {}", base64::encode(mlkem_priv.as_bytes()));
        println!("PQPublicKey = {}", base64::encode(mlkem_pub.as_bytes()));
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

/// Start a VPN tunnel
fn cmd_up(config_path: &PathBuf, foreground: bool) -> Result<()> {
    // Load and validate configuration
    let config = Config::from_file(config_path)
        .with_context(|| format!("Failed to load config from {:?}", config_path))?;
    
    let mode = if config.is_server() { "server" } else { "client" };
    let interface = &config.interface.name;
    
    println!("Starting DyberVPN {} on interface {}...", mode, interface);
    println!("  Mode: {:?}", config.interface.mode);
    println!("  Address: {}", config.interface.address);
    
    if let Some(port) = config.interface.listen_port {
        println!("  Listen port: {}", port);
    }
    
    println!("  Peers: {}", config.peer.len());
    
    if config.interface.mode.uses_pq_kex() {
        println!("  Post-quantum: ML-KEM-768 + X25519 (hybrid)");
    } else {
        println!("  Post-quantum: disabled (classic mode)");
    }
    
    if foreground {
        println!();
        println!("Running in foreground. Press Ctrl+C to stop.");
        
        // TODO: Actually start the tunnel
        // For now, just wait
        println!();
        println!("[NOT YET IMPLEMENTED] Tunnel would start here.");
        println!("The handshake integration with BoringTun is in progress.");
        
    } else {
        // TODO: Daemonize
        println!();
        println!("[NOT YET IMPLEMENTED] Daemonization not yet available on this platform.");
        println!("Use --foreground (-f) to run in the foreground.");
    }
    
    Ok(())
}

/// Stop a VPN tunnel
fn cmd_down(interface: &str) -> Result<()> {
    println!("Stopping DyberVPN interface {}...", interface);
    
    // TODO: Actually stop the tunnel
    println!();
    println!("[NOT YET IMPLEMENTED] Interface shutdown not yet implemented.");
    
    Ok(())
}

/// Show tunnel status
fn cmd_status(interface: Option<&str>) -> Result<()> {
    match interface {
        Some(iface) => {
            println!("Status for interface {}:", iface);
        }
        None => {
            println!("DyberVPN Status");
            println!("===============");
        }
    }
    
    println!();
    println!("[NOT YET IMPLEMENTED] Status display not yet implemented.");
    println!();
    println!("When implemented, this will show:");
    println!("  - Active interfaces");
    println!("  - Connected peers");
    println!("  - Handshake times");
    println!("  - Transfer statistics");
    println!("  - PQ mode status");
    
    Ok(())
}

/// Validate a configuration file
fn cmd_check(config_path: &PathBuf) -> Result<()> {
    println!("Checking configuration: {:?}", config_path);
    
    let config = Config::from_file(config_path)
        .with_context(|| format!("Failed to load config from {:?}", config_path))?;
    
    println!();
    println!("Configuration is valid!");
    println!();
    println!("Summary:");
    println!("  Type: {}", if config.is_server() { "Server" } else { "Client" });
    println!("  Mode: {:?}", config.interface.mode);
    println!("  Interface: {}", config.interface.name);
    println!("  Address: {}", config.interface.address);
    println!("  MTU: {}", config.interface.mtu);
    
    if let Some(port) = config.interface.listen_port {
        println!("  Listen port: {}", port);
    }
    
    println!("  Peers: {}", config.peer.len());
    
    for (i, peer) in config.peer.iter().enumerate() {
        println!();
        println!("  Peer #{}:", i + 1);
        let key_preview = if peer.public_key.len() > 20 { 
            &peer.public_key[..20] 
        } else { 
            &peer.public_key 
        };
        println!("    Public key: {}...", key_preview);
        println!("    Allowed IPs: {}", peer.allowed_ips);
        if let Some(ref endpoint) = peer.endpoint {
            println!("    Endpoint: {}", endpoint);
        }
        if peer.persistent_keepalive > 0 {
            println!("    Keepalive: {}s", peer.persistent_keepalive);
        }
        if peer.pq_public_key.is_some() {
            println!("    PQ key: present");
        }
    }
    
    Ok(())
}

/// Interactive setup wizard
fn cmd_init(server: bool, client: Option<String>, output: Option<PathBuf>) -> Result<()> {
    let backend = select_backend();
    
    // Generate keys
    let (x25519_pub, x25519_priv) = backend.x25519_keygen().context("Failed to generate X25519 key")?;
    let (mlkem_pub, mlkem_priv) = backend.mlkem_keygen().context("Failed to generate ML-KEM key")?;
    
    let config = if server {
        format!(r#"# DyberVPN Server Configuration
# Generated by: dybervpn init --server

[interface]
# Your private keys (KEEP SECRET!)
private_key = "{}"
pq_private_key = "{}"

# Server settings
listen_port = 51820
address = "10.0.0.1/24"
mode = "hybrid"

# Uncomment and configure for each client:
# [[peer]]
# public_key = "CLIENT_PUBLIC_KEY"
# pq_public_key = "CLIENT_PQ_PUBLIC_KEY"
# allowed_ips = "10.0.0.2/32"
"#,
            base64::encode(x25519_priv),
            base64::encode(mlkem_priv.as_bytes())
        )
    } else if let Some(server_ip) = client {
        format!(r#"# DyberVPN Client Configuration
# Generated by: dybervpn init --client {}

[interface]
# Your private keys (KEEP SECRET!)
private_key = "{}"
pq_private_key = "{}"

# Client settings
address = "10.0.0.2/24"
mode = "hybrid"
dns = ["10.0.0.1"]

[[peer]]
# Get these from your server administrator
public_key = "SERVER_PUBLIC_KEY_HERE"
pq_public_key = "SERVER_PQ_PUBLIC_KEY_HERE"

# Server endpoint
endpoint = "{}:51820"

# Route all traffic through VPN
allowed_ips = "0.0.0.0/0, ::/0"

# Keep connection alive
persistent_keepalive = 25
"#,
            server_ip,
            base64::encode(x25519_priv),
            base64::encode(mlkem_priv.as_bytes()),
            server_ip
        )
    } else {
        anyhow::bail!("Please specify --server or --client <SERVER_IP>");
    };
    
    // Output
    match output {
        Some(path) => {
            std::fs::write(&path, &config)?;
            eprintln!("Configuration written to: {:?}", path);
            eprintln!();
            eprintln!("Your public keys (share with peers):");
            eprintln!("  PublicKey = {}", base64::encode(x25519_pub));
            eprintln!("  PQPublicKey = {}", base64::encode(mlkem_pub.as_bytes()));
        }
        None => {
            println!("{}", config);
            eprintln!();
            eprintln!("# Your public keys (share with peers):");
            eprintln!("# PublicKey = {}", base64::encode(x25519_pub));
            eprintln!("# PQPublicKey = {}", base64::encode(mlkem_pub.as_bytes()));
        }
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
    println!("  Authentication: Ed25519 (Phase 1)");
    println!("  AEAD: ChaCha20-Poly1305");
    println!("  Hash: BLAKE2s, SHA-256");
    println!();
    println!("Compliance:");
    println!("  NIST FIPS 203 (ML-KEM)");
    println!("  CNSA 2.0 Aligned");
    println!();
    println!("License: Apache-2.0 (new code), BSD-3-Clause (BoringTun-derived)");

    Ok(())
}
