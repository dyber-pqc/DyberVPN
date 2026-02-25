![DyberVPN logo banner](./banner.svg)

# DyberVPN

**Post-Quantum VPN for Infrastructure You Control**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![Tests](https://img.shields.io/badge/tests-58%20passing-brightgreen.svg)](#testing)

DyberVPN is an open-source, self-hosted, post-quantum cryptography (PQC) VPN built for organizations that cannot route traffic through third-party cloud providers. It implements NIST-standardized post-quantum algorithms (ML-KEM-768, ML-DSA-65) while maintaining WireGuard protocol compatibility.

## ✅ Status: Working PQ-Only VPN

DyberVPN now supports **full post-quantum authentication** with ML-DSA-65 signatures. Both hybrid mode (ML-KEM + Ed25519) and PQ-only mode (ML-KEM + ML-DSA) are fully operational and tested.

## Features

- **Post-Quantum Security**: Hybrid ML-KEM-768 + X25519 key exchange protects against "harvest now, decrypt later" attacks
- **PQ Authentication**: ML-DSA-65 signatures for quantum-resistant mutual authentication (pq-only mode)
- **NIST Compliant**: Uses FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) standardized algorithms
- **WireGuard Compatible**: Data plane uses standard WireGuard encapsulation (ChaCha20-Poly1305)
- **Self-Hosted**: Runs entirely on your infrastructure with zero external dependencies
- **High Performance**: Built in Rust, forked from Cloudflare's BoringTun
- **Zero Trust Access Control**: Per-peer, role-based policy enforcement on every packet
- **Key Revocation & Lifecycle**: CRL management, suspension, reinstatement, auto-expiry
- **Compliance Audit Logging**: NDJSON structured events for SOC 2, FedRAMP, HIPAA (SIEM-ready)
- **Multi-Peer Server**: In-process peer-to-peer routing with split tunneling
- **Hot Reload**: SIGHUP-triggered config reload without dropping connections
- **Automated Provisioning**: Enrollment API for zero-touch peer onboarding

## Quick Start

### Installation

```bash
# Clone and build
git clone https://github.com/dyber-pqc/DyberVPN.git
cd dybervpn
cargo build --release

# Install (optional)
sudo cp target/release/dybervpn /usr/local/bin/
```

### Generate Keys

```bash
# Generate hybrid (ML-KEM + X25519) key pair
dybervpn genkey -m hybrid

# Generate PQ-only (ML-KEM + ML-DSA) key pair
dybervpn genkey -m pqonly
```

### Server Setup

Create `server.toml`:

```toml
[interface]
name = "dvpn0"
listen_port = 51820
address = "10.200.200.1/24"
mode = "pqonly"  # or "hybrid" for Ed25519 auth

private_key = "<your_x25519_private_key>"
pq_private_key = "<your_mlkem_private_key>"
mldsa_private_key = "<your_mldsa_private_key>"  # Required for pqonly mode

[[peer]]
public_key = "<client_x25519_public_key>"
pq_public_key = "<client_mlkem_public_key>"
mldsa_public_key = "<client_mldsa_public_key>"  # Required for pqonly mode
allowed_ips = "10.200.200.2/32"
```

Start the server:

```bash
sudo dybervpn up -c server.toml -f
```

### Client Setup

Create `client.toml`:

```toml
[interface]
name = "dvpn1"
address = "10.200.200.2/24"
mode = "pqonly"

private_key = "<your_x25519_private_key>"
pq_private_key = "<your_mlkem_private_key>"
mldsa_private_key = "<your_mldsa_private_key>"

[[peer]]
public_key = "<server_x25519_public_key>"
pq_public_key = "<server_mlkem_public_key>"
mldsa_public_key = "<server_mldsa_public_key>"
allowed_ips = "10.200.200.0/24"
endpoint = "server_ip:51820"
persistent_keepalive = 25
```

Connect:

```bash
sudo dybervpn up -c client.toml -f
```

### Test Connectivity

```bash
ping 10.200.200.1  # From client to server
```

## Operating Modes

| Mode | Key Exchange | Authentication | Use Case |
|------|--------------|----------------|----------|
| `hybrid` (default) | ML-KEM-768 + X25519 | Ed25519 | Production — defense-in-depth |
| `pqonly` | ML-KEM-768 + X25519 | ML-DSA-65 | Maximum quantum resistance |
| `classic` | X25519 | Ed25519 | WireGuard compatibility |

## CLI Reference

```bash
dybervpn genkey -m <mode>  # Generate key pairs (hybrid, pqonly, classic)
dybervpn up -c <config> -f # Start VPN tunnel (foreground)
dybervpn up -c <config>    # Start VPN tunnel (daemon)
dybervpn down <interface>  # Stop VPN tunnel
dybervpn status            # Show tunnel status
dybervpn check -c <config> # Validate configuration
dybervpn version           # Show version and crypto info
dybervpn benchmark -i 100  # Run crypto benchmarks

# Enterprise: Key Lifecycle
dybervpn revoke-key -c <config> -p <peer> -r <reason>  # Revoke a peer's key
dybervpn suspend-key -c <config> -p <peer> -e 24h      # Suspend temporarily
dybervpn reinstate-key -c <config> -p <peer>           # Reinstate a key
dybervpn list-revoked -c <config>                      # List revoked keys
dybervpn list-revoked -c <config> --json               # JSON output
```

## Enterprise Features

DyberVPN includes three enterprise security features for regulated environments:

| Feature | Config Section | Purpose |
|---------|---------------|---------|
| **Zero Trust Access Control** | `[access_control]` | Per-peer policy enforcement on every packet |
| **Key Lifecycle Management** | `[security]` | Revocation, suspension, expiry, rotation |
| **Structured Audit Logging** | `[audit]` | NDJSON events for SOC 2 / FedRAMP / HIPAA |

```toml
# Enable in server.toml:
[access_control]
enabled = true
default_action = "deny"   # Zero Trust

[security]
crl_path = "/etc/dybervpn/revoked-keys.json"

[audit]
enabled = true
path = "/var/log/dybervpn/audit.jsonl"
```

See `docs/enterprise-features.md` for full documentation, compliance mapping,
and example configurations.

## Performance

Benchmarks on typical hardware (release build):

| Algorithm  | Operation | Time    |
|------------|-----------|---------|
| ML-KEM-768 | keygen    | ~88 µs  |
| ML-KEM-768 | encaps    | ~77 µs  |
| ML-KEM-768 | decaps    | ~91 µs  |
| ML-DSA-65  | keygen    | ~291 µs |
| ML-DSA-65  | sign      | ~328 µs |
| ML-DSA-65  | verify    | ~166 µs |
| X25519     | DH        | ~45 µs  |
| Ed25519    | sign      | ~29 µs  |
| Ed25519    | verify    | ~31 µs  |

**Full hybrid handshake: ~250-300 µs**
**Full PQ-only handshake: ~2-3 ms** (includes ML-DSA signatures)

## Testing

All 58 tests passing:

```bash
cargo test --release --all

# Results:
# boringtun:         37 passed (includes PQ-only auth tests)
# dybervpn-protocol: 15 passed + 1 doc test
# dybervpn-tunnel:    2 passed
# dybervpn-metrics:   3 passed
```

Key tests for PQ-only mode:
- `pqonly_tunnel_creation` - Creates tunnel with ML-DSA keys
- `pqonly_handshake_init` - Initiates handshake with ML-DSA signature
- `pqonly_full_handshake` - Complete handshake with mutual ML-DSA auth
- `pqonly_one_ip_packet` - Data transfer over PQ-authenticated tunnel
- `pqonly_wrong_signature_rejected` - Rejects invalid ML-DSA signatures

## Architecture

```
┌───────────────────────────────────────────────────────┐
│                    DyberVPN                           │
│  ┌───────────┐  ┌───────────────┐  ┌───────────────┐  │
│  │ TUN/TAP   │  │  PQ Handshake │  │  WireGuard    │  │
│  │ Interface │──│  Engine       │──│  Data Plane   │  │
│  │           │  │  (ML-KEM +    │  │  (ChaCha20-   │  │
│  │           │  │   ML-DSA)     │  │   Poly1305)   │  │
│  └───────────┘  └───────────────┘  └───────────────┘  │
│                       │                               │
│            ┌──────────┴──────────┐                    │
│            │   Crypto Backend    │                    │
│            │  ┌────────┐ ┌─────┐ │                    │
│            │  │ ml-kem │ │QUAC │ │                    │
│            │  │ ml-dsa │ │ 100 │ │                    │
│            │  │ dalek  │ │ HW  │ │                    │
│            │  └────────┘ └─────┘ │                    │
│            └─────────────────────┘                    │
└───────────────────────────────────────────────────────┘
```

## Security Model

- **Hybrid Key Exchange**: Both ML-KEM-768 and X25519 must be broken to compromise confidentiality
- **PQ Authentication**: ML-DSA-65 signatures provide quantum-resistant peer authentication
- **Defense in Depth**: Classical algorithms provide fallback if PQ algorithms have undiscovered weaknesses
- **Forward Secrecy**: Ephemeral keys generated per handshake
- **CNSA 2.0 Aligned**: Algorithm choices meet NSA Commercial National Security Algorithm Suite 2.0 requirements

## Project Structure

```
dybervpn/
├── crates/
│   ├── dybervpn-protocol/    # Core crypto, types, config parsing
│   ├── dybervpn-tunnel/      # TUN device, daemon, event loop
│   ├── dybervpn-cli/         # Command-line interface
│   └── dybervpn-metrics/     # Prometheus metrics
├── boringtun/                # Forked WireGuard + PQ extensions
│   └── src/noise/
│       ├── mod.rs            # Tunn implementation
│       ├── handshake.rs      # Classical Noise handshake
│       ├── hybrid_handshake.rs   # ML-KEM/ML-DSA types
│       └── hybrid_integration.rs # PQ state machines
├── deploy/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── dybervpn.service      # systemd unit
│   └── install.sh
└── test-configs/
    ├── pqonly-server.toml    # Example PQ-only server
    └── pqonly-client.toml    # Example PQ-only client
```

## Building from Source

### Requirements

- Rust 1.75+
- Linux (primary), macOS (experimental)
- Root/sudo for TUN device creation

### Build

```bash
cargo build --release
```

### Run Tests

```bash
cargo test --release --all
```

## Deployment

### systemd

```bash
sudo cp deploy/dybervpn.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable dybervpn
sudo systemctl start dybervpn
```

### Docker

```bash
docker build -t dybervpn:latest -f deploy/Dockerfile .
docker-compose -f deploy/docker-compose.yml up -d
```

## Enterprise Security

DyberVPN includes three enterprise security features for production deployment:

```toml
# Zero Trust — deny by default, allow by role
[access_control]
enabled = true
default_action = "deny"

# Key lifecycle — CRL, auto-expiry, forced rotation
[security]
crl_path = "/etc/dybervpn/revoked-keys.json"
key_max_age_hours = 720

# Audit — NDJSON events for SIEM ingest
[audit]
enabled = true
path = "/var/log/dybervpn/audit.jsonl"
events = ["connection", "handshake", "policy", "key_management", "admin"]
```

Key management CLI:
```bash
dybervpn revoke-key -c server.toml -p alice -r employee_departed -b admin@co.com
dybervpn suspend-key -c server.toml -p bob -e 24h
dybervpn reinstate-key -c server.toml -p bob
dybervpn list-revoked -c server.toml --json
```

Full documentation: [docs/enterprise-security.md](docs/enterprise-security.md)

## Compliance

- **NIST FIPS 203**: ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
- **NIST FIPS 204**: ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
- **CNSA 2.0**: NSA Commercial National Security Algorithm Suite 2.0
- **SOC 2**: Structured audit logging (CC6.1, CC6.2, CC6.3, CC7.2)
- **FedRAMP**: Access control + audit trail (AC-2, AC-3, AU-2, AU-3)
- **HIPAA**: Access controls + audit controls (§164.312)

## Roadmap

- [x] Hybrid ML-KEM-768 + X25519 key exchange
- [x] ML-DSA-65 signature support
- [x] Full ML-DSA handshake authentication (pq-only mode)
- [x] CLI with genkey, up, down, status, check
- [x] PID file management and daemonization
- [x] ML-DSA key loading from TOML config
- [x] Zero Trust access control (per-peer policy engine)
- [x] Key revocation & suspension lifecycle management
- [x] Structured audit logging (NDJSON, SOC 2 / FedRAMP / HIPAA)
- [x] Multi-peer server with peer-to-peer forwarding
- [x] Hot-reload (SIGHUP) for config and CRL changes
- [x] Enrollment API for automated provisioning
- [ ] QUAC 100 hardware acceleration
- [ ] FIPS 140-3 validated crypto module
- [ ] Fleet management dashboard (enterprise)
- [ ] iOS/Android clients
- [ ] macOS/Windows clients

## License

- **New code**: Apache 2.0
- **BoringTun-derived code**: BSD-3-Clause

WireGuard® is a registered trademark of Jason A. Donenfeld. DyberVPN is not sponsored or endorsed by Jason A. Donenfeld.

## Contributing

Contributions welcome! Please read our contributing guidelines and submit pull requests.

## Support

- GitHub Issues: Bug reports and feature requests
- Security Issues: security@dyber.org (for responsible disclosure)
