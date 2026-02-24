![DyberVPN logo banner](./banner.svg)

# DyberVPN

**Post-Quantum VPN for Infrastructure You Control**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)

DyberVPN is an open-source, self-hosted, post-quantum cryptography (PQC) VPN built for organizations that cannot route traffic through third-party cloud providers. It implements NIST-standardized post-quantum algorithms (ML-KEM-768, ML-DSA-65) while maintaining WireGuard protocol compatibility.

## Features

- **Post-Quantum Security**: Hybrid ML-KEM-768 + X25519 key exchange protects against "harvest now, decrypt later" attacks
- **NIST Compliant**: Uses FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) standardized algorithms
- **WireGuard Compatible**: Data plane uses standard WireGuard encapsulation (ChaCha20-Poly1305)
- **Self-Hosted**: Runs entirely on your infrastructure with zero external dependencies
- **High Performance**: Built in Rust, forked from Cloudflare's BoringTun

## Quick Start

### Installation

```bash
# Clone and build
git clone https://github.com/dyberinc/dybervpn.git
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
dybervpn genkey -m pq-only
```

### Server Setup

```bash
# Initialize server configuration
dybervpn init --server

# Edit the generated server.toml, then start
sudo dybervpn up -c server.toml -f
```

### Client Setup

```bash
# Initialize client configuration
dybervpn init --client SERVER_IP

# Edit client.toml with server's public keys, then connect
sudo dybervpn up -c client.toml -f
```

## Operating Modes

| Mode               | Key Exchange        | Authentication | Use Case                      |
| ------------------ | ------------------- | -------------- | ----------------------------- |
| `hybrid` (default) | ML-KEM-768 + X25519 | Ed25519        | Production — defense-in-depth |
| `pq-only`          | ML-KEM-768          | ML-DSA-65      | Maximum quantum resistance    |
| `classic`          | X25519              | Ed25519        | WireGuard compatibility       |

## Configuration

```toml
# /etc/dybervpn/server.toml

[interface]
name = "dvpn0"
private_key = "base64_encoded_x25519_private_key"
pq_private_key = "base64_encoded_mlkem_private_key"
listen_port = 51820
address = "10.0.0.1/24"
mode = "hybrid"  # hybrid | pq-only | classic

[[peer]]
public_key = "base64_encoded_x25519_public_key"
pq_public_key = "base64_encoded_mlkem_public_key"
allowed_ips = "10.0.0.2/32"
persistent_keepalive = 25
```

## CLI Reference

```bash
dybervpn genkey      # Generate key pairs
dybervpn pubkey      # Derive public key from private key
dybervpn up          # Start VPN tunnel
dybervpn down        # Stop VPN tunnel
dybervpn status      # Show tunnel status
dybervpn check       # Validate configuration
dybervpn init        # Interactive setup wizard
dybervpn version     # Show version and crypto info
dybervpn benchmark   # Run crypto benchmarks
```

## Performance

Benchmarks on typical hardware (release build):

| Algorithm  | Operation | Time    |
| ---------- | --------- | ------- |
| ML-KEM-768 | keygen    | ~82 µs  |
| ML-KEM-768 | encaps    | ~49 µs  |
| ML-KEM-768 | decaps    | ~51 µs  |
| ML-DSA-65  | keygen    | ~278 µs |
| ML-DSA-65  | sign      | ~473 µs |
| ML-DSA-65  | verify    | ~161 µs |
| X25519     | DH        | ~44 µs  |
| Ed25519    | sign      | ~28 µs  |

**Full hybrid handshake: ~250-300 µs**

## Architecture

```
┌───────────────────────────────────────────────────────┐
│                    DyberVPN                           │
│  ┌───────────┐  ┌───────────────┐  ┌───────────────┐  │
│  │ TUN/TAP   │  │  PQ Handshake │  │  WireGuard    │  │
│  │ Interface │──│  Engine       │──│  Data Plane   │  │
│  │           │  │  (ML-KEM +    │  │  (ChaCha20-   │  │
│  │           │  │   X25519)     │  │   Poly1305)   │  │
│  └───────────┘  └───────────────┘  └───────────────┘  │
└───────────────────────────────────────────────────────┘
```

## Security Model

- **Hybrid Key Exchange**: Both ML-KEM-768 and X25519 must be broken to compromise confidentiality
- **Defense in Depth**: Classical algorithms provide fallback if PQ algorithms have undiscovered weaknesses
- **Forward Secrecy**: Ephemeral keys generated per handshake
- **CNSA 2.0 Aligned**: Algorithm choices meet NSA Commercial National Security Algorithm Suite 2.0 requirements

## Project Structure

```
dybervpn/
├── crates/
│   ├── dybervpn-protocol/    # Core crypto and config
│   ├── dybervpn-tunnel/      # Tunnel management
│   ├── dybervpn-cli/         # Command-line interface
│   └── dybervpn-metrics/     # Prometheus metrics
├── boringtun/                # Forked WireGuard implementation
├── deploy/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── dybervpn.service      # systemd unit
│   └── install.sh
└── config/
    └── example-*.toml
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

## Compliance

- **NIST FIPS 203**: ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
- **NIST FIPS 204**: ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
- **CNSA 2.0**: NSA Commercial National Security Algorithm Suite 2.0

## Roadmap

- [x] Hybrid ML-KEM-768 + X25519 key exchange
- [x] ML-DSA-65 signature support
- [x] CLI with genkey, up, down, status
- [ ] Full ML-DSA handshake authentication
- [ ] QUAC 100 hardware acceleration
- [ ] FIPS 140-3 validated crypto module
- [ ] Enterprise fleet management
- [ ] iOS/Android clients

## License

- **New code**: Apache 2.0
- **BoringTun-derived code**: BSD-3-Clause

WireGuard® is a registered trademark of Jason A. Donenfeld. DyberVPN is not sponsored or endorsed by Jason A. Donenfeld.

## Contributing

Contributions welcome! Please read our contributing guidelines and submit pull requests.

## Support

- GitHub Issues: Bug reports and feature requests
- Security Issues: security@dyber.io (for responsible disclosure)
