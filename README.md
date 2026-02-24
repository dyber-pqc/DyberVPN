# DyberVPN

**Post-Quantum VPN for Infrastructure You Control**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)

DyberVPN is an open-source, self-hosted, post-quantum cryptography (PQC) VPN built for organizations that cannot route traffic through third-party cloud providers — government, defense, financial services, healthcare, and critical infrastructure.

## Features

- **Hybrid Post-Quantum Key Exchange**: ML-KEM-768 + X25519 for defense-in-depth
- **NIST FIPS 203 Compliant**: Uses standardized ML-KEM algorithm
- **WireGuard Compatible**: Based on the WireGuard protocol for proven performance
- **Self-Hosted**: Runs entirely on your infrastructure
- **Hardware Acceleration Ready**: Optional QUAC 100 integration (coming soon)
- **CNSA 2.0 Aligned**: NSA CNSA 2.0 requirements from day one

## Quick Start

### Build

```bash
cargo build --release
```

### Generate Keys

```bash
# Generate hybrid (classical + post-quantum) key pair
cargo run -p dybervpn-cli -- genkey --mode hybrid

# Generate WireGuard-compatible classical keys only
cargo run -p dybervpn-cli -- genkey --mode classic
```

### Show Version

```bash
cargo run -p dybervpn-cli -- version
```

## Operating Modes

| Mode | Key Exchange | Authentication | Use Case |
|------|--------------|----------------|----------|
| `hybrid` (default) | ML-KEM-768 + X25519 | Ed25519 | Production — defense-in-depth |
| `pq-only` | ML-KEM-768 | ML-DSA-65 | Maximum quantum resistance (Phase 2) |
| `classic` | X25519 | Ed25519 | WireGuard compatibility |

## Project Structure

```
dybervpn/
├── boringtun/              # Original WireGuard implementation (being modified)
├── boringtun-cli/          # Original CLI
├── crates/
│   ├── dybervpn-protocol/  # NEW: Post-quantum crypto layer
│   └── dybervpn-cli/       # NEW: DyberVPN CLI
├── config/                 # Example configurations
└── docs/                   # Documentation
```

## Cryptographic Algorithms

| Purpose | Algorithm | Standard | Security Level |
|---------|-----------|----------|----------------|
| Key Encapsulation | ML-KEM-768 | FIPS 203 | NIST Level 3 |
| Classical KEX | X25519 | RFC 7748 | 128-bit |
| Classical Signature | Ed25519 | RFC 8032 | 128-bit |
| AEAD | ChaCha20-Poly1305 | RFC 8439 | 256-bit |
| Hash | BLAKE2s, SHA-256 | RFC 7693 | 256-bit |

## License

- **Apache 2.0** — New code written for DyberVPN
- **BSD-3-Clause** — Code derived from [Cloudflare BoringTun](https://github.com/cloudflare/boringtun)

## Trademark Notice

WireGuard® is a registered trademark of Jason A. Donenfeld. DyberVPN is not sponsored or endorsed by the WireGuard project.

---

**Dyber, Inc.** — Quantum-Safe Infrastructure
