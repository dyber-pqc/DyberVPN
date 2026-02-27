![DyberVPN logo banner](./banner.svg)

# DyberVPN

**Post-Quantum VPN & Zero Trust Network Access**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![Tests](https://img.shields.io/badge/tests-123%20passing-brightgreen.svg)](#testing)

DyberVPN is an open-source, self-hosted, post-quantum VPN and Zero Trust Network Access (ZTNA) platform built for organizations that cannot route traffic through third-party cloud providers. It implements NIST-standardized post-quantum algorithms (ML-KEM-768, ML-DSA-65) while maintaining WireGuard protocol compatibility, and adds a full ZTNA architecture with a cloud/self-hosted Broker, inside-network Connectors, and remote Clients — eliminating inbound firewall rules on private networks.

## Status

DyberVPN supports **full post-quantum authentication** with ML-DSA-65 signatures across three operating modes (classic, hybrid, pq-only) and a complete **ZTNA backend** with Broker relay, Connector agents, and Client access — all with per-packet policy enforcement, key revocation, and structured audit logging. 123 tests passing across 6 crates.

## Features

### Core VPN
- **Post-Quantum Security**: Hybrid ML-KEM-768 + X25519 key exchange protects against "harvest now, decrypt later" attacks
- **PQ Authentication**: ML-DSA-65 signatures for quantum-resistant mutual authentication (pq-only mode)
- **NIST Compliant**: Uses FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) standardized algorithms
- **WireGuard Compatible**: Data plane uses standard WireGuard encapsulation (ChaCha20-Poly1305)
- **Self-Hosted**: Runs entirely on your infrastructure with zero external dependencies
- **High Performance**: Built in Rust, forked from Cloudflare's BoringTun
- **Multi-Peer Server**: In-process peer-to-peer routing with split tunneling
- **Hot Reload**: SIGHUP-triggered config reload without dropping connections
- **Automated Provisioning**: Enrollment API for zero-touch peer onboarding

### Zero Trust Network Access (ZTNA)
- **Broker Relay**: Cloud or self-hosted relay that terminates WireGuard tunnels from both Clients and Connectors, performing session stitching (decrypt → policy check → re-encrypt) entirely in userspace
- **Connector Agent**: Lightweight agent deployed inside private networks that makes outbound-only connections to the Broker, advertising local CIDR routes — no inbound firewall rules required
- **Client Access**: Remote users connect to the Broker via standard WireGuard handshake; the Broker routes traffic to the correct Connector based on longest-prefix-match destination lookup
- **Session Stitching**: Broker decrypts packets from one peer's Tunn, evaluates per-packet policy, then re-encrypts through the destination peer's Tunn — zero TUN device needed on the Broker
- **Service Registry**: Dynamic CIDR-to-Connector mapping with longest-prefix-match routing, automatic cleanup on Connector disconnect
- **Control Plane**: NDJSON-over-TCP protocol for Connector registration, heartbeat keepalive, and graceful disconnect
- **Stale Peer Reaping**: Automatic cleanup of idle Clients and Connectors based on configurable timeouts

### Enterprise Security
- **Zero Trust Access Control**: Per-peer, role-based policy enforcement on every packet (L3/L4 inspection)
- **Key Revocation & Lifecycle**: CRL management, suspension, reinstatement, auto-expiry with configurable `key_max_age_hours`
- **Compliance Audit Logging**: NDJSON structured events for SOC 2, FedRAMP, HIPAA (SIEM-ready)
- **ML-DSA Mutual Authentication**: Post-quantum signature verification for Connector registration in hybrid/pq-only modes
- **Revocation Enforcement**: Revoked keys are rejected at both VPN handshake and ZTNA Connector registration

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

## ZTNA Setup

DyberVPN's Zero Trust Network Access mode uses three components:

```
Client ──(outbound)──> Broker <──(outbound)── Connector
                        │                        │
                   Policy Engine           Private Network
                   Audit Logger            (10.1.0.0/16)
```

### Broker Setup

Create `broker.toml`:

```toml
[broker]
listen_udp = "0.0.0.0:51820"
listen_control = "0.0.0.0:51821"
private_key = "<broker_x25519_private_key>"
mode = "hybrid"
max_clients = 1000
session_timeout_secs = 300
heartbeat_timeout_secs = 120

[access_control]
enabled = true
default_action = "deny"

[security]
crl_path = "/etc/dybervpn/revoked-keys.json"

[audit]
enabled = true
path = "/var/log/dybervpn/broker-audit.jsonl"
```

Start the Broker:

```bash
dybervpn broker -c broker.toml
```

### Connector Setup

Create `connector.toml`:

```toml
[interface]
name = "dvpn-conn0"
mode = "hybrid"
private_key = "<connector_x25519_private_key>"
pq_private_key = "<connector_mlkem_private_key>"

[connector]
broker_endpoint = "broker.example.com:51820"
broker_control = "broker.example.com:51821"
broker_public_key = "<broker_x25519_public_key>"
advertised_routes = ["10.1.0.0/16", "192.168.1.0/24"]
service_name = "corp-network"
heartbeat_interval = 30
```

Start the Connector:

```bash
dybervpn connect -c connector.toml
```

The Connector makes outbound connections only — no inbound firewall rules needed.

### Client Access

Clients connect to the Broker using standard WireGuard configuration with the Broker as their peer. The Broker transparently routes traffic to the correct Connector based on destination IP.

## Operating Modes

| Mode | Key Exchange | Authentication | Use Case |
|------|--------------|----------------|----------|
| `hybrid` (default) | ML-KEM-768 + X25519 | Ed25519 | Production — defense-in-depth |
| `pqonly` | ML-KEM-768 + X25519 | ML-DSA-65 | Maximum quantum resistance |
| `classic` | X25519 | Ed25519 | WireGuard compatibility |

## CLI Reference

```bash
# Core VPN
dybervpn genkey -m <mode>       # Generate key pairs (hybrid, pqonly, classic)
dybervpn up -c <config> -f     # Start VPN tunnel (foreground)
dybervpn up -c <config>        # Start VPN tunnel (daemon)
dybervpn down <interface>      # Stop VPN tunnel
dybervpn status                # Show tunnel status
dybervpn check -c <config>     # Validate configuration
dybervpn version               # Show version and crypto info
dybervpn benchmark -i 100      # Run crypto benchmarks
dybervpn self-test             # Run FIPS crypto self-tests
dybervpn reload <interface>    # Hot-reload config and CRL

# ZTNA
dybervpn broker -c broker.toml     # Start ZTNA Broker relay
dybervpn connect -c connector.toml # Start Connector agent

# Peer Management
dybervpn add-peer -c <config> -n <name> -k <pubkey> -a <allowed_ips>
dybervpn remove-peer -c <config> -p <peer>
dybervpn list-peers -c <config>
dybervpn enroll -c <config> -t <token>  # Automated provisioning

# Key Lifecycle
dybervpn revoke-key -c <config> -p <peer> -r <reason>
dybervpn suspend-key -c <config> -p <peer> -e 24h
dybervpn reinstate-key -c <config> -p <peer>
dybervpn list-revoked -c <config> [--json]

# ML-DSA Signatures
dybervpn sign-keygen -m pqonly     # Generate ML-DSA key pair
dybervpn sign -k <key> -m <msg>   # Sign a message
dybervpn verify -k <key> -m <msg> -s <sig>  # Verify signature
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

All 123 tests passing across 6 crates:

```bash
cargo test --release --all

# Results:
# boringtun:          37 passed (PQ handshake, ML-DSA auth, tunnel tests)
# dybervpn-protocol:  15 passed + 1 doc test
# dybervpn-tunnel:     2 passed
# dybervpn-broker:    16 passed (ZTNA integration tests)
# dybervpn-cli:       49 passed (CLI + enterprise feature tests)
# dybervpn-metrics:    3 passed
```

Key test areas:
- **PQ-only mode**: tunnel creation, handshake initiation, full mutual ML-DSA auth, data transfer, invalid signature rejection
- **ZTNA Broker**: Connector registration/heartbeat, revoked peer rejection, session stitching, policy deny, multi-connector routing, stale peer reaping, config parsing
- **Enterprise**: Policy engine rules, CRL revocation/suspension/reinstatement, audit event logging, hot-reload

## Architecture

### Point-to-Point VPN

```
┌───────────────────────────────────────────────────────┐
│                    DyberVPN Node                      │
│  ┌───────────┐  ┌───────────────┐  ┌───────────────┐  │
│  │ TUN/TAP   │  │  PQ Handshake │  │  WireGuard    │  │
│  │ Interface │──│  Engine       │──│  Data Plane   │  │
│  │           │  │  (ML-KEM +    │  │  (ChaCha20-   │  │
│  │           │  │   ML-DSA)     │  │   Poly1305)   │  │
│  └───────────┘  └───────────────┘  └───────────────┘  │
│                       │                               │
│  ┌─────────────┐ ┌────┴────────┐  ┌───────────────┐   │
│  │ Policy      │ │ Crypto      │  │ Audit Logger  │   │
│  │ Engine      │ │ ml-kem/dsa  │  │ (NDJSON)      │   │
│  │ (L3/L4)     │ │ x25519/ed   │  │               │   │
│  └─────────────┘ └─────────────┘  └───────────────┘   │
└───────────────────────────────────────────────────────┘
```

### ZTNA (Broker Mode)

```
┌──────────┐         ┌────────────────────────────────┐         ┌──────────────┐
│  Client  │  UDP    │          Broker                │  UDP    │  Connector   │
│          │────────>│                                │<────────│              │
│ Tunn(C↔B)│         │  Tunn(C)    Tunn(Conn)         │         │ Tunn(Conn↔B) │
└──────────┘         │     │          │               │         └──────┬───────┘
                     │     ▼          ▼               │                │
                     │  Decrypt → Policy → Re-encrypt │         Private Network
                     │         Engine                 │         (10.1.0.0/16)
                     │                                │
                     │  ┌────────────┐ ┌────────────┐ │
                     │  │ Service    │ │ Revocation │ │
                     │  │ Registry   │ │ Engine     │ │
                     │  │ (CIDR→Conn)│ │ (CRL)      │ │
                     │  └────────────┘ └────────────┘ │
                     │                                │
                     │  TCP Control Plane (NDJSON)    │
                     │  ├─ Register / RegisterAck     │
                     │  ├─ Heartbeat / HeartbeatAck   │
                     │  └─ Disconnect                 │
                     └────────────────────────────────┘
```

## Security Model

- **Hybrid Key Exchange**: Both ML-KEM-768 and X25519 must be broken to compromise confidentiality
- **PQ Authentication**: ML-DSA-65 signatures provide quantum-resistant peer authentication
- **Defense in Depth**: Classical algorithms provide fallback if PQ algorithms have undiscovered weaknesses
- **Forward Secrecy**: Ephemeral keys generated per handshake
- **CNSA 2.0 Aligned**: Algorithm choices meet NSA Commercial National Security Algorithm Suite 2.0 requirements
- **Zero Trust**: No implicit trust — every packet is policy-evaluated at the Broker before forwarding
- **No Inbound Firewall Rules**: Both Connectors and Clients initiate outbound connections to the Broker
- **Session Stitching Isolation**: Traffic between Client and Connector is decrypted, inspected, and re-encrypted at the Broker — each side has an independent WireGuard session
- **Replay Protection**: ML-DSA registration signatures include timestamps validated within a 300-second window

## Project Structure

```
dybervpn/
├── crates/
│   ├── dybervpn-protocol/    # Core crypto, types, config parsing
│   ├── dybervpn-tunnel/      # TUN device, daemon, event loop, connector mode
│   │   └── src/
│   │       ├── daemon.rs     # Daemon with VPN + Connector modes
│   │       ├── connector.rs  # Connector agent (control plane client)
│   │       ├── policy.rs     # L3/L4 policy engine + packet inspection
│   │       ├── revocation.rs # CRL-based key revocation
│   │       └── audit.rs      # NDJSON structured audit logger
│   ├── dybervpn-broker/      # ZTNA Broker relay server
│   │   └── src/
│   │       ├── broker.rs     # Main async event loop (UDP + session stitching)
│   │       ├── control.rs    # TCP control plane (Connector registration)
│   │       ├── session.rs    # Session stitching (decrypt → policy → re-encrypt)
│   │       ├── registry.rs   # Service registry (CIDR → Connector routing)
│   │       ├── peer.rs       # BrokerPeer management (Client/Connector)
│   │       ├── auth.rs       # ML-DSA signature verification
│   │       ├── config.rs     # BrokerConfig + TOML parsing
│   │       └── error.rs      # Error types
│   ├── dybervpn-cli/         # Command-line interface (all subcommands)
│   └── dybervpn-metrics/     # Prometheus metrics
├── boringtun/                # Forked WireGuard + PQ extensions
│   └── src/noise/
│       ├── mod.rs            # Tunn (encapsulate/decapsulate)
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

DyberVPN includes enterprise security features for production deployment, applicable to both point-to-point VPN and ZTNA Broker modes:

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

In ZTNA mode, these features operate at the Broker:
- **Policy Engine** inspects every stitched packet (src/dst IP, protocol, ports) before forwarding
- **Revocation Engine** rejects both VPN handshakes and Connector registrations from revoked keys
- **Audit Logger** records all Broker events including Connector registration, Client connections, policy decisions, and session stitching

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
- [x] ZTNA Broker relay with session stitching
- [x] Connector agent with outbound-only control plane
- [x] Service registry with longest-prefix-match routing
- [x] ML-DSA mutual auth for Connector registration
- [x] Stale peer reaping with configurable timeouts
- [x] Client identity extraction via WireGuard handshake parsing
- [x] Reverse routing (Connector → Client) via learned IP mapping
- [x] Broker CLI command with full enterprise subsystem integration
- [ ] QUAC 100 hardware acceleration
- [ ] FIPS 140-3 validated crypto module
- [ ] Fleet management dashboard (enterprise)
- [ ] iOS/Android clients
- [ ] macOS/Windows clients
- [ ] Tauri desktop app (GUI)

## License

- **New code**: Apache 2.0
- **BoringTun-derived code**: BSD-3-Clause

WireGuard® is a registered trademark of Jason A. Donenfeld. DyberVPN is not sponsored or endorsed by Jason A. Donenfeld.

## Contributing

Contributions welcome! Please read our contributing guidelines and submit pull requests.

## Support

- GitHub Issues: Bug reports and feature requests
- Security Issues: security@dyber.org (for responsible disclosure)
