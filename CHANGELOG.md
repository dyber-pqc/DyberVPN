# Changelog

All notable changes to DyberVPN will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.3] - 2026-02-25

### Added

- **Peer-to-peer forwarding**: Server routes packets directly between connected peers
  in-process, bypassing TUN device and kernel routing for lower latency
- **Hot-reload via SIGHUP**: `dybervpn reload <interface>` or `kill -HUP` reloads
  config, adds/removes peers without dropping existing sessions
- **`remove-peer` command**: Remove peers by name, public key prefix, or VPN IP
  with confirmation prompt (`-y` to skip)
- **`list-peers` command**: Show all configured peers with details; `--json` for
  machine-readable output
- **Enrollment API**: HTTP endpoint for automated client provisioning
  - Server: `[enrollment]` config section with token-based auth
  - Client: `dybervpn enroll -s server:8443 -t token -n name` generates keys,
    enrolls with server, receives complete config
  - `GET /health`, `GET /status`, `POST /enroll` endpoints
  - Auto-triggers config reload after enrollment
- **Daemonization**: Proper double-fork with PID file management
  - PID files in `/var/run/dybervpn/` (fallback `/tmp/`)
  - Stale PID detection and cleanup
  - `dybervpn up` without `-f` runs as background daemon
- **Key rotation/expiry**: Sessions older than 24 hours force re-key automatically
- **IP forwarding auto-enable**: Server auto-enables `net.ipv4.ip_forward` for
  peer-to-peer routing
- **Route management**: Auto-adds `ip route` entries for peer `allowed_ips` through
  TUN device
- **Peer statistics**: Track tx/rx bytes, forwarded packets, handshake times per peer;
  logged on shutdown
- **Multi-peer handshake routing**: Handshake init packets tried against all peers
  (O(n) scan) instead of always picking the first peer
- **`add-peer` command**: One-command peer provisioning — generates client keys,
  appends to server config, outputs complete client config with auto-assigned IP

### Changed

- TUN file descriptor set to non-blocking (`O_NONBLOCK`) — fixes event loop deadlock
  that starved UDP socket reads
- `add-peer` now prints `dybervpn reload` hint instead of suggesting server restart
- Poll-based event loop processes up to 64 packets per fd per iteration

## [0.1.1] - 2026-02-24

### Added

- **ML-DSA-65 Artifact Signing**: Post-quantum code signing for release binaries
  - `dybervpn sign-keygen`: Generate ML-DSA-65 signing keypairs (FIPS 204)
  - `dybervpn sign`: Sign any file with ML-DSA-65 detached signatures
  - `dybervpn verify`: Verify ML-DSA-65 signatures on files
  - Custom binary signature format (`.sig.mldsa`, 3,358 bytes)
  - SHA-256 file hash + Unix timestamp + ML-DSA-65 signature
  - Tamper detection with clear error messages
- **Release signing public key** (`release-signing.mldsa.pub`) included in repo
- **CI/CD PQ signing**: Release workflow automatically signs all artifacts with ML-DSA-65

### Changed

- Release workflow now includes post-quantum signature verification instructions
- Updated `.gitignore` to protect signing keys while allowing public key distribution

## [0.1.0] - 2026-02-24

### Added

- **Post-Quantum Key Exchange**: ML-KEM-768 + X25519 hybrid key exchange (NIST FIPS 203)
- **Post-Quantum Authentication**: ML-DSA-65 signatures for `pqonly` mode (NIST FIPS 204)
- **Three Operating Modes**:
  - `hybrid` (default): ML-KEM-768 + X25519 key exchange, Ed25519 authentication
  - `pqonly`: ML-KEM-768 + X25519 key exchange, ML-DSA-65 mutual authentication
  - `classic`: Standard WireGuard (X25519 + Ed25519)
- **CLI Commands**:
  - `genkey`: Generate key pairs for all modes
  - `up`: Start VPN tunnel (foreground or daemon)
  - `down`: Stop VPN tunnel
  - `status`: Show running tunnels
  - `check`: Validate configuration files
  - `version`: Display version and crypto info
  - `benchmark`: Run cryptographic benchmarks
- **Configuration**: TOML-based configuration with ML-KEM and ML-DSA key fields
- **Deployment**:
  - Docker support with multi-stage builds
  - systemd service file
  - docker-compose for quick deployment
- **Documentation**: README, SECURITY, CONTRIBUTING, and full API documentation
- **Testing**: 58 tests covering protocol, crypto, and tunnel operations

### Security

- CNSA 2.0 aligned algorithm selection
- Hybrid cryptography for defense-in-depth
- Forward secrecy with ephemeral keys
- ChaCha20-Poly1305 AEAD for data plane

### Performance

- ML-KEM-768: ~88 µs keygen, ~77 µs encaps, ~91 µs decaps
- ML-DSA-65: ~291 µs keygen, ~328 µs sign, ~166 µs verify
- Full hybrid handshake: ~250-300 µs
- Full PQ-only handshake: ~2-3 ms

## [Unreleased]

### Planned

- QUAC 100 hardware acceleration
- FIPS 140-3 validated crypto module
- macOS client support
- Windows client support (TAP adapter)
- iOS/Android mobile clients
- Enterprise fleet management
- Certificate-based authentication

---

## Version History

| Version | Date | Highlights |
|---------|------|------------|
| 0.1.0 | 2026-02-24 | Initial release with PQ crypto |

---

Copyright 2026 Dyber, Inc.
