# Changelog

All notable changes to DyberVPN will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
