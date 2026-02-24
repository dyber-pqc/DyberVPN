# DyberVPN Documentation

Welcome to the DyberVPN documentation. This guide covers installation, configuration, and operation of DyberVPN - a post-quantum VPN for infrastructure you control.

## Table of Contents

1. [Quick Start](quickstart.md)
2. [Installation](installation.md)
3. [Configuration](configuration.md)
4. [Security Model](security-model.md)
5. [CLI Reference](cli-reference.md)
6. [Deployment](deployment.md)
7. [Troubleshooting](troubleshooting.md)
8. [Architecture](architecture.md)

## What is DyberVPN?

DyberVPN is an open-source, self-hosted VPN that implements NIST-standardized post-quantum cryptography:

- **ML-KEM-768** (FIPS 203) for key exchange
- **ML-DSA-65** (FIPS 204) for authentication
- **WireGuard®-compatible** data plane

### Why Post-Quantum?

Quantum computers pose a threat to classical cryptography:

- RSA, ECDH, and ECDSA can be broken by Shor's algorithm
- "Harvest now, decrypt later" attacks are happening today
- NIST has standardized new algorithms designed to resist quantum attacks

DyberVPN protects your data today against future quantum threats.

### Operating Modes

| Mode | Key Exchange | Authentication | Use Case |
|------|--------------|----------------|----------|
| `hybrid` | ML-KEM-768 + X25519 | Ed25519 | Default - defense-in-depth |
| `pqonly` | ML-KEM-768 + X25519 | ML-DSA-65 | Maximum quantum resistance |
| `classic` | X25519 | Ed25519 | WireGuard compatibility |

## Quick Links

- [GitHub Repository](https://github.com/dyber-pqc/DyberVPN)
- [Issue Tracker](https://github.com/dyber-pqc/DyberVPN/issues)
- [Discussions](https://github.com/dyber-pqc/DyberVPN/discussions)
- [Security Policy](https://github.com/dyber-pqc/DyberVPN/blob/main/SECURITY.md)

## License

DyberVPN is dual-licensed:
- New code: Apache 2.0
- BoringTun-derived code: BSD-3-Clause

---

*Copyright 2026 Dyber, Inc.*
