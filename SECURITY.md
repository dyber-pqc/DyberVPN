# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in DyberVPN, please report it responsibly.

### How to Report

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please email: **security@dyber.io**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Depends on severity (critical: days, high: weeks, medium: next release)

### What to Expect

1. Acknowledgment of your report
2. Assessment of the vulnerability
3. Development of a fix
4. Coordinated disclosure (we'll credit you unless you prefer anonymity)

## Security Model

### Threat Model

DyberVPN is designed to protect against:

1. **Harvest Now, Decrypt Later (HNDL)**: Adversaries recording encrypted traffic today to decrypt with future quantum computers
2. **Man-in-the-Middle**: Active attackers attempting to intercept or modify traffic
3. **Traffic Analysis**: Passive observers analyzing metadata (mitigated by VPN tunnel)

### Cryptographic Assumptions

| Component | Algorithm | Security Level | Assumption |
|-----------|-----------|----------------|------------|
| Key Exchange | ML-KEM-768 | NIST Level 3 | Module-LWE is hard |
| Key Exchange | X25519 | ~128-bit | ECDLP is hard |
| Authentication | ML-DSA-65 | NIST Level 3 | Module-LWE/SIS is hard |
| Authentication | Ed25519 | ~128-bit | ECDLP is hard |
| Encryption | ChaCha20-Poly1305 | 256-bit | Standard assumptions |

### Hybrid Security Rationale

DyberVPN uses hybrid cryptography (classical + post-quantum) because:

1. **Belt and Suspenders**: If ML-KEM has undiscovered weaknesses, X25519 still provides security
2. **Transition Period**: We're in early days of PQC deployment; hybrid provides a safety net
3. **Regulatory Alignment**: CNSA 2.0 recommends hybrid approaches during transition

### Known Limitations

1. **Metadata Protection**: VPN hides content but not the fact that communication is occurring
2. **Endpoint Security**: DyberVPN cannot protect against compromised endpoints
3. **Side Channels**: Software implementation may be vulnerable to timing attacks (use hardware acceleration for high-security deployments)
4. **Key Management**: Security depends on proper key generation and storage

## Secure Development Practices

- Memory-safe language (Rust)
- No unsafe code in cryptographic paths (except FFI boundaries)
- Dependency auditing with `cargo audit`
- Continuous integration with security linters

## Cryptographic Library Choices

| Library | Purpose | Rationale |
|---------|---------|-----------|
| ml-kem | ML-KEM-768 | RustCrypto implementation, NIST vectors |
| ml-dsa | ML-DSA-65 | RustCrypto implementation, FIPS 204 compliant |
| x25519-dalek | X25519 | Well-audited, widely used |
| ed25519-dalek | Ed25519 | Well-audited, widely used |
| chacha20poly1305 | AEAD | RustCrypto, constant-time |
| blake2 | Hashing | Fast, secure, used in WireGuard |

## Acknowledgments

We thank the following for their contributions to VPN and PQC security:

- Jason A. Donenfeld (WireGuard protocol)
- Cloudflare (BoringTun implementation)
- NIST PQC team
- RustCrypto contributors
