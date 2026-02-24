# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

### How to Report

Email your findings to: **security@dyber.org**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

### What to Expect

| Timeline | Action |
|----------|--------|
| 24 hours | Initial acknowledgment |
| 72 hours | Preliminary assessment |
| 7 days   | Detailed response with timeline |
| 90 days  | Public disclosure (coordinated) |

We follow responsible disclosure practices and will credit reporters (unless anonymity is requested).

### PGP Key

For sensitive reports, encrypt your email using our PGP key:

```
Key ID: [To be published]
Fingerprint: [To be published]
```

## Security Model

### Threat Model

DyberVPN is designed to protect against:

1. **Passive network observers** - All traffic is encrypted
2. **Active network attackers (MITM)** - Authenticated key exchange
3. **Quantum adversaries (future)** - Post-quantum cryptography
4. **"Harvest now, decrypt later"** - Hybrid PQC protects current sessions

### Trust Boundaries

```
┌─────────────────────────────────────────────────────┐
│                  Untrusted Network                  │
│                    (Internet)                       │
└─────────────────────┬───────────────────────────────┘
                      │
              ┌───────┴───────┐
              │   DyberVPN    │  ← Cryptographic boundary
              │   Tunnel      │
              └───────┬───────┘
                      │
┌─────────────────────┴───────────────────────────────┐
│               Trusted Local Network                 │
│            (Behind VPN endpoint)                    │
└─────────────────────────────────────────────────────┘
```

### Cryptographic Algorithms

| Purpose | Algorithm | Standard | Security Level |
|---------|-----------|----------|----------------|
| Key Exchange | ML-KEM-768 + X25519 | FIPS 203 | NIST Level 3 |
| Authentication (hybrid) | Ed25519 | RFC 8032 | 128-bit |
| Authentication (pqonly) | ML-DSA-65 | FIPS 204 | NIST Level 3 |
| Symmetric Encryption | ChaCha20-Poly1305 | RFC 8439 | 256-bit |
| Key Derivation | HKDF-SHA256 | RFC 5869 | 256-bit |
| Hashing | BLAKE2s | RFC 7693 | 256-bit |

### Security Properties

- **Forward Secrecy**: Ephemeral keys per session
- **Hybrid Security**: Both classical and PQ algorithms must be broken
- **Authenticated Encryption**: AEAD for all data
- **Replay Protection**: Nonce-based with anti-replay window
- **Key Rotation**: Every 2 minutes or 2^64 messages

## Known Limitations

### Current Limitations

1. **Platform Support**: Linux only (macOS experimental, Windows not yet)
2. **Hardware Acceleration**: Software-only (QUAC 100 planned)
3. **FIPS Validation**: Not yet validated (planned)
4. **Audit Status**: Not yet independently audited

### Planned Security Improvements

- [ ] Independent security audit (Q2 2026)
- [ ] FIPS 140-3 validation (Q4 2026)
- [ ] Hardware-backed key storage
- [ ] QUAC 100 QRNG integration

## Secure Development Practices

### Code Review

- All changes require code review
- Security-sensitive changes require security review
- No direct commits to main branch

### Dependencies

- Dependencies are regularly updated
- `cargo audit` run in CI
- Dependabot enabled for security updates

### Testing

- Unit tests for all crypto operations
- Integration tests for protocol flows
- Fuzzing for parser and protocol code (planned)

## Incident Response

In case of a security incident:

1. **Assess** - Determine scope and impact
2. **Contain** - Limit damage
3. **Notify** - Inform affected users
4. **Remediate** - Fix the vulnerability
5. **Review** - Post-incident analysis

## Compliance

### Standards Alignment

- **NIST FIPS 203** (ML-KEM)
- **NIST FIPS 204** (ML-DSA)
- **CNSA 2.0** (Algorithm selection)

### Planned Certifications

- FIPS 140-3 Level 3 (crypto module)
- Common Criteria (planned)
- SOC 2 Type II (planned)

## Security Contacts

| Contact | Email |
|---------|-------|
| Security Team | security@dyber.org |
| Engineering | engineering@dyber.org |
| General | info@dyber.org |

---

*This security policy was last updated: February 24, 2026*

*Copyright 2026 Dyber, Inc.*
