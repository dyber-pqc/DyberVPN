# DyberVPN Security Model

## Overview

DyberVPN implements a hybrid post-quantum cryptographic model designed to provide security against both current classical attacks and future quantum computer attacks.

## Threat Model

### What DyberVPN Protects Against

1. **Harvest Now, Decrypt Later (HNDL)**
   - Adversaries recording encrypted traffic today to decrypt with future quantum computers
   - Mitigated by ML-KEM-768 post-quantum key encapsulation

2. **Man-in-the-Middle Attacks**
   - Active attackers intercepting and modifying traffic
   - Mitigated by authenticated key exchange and AEAD encryption

3. **Traffic Analysis**
   - Minimal metadata leakage due to WireGuard's design
   - Fixed packet sizes and timing

4. **Key Compromise**
   - Forward secrecy through ephemeral keys
   - Session keys rotated every 2 minutes

### What DyberVPN Does NOT Protect Against

1. **Endpoint Compromise**
   - If your device is compromised, VPN cannot help
   - Use endpoint security in addition to VPN

2. **Traffic Correlation**
   - Timing attacks by global adversaries
   - Consider Tor for anonymity requirements

3. **Quantum Attacks on Symmetric Crypto**
   - ChaCha20's 256-bit keys provide 128-bit post-quantum security
   - Sufficient for current threat models

## Cryptographic Algorithms

### Key Exchange (Hybrid Mode)

| Algorithm | Type | Security Level | Standard |
|-----------|------|----------------|----------|
| ML-KEM-768 | Post-Quantum KEM | NIST Level 3 | FIPS 203 |
| X25519 | Classical ECDH | 128-bit | RFC 7748 |

The hybrid approach combines both algorithms:
1. Both key exchanges performed in parallel
2. Shared secrets concatenated and fed through HKDF
3. If either is broken, the other still protects

### Authentication

| Algorithm | Type | Security Level | Standard |
|-----------|------|----------------|----------|
| Ed25519 | Classical Signature | 128-bit | RFC 8032 |
| ML-DSA-65 | Post-Quantum Signature | NIST Level 3 | FIPS 204 (Phase 2) |

### Symmetric Encryption

| Algorithm | Purpose | Key Size | Standard |
|-----------|---------|----------|----------|
| ChaCha20-Poly1305 | AEAD | 256-bit | RFC 8439 |
| BLAKE2s | Hashing/MAC | 256-bit | RFC 7693 |
| HKDF-SHA256 | Key Derivation | - | RFC 5869 |

## Key Sizes

| Key Type | Size | Base64 Length |
|----------|------|---------------|
| X25519 Private | 32 bytes | 44 chars |
| X25519 Public | 32 bytes | 44 chars |
| ML-KEM-768 Private | 2400 bytes | ~3200 chars |
| ML-KEM-768 Public | 1184 bytes | ~1580 chars |
| ML-KEM-768 Ciphertext | 1088 bytes | ~1450 chars |

## Protocol Security

### Handshake

1. **Initiator → Responder**
   - Ephemeral X25519 public key
   - Encrypted static public key (AEAD)
   - Encrypted timestamp (replay protection)
   - ML-KEM ciphertext (hybrid mode)

2. **Responder → Initiator**
   - Ephemeral X25519 public key
   - Encrypted empty payload (confirmation)
   - ML-KEM shared secret incorporated

3. **Session Established**
   - Derived sending/receiving keys
   - Counter-based nonces
   - Automatic rekeying

### Session Management

- **Rekey Interval**: 2 minutes or 2^64 messages
- **Handshake Timeout**: 5 seconds
- **Keepalive**: Configurable (default: disabled)

## CNSA 2.0 Compliance

DyberVPN aligns with NSA's Commercial National Security Algorithm Suite 2.0:

| CNSA 2.0 Requirement | DyberVPN Implementation |
|---------------------|------------------------|
| Key Establishment | ML-KEM-768 (Level 3) |
| Digital Signature | ML-DSA-65 (Phase 2) |
| Symmetric Key | AES-256 equivalent (ChaCha20) |
| Hash | SHA-384+ (SHA-256, BLAKE2s) |

## Security Recommendations

### Key Management

1. **Generate keys on secure systems**
   - Use `dybervpn genkey` on trusted hardware
   - Never share private keys

2. **Rotate keys periodically**
   - Recommended: Every 90 days for static keys
   - Session keys rotate automatically

3. **Backup keys securely**
   - Encrypted storage only
   - Consider hardware security modules for enterprise

### Deployment

1. **Use hybrid mode for production**
   - Defense-in-depth against unknown vulnerabilities
   - Classic mode only for legacy compatibility

2. **Enable persistent keepalive for mobile**
   - Prevents NAT timeout
   - 25 seconds recommended

3. **Restrict allowed IPs**
   - Principle of least privilege
   - Only allow necessary subnets

## Responsible Disclosure

Report security vulnerabilities to: security@dyber.com

We follow coordinated disclosure practices and will credit researchers.
