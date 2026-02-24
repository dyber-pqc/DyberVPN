# Architecture

Technical architecture documentation for DyberVPN.

## Overview

DyberVPN is a post-quantum VPN that implements:

- **NIST FIPS 203** (ML-KEM-768) for key encapsulation
- **NIST FIPS 204** (ML-DSA-65) for digital signatures
- **WireGuard®-compatible** data plane

```
┌───────────────────────────────────────────────────────────────┐
│                        DyberVPN Stack                         │
├───────────────────────────────────────────────────────────────┤
│                      dybervpn-cli                             │
│               (Command-line interface)                        │
├───────────────────────────────────────────────────────────────┤
│                     dybervpn-tunnel                           │
│           (TUN device, daemon, event loop)                    │
├───────────────────────────────────────────────────────────────┤
│                      boringtun                                │
│        (Noise protocol, PQ handshake, data plane)             │
├───────────────────────────────────────────────────────────────┤
│                    dybervpn-protocol                          │
│            (Crypto backend, config parsing)                   │
├───────────────────────────────────────────────────────────────┤
│                   Cryptographic Libraries                     │
│    ml-kem │ ml-dsa │ x25519-dalek │ chacha20poly1305          │
└───────────────────────────────────────────────────────────────┘
```

## Component Architecture

### dybervpn-cli

Command-line interface and entry point.

```
crates/dybervpn-cli/
├── src/
│   └── main.rs          # CLI commands, argument parsing
└── Cargo.toml
```

**Responsibilities:**

- Parse command-line arguments
- Load and validate configuration
- Start/stop daemon
- Key generation
- Status reporting

### dybervpn-tunnel

Tunnel management and platform-specific code.

```
crates/dybervpn-tunnel/
├── src/
│   ├── lib.rs           # Public API
│   ├── daemon.rs        # Event loop, packet handling
│   ├── config.rs        # Runtime configuration
│   └── linux.rs         # Linux TUN device
└── Cargo.toml
```

**Responsibilities:**

- TUN device creation/management
- UDP socket handling
- Event loop (TUN ↔ UDP)
- Peer management
- PID file management

### boringtun

Forked from Cloudflare BoringTun with PQ extensions.

```
boringtun/
├── src/
│   ├── lib.rs           # Public API
│   └── noise/
│       ├── mod.rs       # Tunn implementation
│       ├── handshake.rs # Classical Noise handshake
│       ├── hybrid_handshake.rs    # PQ key types
│       ├── hybrid_integration.rs  # PQ state machine
│       ├── session.rs   # Session key management
│       └── timers.rs    # Rekey timers
└── Cargo.toml
```

**Responsibilities:**

- Noise protocol implementation
- PQ handshake (ML-KEM + X25519)
- PQ authentication (ML-DSA)
- Packet encryption/decryption
- Session management

### dybervpn-protocol

Core cryptographic operations and configuration.

```
crates/dybervpn-protocol/
├── src/
│   ├── lib.rs           # CryptoBackend trait
│   ├── software.rs      # Software crypto implementation
│   ├── config/
│   │   └── mod.rs       # TOML parsing
│   └── types.rs         # Operating modes, types
└── Cargo.toml
```

**Responsibilities:**

- `CryptoBackend` trait abstraction
- ML-KEM operations (keygen, encaps, decaps)
- ML-DSA operations (keygen, sign, verify)
- Configuration parsing
- Key type definitions

## Cryptographic Architecture

### Key Hierarchy

```
┌─────────────────────────────────────────────────┐
│                Identity Keys                    │
│  (Long-term, stored in configuration)           │
├─────────────────────────────────────────────────┤
│  X25519 Private Key    │  ML-KEM Private Key    │
│  X25519 Public Key     │  ML-KEM Public Key     │
│  Ed25519 Private Key   │  ML-DSA Private Key    │
│  Ed25519 Public Key    │  ML-DSA Public Key     │
└─────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────┐
│              Ephemeral Keys                     │
│  (Generated per handshake)                      │
├─────────────────────────────────────────────────┤
│  X25519 Ephemeral      │  ML-KEM Ciphertext     │
└─────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────┐
│              Session Keys                       │
│  (Derived, rotated every 2 min)                 │
├─────────────────────────────────────────────────┤
│  ChaCha20-Poly1305 Send Key                     │
│  ChaCha20-Poly1305 Recv Key                     │
└─────────────────────────────────────────────────┘
```

### Handshake Protocol

#### Hybrid Mode

```
Initiator                                    Responder
    │                                            │
    │  Generate ephemeral X25519 key             │
    │  Generate ML-KEM encapsulation             │
    │                                            │
    │─────────────── INIT ─────────────────────▶│
    │  X25519 ephemeral public                   │
    │  ML-KEM ciphertext                         │
    │  Encrypted payload (Ed25519 sig)           │
    │                                            │
    │                    Verify X25519 DH        │
    │                    Decapsulate ML-KEM      │
    │                    Combine shared secrets  │
    │                    Verify signature        │
    │                                            │
    │◀────────────── RESPONSE ───────────────────│
    │  X25519 ephemeral public                   │
    │  Encrypted payload (Ed25519 sig)           │
    │                                            │
    │  Verify X25519 DH                          │
    │  Combine shared secrets                    │
    │  Derive session keys                       │
    │                                            │
    │◀═══════════ ENCRYPTED DATA ═════════════▶│
    │           ChaCha20-Poly1305                │
```

#### PQ-Only Mode

Same as hybrid, but signatures use ML-DSA-65 instead of Ed25519:

```
INIT message:
  + ML-DSA signature of transcript (3309 bytes)

RESPONSE message:
  + ML-DSA signature of transcript (3309 bytes)
```

### CryptoBackend Trait

```rust
pub trait CryptoBackend: Send + Sync {
    // ML-KEM operations
    fn mlkem_keygen(&self) -> Result<(MlKemPublicKey, MlKemSecretKey)>;
    fn mlkem_encaps(&self, pk: &MlKemPublicKey) -> Result<(MlKemCiphertext, SharedSecret)>;
    fn mlkem_decaps(&self, sk: &MlKemSecretKey, ct: &MlKemCiphertext) -> Result<SharedSecret>;

    // ML-DSA operations
    fn mldsa_keygen(&self) -> Result<(MlDsaPublicKey, MlDsaSecretKey)>;
    fn mldsa_sign(&self, sk: &MlDsaSecretKey, msg: &[u8]) -> Result<MlDsaSignature>;
    fn mldsa_verify(&self, pk: &MlDsaPublicKey, msg: &[u8], sig: &MlDsaSignature) -> Result<bool>;

    // Entropy
    fn random_bytes(&self, buf: &mut [u8]) -> Result<()>;
}
```

This abstraction allows for:

- Software implementation (current)
- Hardware acceleration (QUAC 100, planned)
- FIPS-validated module (planned)

## Data Flow

### Packet Processing

```
┌─────────┐     ┌─────────┐     ┌─────────┐     ┌─────────┐
│  App    │───▶│  TUN     │───▶│ Encrypt │───▶│  UDP    │
│         │     │ Device  │     │ (Tunn)  │     │ Socket  │
└─────────┘     └─────────┘     └─────────┘     └─────────┘
                                  │
                          ChaCha20-Poly1305
                                  │
                                  ▼
                            ┌─────────┐
                            │ Network │
                            └─────────┘
                                  │
                                  ▼
┌─────────┐     ┌─────────┐    ┌─────────┐     ┌─────────┐
│  App    │◀───│  TUN    │◀───│ Decrypt │◀───│  UDP    │
│         │     │ Device  │    │ (Tunn)  │     │ Socket  │
└─────────┘     └─────────┘    └─────────┘     └─────────┘
```

### Event Loop

```rust
loop {
    select! {
        // TUN device → Network
        packet = tun.read() => {
            let encrypted = tunn.encapsulate(packet);
            udp.send(encrypted, peer_endpoint);
        }

        // Network → TUN device
        (data, src) = udp.recv() => {
            match tunn.decapsulate(data) {
                TunnResult::WriteToNetwork(packet) => {
                    tun.write(packet);
                }
                TunnResult::WriteToTunnelV4(packet, _) => {
                    tun.write(packet);
                }
                // ... other variants
            }
        }

        // Timer events
        _ = timer.tick() => {
            tunn.update_timers(&mut dst);
        }
    }
}
```

## Security Architecture

### Defense in Depth

1. **Hybrid Key Exchange**: ML-KEM-768 + X25519
   - Both must be broken to compromise confidentiality
   - Protection against unknown weaknesses

2. **Authenticated Encryption**: ChaCha20-Poly1305
   - 256-bit symmetric key (quantum-resistant)
   - Authentication prevents tampering

3. **Forward Secrecy**: Ephemeral keys per session
   - Compromise of identity key doesn't affect past sessions

4. **Key Rotation**: Every 2 minutes or 2^64 messages
   - Limits exposure from any single key compromise

### Memory Safety

- Written in Rust (memory-safe by default)
- `zeroize` crate for secure memory clearing
- No `unsafe` code in new components

### Side-Channel Resistance

- Constant-time operations in crypto libraries
- No secret-dependent branching
- Secure random number generation

## Performance Characteristics

### Handshake Latency

| Mode    | Latency     | Notes                     |
| ------- | ----------- | ------------------------- |
| Hybrid  | ~250-300 µs | ML-KEM + X25519 + Ed25519 |
| PQ-Only | ~2-3 ms     | + ML-DSA signatures       |
| Classic | ~100 µs     | X25519 + Ed25519 only     |

### Data Plane

- Same as WireGuard® (ChaCha20-Poly1305)
- ~1 Gbps+ on modern hardware
- CPU-bound (no hardware offload currently)

### Memory Usage

- ~10 MB base process
- ~1 KB per peer session
- Keys stored in process memory

## Future Architecture

### Hardware Acceleration (QUAC 100)

```rust
pub struct Quac100Backend {
    device: QuacDevice,
    // ...
}

impl CryptoBackend for Quac100Backend {
    fn mlkem_keygen(&self) -> Result<...> {
        self.device.hardware_mlkem_keygen()
    }
    // ...
}
```

### FIPS 140-3 Module

```
┌─────────────────────────────────────────┐
│           FIPS Crypto Module            │
│  ┌─────────────────────────────────┐    │
│  │  ML-KEM-768  │  ML-DSA-65       │    │
│  │  ChaCha20    │  Poly1305        │    │
│  │  HKDF-SHA256 │  BLAKE2s         │    │
│  └─────────────────────────────────┘    │
│         (Cryptographic Boundary)        │
└─────────────────────────────────────────┘
```

---

_Copyright 2026 Dyber, Inc._
