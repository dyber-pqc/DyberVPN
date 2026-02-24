# CLI Reference

Complete reference for all DyberVPN commands.

## Global Options

```
-v, --verbose    Enable verbose logging
-h, --help       Print help
-V, --version    Print version
```

## Commands

### genkey

Generate cryptographic key pairs.

```bash
dybervpn genkey [OPTIONS]
```

**Options:**

| Option | Short | Values | Default | Description |
|--------|-------|--------|---------|-------------|
| `--mode` | `-m` | `hybrid`, `pqonly`, `classic` | `hybrid` | Key generation mode |

**Examples:**

```bash
# Generate hybrid keys (ML-KEM + X25519)
dybervpn genkey -m hybrid

# Generate PQ-only keys (includes ML-DSA)
dybervpn genkey -m pqonly

# Generate classic WireGuard keys
dybervpn genkey -m classic

# Save to file
dybervpn genkey -m hybrid > server_keys.txt
```

**Output:**

```toml
# DyberVPN Key Pair
# Mode: Hybrid
# Generated: 2026-02-24T12:00:00Z

[interface]
private_key = "BASE64..."
# public_key = "BASE64..."

# Post-Quantum Keys (ML-KEM-768)
pq_private_key = "BASE64..."
# pq_public_key = "BASE64..."
```

---

### up

Start a VPN tunnel.

```bash
dybervpn up [OPTIONS]
```

**Options:**

| Option | Short | Required | Default | Description |
|--------|-------|----------|---------|-------------|
| `--config` | `-c` | Yes | - | Path to configuration file |
| `--foreground` | `-f` | No | false | Run in foreground |

**Examples:**

```bash
# Start as daemon
sudo dybervpn up -c /etc/dybervpn/server.toml

# Start in foreground (for debugging)
sudo dybervpn up -c /etc/dybervpn/server.toml -f

# Start with verbose logging
sudo dybervpn up -c /etc/dybervpn/server.toml -f -v
```

**Notes:**

- Requires root or CAP_NET_ADMIN capability
- Creates TUN interface specified in config
- PID file written to `/var/run/dybervpn/{interface}.pid`

---

### down

Stop a VPN tunnel.

```bash
dybervpn down <INTERFACE>
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `INTERFACE` | Yes | Interface name to stop |

**Examples:**

```bash
# Stop tunnel
sudo dybervpn down dvpn0

# Stop all tunnels
for iface in $(dybervpn status --json | jq -r '.interfaces[]'); do
  sudo dybervpn down $iface
done
```

---

### status

Show running tunnel status.

```bash
dybervpn status [OPTIONS]
```

**Options:**

| Option | Short | Description |
|--------|-------|-------------|
| `--json` | `-j` | Output as JSON |

**Examples:**

```bash
# Show status
dybervpn status

# JSON output
dybervpn status --json
```

**Output:**

```
DyberVPN Status
===============

Interface: dvpn0
  Status: running
  PID: 12345
  Mode: hybrid
  Address: 10.200.200.1/24
  Listen Port: 51820
  Peers: 1
```

---

### check

Validate a configuration file.

```bash
dybervpn check [OPTIONS]
```

**Options:**

| Option | Short | Required | Description |
|--------|-------|----------|-------------|
| `--config` | `-c` | Yes | Path to configuration file |

**Examples:**

```bash
# Validate config
dybervpn check -c server.toml

# Validate all configs
for f in /etc/dybervpn/*.toml; do
  echo "Checking $f..."
  dybervpn check -c "$f"
done
```

**Output (valid):**

```
✓ Configuration is valid
Summary:
  Device: dvpn0
  Mode: Hybrid
  Address: 10.200.200.1/24
  Listen Port: 51820
  Peers: 1
```

**Output (invalid):**

```
✗ Configuration is invalid
Error: Missing required field 'pq_private_key' for hybrid mode
```

---

### version

Show version and cryptographic information.

```bash
dybervpn version
```

**Output:**

```
DyberVPN 0.1.0

Protocol: DyberVPN v1 (WireGuard-compatible)
Crypto Backend: software (ml-kem + dalek)

Algorithms:
  Key Exchange: ML-KEM-768 + X25519 (hybrid)
  Authentication: Ed25519 (Phase 1), ML-DSA-65 (pq-only)
  AEAD: ChaCha20-Poly1305
  Hash: BLAKE2s, SHA-256

Compliance:
  NIST FIPS 203 (ML-KEM)
  NIST FIPS 204 (ML-DSA) - pq-only mode
  CNSA 2.0 Aligned

License: Apache-2.0 (new code), BSD-3-Clause (BoringTun-derived)
```

---

### benchmark

Run cryptographic performance benchmarks.

```bash
dybervpn benchmark [OPTIONS]
```

**Options:**

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--iterations` | `-i` | 100 | Number of iterations |

**Examples:**

```bash
# Default benchmark
dybervpn benchmark

# Quick benchmark
dybervpn benchmark -i 50

# Detailed benchmark
dybervpn benchmark -i 1000
```

**Output:**

```
DyberVPN Cryptographic Benchmarks
==================================
Backend: software (ml-kem + dalek)
Iterations: 100

ML-KEM-768 keygen:     88.00 µs/op
ML-KEM-768 encaps:     77.00 µs/op
ML-KEM-768 decaps:     91.00 µs/op
X25519 keygen:         64.00 µs/op
X25519 DH:             45.00 µs/op
Ed25519 sign:          29.00 µs/op
Ed25519 verify:        31.00 µs/op

Post-Quantum Signatures (ML-DSA-65):
ML-DSA-65 keygen:     291.00 µs/op
ML-DSA-65 sign:       328.00 µs/op
ML-DSA-65 verify:     166.00 µs/op

Full hybrid handshake estimate: ~250-300 µs
Full PQ-only handshake estimate: ~2-3 ms (includes ML-DSA)
```

---

### init (Planned)

Interactive setup wizard.

```bash
dybervpn init [OPTIONS]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--server` | Initialize as server |
| `--client` | Initialize as client |

*Note: This command is planned for a future release.*

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Configuration error |
| 3 | Permission denied |
| 4 | Interface already exists |
| 5 | Interface not found |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `DYBERVPN_CONFIG` | Default configuration file path |
| `DYBERVPN_LOG` | Log level (trace, debug, info, warn, error) |
| `RUST_LOG` | Alternative log level setting |

## See Also

- [Configuration Guide](configuration.md)
- [Deployment Guide](deployment.md)
- [Troubleshooting](troubleshooting.md)

---

*Copyright 2026 Dyber, Inc.*
