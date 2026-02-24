# Configuration Guide

DyberVPN uses TOML configuration files. This guide covers all configuration options.

## Configuration File Location

Default locations:
- `/etc/dybervpn/config.toml`
- `./config.toml` (current directory)
- Custom path via `-c` flag

## Basic Configuration

### Server Configuration

```toml
# /etc/dybervpn/server.toml

[interface]
# Interface name (dvpn0, dvpn1, etc.)
name = "dvpn0"

# UDP port to listen on
listen_port = 51820

# VPN IP address for this endpoint
address = "10.200.200.1/24"

# Operating mode: hybrid, pqonly, or classic
mode = "hybrid"

# Private keys (generate with: dybervpn genkey -m hybrid)
private_key = "BASE64_X25519_PRIVATE_KEY"
pq_private_key = "BASE64_MLKEM_PRIVATE_KEY"

# Only for pqonly mode:
# mldsa_private_key = "BASE64_MLDSA_PRIVATE_KEY"

# Peers
[[peer]]
# Peer's public keys
public_key = "BASE64_X25519_PUBLIC_KEY"
pq_public_key = "BASE64_MLKEM_PUBLIC_KEY"

# Only for pqonly mode:
# mldsa_public_key = "BASE64_MLDSA_PUBLIC_KEY"

# Allowed IP ranges for this peer
allowed_ips = "10.200.200.2/32"

# Optional: peer endpoint (for server, usually not needed)
# endpoint = "peer.example.com:51820"
```

### Client Configuration

```toml
# /etc/dybervpn/client.toml

[interface]
name = "dvpn0"
address = "10.200.200.2/24"
mode = "hybrid"

private_key = "BASE64_X25519_PRIVATE_KEY"
pq_private_key = "BASE64_MLKEM_PRIVATE_KEY"

[[peer]]
public_key = "BASE64_SERVER_X25519_PUBLIC_KEY"
pq_public_key = "BASE64_SERVER_MLKEM_PUBLIC_KEY"

# Server endpoint (required for client)
endpoint = "vpn.example.com:51820"

# IP ranges to route through VPN
allowed_ips = "10.200.200.0/24"

# Optional: all traffic through VPN
# allowed_ips = "0.0.0.0/0, ::/0"

# Keep connection alive (seconds)
persistent_keepalive = 25
```

## Configuration Reference

### [interface] Section

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | Yes | - | TUN interface name |
| `listen_port` | integer | Server only | - | UDP port to listen on |
| `address` | string | Yes | - | VPN IP address (CIDR notation) |
| `mode` | string | No | `hybrid` | Operating mode |
| `private_key` | string | Yes | - | X25519 private key (base64) |
| `pq_private_key` | string | Yes* | - | ML-KEM private key (base64) |
| `mldsa_private_key` | string | pqonly | - | ML-DSA private key (base64) |

*Required for `hybrid` and `pqonly` modes.

### [[peer]] Section

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `public_key` | string | Yes | - | Peer's X25519 public key |
| `pq_public_key` | string | Yes* | - | Peer's ML-KEM public key |
| `mldsa_public_key` | string | pqonly | - | Peer's ML-DSA public key |
| `allowed_ips` | string | Yes | - | Comma-separated CIDR ranges |
| `endpoint` | string | Client | - | Peer's endpoint (host:port) |
| `persistent_keepalive` | integer | No | 0 | Keepalive interval (seconds) |

### Operating Modes

#### Hybrid Mode (Default)

```toml
mode = "hybrid"
```

- Key exchange: ML-KEM-768 + X25519
- Authentication: Ed25519
- Best for: Production deployments

#### PQ-Only Mode

```toml
mode = "pqonly"
```

- Key exchange: ML-KEM-768 + X25519
- Authentication: ML-DSA-65
- Best for: Maximum quantum resistance
- Requires: `mldsa_private_key` and `mldsa_public_key`

#### Classic Mode

```toml
mode = "classic"
```

- Key exchange: X25519
- Authentication: Ed25519
- Best for: WireGuard compatibility
- Note: No post-quantum protection

## Key Generation

### Generate Hybrid Keys

```bash
dybervpn genkey -m hybrid
```

Output:
```toml
[interface]
private_key = "..."
# public_key = "..."
pq_private_key = "..."
# pq_public_key = "..."
```

### Generate PQ-Only Keys

```bash
dybervpn genkey -m pqonly
```

Output (includes ML-DSA keys):
```toml
[interface]
private_key = "..."
pq_private_key = "..."
mldsa_private_key = "..."
```

## Validation

Validate configuration before starting:

```bash
dybervpn check -c /etc/dybervpn/server.toml
```

Output:
```
✓ Configuration is valid
Summary:
  Device: dvpn0
  Mode: Hybrid
  Address: 10.200.200.1/24
  Listen Port: 51820
  Peers: 1
```

## Example Configurations

### Site-to-Site VPN

**Site A (Server):**
```toml
[interface]
name = "dvpn0"
listen_port = 51820
address = "10.0.0.1/24"
mode = "hybrid"
private_key = "SITE_A_PRIVATE"
pq_private_key = "SITE_A_PQ_PRIVATE"

[[peer]]
public_key = "SITE_B_PUBLIC"
pq_public_key = "SITE_B_PQ_PUBLIC"
allowed_ips = "10.0.0.2/32, 192.168.2.0/24"
```

**Site B (Client):**
```toml
[interface]
name = "dvpn0"
address = "10.0.0.2/24"
mode = "hybrid"
private_key = "SITE_B_PRIVATE"
pq_private_key = "SITE_B_PQ_PRIVATE"

[[peer]]
public_key = "SITE_A_PUBLIC"
pq_public_key = "SITE_A_PQ_PUBLIC"
endpoint = "site-a.example.com:51820"
allowed_ips = "10.0.0.1/32, 192.168.1.0/24"
persistent_keepalive = 25
```

### Road Warrior (Mobile Client)

```toml
[interface]
name = "dvpn0"
address = "10.200.200.50/24"
mode = "hybrid"
private_key = "..."
pq_private_key = "..."

[[peer]]
public_key = "..."
pq_public_key = "..."
endpoint = "vpn.company.com:51820"
allowed_ips = "0.0.0.0/0"  # Route all traffic
persistent_keepalive = 25
```

## Troubleshooting

### Common Issues

1. **Invalid base64 key**: Ensure keys are properly base64 encoded
2. **Mode mismatch**: Both endpoints must use the same mode
3. **Missing PQ keys**: `hybrid` and `pqonly` modes require PQ keys
4. **Port in use**: Check if another process is using the port

### Debug Mode

```bash
dybervpn up -c config.toml -f -v
```

The `-v` flag enables verbose logging.

---

*Copyright 2026 Dyber, Inc.*
