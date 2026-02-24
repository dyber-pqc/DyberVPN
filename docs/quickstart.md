# DyberVPN Quick Start Guide

## Installation

### From Source

```bash
# Clone repository
git clone https://github.com/dyberinc/dybervpn
cd dybervpn

# Build
cargo build --release

# Install (Linux)
sudo install -m 755 target/release/dybervpn /usr/local/bin/
```

### Using Install Script (Linux)

```bash
curl -sSL https://raw.githubusercontent.com/dyberinc/dybervpn/main/deploy/install.sh | sudo bash
```

## Server Setup

### 1. Generate Server Configuration

```bash
dybervpn init --server --output /etc/dybervpn/server.toml
```

This generates:
- Classical WireGuard keys (X25519)
- Post-quantum keys (ML-KEM-768)
- A template configuration file

### 2. Configure Firewall

```bash
# Allow UDP port 51820
sudo ufw allow 51820/udp

# Enable IP forwarding
echo 'net.ipv4.ip_forward = 1' | sudo tee /etc/sysctl.d/99-dybervpn.conf
sudo sysctl -p /etc/sysctl.d/99-dybervpn.conf
```

### 3. Start Server

```bash
# Using systemd
sudo systemctl enable --now dybervpn

# Or manually
sudo dybervpn up /etc/dybervpn/server.toml --foreground
```

## Client Setup

### 1. Generate Client Configuration

```bash
dybervpn init --client YOUR_SERVER_IP --output client.toml
```

### 2. Add Client to Server

On the server, edit `/etc/dybervpn/server.toml` and add:

```toml
[[peer]]
public_key = "CLIENT_PUBLIC_KEY"
pq_public_key = "CLIENT_PQ_PUBLIC_KEY"
allowed_ips = "10.0.0.2/32"
```

### 3. Add Server to Client

Edit `client.toml` and add the server's public keys:

```toml
[[peer]]
public_key = "SERVER_PUBLIC_KEY"
pq_public_key = "SERVER_PQ_PUBLIC_KEY"
endpoint = "YOUR_SERVER_IP:51820"
allowed_ips = "0.0.0.0/0"
persistent_keepalive = 25
```

### 4. Connect

```bash
dybervpn up client.toml --foreground
```

## Operating Modes

| Mode | Key Exchange | Authentication | Use Case |
|------|--------------|----------------|----------|
| `hybrid` | ML-KEM-768 + X25519 | Ed25519 | Default, defense-in-depth |
| `pq-only` | ML-KEM-768 | ML-DSA-65 | Maximum quantum resistance |
| `classic` | X25519 | Ed25519 | WireGuard compatibility |

Set mode in config:

```toml
[interface]
mode = "hybrid"
```

## Verification

Check connection status:

```bash
dybervpn status
```

Validate configuration:

```bash
dybervpn check /path/to/config.toml
```

## Troubleshooting

### Permission Denied

DyberVPN requires root/admin privileges for network configuration:

```bash
sudo dybervpn up config.toml --foreground
```

### Handshake Failed

1. Verify keys match between server and client
2. Check firewall allows UDP 51820
3. Ensure both use same mode (hybrid/classic)

### Connection Drops

Add keepalive to client config:

```toml
[[peer]]
persistent_keepalive = 25
```
