# Quick Start Guide

Get DyberVPN running in 5 minutes.

## Prerequisites

- Linux (Ubuntu 20.04+ recommended)
- Root access or CAP_NET_ADMIN capability

## Step 1: Install

```bash
# Download latest release
curl -LO https://github.com/dyber-pqc/DyberVPN/releases/latest/download/dybervpn-linux-x86_64.tar.gz

# Extract
tar -xzf dybervpn-linux-x86_64.tar.gz

# Install
sudo mv dybervpn /usr/local/bin/
sudo chmod +x /usr/local/bin/dybervpn

# Verify
dybervpn version
```

## Step 2: Generate Keys

On **both** server and client, generate key pairs:

```bash
# Server
dybervpn genkey -m hybrid > server_keys.txt
cat server_keys.txt

# Client  
dybervpn genkey -m hybrid > client_keys.txt
cat client_keys.txt
```

## Step 3: Configure Server

Create `/etc/dybervpn/server.toml`:

```toml
[interface]
name = "dvpn0"
listen_port = 51820
address = "10.200.200.1/24"
mode = "hybrid"

# Paste from server_keys.txt
private_key = "YOUR_SERVER_PRIVATE_KEY"
pq_private_key = "YOUR_SERVER_PQ_PRIVATE_KEY"

[[peer]]
# Paste CLIENT's public keys
public_key = "CLIENT_PUBLIC_KEY"
pq_public_key = "CLIENT_PQ_PUBLIC_KEY"
allowed_ips = "10.200.200.2/32"
```

## Step 4: Configure Client

Create `/etc/dybervpn/client.toml`:

```toml
[interface]
name = "dvpn0"
address = "10.200.200.2/24"
mode = "hybrid"

# Paste from client_keys.txt
private_key = "YOUR_CLIENT_PRIVATE_KEY"
pq_private_key = "YOUR_CLIENT_PQ_PRIVATE_KEY"

[[peer]]
# Paste SERVER's public keys
public_key = "SERVER_PUBLIC_KEY"
pq_public_key = "SERVER_PQ_PUBLIC_KEY"
endpoint = "your-server-ip:51820"
allowed_ips = "10.200.200.0/24"
persistent_keepalive = 25
```

## Step 5: Validate Configuration

```bash
# Server
dybervpn check -c /etc/dybervpn/server.toml

# Client
dybervpn check -c /etc/dybervpn/client.toml
```

## Step 6: Start VPN

**Server:**
```bash
sudo dybervpn up -c /etc/dybervpn/server.toml -f
```

**Client (new terminal):**
```bash
sudo dybervpn up -c /etc/dybervpn/client.toml -f
```

## Step 7: Test Connection

```bash
# From client, ping server
ping 10.200.200.1

# From server, ping client
ping 10.200.200.2
```

## 🎉 Done!

You now have a post-quantum VPN tunnel with:
- **ML-KEM-768** key exchange (NIST FIPS 203)
- **ChaCha20-Poly1305** encryption
- **Ed25519** authentication

## Next Steps

- [Run as a service](deployment.md#systemd-service)
- [Enable PQ-only mode](configuration.md#pq-only-mode) for ML-DSA authentication
- [Docker deployment](deployment.md#docker)

## Troubleshooting

**Handshake timeout?**
- Check firewall allows UDP port 51820
- Verify endpoint IP is correct
- Ensure keys match (server's public → client, client's public → server)

**Permission denied?**
```bash
sudo setcap cap_net_admin+ep /usr/local/bin/dybervpn
```

**More help:** [Troubleshooting Guide](troubleshooting.md)

---

*Copyright 2026 Dyber, Inc.*
