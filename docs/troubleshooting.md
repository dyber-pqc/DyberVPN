# Troubleshooting Guide

Common issues and solutions for DyberVPN.

## Quick Diagnostics

```bash
# Check version and crypto backend
dybervpn version

# Validate configuration
dybervpn check -c /etc/dybervpn/config.toml

# Check running status
dybervpn status

# View logs (systemd)
journalctl -u dybervpn -f

# Run with verbose logging
sudo dybervpn up -c config.toml -f -v
```

## Common Issues

### 1. Permission Denied

**Symptoms:**
```
Error: Permission denied (os error 13)
Error: Operation not permitted
```

**Solutions:**

```bash
# Option 1: Run as root
sudo dybervpn up -c config.toml -f

# Option 2: Set capabilities
sudo setcap cap_net_admin+ep /usr/local/bin/dybervpn

# Option 3: Check file permissions
ls -la /etc/dybervpn/config.toml
chmod 600 /etc/dybervpn/config.toml
```

### 2. Interface Already Exists

**Symptoms:**
```
Error: Interface dvpn0 already exists
```

**Solutions:**

```bash
# Check if interface exists
ip link show dvpn0

# Remove stale interface
sudo ip link delete dvpn0

# Check for running process
dybervpn status
sudo dybervpn down dvpn0
```

### 3. Invalid Configuration

**Symptoms:**
```
Error: Invalid configuration
TOML parse error at line 5
```

**Solutions:**

```bash
# Validate syntax
dybervpn check -c config.toml

# Common issues:
# - Missing quotes around strings
# - Invalid base64 in keys
# - Mode mismatch between peers
```

### 4. Handshake Timeout

**Symptoms:**
```
WARN: HANDSHAKE(REKEY_TIMEOUT)
Peer not responding
```

**Causes & Solutions:**

| Cause | Solution |
|-------|----------|
| Firewall blocking | Open UDP port 51820 |
| Wrong endpoint | Verify server IP/hostname |
| Key mismatch | Regenerate and exchange keys |
| Mode mismatch | Ensure both sides use same mode |
| NAT issues | Enable persistent_keepalive |

```bash
# Check firewall
sudo ufw status
sudo iptables -L -n | grep 51820

# Test connectivity
nc -vzu server.example.com 51820

# Enable keepalive (in client config)
persistent_keepalive = 25
```

### 5. Key Errors

**Symptoms:**
```
Error: Invalid base64 key
Error: Key length mismatch
```

**Solutions:**

```bash
# Regenerate keys
dybervpn genkey -m hybrid > new_keys.txt

# Verify key format
echo "KEY_HERE" | base64 -d | wc -c

# Expected sizes:
# X25519 private key: 32 bytes
# X25519 public key: 32 bytes
# ML-KEM private key: 2400 bytes
# ML-KEM public key: 1184 bytes
# ML-DSA private key: 4032 bytes
# ML-DSA public key: 1952 bytes
```

### 6. Mode Mismatch

**Symptoms:**
```
Error: Handshake failed - mode mismatch
Incompatible handshake message
```

**Solutions:**

Both endpoints MUST use the same mode:

```toml
# Server
mode = "hybrid"

# Client (must match)
mode = "hybrid"
```

### 7. PQ-Only Mode Errors

**Symptoms:**
```
Error: Missing mldsa_private_key for pqonly mode
Error: ML-DSA signature verification failed
```

**Solutions:**

```bash
# Generate PQ-only keys
dybervpn genkey -m pqonly

# Verify config includes ML-DSA keys
grep mldsa config.toml
```

Required fields for pqonly mode:
- `mldsa_private_key` (interface)
- `mldsa_public_key` (peer)

### 8. No Traffic Flow

**Symptoms:**
- Handshake succeeds
- Ping fails
- No traffic over tunnel

**Solutions:**

```bash
# Check interface is up
ip addr show dvpn0

# Check routing
ip route | grep dvpn0

# Check allowed_ips
# Must include destination IP range

# Enable IP forwarding (for routing)
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

# Check NAT (if routing to internet)
sudo iptables -t nat -L
```

### 9. Docker Issues

**Symptoms:**
```
exec /usr/local/bin/dybervpn: operation not permitted
```

**Solutions:**

```bash
# Ensure capabilities
docker run --cap-add NET_ADMIN --cap-add NET_RAW ...

# Check privileged mode
docker run --privileged ...

# Verify image
docker run --rm dybervpn:latest version
```

### 10. High CPU Usage

**Symptoms:**
- CPU spikes during handshake
- Slow tunnel establishment

**Notes:**
- ML-DSA operations are CPU-intensive (~300-700µs per operation)
- PQ-only handshakes take ~2-3ms (vs ~300µs for hybrid)
- This is expected behavior for post-quantum cryptography

**Optimizations:**
```bash
# Use hybrid mode for lower CPU (if acceptable)
mode = "hybrid"

# Use release build (not debug)
cargo build --release
```

## Debug Mode

### Enable Verbose Logging

```bash
# CLI
dybervpn up -c config.toml -f -v

# Environment variable
RUST_LOG=debug dybervpn up -c config.toml -f

# Specific component
RUST_LOG=boringtun::noise=trace dybervpn up -c config.toml -f
```

### Log Levels

| Level | Description |
|-------|-------------|
| error | Errors only |
| warn | Warnings and errors |
| info | General information (default) |
| debug | Detailed debugging |
| trace | Very verbose (includes crypto) |

## Network Debugging

### tcpdump

```bash
# Capture UDP traffic
sudo tcpdump -i eth0 udp port 51820 -n

# Capture tunnel traffic
sudo tcpdump -i dvpn0 -n
```

### Wireshark

Filter: `udp.port == 51820`

Note: DyberVPN traffic is encrypted; you'll only see encrypted payloads.

## Getting Help

1. **Check Documentation**: [docs/](https://github.com/dyber-pqc/DyberVPN/tree/main/docs)
2. **Search Issues**: [GitHub Issues](https://github.com/dyber-pqc/DyberVPN/issues)
3. **Ask Questions**: [GitHub Discussions](https://github.com/dyber-pqc/DyberVPN/discussions)
4. **Report Bugs**: Use the bug report template
5. **Security Issues**: Email security@dyber.org

## Diagnostic Commands Summary

```bash
# System info
uname -a
dybervpn version

# Network info
ip addr
ip route
ss -ulnp | grep 51820

# Firewall
sudo iptables -L -n
sudo ufw status verbose

# Process info
ps aux | grep dybervpn
dybervpn status

# Logs
journalctl -u dybervpn -n 100
docker logs dybervpn

# Configuration
dybervpn check -c config.toml
```

---

*Copyright 2026 Dyber, Inc.*
