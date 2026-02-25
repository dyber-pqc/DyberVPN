# DyberVPN Enterprise Security Features

## Overview

DyberVPN v0.1.3 includes three enterprise security capabilities designed for SOC 2, FedRAMP, and HIPAA compliance:

1. **Zero Trust Access Control** — per-peer, role-based policy enforcement on every packet
2. **Key Revocation & Lifecycle** — CRL management, suspension, reinstatement, automatic expiry
3. **Structured Audit Logging** — NDJSON compliance-ready events for SIEM integration

All three features are optional and disabled by default. They activate through TOML configuration sections.

---

## 1. Zero Trust Access Control

### How It Works

When `[access_control]` is enabled with `default_action = "deny"`, every forwarded packet is checked against the policy engine before delivery. Peers are assigned **roles**, and each role has ordered **rules** that match on destination network, port, and protocol.

The policy engine runs in the daemon's packet forwarding path:
- **TUN → peer**: packets from the local network to a VPN peer
- **Peer → TUN**: packets from a VPN peer to the local network
- **Peer → peer**: packets forwarded between VPN peers

### Configuration

```toml
[access_control]
enabled = true
default_action = "deny"  # Zero Trust: deny unless explicitly allowed

[[access_control.role]]
name = "engineering"
peers = ["alice", "bob"]           # Match by peer name (from # Peer: comments)
peer_keys = ["aabbccdd"]          # Match by key fingerprint (first 8 hex chars)

[[access_control.role.rule]]
action = "allow"
network = "10.100.0.0/16"
ports = "443,8080-8090"
protocol = "tcp"
description = "Allow HTTPS and dev services"

[[access_control.role.rule]]
action = "deny"
network = "10.100.50.0/24"
description = "Block production database subnet"
```

### Rule Evaluation

Rules are evaluated top-to-bottom within each role. First matching rule wins. If no rule matches, the `default_action` applies.

**Supported fields:**
- `action`: `"allow"` or `"deny"`
- `network`: CIDR notation (`10.0.0.0/8`, `192.168.1.0/24`, `0.0.0.0/0`)
- `ports`: comma-separated ports and ranges (`443`, `8080-8090`, `80,443,8080-9090`)
- `protocol`: `"tcp"`, `"udp"`, `"icmp"`, `"any"` (default: `"any"`)

---

## 2. Key Revocation & Lifecycle

### How It Works

The revocation engine maintains a **Certificate Revocation List (CRL)** — a JSON file listing all revoked and suspended keys. The daemon checks this list:
- On every new handshake attempt (immediate rejection)
- Periodically for existing sessions (configurable interval, default 5 minutes)
- On config reload (`dybervpn reload` or SIGHUP)

### Configuration

```toml
[security]
crl_path = "/etc/dybervpn/revoked-keys.json"
key_max_age_hours = 720              # Force key rotation after 30 days
session_max_age_hours = 24           # Re-handshake daily
check_interval_secs = 300            # Check CRL every 5 minutes
auto_disconnect_revoked = true       # Immediately disconnect revoked peers
```

### CLI Commands

```bash
# Revoke a peer's key (employee departure)
dybervpn revoke-key -c server.toml -p alice -r employee_departed -b admin@company.com

# Temporarily suspend a key (with auto-expiry)
dybervpn suspend-key -c server.toml -p bob -e 24h
dybervpn suspend-key -c server.toml -p bob -e 7d
dybervpn suspend-key -c server.toml -p bob -e "2026-03-15T00:00:00Z"

# Reinstate a suspended/revoked key
dybervpn reinstate-key -c server.toml -p bob

# List all revoked keys
dybervpn list-revoked -c server.toml
dybervpn list-revoked -c server.toml --json    # Machine-readable output

# Force daemon to reload CRL immediately
dybervpn reload dvpn0
```

### Revocation Reasons

| Reason | CLI value | Description |
|--------|-----------|-------------|
| Employee Departed | `employee_departed`, `departed`, `left` | Employee no longer with organization |
| Key Compromised | `key_compromised`, `compromised` | Key suspected or confirmed compromised |
| Device Lost | `device_lost`, `lost`, `stolen` | Device lost or stolen |
| Key Superseded | `key_superseded`, `superseded`, `rotated` | Replaced by a new key pair |
| Policy Violation | `policy_violation`, `violation` | Security policy breach |
| Administrative | `administrative`, `admin` | General admin action |
| Suspended | `suspended` | Temporary suspension |

### CRL File Format

```json
{
  "version": 1,
  "updated_at": "2026-02-25T12:00:00Z",
  "revoked_keys": [
    {
      "public_key_fingerprint": "a1b2c3d4e5f6a7b8",
      "name": "alice-laptop",
      "revoked_at": "2026-02-25T12:00:00Z",
      "reason": "employee_departed",
      "revoked_by": "admin@company.com",
      "expires_at": null
    }
  ]
}
```

---

## 3. Structured Audit Logging

### How It Works

The audit logger emits **NDJSON** (newline-delimited JSON) events — one JSON object per line. This format is directly ingestible by:
- Splunk, Elasticsearch/OpenSearch, Datadog
- AWS CloudWatch Logs, Azure Sentinel
- Any SIEM that accepts structured JSON

### Configuration

```toml
[audit]
enabled = true
path = "/var/log/dybervpn/audit.jsonl"
max_size_mb = 100                    # Rotate at 100 MB
rotate_count = 10                    # Keep 10 rotated files
log_data_packets = false             # Per-packet logging (very high volume)
events = ["connection", "handshake", "policy", "key_management", "admin"]
```

### Event Categories

| Category | Events Logged |
|----------|--------------|
| `connection` | Peer connected, disconnected, session established/expired |
| `handshake` | Handshake initiated, completed, failed, rejected (revoked key) |
| `policy` | Packet allowed, packet denied (with src/dst/port/protocol) |
| `key_management` | Key revoked, suspended, reinstated, rotated, expired |
| `admin` | Config reload, peer added/removed, daemon start/stop |
| `enrollment` | Enrollment request, approved, rejected |
| `data_plane` | Per-packet events (only when `log_data_packets = true`) |
| `system` | Daemon startup, shutdown, errors |

### Event Format

```json
{
  "timestamp": "2026-02-25T14:30:22.123Z",
  "event_id": 42,
  "category": "policy",
  "event_type": "packet_denied",
  "outcome": "denied",
  "peer_id": "a1b2c3d4",
  "peer_name": "alice",
  "source_ip": "10.200.200.2",
  "dest_ip": "10.100.50.5",
  "dest_port": 22,
  "protocol": 6,
  "interface": "dvpn0",
  "message": "Policy DENY: peer alice 10.200.200.2 -> 10.100.50.5:22 (TCP) rule=engineering:rule-1",
  "policy_rule": "engineering:rule-1",
  "hostname": "vpn-server-01",
  "version": "0.1.3"
}
```

### Compliance Mapping

| Requirement | Feature |
|-------------|---------|
| SOC 2 CC6.1 | Audit logging of all access events |
| SOC 2 CC6.2 | Access control enforcement with role-based policies |
| SOC 2 CC6.3 | Key lifecycle management and revocation |
| FedRAMP AC-2 | Account management via peer enrollment + revocation |
| FedRAMP AU-2 | Audit events for security-relevant actions |
| FedRAMP AU-3 | Content of audit records (who, what, when, where) |
| FedRAMP IA-5 | Authenticator management (key rotation, revocation) |
| HIPAA §164.312(b) | Audit controls for ePHI access |
| HIPAA §164.312(d) | Person/entity authentication |

---

## Quick Start

### Enable all enterprise features on existing server

Add these sections to your server config:

```toml
# After [interface] section, before [[peer]] sections:

[security]
crl_path = "/etc/dybervpn/revoked-keys.json"

[access_control]
enabled = true
default_action = "deny"

[[access_control.role]]
name = "default"
peers = ["all-peer-names-here"]
[[access_control.role.rule]]
action = "allow"
network = "0.0.0.0/0"

[audit]
enabled = true
path = "/var/log/dybervpn/audit.jsonl"
events = ["connection", "handshake", "policy", "key_management", "admin"]
```

Then restart:
```bash
sudo dybervpn down dvpn0
sudo dybervpn up -c /etc/dybervpn/server.toml -f
```

### Employee offboarding workflow

```bash
# 1. Revoke the key
dybervpn revoke-key -c server.toml -p alice -r employee_departed -b "security@company.com" -y

# 2. Force immediate disconnect
dybervpn reload dvpn0

# 3. Optionally remove from config
dybervpn remove-peer -c server.toml -p alice

# 4. Verify
dybervpn list-revoked -c server.toml
```

### Incident response: temporary suspension

```bash
# Suspect compromise — suspend for 24 hours while investigating
dybervpn suspend-key -c server.toml -p bob -e 24h -b "soc@company.com"
dybervpn reload dvpn0

# Investigation complete — reinstate
dybervpn reinstate-key -c server.toml -p bob
dybervpn reload dvpn0
```
