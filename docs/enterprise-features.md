# DyberVPN Enterprise Features

**Version 0.1.4** — Access Control, Key Lifecycle, Audit Logging

---

## Overview

DyberVPN includes three enterprise security features designed for SOC 2,
FedRAMP, and HIPAA compliance in production deployments:

| Feature | Purpose | Config Section |
|---------|---------|----------------|
| **Zero Trust Access Control** | Per-peer policy enforcement on every packet | `[access_control]` |
| **Key Lifecycle Management** | Revocation, suspension, expiry, rotation | `[security]` |
| **Structured Audit Logging** | NDJSON events for compliance proof | `[audit]` |

All three are optional — DyberVPN works without them. Enable them when
deploying in regulated environments.

---

## 1. Zero Trust Access Control

### What It Does

Every packet forwarded through the VPN tunnel is checked against per-peer
access control rules. Rules define which networks, ports, and protocols each
peer (or group of peers) can reach.

**Default deny** means: if no rule explicitly allows the traffic, it's dropped.
This is the Zero Trust model.

### Configuration

```toml
[access_control]
enabled = true
default_action = "deny"    # "deny" = Zero Trust, "allow" = permissive

# Define roles with sets of rules
[[access_control.role]]
name = "engineering"
peers = ["alice", "bob"]           # Match by comment name above [[peer]]
peer_keys = ["aabbccdd"]           # Match by key fingerprint (hex prefix)

[[access_control.role.rule]]
action = "allow"
network = "10.100.0.0/16"         # CIDR notation
ports = "443,8080-8090"           # Comma-separated, ranges allowed
protocol = "tcp"                   # tcp | udp | icmp | any
description = "Dev services"

[[access_control.role.rule]]
action = "deny"
network = "10.100.50.0/24"
description = "Block production DB subnet"
```

### How Rules Are Evaluated

1. For each forwarded packet, the daemon identifies the source peer
2. The peer is matched to a role (by name or key fingerprint)
3. Rules within that role are evaluated **in order** — first match wins
4. If no rule matches, the `default_action` applies

### External Policy Files

For dynamic environments, load policy from an external JSON file:

```toml
[access_control]
enabled = true
policy_path = "/etc/dybervpn/policy.json"
```

The policy file is reloaded on SIGHUP (`dybervpn reload dvpn0`).

### Packet Inspection

The policy engine inspects:

- **IPv4/IPv6** source and destination addresses
- **TCP/UDP** destination port (including port ranges)
- **ICMP** protocol type
- Network matching uses CIDR prefix comparison

---

## 2. Key Lifecycle Management

### What It Does

Manages the full lifecycle of peer cryptographic keys:

- **Revocation** — permanently block a compromised or departed key
- **Suspension** — temporarily block a key (with optional auto-expiry)
- **Reinstatement** — un-revoke or un-suspend a key
- **Key age tracking** — warn or disconnect peers with stale keys
- **Session max age** — force re-handshake after configurable interval

### Configuration

```toml
[security]
crl_path = "/etc/dybervpn/revoked-keys.json"
key_max_age_hours = 720        # 30 days — keys older trigger warning/disconnect
session_max_age_hours = 24     # Force re-handshake every 24h
check_interval_secs = 300      # Check CRL every 5 minutes
auto_disconnect_revoked = true # Immediately disconnect revoked peers
```

### CLI Commands

#### Revoke a key

```bash
# By peer name
dybervpn revoke-key -c server.toml -p alice -r "employee_departed" -b "admin@co.com"

# By key prefix
dybervpn revoke-key -c server.toml -p "aabbccdd" -r "key_compromised"

# By IP
dybervpn revoke-key -c server.toml -p "10.200.200.2" -r "device_lost" --yes
```

**Revocation reasons:** `employee_departed`, `key_compromised`, `device_lost`,
`key_superseded`, `policy_violation`, `administrative`

#### Suspend a key (temporary)

```bash
# Suspend for 24 hours
dybervpn suspend-key -c server.toml -p bob -e "24h"

# Suspend until a specific date
dybervpn suspend-key -c server.toml -p bob -e "2026-03-15T00:00:00Z"

# Suspend indefinitely (manual reinstatement required)
dybervpn suspend-key -c server.toml -p bob
```

**Duration formats:** `24h` (hours), `7d` (days), `2w` (weeks), or RFC 3339

#### Reinstate a key

```bash
dybervpn reinstate-key -c server.toml -p bob
```

#### List revoked keys

```bash
# Human-readable
dybervpn list-revoked -c server.toml

# JSON (for automation/scripting)
dybervpn list-revoked -c server.toml --json
```

### CRL File Format

The Certificate Revocation List is stored as JSON:

```json
{
  "version": 1,
  "updated_at": "2026-02-25T03:00:00Z",
  "entries": [
    {
      "public_key_fingerprint": "aabbccddee112233",
      "public_key_full": "base64...",
      "name": "bob-laptop",
      "revoked_at": "2026-02-24T11:00:00Z",
      "reason": "employee_departed",
      "revoked_by": "admin@company.com",
      "expires_at": null
    }
  ]
}
```

### How Revocation Works

1. **On handshake:** Every incoming handshake is checked against the CRL.
   Revoked keys are rejected before the tunnel is established.

2. **Periodic check:** Every `check_interval_secs` (default: 5 min), the
   daemon scans all connected peers against the current CRL. If
   `auto_disconnect_revoked` is true, revoked peers are disconnected.

3. **On reload:** `dybervpn reload dvpn0` (SIGHUP) reloads the CRL from disk
   and immediately applies changes.

---

## 3. Structured Audit Logging

### What It Does

Emits machine-readable NDJSON (newline-delimited JSON) events for every
security-relevant action. Each line is a self-contained JSON object suitable
for ingestion into SIEM systems (Splunk, Elastic, Datadog, etc.).

### Configuration

```toml
[audit]
enabled = true
path = "/var/log/dybervpn/audit.jsonl"
max_size_mb = 100          # Rotate at 100 MB
rotate_count = 10          # Keep 10 rotated files
log_data_packets = false   # Per-packet logging (WARNING: high volume)
events = [
    "connection",          # Peer connect/disconnect
    "handshake",           # PQ handshake lifecycle
    "policy",              # Access control decisions
    "key_management",      # Key revocation, rotation, expiry
    "admin",               # Config changes, peer management
    "enrollment",          # Enrollment API activity
    "system",              # Daemon start/stop/error
]
```

### Event Format

Every line in the audit log is a JSON object:

```json
{
  "timestamp": "2026-02-25T03:15:42.123456Z",
  "event_id": 42,
  "category": "policy",
  "event_type": "packet_denied",
  "outcome": "denied",
  "peer_id": "aabbccdd",
  "peer_name": "alice",
  "source_ip": "10.200.200.2",
  "dest_ip": "10.100.50.5",
  "dest_port": 22,
  "protocol": 6,
  "interface": "dvpn0",
  "message": "Policy DENY: 10.200.200.2 -> 10.100.50.5:22/TCP rule=engineering:rule-1",
  "policy_rule": "engineering:rule-1",
  "hostname": "vpn-server-01",
  "version": "0.1.4"
}
```

### Event Categories

| Category | Events Logged |
|----------|--------------|
| `connection` | Peer connected, peer disconnected, session established, session expired |
| `handshake` | Handshake initiated, completed, failed, rejected (revoked key) |
| `policy` | Packet allowed, packet denied (with source/dest/port/proto details) |
| `key_management` | Key revoked, key suspended, key reinstated, key expired, key rotated |
| `admin` | Config reloaded, peer added, peer removed, daemon settings changed |
| `enrollment` | Enrollment request received, approved, rejected |
| `data_plane` | Per-packet forwarding events (disabled by default — extremely high volume) |
| `system` | Daemon startup, clean shutdown, error conditions |

### Log Rotation

Automatic rotation prevents unbounded disk usage:

- When the log file exceeds `max_size_mb`, it's renamed to `audit.jsonl.1`
- Previous `.1` becomes `.2`, etc.
- Files beyond `rotate_count` are deleted
- Rotation is atomic — no events are lost during rotation

### SIEM Integration

The NDJSON format is directly compatible with:

- **Splunk:** Configure a file monitor on the audit log path
- **Elastic/OpenSearch:** Use Filebeat with JSON input
- **Datadog:** Use the log agent with JSON parsing
- **Fluentd/Fluent Bit:** Parse as JSON lines
- **syslog:** Forward the file with rsyslog/syslog-ng

---

## Compliance Mapping

| Requirement | DyberVPN Feature |
|-------------|-----------------|
| **SOC 2 CC6.1** — Logical access | Zero Trust access control with per-peer policies |
| **SOC 2 CC6.2** — Access provisioning | Enrollment API + key lifecycle management |
| **SOC 2 CC6.3** — Access removal | Key revocation CLI with immediate disconnect |
| **SOC 2 CC7.2** — System monitoring | Audit logging with connection/policy events |
| **FedRAMP AC-2** — Account management | Per-peer identity with key fingerprints |
| **FedRAMP AC-3** — Access enforcement | Policy engine on every forwarded packet |
| **FedRAMP AU-2** — Auditable events | Structured NDJSON audit trail |
| **FedRAMP AU-3** — Audit content | Timestamp, peer ID, action, outcome in every event |
| **HIPAA §164.312(a)(1)** — Access control | Zero Trust default deny with role-based rules |
| **HIPAA §164.312(b)** — Audit controls | Comprehensive audit logging |
| **HIPAA §164.312(d)** — Authentication | Post-quantum peer authentication |

---

## Quick Start

### 1. Enable enterprise features in your server config

```toml
[access_control]
enabled = true
default_action = "deny"

[[access_control.role]]
name = "team"
peers = ["alice", "bob"]

[[access_control.role.rule]]
action = "allow"
network = "10.0.0.0/8"
protocol = "tcp"
ports = "443,22"

[security]
crl_path = "/etc/dybervpn/revoked-keys.json"

[audit]
enabled = true
path = "/var/log/dybervpn/audit.jsonl"
```

### 2. Create log directory

```bash
sudo mkdir -p /var/log/dybervpn
sudo chown root:root /var/log/dybervpn
sudo chmod 750 /var/log/dybervpn
```

### 3. Start the server

```bash
sudo dybervpn up -c /etc/dybervpn/server.toml -f
```

### 4. Verify audit logging

```bash
tail -f /var/log/dybervpn/audit.jsonl | jq .
```

### 5. Manage keys

```bash
# Employee leaves — revoke immediately
dybervpn revoke-key -c server.toml -p alice -r departed --yes
dybervpn reload dvpn0

# Contractor on leave — suspend for 2 weeks
dybervpn suspend-key -c server.toml -p frank -e 2w

# Check who's revoked
dybervpn list-revoked -c server.toml
```
