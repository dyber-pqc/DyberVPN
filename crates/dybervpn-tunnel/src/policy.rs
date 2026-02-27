//! Access Control Policy Engine — Zero Trust Network Enforcement
//!
//! Enforces per-peer access control policies at the packet level.
//! Every packet transiting the VPN server is checked against the policy
//! before being forwarded to the TUN device or to another peer.
//!
//! # Policy Model
//!
//! - **Roles**: Named groups of access rules (e.g., "engineering", "finance")
//! - **Rules**: Individual allow/deny entries with network, port, and protocol
//! - **Peer assignment**: Each peer is assigned one or more roles
//! - **Default action**: deny-all unless explicitly allowed (Zero Trust)
//!
//! # Configuration
//!
//! ```toml
//! [access_control]
//! enabled = true
//! default_action = "deny"                    # deny | allow
//! policy_path = "/etc/dybervpn/policy.json"  # hot-reloadable policy file
//!
//! # Inline policies (alternative to policy_path):
//! [[access_control.role]]
//! name = "engineering"
//! peers = ["alice", "bob"]       # by peer name
//! peer_keys = ["aabb..."]        # or by key fingerprint (first 8 hex)
//!
//! [[access_control.role.rule]]
//! action = "allow"
//! network = "10.100.0.0/16"
//! ports = "443,8080-8090"
//! protocol = "tcp"
//!
//! [[access_control.role.rule]]
//! action = "deny"
//! network = "10.100.50.0/24"    # explicit deny of sensitive subnet
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

// ─── Policy Data Model ──────────────────────────────────────────────────────

/// Top-level policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Whether access control is enabled
    #[serde(default)]
    pub enabled: bool,

    /// Default action when no rule matches: "deny" (Zero Trust) or "allow"
    #[serde(default = "default_action")]
    pub default_action: String,

    /// Optional path to external policy JSON file (hot-reloadable)
    #[serde(default)]
    pub policy_path: Option<String>,

    /// Inline role definitions
    #[serde(default)]
    pub role: Vec<RoleConfig>,
}

fn default_action() -> String {
    "deny".to_string()
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_action: "deny".to_string(),
            policy_path: None,
            role: Vec::new(),
        }
    }
}

/// A named role with a set of access rules and assigned peers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleConfig {
    /// Role name (e.g., "engineering", "admin", "contractor")
    pub name: String,

    /// Peer names assigned to this role
    #[serde(default)]
    pub peers: Vec<String>,

    /// Peer key fingerprints (first 8 hex chars of public key)
    #[serde(default)]
    pub peer_keys: Vec<String>,

    /// Access rules for this role (evaluated in order, first match wins)
    #[serde(default)]
    pub rule: Vec<RuleConfig>,
}

/// A single access control rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    /// "allow" or "deny"
    pub action: String,

    /// Target network in CIDR notation (e.g., "10.100.0.0/16")
    pub network: String,

    /// Comma-separated ports or port ranges (e.g., "443,8080-8090")
    /// Empty or absent means all ports
    #[serde(default)]
    pub ports: Option<String>,

    /// Protocol: "tcp", "udp", "icmp", "any" (default: "any")
    #[serde(default = "default_protocol")]
    pub protocol: String,

    /// Human-readable description
    #[serde(default)]
    pub description: Option<String>,
}

fn default_protocol() -> String {
    "any".to_string()
}

// ─── Compiled Policy Engine ─────────────────────────────────────────────────

/// Action to take on a packet
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAction {
    /// Allow the packet to pass through
    Allow,
    /// Deny (drop) the packet
    Deny,
}

/// A compiled (parsed + optimized) access rule ready for fast evaluation
#[derive(Debug, Clone)]
struct CompiledRule {
    action: PolicyAction,
    network: IpAddr,
    prefix: u8,
    /// Flattened set of allowed/denied ports. None = all ports.
    ports: Option<Vec<PortRange>>,
    /// IP protocol number. None = any.
    protocol: Option<u8>,
    /// Full rule name for audit logging: "role:rule-index"
    rule_name: String,
}

/// A port range (inclusive)
#[derive(Debug, Clone, Copy)]
struct PortRange {
    start: u16,
    end: u16,
}

impl PortRange {
    fn contains(&self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }
}

/// Compiled policy for a single peer
#[derive(Debug, Clone)]
struct PeerPolicy {
    rules: Vec<CompiledRule>,
    role_names: Vec<String>,
}

/// The policy engine — precompiled for fast per-packet evaluation
pub struct PolicyEngine {
    /// Whether the engine is enabled
    enabled: bool,
    /// Default action when no rule matches
    default_action: PolicyAction,
    /// Compiled per-peer policies indexed by peer public key (first 8 hex)
    peer_policies_by_fingerprint: HashMap<String, PeerPolicy>,
    /// Compiled per-peer policies indexed by peer name
    peer_policies_by_name: HashMap<String, PeerPolicy>,
    /// External policy file path (for hot-reload)
    policy_path: Option<PathBuf>,
    /// Stats
    packets_allowed: u64,
    packets_denied: u64,
}

impl PolicyEngine {
    /// Create a new policy engine from configuration
    pub fn new(config: &PolicyConfig) -> Self {
        let default_action = if config.default_action.eq_ignore_ascii_case("allow") {
            PolicyAction::Allow
        } else {
            PolicyAction::Deny
        };

        let mut engine = Self {
            enabled: config.enabled,
            default_action,
            peer_policies_by_fingerprint: HashMap::new(),
            peer_policies_by_name: HashMap::new(),
            policy_path: config.policy_path.as_ref().map(PathBuf::from),
            packets_allowed: 0,
            packets_denied: 0,
        };

        if !config.enabled {
            return engine;
        }

        // Load from external file if configured
        let roles = if let Some(ref path) = config.policy_path {
            match Self::load_policy_file(Path::new(path)) {
                Ok(roles) => {
                    tracing::info!("Loaded {} roles from policy file: {}", roles.len(), path);
                    roles
                }
                Err(e) => {
                    tracing::error!("Failed to load policy file {}: {}", path, e);
                    config.role.clone()
                }
            }
        } else {
            config.role.clone()
        };

        engine.compile_roles(&roles);
        engine
    }

    /// Create a disabled (pass-through) policy engine
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            default_action: PolicyAction::Allow,
            peer_policies_by_fingerprint: HashMap::new(),
            peer_policies_by_name: HashMap::new(),
            policy_path: None,
            packets_allowed: 0,
            packets_denied: 0,
        }
    }

    /// Check if policy enforcement is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Evaluate a packet against the policy for a given peer.
    ///
    /// Returns `(PolicyAction, &str)` — the action and the name of the
    /// matching rule (for audit logging). If no rule matches, the default
    /// action and "default" are returned.
    ///
    /// # Arguments
    /// - `peer_key`: The peer's public key (full 32 bytes)
    /// - `peer_name`: Optional peer name
    /// - `dst_ip`: Destination IP from the decrypted packet
    /// - `dst_port`: Destination port (from TCP/UDP header), if available
    /// - `protocol`: IP protocol number (6=TCP, 17=UDP, 1=ICMP)
    pub fn evaluate(
        &mut self,
        peer_key: &[u8; 32],
        peer_name: Option<&str>,
        dst_ip: IpAddr,
        dst_port: Option<u16>,
        protocol: Option<u8>,
    ) -> (PolicyAction, String) {
        if !self.enabled {
            self.packets_allowed += 1;
            return (PolicyAction::Allow, "disabled".to_string());
        }

        // Look up by name first, then by fingerprint
        let fingerprint = hex::encode(&peer_key[..4]);
        let policy = peer_name
            .and_then(|n| self.peer_policies_by_name.get(n))
            .or_else(|| self.peer_policies_by_fingerprint.get(&fingerprint));

        let rules = match policy {
            Some(p) => &p.rules,
            None => {
                // No policy for this peer — use default
                match self.default_action {
                    PolicyAction::Allow => self.packets_allowed += 1,
                    PolicyAction::Deny => self.packets_denied += 1,
                }
                return (self.default_action, "no-policy:default".to_string());
            }
        };

        // Evaluate rules in order — first match wins
        for rule in rules {
            // Check network match
            if !ip_in_network(dst_ip, rule.network, rule.prefix) {
                continue;
            }

            // Check protocol match
            if let Some(rule_proto) = rule.protocol {
                if let Some(pkt_proto) = protocol {
                    if rule_proto != pkt_proto {
                        continue;
                    }
                }
                // If packet protocol is unknown, skip protocol check
            }

            // Check port match
            if let Some(ref port_ranges) = rule.ports {
                if let Some(port) = dst_port {
                    if !port_ranges.iter().any(|r| r.contains(port)) {
                        continue;
                    }
                }
                // If packet port is unknown (e.g., ICMP), skip port check
            }

            // Match!
            match rule.action {
                PolicyAction::Allow => self.packets_allowed += 1,
                PolicyAction::Deny => self.packets_denied += 1,
            }
            return (rule.action, rule.rule_name.clone());
        }

        // No rule matched — use default
        match self.default_action {
            PolicyAction::Allow => self.packets_allowed += 1,
            PolicyAction::Deny => self.packets_denied += 1,
        }
        (self.default_action, "default".to_string())
    }

    /// Hot-reload the policy from the external file (if configured)
    pub fn reload(&mut self) -> Result<(), String> {
        let path = match &self.policy_path {
            Some(p) => p.clone(),
            None => return Ok(()), // No external file, nothing to reload
        };

        let roles = Self::load_policy_file(&path)?;
        tracing::info!("Reloading {} roles from {}", roles.len(), path.display());

        self.peer_policies_by_fingerprint.clear();
        self.peer_policies_by_name.clear();
        self.compile_roles(&roles);

        Ok(())
    }

    /// Get stats
    pub fn stats(&self) -> (u64, u64) {
        (self.packets_allowed, self.packets_denied)
    }

    // ─── Internal ────────────────────────────────────────────────────────

    /// Load roles from a JSON policy file
    fn load_policy_file(path: &Path) -> Result<Vec<RoleConfig>, String> {
        let content =
            fs::read_to_string(path).map_err(|e| format!("read {}: {}", path.display(), e))?;
        let roles: Vec<RoleConfig> = serde_json::from_str(&content)
            .map_err(|e| format!("parse {}: {}", path.display(), e))?;
        Ok(roles)
    }

    /// Compile role configs into per-peer lookup tables
    fn compile_roles(&mut self, roles: &[RoleConfig]) {
        for role in roles {
            let compiled_rules: Vec<CompiledRule> = role
                .rule
                .iter()
                .enumerate()
                .filter_map(|(idx, r)| self.compile_rule(r, &role.name, idx))
                .collect();

            let policy = PeerPolicy {
                rules: compiled_rules,
                role_names: vec![role.name.clone()],
            };

            // Index by name
            for name in &role.peers {
                self.peer_policies_by_name
                    .entry(name.clone())
                    .and_modify(|existing| {
                        existing.rules.extend(policy.rules.clone());
                        existing.role_names.push(role.name.clone());
                    })
                    .or_insert_with(|| policy.clone());
            }

            // Index by key fingerprint
            for key_fp in &role.peer_keys {
                self.peer_policies_by_fingerprint
                    .entry(key_fp.clone())
                    .and_modify(|existing| {
                        existing.rules.extend(policy.rules.clone());
                        existing.role_names.push(role.name.clone());
                    })
                    .or_insert_with(|| policy.clone());
            }

            tracing::info!(
                "Policy role '{}': {} rules, {} peers (by name), {} peers (by key)",
                role.name,
                role.rule.len(),
                role.peers.len(),
                role.peer_keys.len(),
            );
        }
    }

    /// Compile a single rule
    fn compile_rule(
        &self,
        rule: &RuleConfig,
        role_name: &str,
        index: usize,
    ) -> Option<CompiledRule> {
        let action = if rule.action.eq_ignore_ascii_case("allow") {
            PolicyAction::Allow
        } else {
            PolicyAction::Deny
        };

        // Parse network
        let (network, prefix) = parse_cidr(&rule.network)?;

        // Parse ports
        let ports = rule.ports.as_ref().and_then(|p| {
            if p.is_empty() || p == "*" {
                None
            } else {
                Some(parse_port_spec(p))
            }
        });

        // Parse protocol
        let protocol = match rule.protocol.to_lowercase().as_str() {
            "tcp" => Some(6u8),
            "udp" => Some(17u8),
            "icmp" => Some(1u8),
            "any" | "" => None,
            other => {
                if let Ok(n) = other.parse::<u8>() {
                    Some(n)
                } else {
                    tracing::warn!(
                        "Unknown protocol '{}' in rule {}:{}",
                        other,
                        role_name,
                        index
                    );
                    None
                }
            }
        };

        let rule_name = format!("{}:rule-{}", role_name, index);
        if let Some(ref desc) = rule.description {
            tracing::debug!(
                "  Rule {}: {} {} {} ({})",
                rule_name,
                rule.action,
                rule.network,
                rule.protocol,
                desc
            );
        }

        Some(CompiledRule {
            action,
            network,
            prefix,
            ports,
            protocol,
            rule_name,
        })
    }
}

// ─── Packet Inspection Helpers ──────────────────────────────────────────────

/// Extract L4 info from a decrypted IP packet: (src_ip, dst_ip, dst_port, protocol)
pub fn inspect_packet(packet: &[u8]) -> Option<(IpAddr, IpAddr, Option<u16>, u8)> {
    if packet.is_empty() {
        return None;
    }

    let version = packet[0] >> 4;

    match version {
        4 if packet.len() >= 20 => {
            let protocol = packet[9];
            let src = IpAddr::V4(std::net::Ipv4Addr::new(
                packet[12], packet[13], packet[14], packet[15],
            ));
            let dst = IpAddr::V4(std::net::Ipv4Addr::new(
                packet[16], packet[17], packet[18], packet[19],
            ));
            let ihl = (packet[0] & 0x0F) as usize * 4;
            let dst_port = extract_dst_port(packet, ihl, protocol);
            Some((src, dst, dst_port, protocol))
        }
        6 if packet.len() >= 40 => {
            let protocol = packet[6]; // Next Header
            let mut src_bytes = [0u8; 16];
            let mut dst_bytes = [0u8; 16];
            src_bytes.copy_from_slice(&packet[8..24]);
            dst_bytes.copy_from_slice(&packet[24..40]);
            let src = IpAddr::V6(src_bytes.into());
            let dst = IpAddr::V6(dst_bytes.into());
            let dst_port = extract_dst_port(packet, 40, protocol);
            Some((src, dst, dst_port, protocol))
        }
        _ => None,
    }
}

/// Extract destination port from TCP (6) or UDP (17) header
fn extract_dst_port(packet: &[u8], l4_offset: usize, protocol: u8) -> Option<u16> {
    match protocol {
        6 | 17 => {
            // TCP and UDP both have dst_port at bytes 2-3 of their header
            if packet.len() >= l4_offset + 4 {
                Some(u16::from_be_bytes([
                    packet[l4_offset + 2],
                    packet[l4_offset + 3],
                ]))
            } else {
                None
            }
        }
        _ => None,
    }
}

// ─── Parsing helpers ────────────────────────────────────────────────────────

fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let s = s.trim();
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 {
        return None;
    }
    let ip: IpAddr = parts[0].parse().ok()?;
    let prefix: u8 = parts[1].parse().ok()?;
    Some((ip, prefix))
}

fn parse_port_spec(spec: &str) -> Vec<PortRange> {
    let mut ranges = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if let Some((start_s, end_s)) = part.split_once('-') {
            if let (Ok(start), Ok(end)) = (start_s.trim().parse(), end_s.trim().parse()) {
                ranges.push(PortRange { start, end });
            }
        } else if let Ok(port) = part.parse() {
            ranges.push(PortRange {
                start: port,
                end: port,
            });
        }
    }
    ranges
}

fn ip_in_network(ip: IpAddr, network: IpAddr, prefix: u8) -> bool {
    match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            if prefix == 0 {
                return true;
            }
            let ip_bits = u32::from_be_bytes(ip.octets());
            let net_bits = u32::from_be_bytes(net.octets());
            let mask = !0u32 << (32 - prefix);
            (ip_bits & mask) == (net_bits & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            if prefix == 0 {
                return true;
            }
            let ip_bits = u128::from_be_bytes(ip.octets());
            let net_bits = u128::from_be_bytes(net.octets());
            let mask = !0u128 << (128 - prefix);
            (ip_bits & mask) == (net_bits & mask)
        }
        _ => false,
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn make_test_policy() -> PolicyConfig {
        PolicyConfig {
            enabled: true,
            default_action: "deny".to_string(),
            policy_path: None,
            role: vec![
                RoleConfig {
                    name: "engineering".to_string(),
                    peers: vec!["alice".to_string(), "bob".to_string()],
                    peer_keys: vec![],
                    rule: vec![
                        RuleConfig {
                            action: "allow".to_string(),
                            network: "10.100.0.0/16".to_string(),
                            ports: Some("443,8080-8090".to_string()),
                            protocol: "tcp".to_string(),
                            description: Some("Allow HTTPS and dev ports".to_string()),
                        },
                        RuleConfig {
                            action: "deny".to_string(),
                            network: "10.100.50.0/24".to_string(),
                            ports: None,
                            protocol: "any".to_string(),
                            description: Some("Block sensitive subnet".to_string()),
                        },
                        RuleConfig {
                            action: "allow".to_string(),
                            network: "10.200.200.0/24".to_string(),
                            ports: None,
                            protocol: "any".to_string(),
                            description: Some("Allow VPN mesh".to_string()),
                        },
                    ],
                },
                RoleConfig {
                    name: "admin".to_string(),
                    peers: vec!["charlie".to_string()],
                    peer_keys: vec![],
                    rule: vec![RuleConfig {
                        action: "allow".to_string(),
                        network: "0.0.0.0/0".to_string(),
                        ports: None,
                        protocol: "any".to_string(),
                        description: Some("Full access".to_string()),
                    }],
                },
            ],
        }
    }

    #[test]
    fn test_engineering_allowed_https() {
        let config = make_test_policy();
        let mut engine = PolicyEngine::new(&config);

        let peer_key = [0xAA; 32];
        let (action, rule) = engine.evaluate(
            &peer_key,
            Some("alice"),
            IpAddr::V4(Ipv4Addr::new(10, 100, 5, 10)),
            Some(443),
            Some(6), // TCP
        );
        assert_eq!(action, PolicyAction::Allow);
        assert!(rule.contains("engineering"));
    }

    #[test]
    fn test_engineering_denied_ssh() {
        let config = make_test_policy();
        let mut engine = PolicyEngine::new(&config);

        let peer_key = [0xAA; 32];
        // SSH (port 22) not in allowed ports for engineering
        let (action, _rule) = engine.evaluate(
            &peer_key,
            Some("alice"),
            IpAddr::V4(Ipv4Addr::new(10, 100, 5, 10)),
            Some(22),
            Some(6),
        );
        // Rule won't match (port 22 not in 443,8080-8090), falls to deny rule for subnet,
        // then to VPN mesh rule (wrong subnet), then to default deny
        assert_eq!(action, PolicyAction::Deny);
    }

    #[test]
    fn test_admin_full_access() {
        let config = make_test_policy();
        let mut engine = PolicyEngine::new(&config);

        let peer_key = [0xCC; 32];
        let (action, rule) = engine.evaluate(
            &peer_key,
            Some("charlie"),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            Some(22),
            Some(6),
        );
        assert_eq!(action, PolicyAction::Allow);
        assert!(rule.contains("admin"));
    }

    #[test]
    fn test_unknown_peer_default_deny() {
        let config = make_test_policy();
        let mut engine = PolicyEngine::new(&config);

        let peer_key = [0xFF; 32];
        let (action, rule) = engine.evaluate(
            &peer_key,
            Some("mallory"),
            IpAddr::V4(Ipv4Addr::new(10, 100, 5, 10)),
            Some(443),
            Some(6),
        );
        assert_eq!(action, PolicyAction::Deny);
        assert!(rule.contains("default"));
    }

    #[test]
    fn test_disabled_engine_allows_all() {
        let mut engine = PolicyEngine::disabled();

        let peer_key = [0xFF; 32];
        let (action, _) = engine.evaluate(
            &peer_key,
            None,
            IpAddr::V4(Ipv4Addr::new(10, 100, 5, 10)),
            Some(443),
            Some(6),
        );
        assert_eq!(action, PolicyAction::Allow);
    }

    #[test]
    fn test_port_range_parsing() {
        let ranges = parse_port_spec("80, 443, 8000-8999");
        assert_eq!(ranges.len(), 3);
        assert!(ranges[0].contains(80));
        assert!(!ranges[0].contains(81));
        assert!(ranges[1].contains(443));
        assert!(ranges[2].contains(8000));
        assert!(ranges[2].contains(8500));
        assert!(ranges[2].contains(8999));
        assert!(!ranges[2].contains(9000));
    }

    #[test]
    fn test_packet_inspection_ipv4_tcp() {
        // Minimal IPv4 + TCP packet
        let mut pkt = vec![0u8; 44]; // 20 (IP) + 20 (TCP) + 4 (data)
        pkt[0] = 0x45; // IPv4, IHL=5
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&[10, 0, 0, 2]); // src
        pkt[16..20].copy_from_slice(&[10, 100, 5, 10]); // dst
                                                        // TCP dst port at offset 22-23
        pkt[22] = 0x01;
        pkt[23] = 0xBB; // port 443

        let (src, dst, port, proto) = inspect_packet(&pkt).unwrap();
        assert_eq!(src, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(dst, IpAddr::V4(Ipv4Addr::new(10, 100, 5, 10)));
        assert_eq!(port, Some(443));
        assert_eq!(proto, 6);
    }

    #[test]
    fn test_policy_from_json_file() {
        let dir = std::env::temp_dir().join("dybervpn-policy-test");
        let _ = fs::create_dir_all(&dir);
        let policy_path = dir.join("policy.json");

        let roles = vec![RoleConfig {
            name: "test-role".to_string(),
            peers: vec!["testuser".to_string()],
            peer_keys: vec![],
            rule: vec![RuleConfig {
                action: "allow".to_string(),
                network: "10.0.0.0/8".to_string(),
                ports: None,
                protocol: "any".to_string(),
                description: None,
            }],
        }];

        let json = serde_json::to_string_pretty(&roles).unwrap();
        fs::write(&policy_path, &json).unwrap();

        let config = PolicyConfig {
            enabled: true,
            default_action: "deny".to_string(),
            policy_path: Some(policy_path.to_string_lossy().to_string()),
            role: vec![],
        };

        let mut engine = PolicyEngine::new(&config);

        let peer_key = [0x11; 32];
        let (action, _) = engine.evaluate(
            &peer_key,
            Some("testuser"),
            IpAddr::V4(Ipv4Addr::new(10, 5, 5, 5)),
            Some(80),
            Some(6),
        );
        assert_eq!(action, PolicyAction::Allow);

        let (action, _) = engine.evaluate(
            &peer_key,
            Some("testuser"),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            Some(80),
            Some(6),
        );
        assert_eq!(action, PolicyAction::Deny); // Outside 10.0.0.0/8

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_stats_tracking() {
        let config = make_test_policy();
        let mut engine = PolicyEngine::new(&config);

        let pk = [0xAA; 32];
        engine.evaluate(
            &pk,
            Some("alice"),
            IpAddr::V4(Ipv4Addr::new(10, 100, 5, 10)),
            Some(443),
            Some(6),
        );
        engine.evaluate(
            &pk,
            Some("alice"),
            IpAddr::V4(Ipv4Addr::new(10, 100, 5, 10)),
            Some(22),
            Some(6),
        );

        let (allowed, denied) = engine.stats();
        assert_eq!(allowed, 1);
        assert_eq!(denied, 1);
    }
}
