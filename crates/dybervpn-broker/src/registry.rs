//! Service Registry — maps destination CIDRs to Connector public keys
//!
//! When a Connector registers with the Broker, it advertises the CIDRs it can
//! reach. The registry stores these routes and provides longest-prefix-match
//! lookup so the Broker can find the right Connector for any destination IP.

use std::net::IpAddr;
use std::sync::RwLock;

/// A route entry mapping a CIDR to a Connector
#[derive(Debug, Clone)]
struct RouteEntry {
    /// Network address
    network: IpAddr,
    /// CIDR prefix length
    prefix: u8,
    /// Connector's X25519 public key
    connector_key: [u8; 32],
}

/// Service registry: maps destination IPs to the Connector that serves them
pub struct ServiceRegistry {
    /// Routes sorted by prefix length (longest first) for longest-prefix-match
    routes: RwLock<Vec<RouteEntry>>,
}

impl ServiceRegistry {
    /// Create an empty registry
    pub fn new() -> Self {
        Self {
            routes: RwLock::new(Vec::new()),
        }
    }

    /// Register routes for a Connector
    pub fn register(&self, connector_key: [u8; 32], routes: &[(IpAddr, u8)]) {
        let mut table = self.routes.write().unwrap();

        // Remove any existing routes for this connector first
        table.retain(|e| e.connector_key != connector_key);

        // Add new routes
        for &(network, prefix) in routes {
            table.push(RouteEntry {
                network,
                prefix,
                connector_key,
            });
        }

        // Sort by prefix length descending (longest-prefix-match first)
        table.sort_by(|a, b| b.prefix.cmp(&a.prefix));

        tracing::debug!(
            "Registry updated: {} total routes ({} for connector {})",
            table.len(),
            routes.len(),
            hex::encode(&connector_key[..4]),
        );
    }

    /// Remove all routes for a Connector
    pub fn unregister(&self, connector_key: &[u8; 32]) {
        let mut table = self.routes.write().unwrap();
        let before = table.len();
        table.retain(|e| &e.connector_key != connector_key);
        let removed = before - table.len();
        if removed > 0 {
            tracing::debug!(
                "Unregistered {} routes for connector {}",
                removed,
                hex::encode(&connector_key[..4]),
            );
        }
    }

    /// Find the Connector that serves a given destination IP (longest-prefix-match)
    pub fn lookup(&self, dst_ip: IpAddr) -> Option<[u8; 32]> {
        let table = self.routes.read().unwrap();
        // Routes are already sorted by prefix length descending,
        // so the first match is the longest prefix match
        for entry in table.iter() {
            if ip_in_network(dst_ip, entry.network, entry.prefix) {
                return Some(entry.connector_key);
            }
        }
        None
    }

    /// Number of registered routes
    pub fn route_count(&self) -> usize {
        self.routes.read().unwrap().len()
    }

    /// Number of unique connectors
    pub fn connector_count(&self) -> usize {
        let table = self.routes.read().unwrap();
        let mut keys: Vec<[u8; 32]> = table.iter().map(|e| e.connector_key).collect();
        keys.sort();
        keys.dedup();
        keys.len()
    }
}

impl Default for ServiceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if an IP address falls within a CIDR network
fn ip_in_network(ip: IpAddr, network: IpAddr, prefix: u8) -> bool {
    match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            if prefix == 0 {
                return true;
            }
            if prefix > 32 {
                return false;
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
            if prefix > 128 {
                return false;
            }
            let ip_bits = u128::from_be_bytes(ip.octets());
            let net_bits = u128::from_be_bytes(net.octets());
            let mask = !0u128 << (128 - prefix);
            (ip_bits & mask) == (net_bits & mask)
        }
        _ => false, // V4/V6 mismatch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_ip_in_network() {
        let net = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0));
        assert!(ip_in_network(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1)), net, 16));
        assert!(ip_in_network(IpAddr::V4(Ipv4Addr::new(10, 1, 255, 255)), net, 16));
        assert!(!ip_in_network(IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1)), net, 16));
    }

    #[test]
    fn test_longest_prefix_match() {
        let registry = ServiceRegistry::new();

        let connector_a = [1u8; 32]; // serves 10.0.0.0/8
        let connector_b = [2u8; 32]; // serves 10.1.0.0/16

        registry.register(connector_a, &[
            (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8),
        ]);
        registry.register(connector_b, &[
            (IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)), 16),
        ]);

        // 10.1.0.5 matches both, but /16 is more specific
        let result = registry.lookup(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 5)));
        assert_eq!(result, Some(connector_b));

        // 10.2.0.5 only matches /8
        let result = registry.lookup(IpAddr::V4(Ipv4Addr::new(10, 2, 0, 5)));
        assert_eq!(result, Some(connector_a));

        // 192.168.1.1 matches nothing
        let result = registry.lookup(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(result, None);
    }

    #[test]
    fn test_unregister() {
        let registry = ServiceRegistry::new();
        let key = [3u8; 32];
        registry.register(key, &[
            (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8),
        ]);
        assert_eq!(registry.route_count(), 1);

        registry.unregister(&key);
        assert_eq!(registry.route_count(), 0);
        assert_eq!(registry.lookup(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))), None);
    }

    #[test]
    fn test_register_replaces_old_routes() {
        let registry = ServiceRegistry::new();
        let key = [4u8; 32];

        registry.register(key, &[
            (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8),
            (IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)), 12),
        ]);
        assert_eq!(registry.route_count(), 2);

        // Re-register with different routes — old ones removed
        registry.register(key, &[
            (IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 16),
        ]);
        assert_eq!(registry.route_count(), 1);
        assert_eq!(
            registry.lookup(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            None,
        );
    }
}
