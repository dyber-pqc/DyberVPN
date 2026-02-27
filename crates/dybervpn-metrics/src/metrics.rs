//! Prometheus-compatible metrics

#[cfg(feature = "prometheus")]
use prometheus_client::{
    encoding::text::encode,
    metrics::{counter::Counter, gauge::Gauge, histogram::Histogram},
    registry::Registry,
};

use std::sync::atomic::AtomicU64;
use std::sync::Arc;

/// Metrics configuration
#[derive(Debug, Clone)]
pub struct MetricsConfig {
    /// Prometheus endpoint path
    pub path: String,
    /// Listen address for metrics server
    pub listen_addr: String,
    /// Enable detailed per-peer metrics
    pub per_peer_metrics: bool,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            path: "/metrics".to_string(),
            listen_addr: "127.0.0.1:9090".to_string(),
            per_peer_metrics: true,
        }
    }
}

/// DyberVPN metrics collector
#[derive(Clone)]
pub struct Metrics {
    #[cfg(feature = "prometheus")]
    registry: Arc<Registry>,

    #[cfg(feature = "prometheus")]
    handshakes_total: Counter<u64, AtomicU64>,
    #[cfg(feature = "prometheus")]
    handshakes_failed: Counter<u64, AtomicU64>,
    #[cfg(feature = "prometheus")]
    active_sessions: Gauge<i64, std::sync::atomic::AtomicI64>,
    #[cfg(feature = "prometheus")]
    bytes_sent: Counter<u64, AtomicU64>,
    #[cfg(feature = "prometheus")]
    bytes_received: Counter<u64, AtomicU64>,
    #[cfg(feature = "prometheus")]
    packets_sent: Counter<u64, AtomicU64>,
    #[cfg(feature = "prometheus")]
    packets_received: Counter<u64, AtomicU64>,
    #[cfg(feature = "prometheus")]
    errors_total: Counter<u64, AtomicU64>,
    #[cfg(feature = "prometheus")]
    decryption_failures: Counter<u64, AtomicU64>,
    #[cfg(feature = "prometheus")]
    handshake_duration_seconds: Histogram,

    #[cfg(not(feature = "prometheus"))]
    simple_counters: Arc<SimpleCounters>,
}

#[cfg(not(feature = "prometheus"))]
struct SimpleCounters {
    handshakes_total: AtomicU64,
    handshakes_failed: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
}

#[cfg(not(feature = "prometheus"))]
impl Default for SimpleCounters {
    fn default() -> Self {
        Self {
            handshakes_total: AtomicU64::new(0),
            handshakes_failed: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    /// Create a new metrics collector
    pub fn new() -> Self {
        #[cfg(feature = "prometheus")]
        {
            let mut registry = Registry::default();

            let handshakes_total = Counter::default();
            registry.register(
                "dybervpn_handshakes_total",
                "Total number of handshakes initiated",
                handshakes_total.clone(),
            );

            let handshakes_failed = Counter::default();
            registry.register(
                "dybervpn_handshakes_failed_total",
                "Total number of failed handshakes",
                handshakes_failed.clone(),
            );

            let active_sessions = Gauge::default();
            registry.register(
                "dybervpn_active_sessions",
                "Number of active VPN sessions",
                active_sessions.clone(),
            );

            let bytes_sent = Counter::default();
            registry.register(
                "dybervpn_bytes_sent_total",
                "Total bytes sent",
                bytes_sent.clone(),
            );

            let bytes_received = Counter::default();
            registry.register(
                "dybervpn_bytes_received_total",
                "Total bytes received",
                bytes_received.clone(),
            );

            let packets_sent = Counter::default();
            registry.register(
                "dybervpn_packets_sent_total",
                "Total packets sent",
                packets_sent.clone(),
            );

            let packets_received = Counter::default();
            registry.register(
                "dybervpn_packets_received_total",
                "Total packets received",
                packets_received.clone(),
            );

            let errors_total = Counter::default();
            registry.register(
                "dybervpn_errors_total",
                "Total number of errors",
                errors_total.clone(),
            );

            let decryption_failures = Counter::default();
            registry.register(
                "dybervpn_decryption_failures_total",
                "Total number of decryption failures",
                decryption_failures.clone(),
            );

            let handshake_duration_seconds =
                Histogram::new([0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0].into_iter());
            registry.register(
                "dybervpn_handshake_duration_seconds",
                "Handshake duration in seconds",
                handshake_duration_seconds.clone(),
            );

            Self {
                registry: Arc::new(registry),
                handshakes_total,
                handshakes_failed,
                active_sessions,
                bytes_sent,
                bytes_received,
                packets_sent,
                packets_received,
                errors_total,
                decryption_failures,
                handshake_duration_seconds,
            }
        }

        #[cfg(not(feature = "prometheus"))]
        {
            Self {
                simple_counters: Arc::new(SimpleCounters::default()),
            }
        }
    }

    /// Record a successful handshake
    pub fn record_handshake(&self, duration_ms: u64) {
        #[cfg(feature = "prometheus")]
        {
            self.handshakes_total.inc();
            self.handshake_duration_seconds
                .observe(duration_ms as f64 / 1000.0);
        }

        #[cfg(not(feature = "prometheus"))]
        {
            use std::sync::atomic::Ordering;
            self.simple_counters
                .handshakes_total
                .fetch_add(1, Ordering::Relaxed);
            let _ = duration_ms;
        }
    }

    /// Record a failed handshake
    pub fn record_handshake_failure(&self) {
        #[cfg(feature = "prometheus")]
        {
            self.handshakes_failed.inc();
        }

        #[cfg(not(feature = "prometheus"))]
        {
            use std::sync::atomic::Ordering;
            self.simple_counters
                .handshakes_failed
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Update active session count
    #[allow(unused_variables)]
    pub fn set_active_sessions(&self, count: i64) {
        #[cfg(feature = "prometheus")]
        {
            self.active_sessions.set(count);
        }
    }

    /// Record bytes sent
    pub fn record_bytes_sent(&self, bytes: u64) {
        #[cfg(feature = "prometheus")]
        {
            self.bytes_sent.inc_by(bytes);
        }

        #[cfg(not(feature = "prometheus"))]
        {
            use std::sync::atomic::Ordering;
            self.simple_counters
                .bytes_sent
                .fetch_add(bytes, Ordering::Relaxed);
        }
    }

    /// Record bytes received
    pub fn record_bytes_received(&self, bytes: u64) {
        #[cfg(feature = "prometheus")]
        {
            self.bytes_received.inc_by(bytes);
        }

        #[cfg(not(feature = "prometheus"))]
        {
            use std::sync::atomic::Ordering;
            self.simple_counters
                .bytes_received
                .fetch_add(bytes, Ordering::Relaxed);
        }
    }

    /// Record packets sent
    #[allow(unused_variables)]
    pub fn record_packets_sent(&self, count: u64) {
        #[cfg(feature = "prometheus")]
        {
            self.packets_sent.inc_by(count);
        }
    }

    /// Record packets received
    #[allow(unused_variables)]
    pub fn record_packets_received(&self, count: u64) {
        #[cfg(feature = "prometheus")]
        {
            self.packets_received.inc_by(count);
        }
    }

    /// Record an error
    pub fn record_error(&self) {
        #[cfg(feature = "prometheus")]
        {
            self.errors_total.inc();
        }
    }

    /// Record a decryption failure
    pub fn record_decryption_failure(&self) {
        #[cfg(feature = "prometheus")]
        {
            self.decryption_failures.inc();
        }
    }

    /// Encode metrics in Prometheus text format
    #[cfg(feature = "prometheus")]
    pub fn encode(&self) -> String {
        let mut buffer = String::new();
        encode(&mut buffer, &self.registry).unwrap();
        buffer
    }

    #[cfg(not(feature = "prometheus"))]
    pub fn encode(&self) -> String {
        use std::sync::atomic::Ordering;
        format!(
            "# DyberVPN Metrics (Prometheus disabled)\n\
             handshakes_total: {}\n\
             handshakes_failed: {}\n\
             bytes_sent: {}\n\
             bytes_received: {}\n",
            self.simple_counters
                .handshakes_total
                .load(Ordering::Relaxed),
            self.simple_counters
                .handshakes_failed
                .load(Ordering::Relaxed),
            self.simple_counters.bytes_sent.load(Ordering::Relaxed),
            self.simple_counters.bytes_received.load(Ordering::Relaxed),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_creation() {
        let metrics = Metrics::new();
        metrics.record_handshake(100);
        metrics.record_bytes_sent(1000);
        metrics.record_bytes_received(2000);

        let output = metrics.encode();
        assert!(!output.is_empty());
    }
}
