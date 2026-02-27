//! DyberVPN Observability & Metrics
//!
//! This crate provides:
//! - Prometheus-compatible metrics
//! - Structured logging with tracing
//! - Health checks
//! - Metrics HTTP server (feature: `server`)
//! - Zero Trust device posture assessment

#![warn(missing_docs)]
// Platform-specific posture checks differ between Linux/macOS/Windows
#![allow(unused_imports, unused_variables, dead_code)]

pub mod health;
pub mod logging;
pub mod metrics;
pub mod posture;
#[cfg(feature = "server")]
pub mod server;

// Re-exports
pub use health::{HealthCheck, HealthStatus};
pub use logging::{init_logging, LogConfig};
pub use metrics::{Metrics, MetricsConfig};
pub use posture::{assess_posture, PostureCategory, PostureCheck, PostureConfig, PostureResult};
#[cfg(feature = "server")]
pub use server::{start_metrics_server, MetricsServerConfig, MetricsServerState};
