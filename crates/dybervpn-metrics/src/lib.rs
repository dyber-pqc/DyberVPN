//! DyberVPN Observability & Metrics
//!
//! This crate provides:
//! - Prometheus-compatible metrics
//! - Structured logging with tracing
//! - Health checks
//! - Metrics HTTP server (feature: `server`)
//! - Zero Trust device posture assessment

#![warn(missing_docs)]

pub mod logging;
pub mod metrics;
pub mod health;
pub mod posture;
#[cfg(feature = "server")]
pub mod server;

// Re-exports
pub use logging::{init_logging, LogConfig};
pub use metrics::{Metrics, MetricsConfig};
pub use health::{HealthCheck, HealthStatus};
pub use posture::{PostureConfig, PostureResult, PostureCheck, PostureCategory, assess_posture};
#[cfg(feature = "server")]
pub use server::{MetricsServerConfig, MetricsServerState, start_metrics_server};
