//! DyberVPN Observability & Metrics
//!
//! This crate provides:
//! - Prometheus-compatible metrics
//! - Structured logging with tracing
//! - Health checks
//! - Performance monitoring

#![warn(missing_docs)]

pub mod logging;
pub mod metrics;
pub mod health;

// Re-exports
pub use logging::{init_logging, LogConfig};
pub use metrics::{Metrics, MetricsConfig};
pub use health::{HealthCheck, HealthStatus};
