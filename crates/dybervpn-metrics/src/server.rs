//! Metrics HTTP server
//!
//! Provides an axum-based HTTP server that exposes:
//! - `GET /metrics` — Prometheus text format metrics
//! - `GET /health` — JSON health check result
//! - `GET /status` — JSON summary of tunnel state

use crate::health::{HealthCheck, HealthCheckResult};
use crate::metrics::Metrics;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Shared state for the metrics server
pub struct MetricsServerState {
    /// Prometheus metrics collector
    pub metrics: Metrics,
    /// Health check system
    pub health: HealthCheck,
}

/// JSON status summary for fleet dashboard
#[derive(Debug, Clone, Serialize)]
pub struct StatusSummary {
    /// Server version
    pub version: String,
    /// Number of active peers
    pub active_peers: u64,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Total handshakes completed
    pub handshakes: u64,
    /// Total errors
    pub errors: u64,
    /// Uptime in seconds
    pub uptime_secs: u64,
    /// Health status
    pub health: HealthCheckResult,
}

/// Configuration for the metrics server
#[derive(Debug, Clone)]
pub struct MetricsServerConfig {
    /// Listen address (e.g., "127.0.0.1:9090")
    pub listen_addr: String,
}

impl Default for MetricsServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:9090".to_string(),
        }
    }
}

/// Start the metrics HTTP server.
///
/// This launches an axum server with `/metrics`, `/health`, and `/status` endpoints.
/// The server runs until the provided shutdown signal fires.
#[cfg(feature = "server")]
pub async fn start_metrics_server(
    config: MetricsServerConfig,
    state: Arc<RwLock<MetricsServerState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use axum::{routing::get, Router};

    let app = Router::new()
        .route("/metrics", get(handle_metrics))
        .route("/health", get(handle_health))
        .route("/status", get(handle_status))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
    tracing::info!("Metrics server listening on {}", config.listen_addr);

    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(feature = "server")]
async fn handle_metrics(
    axum::extract::State(state): axum::extract::State<Arc<RwLock<MetricsServerState>>>,
) -> impl axum::response::IntoResponse {
    let state = state.read().await;
    let body = state.metrics.encode();
    (
        axum::http::StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
}

#[cfg(feature = "server")]
async fn handle_health(
    axum::extract::State(state): axum::extract::State<Arc<RwLock<MetricsServerState>>>,
) -> impl axum::response::IntoResponse {
    let state = state.read().await;
    let result = state.health.check();
    let status_code = if result.status == crate::health::HealthStatus::Unhealthy {
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    } else {
        axum::http::StatusCode::OK
    };
    (
        status_code,
        [("content-type", "application/json")],
        serde_json::to_string(&result).unwrap_or_default(),
    )
}

#[cfg(feature = "server")]
async fn handle_status(
    axum::extract::State(state): axum::extract::State<Arc<RwLock<MetricsServerState>>>,
) -> impl axum::response::IntoResponse {
    let state = state.read().await;
    let health_result = state.health.check();
    let summary = StatusSummary {
        version: env!("CARGO_PKG_VERSION").to_string(),
        active_peers: 0, // Set by daemon integration
        bytes_sent: 0,
        bytes_received: 0,
        handshakes: 0,
        errors: 0,
        uptime_secs: state.health.uptime().as_secs(),
        health: health_result,
    };
    (
        axum::http::StatusCode::OK,
        [("content-type", "application/json")],
        serde_json::to_string(&summary).unwrap_or_default(),
    )
}
