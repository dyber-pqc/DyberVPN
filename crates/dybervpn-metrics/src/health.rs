//! Health check system

use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};

/// Health status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// All systems operational
    Healthy,
    /// System is degraded but functional
    Degraded,
    /// System is unhealthy
    Unhealthy,
}

impl HealthStatus {
    /// Convert to HTTP status code
    pub fn http_status(&self) -> u16 {
        match self {
            HealthStatus::Healthy => 200,
            HealthStatus::Degraded => 200,
            HealthStatus::Unhealthy => 503,
        }
    }
}

/// Health check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    /// Overall status
    pub status: HealthStatus,
    /// Component checks
    pub checks: Vec<ComponentCheck>,
    /// Timestamp
    pub timestamp: String,
    /// Uptime in seconds
    pub uptime_seconds: u64,
}

/// Individual component health check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentCheck {
    /// Component name
    pub name: String,
    /// Component status
    pub status: HealthStatus,
    /// Optional message
    pub message: Option<String>,
    /// Check duration in ms
    pub duration_ms: u64,
}

/// Health check system
pub struct HealthCheck {
    start_time: Instant,
    checks: Vec<Box<dyn Fn() -> ComponentCheck + Send + Sync>>,
}

impl Default for HealthCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthCheck {
    /// Create a new health check system
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            checks: Vec::new(),
        }
    }
    
    /// Add a component check
    pub fn add_check<F>(&mut self, check: F)
    where
        F: Fn() -> ComponentCheck + Send + Sync + 'static,
    {
        self.checks.push(Box::new(check));
    }
    
    /// Run all health checks
    pub fn check(&self) -> HealthCheckResult {
        let mut results = Vec::new();
        let mut overall_status = HealthStatus::Healthy;
        
        for check in &self.checks {
            let result = check();
            
            // Update overall status
            match (&overall_status, &result.status) {
                (_, HealthStatus::Unhealthy) => overall_status = HealthStatus::Unhealthy,
                (HealthStatus::Healthy, HealthStatus::Degraded) => {
                    overall_status = HealthStatus::Degraded
                }
                _ => {}
            }
            
            results.push(result);
        }
        
        HealthCheckResult {
            status: overall_status,
            checks: results,
            timestamp: chrono::Utc::now().to_rfc3339(),
            uptime_seconds: self.start_time.elapsed().as_secs(),
        }
    }
    
    /// Get uptime
    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }
}

/// Create a simple component check
pub fn simple_check(name: &str, healthy: bool, message: Option<&str>) -> ComponentCheck {
    ComponentCheck {
        name: name.to_string(),
        status: if healthy {
            HealthStatus::Healthy
        } else {
            HealthStatus::Unhealthy
        },
        message: message.map(|s| s.to_string()),
        duration_ms: 0,
    }
}

/// Create a timed component check
pub fn timed_check<F>(name: &str, check: F) -> ComponentCheck
where
    F: FnOnce() -> (bool, Option<String>),
{
    let start = Instant::now();
    let (healthy, message) = check();
    let duration = start.elapsed();
    
    ComponentCheck {
        name: name.to_string(),
        status: if healthy {
            HealthStatus::Healthy
        } else {
            HealthStatus::Unhealthy
        },
        message,
        duration_ms: duration.as_millis() as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_health_check() {
        let mut health = HealthCheck::new();
        
        health.add_check(|| simple_check("test", true, None));
        health.add_check(|| simple_check("test2", true, Some("OK")));
        
        let result = health.check();
        assert_eq!(result.status, HealthStatus::Healthy);
        assert_eq!(result.checks.len(), 2);
    }
    
    #[test]
    fn test_degraded_status() {
        let mut health = HealthCheck::new();
        
        health.add_check(|| ComponentCheck {
            name: "degraded".to_string(),
            status: HealthStatus::Degraded,
            message: Some("Performance issues".to_string()),
            duration_ms: 0,
        });
        
        let result = health.check();
        assert_eq!(result.status, HealthStatus::Degraded);
    }
}
