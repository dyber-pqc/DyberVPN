//! Structured logging configuration

use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Logging configuration
#[derive(Debug, Clone)]
pub struct LogConfig {
    /// Log level (trace, debug, info, warn, error)
    pub level: String,
    /// Output format (pretty, compact)
    pub format: LogFormat,
    /// Include file/line info
    pub file_info: bool,
    /// Include thread IDs
    pub thread_ids: bool,
}

/// Log output format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// Pretty colored output (for humans)
    Pretty,
    /// Compact single-line format
    Compact,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: LogFormat::Pretty,
            file_info: false,
            thread_ids: false,
        }
    }
}

impl LogConfig {
    /// Create a new log config for development
    pub fn development() -> Self {
        Self {
            level: "debug".to_string(),
            format: LogFormat::Pretty,
            file_info: true,
            thread_ids: false,
        }
    }

    /// Create a new log config for production
    pub fn production() -> Self {
        Self {
            level: "info".to_string(),
            format: LogFormat::Compact,
            file_info: false,
            thread_ids: true,
        }
    }
}

/// Initialize logging with the given configuration
pub fn init_logging(config: &LogConfig) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.level));

    match config.format {
        LogFormat::Pretty => {
            let layer = fmt::layer()
                .pretty()
                .with_file(config.file_info)
                .with_line_number(config.file_info)
                .with_thread_ids(config.thread_ids);

            tracing_subscriber::registry()
                .with(filter)
                .with(layer)
                .init();
        }
        LogFormat::Compact => {
            let layer = fmt::layer()
                .compact()
                .with_file(config.file_info)
                .with_line_number(config.file_info)
                .with_thread_ids(config.thread_ids);

            tracing_subscriber::registry()
                .with(filter)
                .with(layer)
                .init();
        }
    }

    tracing::info!(
        level = %config.level,
        format = ?config.format,
        "Logging initialized"
    );
}
