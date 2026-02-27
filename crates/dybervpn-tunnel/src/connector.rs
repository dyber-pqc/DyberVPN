//! Connector Mode for ZTNA
//!
//! When running in connector mode, the daemon establishes an outbound connection
//! to a Broker and advertises local network routes. The Broker relays traffic
//! from authenticated Clients to the Connector's advertised networks.
//!
//! The control plane uses newline-delimited JSON (NDJSON) over TCP.
//! The data plane reuses the standard WireGuard UDP tunnel (the Broker
//! is just another peer from the daemon's perspective).

use crate::config::ConnectorConfig;
use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Control plane messages exchanged between Connector and Broker
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
#[allow(missing_docs)]
pub enum ControlMessage {
    /// Connector → Broker: register with advertised routes
    Register {
        public_key: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pq_public_key: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        mldsa_signature: Option<String>,
        advertised_routes: Vec<String>,
        service_name: String,
        timestamp: u64,
    },

    /// Broker → Connector: registration acknowledgment
    RegisterAck {
        success: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },

    /// Bidirectional: keepalive heartbeat
    Heartbeat { timestamp: u64 },

    /// Bidirectional: heartbeat acknowledgment
    HeartbeatAck { timestamp: u64 },

    /// Either side: graceful disconnect
    Disconnect { reason: String },
}

/// Connector agent — manages the TCP control plane to the Broker
pub struct ConnectorAgent {
    /// TCP connection to the Broker's control plane
    stream: TcpStream,
    /// Buffered reader for NDJSON parsing
    reader: BufReader<TcpStream>,
    /// Configuration
    config: ConnectorConfig,
    /// Last heartbeat sent
    last_heartbeat: Instant,
    /// Whether registration was acknowledged
    registered: bool,
}

impl ConnectorAgent {
    /// Connect to the Broker's control plane
    pub fn new(config: &ConnectorConfig) -> io::Result<Self> {
        tracing::info!(
            "Connecting to Broker control plane at {}",
            config.broker_control
        );

        let stream = TcpStream::connect_timeout(&config.broker_control, Duration::from_secs(10))?;

        // Set TCP keepalive and read timeout
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(Duration::from_secs(1)))?;

        let reader = BufReader::new(stream.try_clone()?);

        Ok(Self {
            stream,
            reader,
            config: config.clone(),
            last_heartbeat: Instant::now(),
            registered: false,
        })
    }

    /// Send a control message (NDJSON — one JSON object per line)
    fn send(&mut self, msg: &ControlMessage) -> io::Result<()> {
        let json = serde_json::to_string(msg)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        self.stream.write_all(json.as_bytes())?;
        self.stream.write_all(b"\n")?;
        self.stream.flush()?;
        Ok(())
    }

    /// Try to read one control message (non-blocking due to read timeout)
    fn try_recv(&mut self) -> io::Result<Option<ControlMessage>> {
        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(0) => Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "Broker closed connection",
            )),
            Ok(_) => {
                let msg: ControlMessage = serde_json::from_str(line.trim())
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                Ok(Some(msg))
            }
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Current unix timestamp
    fn now_unix() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Register this Connector with the Broker
    ///
    /// Sends a Register message with our public key, advertised routes,
    /// and optional ML-DSA signature for PQ authentication.
    pub fn register(
        &mut self,
        public_key: &[u8; 32],
        mldsa_signature: Option<Vec<u8>>,
    ) -> io::Result<()> {
        let timestamp = Self::now_unix();

        let routes: Vec<String> = self
            .config
            .advertised_routes
            .iter()
            .map(|(ip, prefix)| format!("{}/{}", ip, prefix))
            .collect();

        let msg = ControlMessage::Register {
            public_key: base64::encode(public_key),
            pq_public_key: self
                .config
                .broker_pq_public_key
                .as_ref()
                .map(base64::encode),
            mldsa_signature: mldsa_signature.map(|s| base64::encode(&s)),
            advertised_routes: routes,
            service_name: self.config.service_name.clone(),
            timestamp,
        };

        tracing::info!(
            "Registering with Broker: service={}, routes={}",
            self.config.service_name,
            self.config.advertised_routes.len()
        );

        self.send(&msg)?;

        // Wait for RegisterAck (with timeout)
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Some(reply) = self.try_recv()? {
                match reply {
                    ControlMessage::RegisterAck { success, error } => {
                        if success {
                            tracing::info!("Broker accepted registration");
                            self.registered = true;
                            return Ok(());
                        } else {
                            let err_msg = error.unwrap_or_else(|| "unknown".into());
                            tracing::error!("Broker rejected registration: {}", err_msg);
                            return Err(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                format!("registration rejected: {}", err_msg),
                            ));
                        }
                    }
                    other => {
                        tracing::warn!("Unexpected message during registration: {:?}", other);
                    }
                }
            }
        }

        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Broker did not respond to registration",
        ))
    }

    /// Send a heartbeat if the interval has elapsed.
    /// Returns true if a heartbeat was sent.
    pub fn maybe_heartbeat(&mut self) -> io::Result<bool> {
        if self.last_heartbeat.elapsed() < self.config.heartbeat_interval {
            return Ok(false);
        }

        let msg = ControlMessage::Heartbeat {
            timestamp: Self::now_unix(),
        };
        self.send(&msg)?;
        self.last_heartbeat = Instant::now();
        Ok(true)
    }

    /// Process any incoming control messages from the Broker.
    /// Returns `Err` if the connection is lost.
    pub fn poll(&mut self) -> io::Result<()> {
        while let Some(msg) = self.try_recv()? {
            match msg {
                ControlMessage::HeartbeatAck { timestamp } => {
                    let rtt_ms = Self::now_unix().saturating_sub(timestamp) * 1000;
                    tracing::trace!("Heartbeat ACK (rtt ~{}ms)", rtt_ms);
                }
                ControlMessage::Disconnect { reason } => {
                    tracing::warn!("Broker requested disconnect: {}", reason);
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        format!("broker disconnect: {}", reason),
                    ));
                }
                ControlMessage::Heartbeat { timestamp } => {
                    // Broker sent us a heartbeat — reply
                    self.send(&ControlMessage::HeartbeatAck { timestamp })?;
                }
                other => {
                    tracing::debug!("Unhandled control message: {:?}", other);
                }
            }
        }
        Ok(())
    }

    /// Send a graceful disconnect and close the connection
    pub fn disconnect(&mut self, reason: &str) -> io::Result<()> {
        let msg = ControlMessage::Disconnect {
            reason: reason.to_string(),
        };
        let _ = self.send(&msg); // Best-effort
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
        self.registered = false;
        Ok(())
    }

    /// Whether the Broker acknowledged our registration
    pub fn is_registered(&self) -> bool {
        self.registered
    }
}

impl Drop for ConnectorAgent {
    fn drop(&mut self) {
        let _ = self.disconnect("connector shutting down");
    }
}
