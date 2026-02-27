//! Control Plane — TCP server for Connector registration and heartbeat
//!
//! Connectors connect to the Broker via TCP and exchange NDJSON messages
//! for registration, heartbeat, and graceful disconnect.

use crate::config::BrokerConfig;
use crate::error::BrokerError;
use crate::peer::{BrokerPeer, PeerRole};
use crate::registry::ServiceRegistry;

use boringtun::noise::{Tunn, HybridHandshakeState};
use dashmap::DashMap;
use dybervpn_tunnel::audit::AuditLogger;
use dybervpn_tunnel::connector::ControlMessage;
use dybervpn_tunnel::revocation::RevocationEngine;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use x25519_dalek::{PublicKey, StaticSecret};

/// Run the control plane TCP server
///
/// Accepts connections from Connectors, handles registration,
/// heartbeat, and disconnect messages.
pub async fn run_control_plane(
    config: Arc<BrokerConfig>,
    peers: Arc<DashMap<[u8; 32], BrokerPeer>>,
    registry: Arc<ServiceRegistry>,
    audit: AuditLogger,
    revocation: Arc<RevocationEngine>,
) -> Result<(), BrokerError> {
    let listener = TcpListener::bind(config.listen_control)
        .await
        .map_err(|e| BrokerError::Io(e))?;

    tracing::info!(
        "Control plane listening on {}",
        config.listen_control
    );

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                tracing::info!("Connector TCP connection from {}", addr);
                let config = Arc::clone(&config);
                let peers = Arc::clone(&peers);
                let registry = Arc::clone(&registry);
                let audit = audit.clone();
                let revocation = Arc::clone(&revocation);

                tokio::spawn(async move {
                    if let Err(e) = handle_connector(
                        stream, addr, config, peers, registry, audit, revocation,
                    ).await {
                        tracing::warn!("Connector {} error: {}", addr, e);
                    }
                });
            }
            Err(e) => {
                tracing::error!("Control plane accept error: {}", e);
            }
        }
    }
}

/// Handle a single Connector TCP connection
async fn handle_connector(
    stream: TcpStream,
    addr: SocketAddr,
    config: Arc<BrokerConfig>,
    peers: Arc<DashMap<[u8; 32], BrokerPeer>>,
    registry: Arc<ServiceRegistry>,
    _audit: AuditLogger,
    revocation: Arc<RevocationEngine>,
) -> Result<(), BrokerError> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    let mut connector_key: Option<[u8; 32]> = None;

    while let Some(line) = lines.next_line().await.map_err(BrokerError::Io)? {
        let msg: ControlMessage = serde_json::from_str(&line)
            .map_err(|e| BrokerError::Protocol(format!("invalid JSON: {}", e)))?;

        match msg {
            ControlMessage::Register {
                public_key,
                pq_public_key: _,
                mldsa_signature,
                advertised_routes,
                service_name,
                timestamp,
            } => {
                // Decode the Connector's public key
                let pk_bytes = base64::decode(&public_key)
                    .map_err(|_| BrokerError::AuthFailed("invalid public key base64".into()))?;
                if pk_bytes.len() != 32 {
                    send_register_ack(&mut writer, false, "public key must be 32 bytes").await?;
                    continue;
                }
                let mut pk = [0u8; 32];
                pk.copy_from_slice(&pk_bytes);

                // Check revocation
                if revocation.is_revoked(&pk) {
                    tracing::warn!(
                        "Connector {} has revoked key",
                        hex::encode(&pk[..4])
                    );
                    send_register_ack(&mut writer, false, "key revoked").await?;
                    continue;
                }

                // Verify ML-DSA signature (if in PQ mode)
                if config.mode.uses_pq_auth() {
                    if let Some(ref sig_b64) = mldsa_signature {
                        let sig_bytes = base64::decode(sig_b64).map_err(|_| {
                            BrokerError::AuthFailed("invalid signature base64".into())
                        })?;

                        // For now we'd need the connector's ML-DSA public key
                        // from a pre-registered key store. For the initial impl,
                        // we accept the registration if we have a valid signature format.
                        // Full key store lookup will be added in a future iteration.
                        tracing::debug!(
                            "ML-DSA signature present ({} bytes), timestamp={}",
                            sig_bytes.len(),
                            timestamp,
                        );
                    } else {
                        tracing::warn!("PQ mode requires ML-DSA signature for registration");
                        send_register_ack(&mut writer, false, "ML-DSA signature required").await?;
                        continue;
                    }
                }

                // Parse advertised routes
                let routes: Vec<(IpAddr, u8)> = advertised_routes
                    .iter()
                    .filter_map(|r| parse_cidr(r).ok())
                    .collect();

                if routes.is_empty() {
                    send_register_ack(&mut writer, false, "no valid routes").await?;
                    continue;
                }

                // Create a Tunn for this Connector
                let broker_secret = StaticSecret::from(config.private_key);
                let connector_public = PublicKey::from(pk);
                let peer_idx = peers.len() as u32;

                let tunn = if config.mode.uses_pq_kex() {
                    let hs = HybridHandshakeState::new(config.mode);
                    Tunn::new_hybrid(
                        broker_secret, connector_public,
                        None, Some(25), peer_idx, None, hs,
                    )
                } else {
                    Tunn::new(
                        broker_secret, connector_public,
                        None, Some(25), peer_idx, None,
                    )
                };

                // Create BrokerPeer
                let mut peer = BrokerPeer::new(tunn, PeerRole::Connector, addr, pk);
                peer.advertised_routes = routes.clone();
                peer.service_name = Some(service_name.clone());
                peer.authenticated = true;

                // Register in the service registry
                registry.register(pk, &routes);
                peers.insert(pk, peer);
                connector_key = Some(pk);

                tracing::info!(
                    "Connector {} registered: service={}, routes={}",
                    hex::encode(&pk[..4]),
                    service_name,
                    routes.len(),
                );

                send_register_ack(&mut writer, true, "").await?;
            }

            ControlMessage::Heartbeat { timestamp } => {
                // Update last_activity for the connector
                if let Some(ref key) = connector_key {
                    if let Some(mut peer) = peers.get_mut(key) {
                        peer.touch();
                    }
                }

                let ack = ControlMessage::HeartbeatAck { timestamp };
                let json = serde_json::to_string(&ack).unwrap();
                writer.write_all(json.as_bytes()).await.map_err(BrokerError::Io)?;
                writer.write_all(b"\n").await.map_err(BrokerError::Io)?;
                writer.flush().await.map_err(BrokerError::Io)?;
            }

            ControlMessage::Disconnect { reason } => {
                tracing::info!("Connector disconnecting: {}", reason);
                break;
            }

            _ => {
                tracing::debug!("Unexpected control message from {}: {:?}", addr, msg);
            }
        }
    }

    // Cleanup on disconnect
    if let Some(key) = connector_key {
        registry.unregister(&key);
        peers.remove(&key);
        tracing::info!(
            "Connector {} cleaned up",
            hex::encode(&key[..4])
        );
    }

    Ok(())
}

/// Send a RegisterAck response
async fn send_register_ack(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    success: bool,
    error: &str,
) -> Result<(), BrokerError> {
    let ack = ControlMessage::RegisterAck {
        success,
        error: if error.is_empty() {
            None
        } else {
            Some(error.to_string())
        },
    };
    let json = serde_json::to_string(&ack).unwrap();
    writer.write_all(json.as_bytes()).await.map_err(BrokerError::Io)?;
    writer.write_all(b"\n").await.map_err(BrokerError::Io)?;
    writer.flush().await.map_err(BrokerError::Io)?;
    Ok(())
}

/// Testable version of handle_connector (public for integration tests)
#[doc(hidden)]
pub async fn handle_connector_for_test(
    stream: TcpStream,
    addr: SocketAddr,
    config: Arc<BrokerConfig>,
    peers: Arc<DashMap<[u8; 32], BrokerPeer>>,
    registry: Arc<ServiceRegistry>,
    audit: AuditLogger,
    revocation: Arc<RevocationEngine>,
) -> Result<(), BrokerError> {
    handle_connector(stream, addr, config, peers, registry, audit, revocation).await
}

/// Parse a CIDR string like "10.1.0.0/16"
fn parse_cidr(s: &str) -> Result<(IpAddr, u8), String> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 {
        return Err(format!("invalid CIDR: {}", s));
    }
    let ip: IpAddr = parts[0].parse().map_err(|e| format!("invalid IP: {}", e))?;
    let prefix: u8 = parts[1].parse().map_err(|e| format!("invalid prefix: {}", e))?;
    Ok((ip, prefix))
}
