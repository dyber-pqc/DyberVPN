//! Control Plane — TCP server for Connector registration and heartbeat
//!
//! Connectors connect to the Broker via TCP and exchange NDJSON messages
//! for registration, heartbeat, and graceful disconnect.

use crate::config::BrokerConfig;
use crate::error::BrokerError;
use crate::peer::{BrokerPeer, PeerRole};
use crate::registry::ServiceRegistry;

use boringtun::noise::{HybridHandshakeState, Tunn};
use dashmap::DashMap;
use dybervpn_tunnel::audit::AuditLogger;
use dybervpn_tunnel::connector::ControlMessage;
use dybervpn_tunnel::revocation::RevocationEngine;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use x25519_dalek::{PublicKey, StaticSecret};

/// Maximum length of a single control-plane NDJSON line. Registration is a few
/// KB; larger lines are rejected to bound per-connection memory (audit M9).
const MAX_CONTROL_LINE_BYTES: usize = 64 * 1024;
/// Maximum routes a single connector may advertise (bounds registry growth and
/// the per-packet longest-prefix scan).
const MAX_ADVERTISED_ROUTES: usize = 256;
/// Idle read timeout for a control connection — a connection that sends nothing
/// within this window is closed (mitigates slow-loris accumulation).
const CONTROL_READ_TIMEOUT: Duration = Duration::from_secs(120);

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
        .map_err(BrokerError::Io)?;

    tracing::info!("Control plane listening on {}", config.listen_control);

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
                    if let Err(e) =
                        handle_connector(stream, addr, config, peers, registry, audit, revocation)
                            .await
                    {
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

    loop {
        // M9: bound how long we wait for a line, and reject oversized lines,
        // so a single connection cannot tie up the broker or exhaust memory.
        let line = match tokio::time::timeout(CONTROL_READ_TIMEOUT, lines.next_line()).await {
            Ok(Ok(Some(line))) => line,
            Ok(Ok(None)) => break, // clean EOF
            Ok(Err(e)) => return Err(BrokerError::Io(e)),
            Err(_) => {
                tracing::debug!("Control connection {} idle-timed out", addr);
                break;
            }
        };

        if line.len() > MAX_CONTROL_LINE_BYTES {
            tracing::warn!(
                "Control connection {} sent an oversized line ({} bytes) — closing",
                addr,
                line.len()
            );
            break;
        }

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
                    tracing::warn!("Connector {} has revoked key", hex::encode(&pk[..4]));
                    send_register_ack(&mut writer, false, "key revoked").await?;
                    continue;
                }

                // M9: bound the number of advertised routes to protect the
                // registry (and the per-packet longest-prefix-match scan).
                if advertised_routes.len() > MAX_ADVERTISED_ROUTES {
                    send_register_ack(&mut writer, false, "too many advertised routes").await?;
                    continue;
                }

                // Authorization: the connector must be on the fail-closed
                // allowlist (security audit C3). This replaces the previous
                // behaviour of accepting any key that presented a well-formed
                // (but never verified) signature.
                let authz = match config
                    .authorized_connectors
                    .iter()
                    .find(|c| c.public_key == pk)
                {
                    Some(c) => c,
                    None => {
                        if config.authorized_connectors.is_empty() {
                            tracing::error!(
                                "Rejecting connector {}: no [[authorized_connector]] entries are \
                                 configured — the Broker is fail-closed. Add the connector's \
                                 X25519 (and ML-DSA) public key to the broker config to allow it.",
                                hex::encode(&pk[..4])
                            );
                        } else {
                            tracing::warn!(
                                "Rejecting connector {}: not in the authorized_connectors allowlist",
                                hex::encode(&pk[..4])
                            );
                        }
                        send_register_ack(&mut writer, false, "connector not authorized").await?;
                        continue;
                    }
                };

                // Verify the ML-DSA registration signature against the
                // connector's *pre-registered* ML-DSA public key (security
                // audit C3). Previously the signature was decoded and its
                // length logged, but never actually verified.
                if let Some(ref mldsa_pk) = authz.mldsa_public_key {
                    let sig_b64 = match mldsa_signature {
                        Some(ref s) => s,
                        None => {
                            send_register_ack(&mut writer, false, "ML-DSA signature required")
                                .await?;
                            continue;
                        }
                    };
                    let sig_bytes = match base64::decode(sig_b64) {
                        Ok(b) => b,
                        Err(_) => {
                            send_register_ack(&mut writer, false, "invalid signature base64")
                                .await?;
                            continue;
                        }
                    };
                    match crate::auth::verify_mldsa_auth(mldsa_pk, &pk, timestamp, &sig_bytes) {
                        Ok(true) => {}
                        Ok(false) => {
                            tracing::warn!(
                                "Rejecting connector {}: ML-DSA signature invalid or timestamp stale",
                                hex::encode(&pk[..4])
                            );
                            send_register_ack(&mut writer, false, "ML-DSA verification failed")
                                .await?;
                            continue;
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Connector {} auth error: {}",
                                hex::encode(&pk[..4]),
                                e
                            );
                            send_register_ack(&mut writer, false, "ML-DSA verification error")
                                .await?;
                            continue;
                        }
                    }
                } else if config.mode.uses_pq_auth() {
                    // pq-only mode mandates post-quantum connector authentication.
                    tracing::warn!(
                        "Rejecting connector {}: pq-only mode requires a configured ML-DSA public key",
                        hex::encode(&pk[..4])
                    );
                    send_register_ack(
                        &mut writer,
                        false,
                        "connector has no ML-DSA key configured for pq-only mode",
                    )
                    .await?;
                    continue;
                }

                // Authorize advertised routes: each must be covered by (equal
                // to or more specific than) one of the connector's allowed
                // CIDRs (security audit C4). Invalid or unauthorized routes are
                // dropped rather than silently trusted, preventing route hijack.
                let mut routes: Vec<(IpAddr, u8)> = Vec::new();
                for r in &advertised_routes {
                    match crate::config::parse_cidr(r) {
                        Ok(route) => {
                            if route_is_authorized(route, &authz.allowed_routes) {
                                routes.push(route);
                            } else {
                                tracing::warn!(
                                    "Connector {} advertised unauthorized route {} — dropping",
                                    hex::encode(&pk[..4]),
                                    r
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Connector {} sent invalid route {}: {}",
                                hex::encode(&pk[..4]),
                                r,
                                e
                            );
                        }
                    }
                }

                if routes.is_empty() {
                    send_register_ack(&mut writer, false, "no authorized routes").await?;
                    continue;
                }

                // M9: enforce capacity before creating a Tunn/peer, so the
                // control plane can't grow the peer map without bound.
                if !peers.contains_key(&pk) && peers.len() >= config.max_clients {
                    send_register_ack(&mut writer, false, "broker at capacity").await?;
                    continue;
                }

                // Create a Tunn for this Connector
                let broker_secret = StaticSecret::from(config.private_key);
                let connector_public = PublicKey::from(pk);
                let peer_idx = peers.len() as u32;

                let tunn = if config.mode.uses_pq_kex() {
                    let hs = HybridHandshakeState::new(config.mode);
                    Tunn::new_hybrid(
                        broker_secret,
                        connector_public,
                        None,
                        Some(25),
                        peer_idx,
                        None,
                        hs,
                    )
                } else {
                    Tunn::new(
                        broker_secret,
                        connector_public,
                        None,
                        Some(25),
                        peer_idx,
                        None,
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
                writer
                    .write_all(json.as_bytes())
                    .await
                    .map_err(BrokerError::Io)?;
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
        tracing::info!("Connector {} cleaned up", hex::encode(&key[..4]));
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
    writer
        .write_all(json.as_bytes())
        .await
        .map_err(BrokerError::Io)?;
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

/// Returns true if `route` is covered by one of the connector's `allowed`
/// CIDRs — i.e. the advertised route is equal to, or more specific than, an
/// allowed CIDR (same network bits and a prefix at least as long).
fn route_is_authorized(route: (IpAddr, u8), allowed: &[(IpAddr, u8)]) -> bool {
    let (net, prefix) = route;
    allowed.iter().any(|&(allowed_net, allowed_prefix)| {
        prefix >= allowed_prefix && crate::config::cidr_contains(allowed_net, allowed_prefix, net)
    })
}

#[cfg(test)]
mod tests {
    use super::route_is_authorized;
    use std::net::{IpAddr, Ipv4Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn route_authorization_enforces_subset() {
        // Connector is allowed only 10.1.0.0/16.
        let allowed = vec![(v4(10, 1, 0, 0), 16)];

        // Equal route: authorized.
        assert!(route_is_authorized((v4(10, 1, 0, 0), 16), &allowed));
        // More specific (subset): authorized.
        assert!(route_is_authorized((v4(10, 1, 5, 0), 24), &allowed));
        // Broader (superset /8): NOT authorized — this is the route-hijack case.
        assert!(!route_is_authorized((v4(10, 0, 0, 0), 8), &allowed));
        // A default route grab: NOT authorized.
        assert!(!route_is_authorized((v4(0, 0, 0, 0), 0), &allowed));
        // Different network: NOT authorized.
        assert!(!route_is_authorized((v4(192, 168, 1, 0), 24), &allowed));
    }
}
