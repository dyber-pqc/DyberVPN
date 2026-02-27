//! Session Stitching — the core data-plane logic
//!
//! The Broker decrypts a packet from one peer's `Tunn`, inspects the plaintext
//! for policy evaluation, then re-encrypts through the destination peer's `Tunn`.
//! This is the fundamental operation that makes Zero Trust relay work.

use crate::error::{BrokerError, BrokerResult};
use crate::peer::BrokerPeer;

use boringtun::noise::TunnResult;
use dybervpn_tunnel::audit::AuditLogger;
use dybervpn_tunnel::policy::{self, PolicyAction, PolicyEngine};

/// Stitch a packet from one peer to another through the Broker
///
/// 1. Decrypt the incoming packet using `src_peer.tunn.decapsulate()`
/// 2. Extract L3/L4 headers from the plaintext for policy evaluation
/// 3. Evaluate the policy — deny if not allowed
/// 4. Re-encrypt through `dst_peer.tunn.encapsulate()`
/// 5. Return the re-encrypted bytes to send to `dst_peer.endpoint`
///
/// Returns `Ok(None)` if the packet was handled but produced no output
/// (e.g., handshake, keepalive, or policy-denied).
///
/// Returns `Ok(Some(packets))` — a vec of (encrypted_bytes, dest_endpoint) to send.
pub fn stitch_packet(
    src_peer: &mut BrokerPeer,
    dst_peer: &mut BrokerPeer,
    encrypted_packet: &[u8],
    policy: &mut PolicyEngine,
    _audit: &AuditLogger,
) -> BrokerResult<StitchResult> {
    let mut dst_buf = vec![0u8; 65535];

    // Step 1: Decrypt incoming packet
    let decap_result = src_peer.tunn.decapsulate(
        Some(src_peer.endpoint.ip()),
        encrypted_packet,
        &mut dst_buf,
    );

    match decap_result {
        TunnResult::WriteToTunnelV4(plaintext, _) | TunnResult::WriteToTunnelV6(plaintext, _) => {
            // Got a decrypted IP packet — proceed to policy check
            let plaintext = plaintext.to_vec();

            // Step 2: Extract L3/L4 info
            let packet_info = policy::inspect_packet(&plaintext);
            let (src_ip, dst_ip, dst_port, proto) = match packet_info {
                Some(info) => info,
                None => {
                    tracing::debug!("Could not parse decrypted packet, dropping");
                    return Ok(StitchResult::Dropped);
                }
            };

            // Step 3: Policy evaluation
            if policy.is_enabled() {
                let peer_name = src_peer.service_name.as_deref();
                let (action, reason) = policy.evaluate(
                    &src_peer.public_key,
                    peer_name,
                    dst_ip,
                    dst_port,
                    Some(proto),
                );

                match action {
                    PolicyAction::Deny => {
                        tracing::debug!(
                            "Policy denied: {} -> {}:{} proto={} ({})",
                            src_ip, dst_ip, dst_port.unwrap_or(0), proto, reason
                        );
                        src_peer.stitched_packets += 1;
                        return Ok(StitchResult::PolicyDenied(reason));
                    }
                    PolicyAction::Allow => {}
                }
            }

            // Step 4: Re-encrypt through destination peer's Tunn
            let mut out_buf = vec![0u8; 65535];
            let encap_result = dst_peer.tunn.encapsulate(&plaintext, &mut out_buf);

            match encap_result {
                TunnResult::WriteToNetwork(data) => {
                    let encrypted = data.to_vec();

                    src_peer.rx_bytes += encrypted_packet.len() as u64;
                    dst_peer.tx_bytes += encrypted.len() as u64;
                    src_peer.stitched_packets += 1;
                    dst_peer.stitched_packets += 1;

                    Ok(StitchResult::Forward(encrypted))
                }
                TunnResult::Done => {
                    // Encapsulate produced nothing (might need handshake first)
                    Ok(StitchResult::NeedHandshake)
                }
                TunnResult::Err(e) => {
                    tracing::warn!("Re-encrypt failed: {:?}", e);
                    Err(BrokerError::Protocol(format!("re-encrypt error: {:?}", e)))
                }
                _ => Ok(StitchResult::Dropped),
            }
        }

        TunnResult::WriteToNetwork(data) => {
            // This is a handshake or cookie response — forward as-is
            let response = data.to_vec();
            Ok(StitchResult::HandshakeResponse(response))
        }

        TunnResult::Done => {
            // Keepalive or empty — no data to forward
            Ok(StitchResult::Dropped)
        }

        TunnResult::Err(e) => {
            tracing::debug!("Decapsulate error: {:?}", e);
            Err(BrokerError::Protocol(format!("decrypt error: {:?}", e)))
        }
    }
}

/// Result of a stitch operation
#[derive(Debug)]
pub enum StitchResult {
    /// Re-encrypted packet ready to send to the destination peer
    Forward(Vec<u8>),
    /// Handshake/cookie response to send back to the source peer
    HandshakeResponse(Vec<u8>),
    /// Packet denied by policy
    PolicyDenied(String),
    /// Destination peer needs a handshake first
    NeedHandshake,
    /// Packet was consumed but produced no output
    Dropped,
}
