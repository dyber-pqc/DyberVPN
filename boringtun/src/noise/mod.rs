// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod errors;
pub mod handshake;
pub mod hybrid_handshake;
pub mod hybrid_integration;
pub mod rate_limiter;

mod session;
mod timers;

use crate::noise::errors::WireGuardError;
use crate::noise::handshake::Handshake;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::timers::{TimerName, Timers};
use crate::x25519;

use std::collections::VecDeque;
use std::convert::{TryFrom, TryInto};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use dybervpn_protocol::OperatingMode;

/// The default value to use for rate limiting, when no other rate limiter is defined
const PEER_HANDSHAKE_RATE_LIMIT: u64 = 10;

const IPV4_MIN_HEADER_SIZE: usize = 20;
const IPV4_LEN_OFF: usize = 2;
const IPV4_SRC_IP_OFF: usize = 12;
const IPV4_DST_IP_OFF: usize = 16;
const IPV4_IP_SZ: usize = 4;

const IPV6_MIN_HEADER_SIZE: usize = 40;
const IPV6_LEN_OFF: usize = 4;
const IPV6_SRC_IP_OFF: usize = 8;
const IPV6_DST_IP_OFF: usize = 24;
const IPV6_IP_SZ: usize = 16;

const IP_LEN_SZ: usize = 2;

const MAX_QUEUE_DEPTH: usize = 256;
/// number of sessions in the ring, better keep a PoT
const N_SESSIONS: usize = 8;

// Re-export hybrid handshake types
pub use hybrid_handshake::{
    HybridHandshakeState,
    MlDsaKeyPair,
    PqKeyPair,
    // Hybrid mode (ML-KEM only)
    HANDSHAKE_INIT_PQ,
    // PQ-only mode (ML-KEM + ML-DSA auth)
    HANDSHAKE_INIT_PQ_AUTH,
    HANDSHAKE_INIT_PQ_AUTH_SZ,
    HANDSHAKE_INIT_PQ_SZ,
    HANDSHAKE_RESP_PQ,
    HANDSHAKE_RESP_PQ_AUTH,
    HANDSHAKE_RESP_PQ_AUTH_SZ,
    HANDSHAKE_RESP_PQ_SZ,
    MLDSA_PUBLIC_KEY_SIZE,
    MLDSA_SECRET_KEY_SIZE,
    MLDSA_SIGNATURE_SIZE,
    // Key/signature sizes
    MLKEM_CIPHERTEXT_SIZE,
    MLKEM_PUBLIC_KEY_SIZE,
};

#[derive(Debug)]
pub enum TunnResult<'a> {
    Done,
    Err(WireGuardError),
    WriteToNetwork(&'a mut [u8]),
    WriteToTunnelV4(&'a mut [u8], Ipv4Addr),
    WriteToTunnelV6(&'a mut [u8], Ipv6Addr),
}

impl<'a> From<WireGuardError> for TunnResult<'a> {
    fn from(err: WireGuardError) -> TunnResult<'a> {
        TunnResult::Err(err)
    }
}

/// Tunnel represents a point-to-point WireGuard connection
pub struct Tunn {
    /// The handshake currently in progress
    handshake: handshake::Handshake,
    /// Operating mode (Classic, Hybrid, PqOnly)
    mode: OperatingMode,
    /// PQ initiator state (when we initiate handshake)
    pq_initiator_state: Option<hybrid_integration::HybridInitiatorState>,
    /// ML-DSA signing keypair (for pq-only mode authentication)
    mldsa_keypair: Option<MlDsaKeyPair>,
    /// Peer's ML-DSA public key (for verifying peer in pq-only mode)
    peer_mldsa_public_key: Option<dybervpn_protocol::MlDsaPublicKey>,
    /// The N_SESSIONS most recent sessions, index is session id modulo N_SESSIONS
    sessions: [Option<session::Session>; N_SESSIONS],
    /// Index of most recently used session
    current: usize,
    /// Queue to store blocked packets
    packet_queue: VecDeque<Vec<u8>>,
    /// Keeps tabs on the expiring timers
    timers: timers::Timers,
    tx_bytes: usize,
    rx_bytes: usize,
    rate_limiter: Arc<RateLimiter>,
}

type MessageType = u32;
const HANDSHAKE_INIT: MessageType = 1;
const HANDSHAKE_RESP: MessageType = 2;
const COOKIE_REPLY: MessageType = 3;
const DATA: MessageType = 4;

const HANDSHAKE_INIT_SZ: usize = 148;
const HANDSHAKE_RESP_SZ: usize = 92;
const COOKIE_REPLY_SZ: usize = 64;
const DATA_OVERHEAD_SZ: usize = 32;

#[derive(Debug)]
pub struct HandshakeInit<'a> {
    sender_idx: u32,
    unencrypted_ephemeral: &'a [u8; 32],
    encrypted_static: &'a [u8],
    encrypted_timestamp: &'a [u8],
}

#[derive(Debug)]
pub struct HandshakeResponse<'a> {
    sender_idx: u32,
    pub receiver_idx: u32,
    unencrypted_ephemeral: &'a [u8; 32],
    encrypted_nothing: &'a [u8],
}

#[derive(Debug)]
pub struct PacketCookieReply<'a> {
    pub receiver_idx: u32,
    nonce: &'a [u8],
    encrypted_cookie: &'a [u8],
}

#[derive(Debug)]
pub struct PacketData<'a> {
    pub receiver_idx: u32,
    counter: u64,
    encrypted_encapsulated_packet: &'a [u8],
}

/// Describes a packet from network
#[derive(Debug)]
pub enum Packet<'a> {
    HandshakeInit(HandshakeInit<'a>),
    HandshakeResponse(HandshakeResponse<'a>),
    PacketCookieReply(PacketCookieReply<'a>),
    PacketData(PacketData<'a>),
    // PQ handshake variants (hybrid mode - ML-KEM only, Ed25519 auth)
    HandshakeInitPq(hybrid_handshake::HandshakeInitPq<'a>),
    HandshakeResponsePq(hybrid_handshake::HandshakeResponsePq<'a>),
    // PQ-only handshake variants (ML-KEM + ML-DSA auth)
    HandshakeInitPqAuth(hybrid_handshake::HandshakeInitPqAuth<'a>),
    HandshakeResponsePqAuth(hybrid_handshake::HandshakeResponsePqAuth<'a>),
}

impl Tunn {
    #[inline(always)]
    pub fn parse_incoming_packet(src: &[u8]) -> Result<Packet<'_>, WireGuardError> {
        if src.len() < 4 {
            return Err(WireGuardError::InvalidPacket);
        }

        // Checks the type, as well as the reserved zero fields
        let packet_type = u32::from_le_bytes(src[0..4].try_into().unwrap());

        Ok(match (packet_type, src.len()) {
            (HANDSHAKE_INIT, HANDSHAKE_INIT_SZ) => Packet::HandshakeInit(HandshakeInit {
                sender_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                unencrypted_ephemeral: <&[u8; 32] as TryFrom<&[u8]>>::try_from(&src[8..40])
                    .expect("length already checked above"),
                encrypted_static: &src[40..88],
                encrypted_timestamp: &src[88..116],
            }),
            (HANDSHAKE_RESP, HANDSHAKE_RESP_SZ) => Packet::HandshakeResponse(HandshakeResponse {
                sender_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                receiver_idx: u32::from_le_bytes(src[8..12].try_into().unwrap()),
                unencrypted_ephemeral: <&[u8; 32] as TryFrom<&[u8]>>::try_from(&src[12..44])
                    .expect("length already checked above"),
                encrypted_nothing: &src[44..60],
            }),
            (COOKIE_REPLY, COOKIE_REPLY_SZ) => Packet::PacketCookieReply(PacketCookieReply {
                receiver_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                nonce: &src[8..32],
                encrypted_cookie: &src[32..64],
            }),
            (DATA, DATA_OVERHEAD_SZ..=std::usize::MAX) => Packet::PacketData(PacketData {
                receiver_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                counter: u64::from_le_bytes(src[8..16].try_into().unwrap()),
                encrypted_encapsulated_packet: &src[16..],
            }),
            // PQ handshake messages (hybrid mode - ML-KEM only)
            (HANDSHAKE_INIT_PQ, HANDSHAKE_INIT_PQ_SZ) => Packet::HandshakeInitPq(
                hybrid_handshake::HandshakeInitPq::parse(src)
                    .map_err(|_| WireGuardError::InvalidPacket)?,
            ),
            (HANDSHAKE_RESP_PQ, HANDSHAKE_RESP_PQ_SZ) => Packet::HandshakeResponsePq(
                hybrid_handshake::HandshakeResponsePq::parse(src)
                    .map_err(|_| WireGuardError::InvalidPacket)?,
            ),
            // PQ-only handshake messages (ML-KEM + ML-DSA auth)
            (HANDSHAKE_INIT_PQ_AUTH, HANDSHAKE_INIT_PQ_AUTH_SZ) => Packet::HandshakeInitPqAuth(
                hybrid_handshake::HandshakeInitPqAuth::parse(src)
                    .map_err(|_| WireGuardError::InvalidPacket)?,
            ),
            (HANDSHAKE_RESP_PQ_AUTH, HANDSHAKE_RESP_PQ_AUTH_SZ) => Packet::HandshakeResponsePqAuth(
                hybrid_handshake::HandshakeResponsePqAuth::parse(src)
                    .map_err(|_| WireGuardError::InvalidPacket)?,
            ),
            _ => return Err(WireGuardError::InvalidPacket),
        })
    }

    pub fn is_expired(&self) -> bool {
        self.handshake.is_expired()
    }

    pub fn dst_address(packet: &[u8]) -> Option<IpAddr> {
        if packet.is_empty() {
            return None;
        }

        match packet[0] >> 4 {
            4 if packet.len() >= IPV4_MIN_HEADER_SIZE => {
                let addr_bytes: [u8; IPV4_IP_SZ] = packet
                    [IPV4_DST_IP_OFF..IPV4_DST_IP_OFF + IPV4_IP_SZ]
                    .try_into()
                    .unwrap();
                Some(IpAddr::from(addr_bytes))
            }
            6 if packet.len() >= IPV6_MIN_HEADER_SIZE => {
                let addr_bytes: [u8; IPV6_IP_SZ] = packet
                    [IPV6_DST_IP_OFF..IPV6_DST_IP_OFF + IPV6_IP_SZ]
                    .try_into()
                    .unwrap();
                Some(IpAddr::from(addr_bytes))
            }
            _ => None,
        }
    }

    /// Create a new tunnel using own private key and the peer public key
    pub fn new(
        static_private: x25519::StaticSecret,
        peer_static_public: x25519::PublicKey,
        preshared_key: Option<[u8; 32]>,
        persistent_keepalive: Option<u16>,
        index: u32,
        rate_limiter: Option<Arc<RateLimiter>>,
    ) -> Self {
        let static_public = x25519::PublicKey::from(&static_private);

        Tunn {
            handshake: Handshake::new(
                static_private,
                static_public,
                peer_static_public,
                index << 8,
                preshared_key,
            ),
            mode: OperatingMode::Classic,
            pq_initiator_state: None,
            mldsa_keypair: None,
            peer_mldsa_public_key: None,
            sessions: Default::default(),
            current: Default::default(),
            tx_bytes: Default::default(),
            rx_bytes: Default::default(),

            packet_queue: VecDeque::new(),
            timers: Timers::new(persistent_keepalive, rate_limiter.is_none()),

            rate_limiter: rate_limiter.unwrap_or_else(|| {
                Arc::new(RateLimiter::new(&static_public, PEER_HANDSHAKE_RATE_LIMIT))
            }),
        }
    }

    /// Create a new tunnel with hybrid PQ support
    pub fn new_hybrid(
        static_private: x25519::StaticSecret,
        peer_static_public: x25519::PublicKey,
        preshared_key: Option<[u8; 32]>,
        persistent_keepalive: Option<u16>,
        index: u32,
        rate_limiter: Option<Arc<RateLimiter>>,
        hybrid_state: HybridHandshakeState,
    ) -> Self {
        let mut tunn = Self::new(
            static_private,
            peer_static_public,
            preshared_key,
            persistent_keepalive,
            index,
            rate_limiter,
        );
        tunn.mode = hybrid_state.mode;
        // Copy ML-DSA keys from hybrid state if present
        tunn.mldsa_keypair = hybrid_state.mldsa_keypair;
        tunn.peer_mldsa_public_key = hybrid_state.peer_mldsa_public_key;
        tunn
    }

    /// Set ML-DSA keypair for PQ-only authentication
    pub fn set_mldsa_keypair(&mut self, keypair: MlDsaKeyPair) {
        self.mldsa_keypair = Some(keypair);
    }

    /// Set peer's ML-DSA public key for PQ-only authentication
    pub fn set_peer_mldsa_public_key(&mut self, public_key: dybervpn_protocol::MlDsaPublicKey) {
        self.peer_mldsa_public_key = Some(public_key);
    }

    /// Check if PQ-only authentication is enabled and keys are configured
    pub fn is_pq_auth_ready(&self) -> bool {
        self.mode.uses_pq_auth()
            && self.mldsa_keypair.is_some()
            && self.peer_mldsa_public_key.is_some()
    }

    /// Check if this tunnel uses hybrid PQ mode
    pub fn is_hybrid(&self) -> bool {
        self.mode.uses_pq_kex()
    }

    /// Get the operating mode
    pub fn mode(&self) -> OperatingMode {
        self.mode
    }

    /// Get the peer's static public key bytes
    pub fn peer_public_key(&self) -> [u8; 32] {
        *self.handshake.peer_public_key_bytes()
    }

    /// Update the private key and clear existing sessions
    pub fn set_static_private(
        &mut self,
        static_private: x25519::StaticSecret,
        static_public: x25519::PublicKey,
        rate_limiter: Option<Arc<RateLimiter>>,
    ) {
        self.timers.should_reset_rr = rate_limiter.is_none();
        self.rate_limiter = rate_limiter.unwrap_or_else(|| {
            Arc::new(RateLimiter::new(&static_public, PEER_HANDSHAKE_RATE_LIMIT))
        });
        self.handshake
            .set_static_private(static_private, static_public);
        for s in &mut self.sessions {
            *s = None;
        }
    }

    /// Encapsulate a single packet from the tunnel interface.
    /// Returns TunnResult.
    ///
    /// # Panics
    /// Panics if dst buffer is too small.
    /// Size of dst should be at least src.len() + 32, and no less than 148 bytes.
    pub fn encapsulate<'a>(&mut self, src: &[u8], dst: &'a mut [u8]) -> TunnResult<'a> {
        let current = self.current;
        if let Some(ref session) = self.sessions[current % N_SESSIONS] {
            // Send the packet using an established session
            let packet = session.format_packet_data(src, dst);
            self.timer_tick(TimerName::TimeLastPacketSent);
            // Exclude Keepalive packets from timer update.
            if !src.is_empty() {
                self.timer_tick(TimerName::TimeLastDataPacketSent);
            }
            self.tx_bytes += src.len();
            return TunnResult::WriteToNetwork(packet);
        }

        // If there is no session, queue the packet for future retry
        self.queue_packet(src);
        // Initiate a new handshake if none is in progress
        self.format_handshake_initiation(dst, false)
    }

    /// Receives a UDP datagram from the network and parses it.
    /// Returns TunnResult.
    ///
    /// If the result is of type TunnResult::WriteToNetwork, should repeat the call with empty datagram,
    /// until TunnResult::Done is returned. If batch processing packets, it is OK to defer until last
    /// packet is processed.
    pub fn decapsulate<'a>(
        &mut self,
        src_addr: Option<IpAddr>,
        datagram: &[u8],
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        if datagram.is_empty() {
            // Indicates a repeated call
            return self.send_queued_packet(dst);
        }

        let mut cookie = [0u8; COOKIE_REPLY_SZ];
        let packet = match self
            .rate_limiter
            .verify_packet(src_addr, datagram, &mut cookie)
        {
            Ok(packet) => packet,
            Err(TunnResult::WriteToNetwork(cookie)) => {
                dst[..cookie.len()].copy_from_slice(cookie);
                return TunnResult::WriteToNetwork(&mut dst[..cookie.len()]);
            }
            Err(TunnResult::Err(e)) => return TunnResult::Err(e),
            _ => unreachable!(),
        };

        self.handle_verified_packet(packet, dst)
    }

    pub(crate) fn handle_verified_packet<'a>(
        &mut self,
        packet: Packet,
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        match packet {
            Packet::HandshakeInit(p) => self.handle_handshake_init(p, dst),
            Packet::HandshakeResponse(p) => self.handle_handshake_response(p, dst),
            Packet::PacketCookieReply(p) => self.handle_cookie_reply(p),
            Packet::PacketData(p) => self.handle_data(p, dst),
            Packet::HandshakeInitPq(p) => self.handle_handshake_init_pq(p, dst),
            Packet::HandshakeResponsePq(p) => self.handle_handshake_response_pq(p, dst),
            Packet::HandshakeInitPqAuth(p) => self.handle_handshake_init_pq_auth(p, dst),
            Packet::HandshakeResponsePqAuth(p) => self.handle_handshake_response_pq_auth(p, dst),
        }
        .unwrap_or_else(TunnResult::from)
    }

    fn handle_handshake_init<'a>(
        &mut self,
        p: HandshakeInit,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        tracing::debug!(
            message = "Received handshake_initiation",
            remote_idx = p.sender_idx
        );

        let (packet, session) = self.handshake.receive_handshake_initialization(p, dst)?;

        // Store new session in ring buffer
        let index = session.local_index();
        self.sessions[index % N_SESSIONS] = Some(session);

        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick(TimerName::TimeLastPacketSent);
        self.timer_tick_session_established(false, index); // New session established, we are not the initiator

        tracing::debug!(message = "Sending handshake_response", local_idx = index);

        Ok(TunnResult::WriteToNetwork(packet))
    }

    /// Handle PQ handshake initiation (responder side)
    fn handle_handshake_init_pq<'a>(
        &mut self,
        p: hybrid_handshake::HandshakeInitPq,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        tracing::debug!(
            message = "Received PQ handshake_initiation",
            remote_idx = p.sender_idx
        );

        // First, process the classical part of the handshake
        let classic_init = HandshakeInit {
            sender_idx: p.sender_idx,
            unencrypted_ephemeral: p.unencrypted_ephemeral,
            encrypted_static: p.encrypted_static,
            encrypted_timestamp: p.encrypted_timestamp,
        };

        // Get classical response - copy to temp buffer to avoid borrow issues
        let mut temp_buf = [0u8; HANDSHAKE_RESP_SZ];
        let (classic_packet, mut session) = self
            .handshake
            .receive_handshake_initialization(classic_init, dst)?;
        temp_buf.copy_from_slice(classic_packet);

        // Now handle PQ part: encapsulate to initiator's ephemeral PQ public key
        let pq_responder =
            hybrid_integration::HybridResponderState::new(self.mode, p.pq_ephemeral_public)?;

        // Derive hybrid session keys
        // Note: For responder, we swap the keys - our sending key is initiator's receiving key
        let (initiator_send, initiator_recv) = hybrid_integration::derive_hybrid_session_keys(
            session.chaining_key(),
            Some(&pq_responder.pq_shared_secret),
        );

        // Update session with hybrid keys (swapped for responder)
        session.set_hybrid_keys(initiator_recv, initiator_send);

        // Format PQ response: classic response + ML-KEM ciphertext
        // Now we can safely use dst since classic_packet borrow is released
        let response_len = hybrid_handshake::format_handshake_response_pq(
            &temp_buf,
            &pq_responder.pq_ciphertext,
            dst,
        )
        .map_err(|_| WireGuardError::DestinationBufferTooSmall)?;

        // Store new session in ring buffer
        let index = session.local_index();
        self.sessions[index % N_SESSIONS] = Some(session);

        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick(TimerName::TimeLastPacketSent);
        self.timer_tick_session_established(false, index);

        tracing::info!(
            message = "Sending PQ handshake_response",
            local_idx = index,
            pq_mode = ?self.mode
        );

        Ok(TunnResult::WriteToNetwork(&mut dst[..response_len]))
    }

    fn handle_handshake_response<'a>(
        &mut self,
        p: HandshakeResponse,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        tracing::debug!(
            message = "Received handshake_response",
            local_idx = p.receiver_idx,
            remote_idx = p.sender_idx
        );

        let session = self.handshake.receive_handshake_response(p)?;

        let keepalive_packet = session.format_packet_data(&[], dst);
        // Store new session in ring buffer
        let l_idx = session.local_index();
        let index = l_idx % N_SESSIONS;
        self.sessions[index] = Some(session);

        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick_session_established(true, index); // New session established, we are the initiator
        self.set_current_session(l_idx);

        tracing::debug!("Sending keepalive");

        Ok(TunnResult::WriteToNetwork(keepalive_packet)) // Send a keepalive as a response
    }

    /// Handle PQ handshake response (initiator side)
    fn handle_handshake_response_pq<'a>(
        &mut self,
        p: hybrid_handshake::HandshakeResponsePq,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        tracing::debug!(
            message = "Received PQ handshake_response",
            local_idx = p.receiver_idx,
            remote_idx = p.sender_idx
        );

        // First, process the classical part
        let classic_resp = HandshakeResponse {
            sender_idx: p.sender_idx,
            receiver_idx: p.receiver_idx,
            unencrypted_ephemeral: p.unencrypted_ephemeral,
            encrypted_nothing: p.encrypted_nothing,
        };

        let mut session = self.handshake.receive_handshake_response(classic_resp)?;

        // Now handle PQ part: decapsulate using our ephemeral secret key
        let pq_shared_secret = if let Some(ref mut pq_state) = self.pq_initiator_state {
            pq_state.process_response(p.pq_ciphertext)?
        } else {
            return Err(WireGuardError::UnexpectedPacket);
        };

        // Derive hybrid session keys
        let (sending_key, receiving_key) = hybrid_integration::derive_hybrid_session_keys(
            session.chaining_key(),
            Some(&pq_shared_secret),
        );

        // Update session with hybrid keys
        session.set_hybrid_keys(sending_key, receiving_key);

        // Clear PQ initiator state
        self.pq_initiator_state = None;

        let keepalive_packet = session.format_packet_data(&[], dst);

        // Store new session in ring buffer
        let l_idx = session.local_index();
        let index = l_idx % N_SESSIONS;
        self.sessions[index] = Some(session);

        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick_session_established(true, index);
        self.set_current_session(l_idx);

        tracing::info!(
            message = "PQ handshake complete",
            local_idx = l_idx,
            pq_mode = ?self.mode
        );

        Ok(TunnResult::WriteToNetwork(keepalive_packet))
    }

    /// Handle PQ-only handshake initiation with ML-DSA auth (responder side)
    ///
    /// This is similar to handle_handshake_init_pq but additionally:
    /// 1. Verifies the initiator's ML-DSA signature over the handshake transcript
    /// 2. Includes our ML-DSA signature in the response
    fn handle_handshake_init_pq_auth<'a>(
        &mut self,
        p: hybrid_handshake::HandshakeInitPqAuth,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        tracing::debug!(
            message = "Received PQ-auth handshake_initiation",
            remote_idx = p.sender_idx
        );

        // Check if we have ML-DSA keys configured for verification
        if !self.is_pq_auth_ready() {
            tracing::warn!(
                "Received PQ-auth init but ML-DSA keys not configured - falling back to hybrid"
            );
            // Fall back to treating it like a regular PQ init (without auth verification)
            let pq_init = hybrid_handshake::HandshakeInitPq {
                sender_idx: p.sender_idx,
                unencrypted_ephemeral: p.unencrypted_ephemeral,
                encrypted_static: p.encrypted_static,
                encrypted_timestamp: p.encrypted_timestamp,
                pq_ephemeral_public: p.pq_ephemeral_public,
            };
            return self.handle_handshake_init_pq(pq_init, dst);
        }

        // Step 1: Build the transcript that was signed by the initiator
        // The initiator signed: classic_init (148 bytes, with type=1 and actual MACs) + pq_ephemeral_pk
        //
        // IMPORTANT: The initiator signs dst[..148] which includes:
        // - type (4 bytes) = 1 (HANDSHAKE_INIT)
        // - sender_idx (4 bytes)
        // - unencrypted_ephemeral (32 bytes)
        // - encrypted_static (48 bytes)
        // - encrypted_timestamp (28 bytes)
        // - mac1 (16 bytes) - actual computed MACs
        // - mac2 (16 bytes) - actual computed MACs (or zeros)
        //
        // We need to reconstruct the exact same transcript.
        // The HandshakeInitPqAuth parser doesn't give us bytes 116-148 (the MACs),
        // but we can access them through the raw packet. However, since parsing
        // already happened, we need to reconstruct with the data we have.
        //
        // Actually, looking at HandshakeInitPqAuth::parse(), it skips MACs at bytes 116-148.
        // The initiator signs with actual MACs, so we need to include zeros here
        // and hope that's what they used... NO - that won't work!
        //
        // The fix is that HandshakeInitPqAuth needs to also capture the MAC bytes,
        // OR the initiator needs to sign without MACs (zeros).
        //
        // For now, let's assume the initiator signs with zeros for MACs
        // (we'll need to update format_handshake_initiation to match)
        let mut init_transcript = Vec::with_capacity(148 + MLKEM_PUBLIC_KEY_SIZE);
        init_transcript.extend_from_slice(&(1u32).to_le_bytes()); // Original type was 1 before changing to 7
        init_transcript.extend_from_slice(&p.sender_idx.to_le_bytes());
        init_transcript.extend_from_slice(p.unencrypted_ephemeral);
        init_transcript.extend_from_slice(p.encrypted_static);
        init_transcript.extend_from_slice(p.encrypted_timestamp);
        init_transcript.extend_from_slice(&[0u8; 32]); // MAC1 + MAC2 - both sides use zeros
        init_transcript.extend_from_slice(p.pq_ephemeral_public);

        // Step 2: Verify the initiator's ML-DSA signature
        let peer_mldsa_pk = self.peer_mldsa_public_key.as_ref().unwrap();
        let signature =
            dybervpn_protocol::MlDsaSignature::from_bytes(p.mldsa_signature).map_err(|_| {
                tracing::error!("Invalid ML-DSA signature format in PQ-auth init");
                WireGuardError::InvalidPacket
            })?;

        let valid = hybrid_handshake::mldsa_verify(peer_mldsa_pk, &init_transcript, &signature)
            .map_err(|e| {
                tracing::error!("ML-DSA verification failed: {}", e);
                WireGuardError::InvalidPacket
            })?;

        if !valid {
            tracing::error!("ML-DSA signature verification failed - rejecting PQ-auth init");
            return Err(WireGuardError::InvalidPacket);
        }

        tracing::info!("ML-DSA signature verified for PQ-auth init");

        // Step 3: Process the classical part of the handshake
        let classic_init = HandshakeInit {
            sender_idx: p.sender_idx,
            unencrypted_ephemeral: p.unencrypted_ephemeral,
            encrypted_static: p.encrypted_static,
            encrypted_timestamp: p.encrypted_timestamp,
        };

        let mut temp_buf = [0u8; HANDSHAKE_RESP_SZ];
        let (classic_packet, mut session) = self
            .handshake
            .receive_handshake_initialization(classic_init, dst)?;
        temp_buf.copy_from_slice(classic_packet);

        // Step 4: Handle PQ part - encapsulate to initiator's ephemeral PQ public key
        let pq_responder =
            hybrid_integration::HybridResponderState::new(self.mode, p.pq_ephemeral_public)?;

        // Derive hybrid session keys
        let (initiator_send, initiator_recv) = hybrid_integration::derive_hybrid_session_keys(
            session.chaining_key(),
            Some(&pq_responder.pq_shared_secret),
        );
        session.set_hybrid_keys(initiator_recv, initiator_send);

        // Step 5: Build response transcript and sign it
        // Response transcript = init_transcript + classic_response (with zeros for MACs) + pq_ciphertext
        // IMPORTANT: Use zeros for MAC bytes in response too, so initiator can reconstruct
        let mut response_transcript = init_transcript.clone();
        // Add classic response with zeros for MACs (bytes 60-92 in the 92-byte response)
        response_transcript.extend_from_slice(&temp_buf[..60]); // Everything before MACs
        response_transcript.extend_from_slice(&[0u8; 32]); // Zero MACs
        response_transcript.extend_from_slice(&pq_responder.pq_ciphertext);

        let our_signature = self
            .mldsa_keypair
            .as_ref()
            .unwrap()
            .sign(&response_transcript)
            .map_err(|e| {
                tracing::error!("Failed to sign PQ-auth response: {}", e);
                WireGuardError::InvalidPacket
            })?;

        // Step 6: Format PQ-auth response: classic response + ML-KEM ciphertext + ML-DSA signature
        let response_len = hybrid_handshake::format_handshake_response_pq_auth(
            &temp_buf,
            &pq_responder.pq_ciphertext,
            our_signature.as_bytes(),
            dst,
        )
        .map_err(|_| WireGuardError::DestinationBufferTooSmall)?;

        // Store new session
        let index = session.local_index();
        self.sessions[index % N_SESSIONS] = Some(session);

        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick(TimerName::TimeLastPacketSent);
        self.timer_tick_session_established(false, index);

        tracing::info!(
            message = "Sending PQ-auth handshake_response",
            local_idx = index,
            pq_mode = ?self.mode,
            with_mldsa_signature = true
        );

        Ok(TunnResult::WriteToNetwork(&mut dst[..response_len]))
    }

    /// Handle PQ-only handshake response with ML-DSA auth (initiator side)
    ///
    /// This is similar to handle_handshake_response_pq but additionally:
    /// 1. Verifies the responder's ML-DSA signature over the handshake transcript
    fn handle_handshake_response_pq_auth<'a>(
        &mut self,
        p: hybrid_handshake::HandshakeResponsePqAuth,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        tracing::debug!(
            message = "Received PQ-auth handshake_response",
            local_idx = p.receiver_idx,
            remote_idx = p.sender_idx
        );

        // Check if we have ML-DSA keys configured for verification
        if !self.is_pq_auth_ready() {
            tracing::warn!(
                "Received PQ-auth response but ML-DSA keys not configured - falling back to hybrid"
            );
            let pq_resp = hybrid_handshake::HandshakeResponsePq {
                sender_idx: p.sender_idx,
                receiver_idx: p.receiver_idx,
                unencrypted_ephemeral: p.unencrypted_ephemeral,
                encrypted_nothing: p.encrypted_nothing,
                pq_ciphertext: p.pq_ciphertext,
            };
            return self.handle_handshake_response_pq(pq_resp, dst);
        }

        // We need access to our original init to build the transcript
        // The responder signed: init_transcript + classic_response + pq_ciphertext
        let pq_state = self
            .pq_initiator_state
            .as_ref()
            .ok_or(WireGuardError::UnexpectedPacket)?;

        // Get the init message we sent from handshake state
        let sent_init = self.handshake.get_sent_init().ok_or_else(|| {
            tracing::error!("No sent init message stored for PQ-auth transcript");
            WireGuardError::UnexpectedPacket
        })?;

        // Build init_transcript = classic_init (148 bytes, with zeros for MACs) + pq_ephemeral_pk
        // IMPORTANT: Both sides use zeros for MAC bytes (116-148) in the transcript
        let mut init_transcript = Vec::with_capacity(148 + MLKEM_PUBLIC_KEY_SIZE);
        // Copy first 116 bytes (everything before MACs)
        init_transcript.extend_from_slice(&sent_init[..116]);
        // Use zeros for MAC1 + MAC2 (32 bytes) - matching what we signed
        init_transcript.extend_from_slice(&[0u8; 32]);
        // Add PQ ephemeral public key
        init_transcript.extend_from_slice(&pq_state.pq_ephemeral_pk);

        // Build full response transcript
        // response_transcript = init_transcript + classic_response (60 bytes before MACs + 32 zero MACs) + pq_ciphertext
        // IMPORTANT: Both sides use zeros for MAC bytes in the transcript
        let mut response_transcript = init_transcript;
        // Add classic response with zeros for MACs:
        // type(4) + sender_idx(4) + receiver_idx(4) + ephemeral(32) + encrypted_nothing(16) = 60 bytes
        response_transcript.extend_from_slice(&(2u32).to_le_bytes()); // Response type
        response_transcript.extend_from_slice(&p.sender_idx.to_le_bytes());
        response_transcript.extend_from_slice(&p.receiver_idx.to_le_bytes());
        response_transcript.extend_from_slice(p.unencrypted_ephemeral);
        response_transcript.extend_from_slice(p.encrypted_nothing);
        response_transcript.extend_from_slice(&[0u8; 32]); // MAC1 + MAC2 - zeros for transcript matching
        response_transcript.extend_from_slice(p.pq_ciphertext);

        // Verify responder's signature
        let peer_mldsa_pk = self.peer_mldsa_public_key.as_ref().unwrap();
        let signature =
            dybervpn_protocol::MlDsaSignature::from_bytes(p.mldsa_signature).map_err(|_| {
                tracing::error!("Invalid ML-DSA signature format in PQ-auth response");
                WireGuardError::InvalidPacket
            })?;

        let valid = hybrid_handshake::mldsa_verify(peer_mldsa_pk, &response_transcript, &signature)
            .map_err(|e| {
                tracing::error!("ML-DSA verification failed: {}", e);
                WireGuardError::InvalidPacket
            })?;

        if !valid {
            tracing::error!("ML-DSA signature verification failed - rejecting PQ-auth response");
            return Err(WireGuardError::InvalidPacket);
        }

        tracing::info!("ML-DSA signature verified for PQ-auth response");

        // Process the classical part
        let classic_resp = HandshakeResponse {
            sender_idx: p.sender_idx,
            receiver_idx: p.receiver_idx,
            unencrypted_ephemeral: p.unencrypted_ephemeral,
            encrypted_nothing: p.encrypted_nothing,
        };

        let mut session = self.handshake.receive_handshake_response(classic_resp)?;

        // Handle PQ part: decapsulate using our ephemeral secret key
        let pq_shared_secret = if let Some(ref mut pq_state) = self.pq_initiator_state {
            pq_state.process_response(p.pq_ciphertext)?
        } else {
            return Err(WireGuardError::UnexpectedPacket);
        };

        // Derive hybrid session keys
        let (sending_key, receiving_key) = hybrid_integration::derive_hybrid_session_keys(
            session.chaining_key(),
            Some(&pq_shared_secret),
        );
        session.set_hybrid_keys(sending_key, receiving_key);

        // Clear PQ initiator state
        self.pq_initiator_state = None;

        let keepalive_packet = session.format_packet_data(&[], dst);

        // Store new session
        let l_idx = session.local_index();
        let index = l_idx % N_SESSIONS;
        self.sessions[index] = Some(session);

        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick_session_established(true, index);
        self.set_current_session(l_idx);

        tracing::info!(
            message = "PQ-auth handshake complete",
            local_idx = l_idx,
            pq_mode = ?self.mode,
            mldsa_verified = true
        );

        Ok(TunnResult::WriteToNetwork(keepalive_packet))
    }

    fn handle_cookie_reply<'a>(
        &mut self,
        p: PacketCookieReply,
    ) -> Result<TunnResult<'a>, WireGuardError> {
        tracing::debug!(
            message = "Received cookie_reply",
            local_idx = p.receiver_idx
        );

        self.handshake.receive_cookie_reply(p)?;
        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick(TimerName::TimeCookieReceived);

        tracing::debug!("Did set cookie");

        Ok(TunnResult::Done)
    }

    /// Update the index of the currently used session, if needed
    fn set_current_session(&mut self, new_idx: usize) {
        let cur_idx = self.current;
        if cur_idx == new_idx {
            // There is nothing to do, already using this session, this is the common case
            return;
        }
        if self.sessions[cur_idx % N_SESSIONS].is_none()
            || self.timers.session_timers[new_idx % N_SESSIONS]
                >= self.timers.session_timers[cur_idx % N_SESSIONS]
        {
            self.current = new_idx;
            tracing::debug!(message = "New session", session = new_idx);
        }
    }

    /// Decrypts a data packet, and stores the decapsulated packet in dst.
    fn handle_data<'a>(
        &mut self,
        packet: PacketData,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        let r_idx = packet.receiver_idx as usize;
        let idx = r_idx % N_SESSIONS;

        // Get the (probably) right session
        let decapsulated_packet = {
            let session = self.sessions[idx].as_ref();
            let session = session.ok_or_else(|| {
                tracing::trace!(message = "No current session available", remote_idx = r_idx);
                WireGuardError::NoCurrentSession
            })?;
            session.receive_packet_data(packet, dst)?
        };

        self.set_current_session(r_idx);

        self.timer_tick(TimerName::TimeLastPacketReceived);

        Ok(self.validate_decapsulated_packet(decapsulated_packet))
    }

    /// Formats a new handshake initiation message and store it in dst. If force_resend is true will send
    /// a new handshake, even if a handshake is already in progress (for example when a handshake times out)
    pub fn format_handshake_initiation<'a>(
        &mut self,
        dst: &'a mut [u8],
        force_resend: bool,
    ) -> TunnResult<'a> {
        if self.handshake.is_in_progress() && !force_resend {
            return TunnResult::Done;
        }

        if self.handshake.is_expired() {
            self.timers.clear();
        }

        let starting_new_handshake = !self.handshake.is_in_progress();

        // For hybrid/pq-only mode, generate PQ ephemeral keypair
        if self.is_hybrid() {
            match hybrid_integration::HybridInitiatorState::new(self.mode) {
                Ok(pq_state) => {
                    self.pq_initiator_state = Some(pq_state);
                }
                Err(e) => {
                    tracing::error!("Failed to generate PQ ephemeral key: {:?}", e);
                    return TunnResult::Err(e);
                }
            }
        }

        match self.handshake.format_handshake_initiation(dst) {
            Ok(classic_packet) => {
                // Get the length of classic packet before any borrowing issues
                let classic_len = classic_packet.len();

                // If hybrid/pq-only mode, append PQ public key (and signature for pq-only)
                let final_len = if self.is_hybrid() {
                    if let Some(ref pq_state) = self.pq_initiator_state {
                        let pq_pk_bytes = &pq_state.pq_ephemeral_pk;

                        // Check if we're in PQ-only mode with ML-DSA keys configured
                        if self.is_pq_auth_ready() {
                            // PQ-only mode: include ML-DSA signature
                            // Build transcript: classic init (148 bytes, with zeros for MACs) + PQ public key
                            //
                            // IMPORTANT: We sign with zeros for MAC bytes (116-148) so both sides can
                            // reconstruct the same transcript. The responder doesn't have access to
                            // our computed MACs, so both sides agree to use zeros in the transcript.
                            let mut transcript =
                                Vec::with_capacity(classic_len + pq_pk_bytes.len());
                            // Copy first 116 bytes (everything before MACs)
                            transcript.extend_from_slice(&dst[..116]);
                            // Use zeros for MAC1 + MAC2 (32 bytes)
                            transcript.extend_from_slice(&[0u8; 32]);
                            // Add PQ public key
                            transcript.extend_from_slice(pq_pk_bytes);

                            // Sign the transcript
                            let signature =
                                match self.mldsa_keypair.as_ref().unwrap().sign(&transcript) {
                                    Ok(sig) => sig,
                                    Err(e) => {
                                        tracing::error!("Failed to sign handshake init: {}", e);
                                        return TunnResult::Err(WireGuardError::InvalidPacket);
                                    }
                                };

                            // Format PQ-auth init: classic + PQ public key + ML-DSA signature
                            dst[0..4].copy_from_slice(&HANDSHAKE_INIT_PQ_AUTH.to_le_bytes());
                            dst[classic_len..classic_len + pq_pk_bytes.len()]
                                .copy_from_slice(pq_pk_bytes);
                            let sig_start = classic_len + pq_pk_bytes.len();
                            dst[sig_start..sig_start + MLDSA_SIGNATURE_SIZE]
                                .copy_from_slice(signature.as_bytes());

                            let total_len = HANDSHAKE_INIT_PQ_AUTH_SZ;
                            tracing::info!(
                                message = "Sending PQ-auth handshake_initiation",
                                pq_mode = ?self.mode,
                                with_mldsa_signature = true
                            );
                            total_len
                        } else {
                            // Hybrid mode (or pq-only without keys): no ML-DSA signature
                            dst[0..4].copy_from_slice(&HANDSHAKE_INIT_PQ.to_le_bytes());
                            dst[classic_len..classic_len + pq_pk_bytes.len()]
                                .copy_from_slice(pq_pk_bytes);

                            let total_len = classic_len + pq_pk_bytes.len();
                            tracing::info!(
                                message = "Sending PQ handshake_initiation",
                                pq_mode = ?self.mode
                            );
                            total_len
                        }
                    } else {
                        classic_len
                    }
                } else {
                    tracing::debug!("Sending handshake_initiation");
                    classic_len
                };

                if starting_new_handshake {
                    self.timer_tick(TimerName::TimeLastHandshakeStarted);
                }
                self.timer_tick(TimerName::TimeLastPacketSent);
                TunnResult::WriteToNetwork(&mut dst[..final_len])
            }
            Err(e) => TunnResult::Err(e),
        }
    }

    /// Check if an IP packet is v4 or v6, truncate to the length indicated by the length field
    /// Returns the truncated packet and the source IP as TunnResult
    fn validate_decapsulated_packet<'a>(&mut self, packet: &'a mut [u8]) -> TunnResult<'a> {
        let (computed_len, src_ip_address) = match packet.len() {
            0 => return TunnResult::Done, // This is keepalive, and not an error
            _ if packet[0] >> 4 == 4 && packet.len() >= IPV4_MIN_HEADER_SIZE => {
                let len_bytes: [u8; IP_LEN_SZ] = packet[IPV4_LEN_OFF..IPV4_LEN_OFF + IP_LEN_SZ]
                    .try_into()
                    .unwrap();
                let addr_bytes: [u8; IPV4_IP_SZ] = packet
                    [IPV4_SRC_IP_OFF..IPV4_SRC_IP_OFF + IPV4_IP_SZ]
                    .try_into()
                    .unwrap();
                (
                    u16::from_be_bytes(len_bytes) as usize,
                    IpAddr::from(addr_bytes),
                )
            }
            _ if packet[0] >> 4 == 6 && packet.len() >= IPV6_MIN_HEADER_SIZE => {
                let len_bytes: [u8; IP_LEN_SZ] = packet[IPV6_LEN_OFF..IPV6_LEN_OFF + IP_LEN_SZ]
                    .try_into()
                    .unwrap();
                let addr_bytes: [u8; IPV6_IP_SZ] = packet
                    [IPV6_SRC_IP_OFF..IPV6_SRC_IP_OFF + IPV6_IP_SZ]
                    .try_into()
                    .unwrap();
                (
                    u16::from_be_bytes(len_bytes) as usize + IPV6_MIN_HEADER_SIZE,
                    IpAddr::from(addr_bytes),
                )
            }
            _ => return TunnResult::Err(WireGuardError::InvalidPacket),
        };

        if computed_len > packet.len() {
            return TunnResult::Err(WireGuardError::InvalidPacket);
        }

        self.timer_tick(TimerName::TimeLastDataPacketReceived);
        self.rx_bytes += computed_len;

        match src_ip_address {
            IpAddr::V4(addr) => TunnResult::WriteToTunnelV4(&mut packet[..computed_len], addr),
            IpAddr::V6(addr) => TunnResult::WriteToTunnelV6(&mut packet[..computed_len], addr),
        }
    }

    /// Get a packet from the queue, and try to encapsulate it
    fn send_queued_packet<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        if let Some(packet) = self.dequeue_packet() {
            match self.encapsulate(&packet, dst) {
                TunnResult::Err(_) => {
                    // On error, return packet to the queue
                    self.requeue_packet(packet);
                }
                r => return r,
            }
        }
        TunnResult::Done
    }

    /// Push packet to the back of the queue
    fn queue_packet(&mut self, packet: &[u8]) {
        if self.packet_queue.len() < MAX_QUEUE_DEPTH {
            // Drop if too many are already in queue
            self.packet_queue.push_back(packet.to_vec());
        }
    }

    /// Push packet to the front of the queue
    fn requeue_packet(&mut self, packet: Vec<u8>) {
        if self.packet_queue.len() < MAX_QUEUE_DEPTH {
            // Drop if too many are already in queue
            self.packet_queue.push_front(packet);
        }
    }

    fn dequeue_packet(&mut self) -> Option<Vec<u8>> {
        self.packet_queue.pop_front()
    }

    fn estimate_loss(&self) -> f32 {
        let session_idx = self.current;

        let mut weight = 9.0;
        let mut cur_avg = 0.0;
        let mut total_weight = 0.0;

        for i in 0..N_SESSIONS {
            if let Some(ref session) = self.sessions[(session_idx.wrapping_sub(i)) % N_SESSIONS] {
                let (expected, received) = session.current_packet_cnt();

                let loss = if expected == 0 {
                    0.0
                } else {
                    1.0 - received as f32 / expected as f32
                };

                cur_avg += loss * weight;
                total_weight += weight;
                weight /= 3.0;
            }
        }

        if total_weight == 0.0 {
            0.0
        } else {
            cur_avg / total_weight
        }
    }

    /// Return stats from the tunnel:
    /// * Time since last handshake in seconds
    /// * Data bytes sent
    /// * Data bytes received
    pub fn stats(&self) -> (Option<Duration>, usize, usize, f32, Option<u32>) {
        let time = self.time_since_last_handshake();
        let tx_bytes = self.tx_bytes;
        let rx_bytes = self.rx_bytes;
        let loss = self.estimate_loss();
        let rtt = self.handshake.last_rtt;

        (time, tx_bytes, rx_bytes, loss, rtt)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "mock-instant")]
    use crate::noise::timers::{REKEY_AFTER_TIME, REKEY_TIMEOUT};

    use super::*;
    use rand_core::{OsRng, RngCore};

    fn create_two_tuns() -> (Tunn, Tunn) {
        let my_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let my_public_key = x25519_dalek::PublicKey::from(&my_secret_key);
        let my_idx = OsRng.next_u32();

        let their_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let their_public_key = x25519_dalek::PublicKey::from(&their_secret_key);
        let their_idx = OsRng.next_u32();

        let my_tun = Tunn::new(my_secret_key, their_public_key, None, None, my_idx, None);

        let their_tun = Tunn::new(their_secret_key, my_public_key, None, None, their_idx, None);

        (my_tun, their_tun)
    }

    fn create_two_hybrid_tuns() -> (Tunn, Tunn) {
        let my_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let my_public_key = x25519_dalek::PublicKey::from(&my_secret_key);
        let my_idx = OsRng.next_u32();

        let their_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let their_public_key = x25519_dalek::PublicKey::from(&their_secret_key);
        let their_idx = OsRng.next_u32();

        let my_hybrid_state = HybridHandshakeState::new(OperatingMode::Hybrid);
        let their_hybrid_state = HybridHandshakeState::new(OperatingMode::Hybrid);

        let my_tun = Tunn::new_hybrid(
            my_secret_key,
            their_public_key,
            None,
            None,
            my_idx,
            None,
            my_hybrid_state,
        );

        let their_tun = Tunn::new_hybrid(
            their_secret_key,
            my_public_key,
            None,
            None,
            their_idx,
            None,
            their_hybrid_state,
        );

        (my_tun, their_tun)
    }

    fn create_handshake_init(tun: &mut Tunn) -> Vec<u8> {
        let mut dst = vec![0u8; 2048];
        let handshake_init = tun.format_handshake_initiation(&mut dst, false);
        assert!(matches!(handshake_init, TunnResult::WriteToNetwork(_)));
        let handshake_init = if let TunnResult::WriteToNetwork(sent) = handshake_init {
            sent
        } else {
            unreachable!();
        };

        handshake_init.into()
    }

    fn create_handshake_response(tun: &mut Tunn, handshake_init: &[u8]) -> Vec<u8> {
        let mut dst = vec![0u8; 2048];
        let handshake_resp = tun.decapsulate(None, handshake_init, &mut dst);
        assert!(matches!(handshake_resp, TunnResult::WriteToNetwork(_)));

        let handshake_resp = if let TunnResult::WriteToNetwork(sent) = handshake_resp {
            sent
        } else {
            unreachable!();
        };

        handshake_resp.into()
    }

    fn parse_handshake_resp(tun: &mut Tunn, handshake_resp: &[u8]) -> Vec<u8> {
        let mut dst = vec![0u8; 2048];
        let keepalive = tun.decapsulate(None, handshake_resp, &mut dst);
        assert!(matches!(keepalive, TunnResult::WriteToNetwork(_)));

        let keepalive = if let TunnResult::WriteToNetwork(sent) = keepalive {
            sent
        } else {
            unreachable!();
        };

        keepalive.into()
    }

    fn parse_keepalive(tun: &mut Tunn, keepalive: &[u8]) {
        let mut dst = vec![0u8; 2048];
        let keepalive = tun.decapsulate(None, keepalive, &mut dst);
        assert!(matches!(keepalive, TunnResult::Done));
    }

    fn create_two_tuns_and_handshake() -> (Tunn, Tunn) {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, &init);
        let keepalive = parse_handshake_resp(&mut my_tun, &resp);
        parse_keepalive(&mut their_tun, &keepalive);

        (my_tun, their_tun)
    }

    fn create_ipv4_udp_packet() -> Vec<u8> {
        let header =
            etherparse::PacketBuilder::ipv4([192, 168, 1, 2], [192, 168, 1, 3], 5).udp(5678, 23);
        let payload = [0, 1, 2, 3];
        let mut packet = Vec::<u8>::with_capacity(header.size(payload.len()));
        header.write(&mut packet, &payload).unwrap();
        packet
    }

    #[cfg(feature = "mock-instant")]
    fn update_timer_results_in_handshake(tun: &mut Tunn) {
        let mut dst = vec![0u8; 2048];
        let result = tun.update_timers(&mut dst);
        assert!(matches!(result, TunnResult::WriteToNetwork(_)));
        let packet_data = if let TunnResult::WriteToNetwork(data) = result {
            data
        } else {
            unreachable!();
        };
        let packet = Tunn::parse_incoming_packet(packet_data).unwrap();
        assert!(matches!(packet, Packet::HandshakeInit(_)));
    }

    #[test]
    fn create_two_tunnels_linked_to_eachother() {
        let (_my_tun, _their_tun) = create_two_tuns();
    }

    #[test]
    fn handshake_init() {
        let (mut my_tun, _their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let packet = Tunn::parse_incoming_packet(&init).unwrap();
        assert!(matches!(packet, Packet::HandshakeInit(_)));
    }

    #[test]
    fn handshake_init_and_response() {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, &init);
        let packet = Tunn::parse_incoming_packet(&resp).unwrap();
        assert!(matches!(packet, Packet::HandshakeResponse(_)));
    }

    #[test]
    fn full_handshake() {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, &init);
        let keepalive = parse_handshake_resp(&mut my_tun, &resp);
        let packet = Tunn::parse_incoming_packet(&keepalive).unwrap();
        assert!(matches!(packet, Packet::PacketData(_)));
    }

    #[test]
    fn full_handshake_plus_timers() {
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
        // Time has not yet advanced so their is nothing to do
        assert!(matches!(my_tun.update_timers(&mut []), TunnResult::Done));
        assert!(matches!(their_tun.update_timers(&mut []), TunnResult::Done));
    }

    #[test]
    #[cfg(feature = "mock-instant")]
    fn new_handshake_after_two_mins() {
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
        let mut my_dst = [0u8; 1024];

        // Advance time 1 second and "send" 1 packet so that we send a handshake
        // after the timeout
        mock_instant::MockClock::advance(Duration::from_secs(1));
        assert!(matches!(their_tun.update_timers(&mut []), TunnResult::Done));
        assert!(matches!(
            my_tun.update_timers(&mut my_dst),
            TunnResult::Done
        ));
        let sent_packet_buf = create_ipv4_udp_packet();
        let data = my_tun.encapsulate(&sent_packet_buf, &mut my_dst);
        assert!(matches!(data, TunnResult::WriteToNetwork(_)));

        //Advance to timeout
        mock_instant::MockClock::advance(REKEY_AFTER_TIME);
        assert!(matches!(their_tun.update_timers(&mut []), TunnResult::Done));
        update_timer_results_in_handshake(&mut my_tun);
    }

    #[test]
    #[cfg(feature = "mock-instant")]
    fn handshake_no_resp_rekey_timeout() {
        let (mut my_tun, _their_tun) = create_two_tuns();

        let init = create_handshake_init(&mut my_tun);
        let packet = Tunn::parse_incoming_packet(&init).unwrap();
        assert!(matches!(packet, Packet::HandshakeInit(_)));

        mock_instant::MockClock::advance(REKEY_TIMEOUT);
        update_timer_results_in_handshake(&mut my_tun)
    }

    #[test]
    fn one_ip_packet() {
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
        let mut my_dst = [0u8; 1024];
        let mut their_dst = [0u8; 1024];

        let sent_packet_buf = create_ipv4_udp_packet();

        let data = my_tun.encapsulate(&sent_packet_buf, &mut my_dst);
        assert!(matches!(data, TunnResult::WriteToNetwork(_)));
        let data = if let TunnResult::WriteToNetwork(sent) = data {
            sent
        } else {
            unreachable!();
        };

        let data = their_tun.decapsulate(None, data, &mut their_dst);
        assert!(matches!(data, TunnResult::WriteToTunnelV4(..)));
        let recv_packet_buf = if let TunnResult::WriteToTunnelV4(recv, _addr) = data {
            recv
        } else {
            unreachable!();
        };
        assert_eq!(sent_packet_buf, recv_packet_buf);
    }

    // PQ Hybrid tests
    #[test]
    fn hybrid_tunnel_creation() {
        let (my_tun, their_tun) = create_two_hybrid_tuns();
        assert!(my_tun.is_hybrid());
        assert!(their_tun.is_hybrid());
        assert_eq!(my_tun.mode(), OperatingMode::Hybrid);
        assert_eq!(their_tun.mode(), OperatingMode::Hybrid);
    }

    #[test]
    fn hybrid_handshake_init() {
        let (mut my_tun, _their_tun) = create_two_hybrid_tuns();
        let init = create_handshake_init(&mut my_tun);

        // Should be a PQ init (larger than classic)
        assert_eq!(init.len(), HANDSHAKE_INIT_PQ_SZ);

        let packet = Tunn::parse_incoming_packet(&init).unwrap();
        assert!(matches!(packet, Packet::HandshakeInitPq(_)));
    }

    #[test]
    fn hybrid_full_handshake() {
        let (mut my_tun, mut their_tun) = create_two_hybrid_tuns();

        // Initiator sends PQ handshake init
        let init = create_handshake_init(&mut my_tun);
        assert_eq!(init.len(), HANDSHAKE_INIT_PQ_SZ);

        // Responder processes and returns PQ response
        let resp = create_handshake_response(&mut their_tun, &init);
        assert_eq!(resp.len(), HANDSHAKE_RESP_PQ_SZ);

        // Initiator processes response and sends keepalive
        let keepalive = parse_handshake_resp(&mut my_tun, &resp);

        // Responder receives keepalive
        parse_keepalive(&mut their_tun, &keepalive);
    }

    #[test]
    fn hybrid_one_ip_packet() {
        let (mut my_tun, mut their_tun) = create_two_hybrid_tuns();

        // Complete handshake
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, &init);
        let keepalive = parse_handshake_resp(&mut my_tun, &resp);
        parse_keepalive(&mut their_tun, &keepalive);

        // Now send data
        let mut my_dst = [0u8; 1024];
        let mut their_dst = [0u8; 1024];
        let sent_packet_buf = create_ipv4_udp_packet();

        let data = my_tun.encapsulate(&sent_packet_buf, &mut my_dst);
        assert!(matches!(data, TunnResult::WriteToNetwork(_)));
        let data = if let TunnResult::WriteToNetwork(sent) = data {
            sent
        } else {
            unreachable!();
        };

        let data = their_tun.decapsulate(None, data, &mut their_dst);
        assert!(matches!(data, TunnResult::WriteToTunnelV4(..)));
        let recv_packet_buf = if let TunnResult::WriteToTunnelV4(recv, _addr) = data {
            recv
        } else {
            unreachable!();
        };
        assert_eq!(sent_packet_buf, recv_packet_buf);
    }

    // PQ-Only mode tests (ML-KEM + ML-DSA authentication)

    // Buffer size large enough for PQ-auth messages (init: 4641 bytes, resp: 4489 bytes)
    const PQONLY_BUF_SIZE: usize = 8192;

    /// Helper for PQ-only handshake init (uses larger buffer)
    fn create_pqonly_handshake_init(tun: &mut Tunn) -> Vec<u8> {
        let mut dst = vec![0u8; PQONLY_BUF_SIZE];
        let handshake_init = tun.format_handshake_initiation(&mut dst, false);
        assert!(matches!(handshake_init, TunnResult::WriteToNetwork(_)));
        let handshake_init = if let TunnResult::WriteToNetwork(sent) = handshake_init {
            sent
        } else {
            unreachable!();
        };
        handshake_init.into()
    }

    /// Helper for PQ-only handshake response (uses larger buffer)
    fn create_pqonly_handshake_response(tun: &mut Tunn, handshake_init: &[u8]) -> Vec<u8> {
        let mut dst = vec![0u8; PQONLY_BUF_SIZE];
        let handshake_resp = tun.decapsulate(None, handshake_init, &mut dst);
        assert!(matches!(handshake_resp, TunnResult::WriteToNetwork(_)));
        let handshake_resp = if let TunnResult::WriteToNetwork(sent) = handshake_resp {
            sent
        } else {
            unreachable!();
        };
        handshake_resp.into()
    }

    /// Helper for parsing PQ-only handshake response (uses larger buffer)
    fn parse_pqonly_handshake_resp(tun: &mut Tunn, handshake_resp: &[u8]) -> Vec<u8> {
        let mut dst = vec![0u8; PQONLY_BUF_SIZE];
        let keepalive = tun.decapsulate(None, handshake_resp, &mut dst);
        assert!(matches!(keepalive, TunnResult::WriteToNetwork(_)));
        let keepalive = if let TunnResult::WriteToNetwork(sent) = keepalive {
            sent
        } else {
            unreachable!();
        };
        keepalive.into()
    }

    /// Helper for parsing keepalive in PQ-only mode (uses larger buffer)
    fn parse_pqonly_keepalive(tun: &mut Tunn, keepalive: &[u8]) {
        let mut dst = vec![0u8; PQONLY_BUF_SIZE];
        let keepalive = tun.decapsulate(None, keepalive, &mut dst);
        assert!(matches!(keepalive, TunnResult::Done));
    }

    /// Create two tunnels configured for PQ-only mode with ML-DSA authentication
    fn create_two_pqonly_tuns() -> (Tunn, Tunn) {
        let my_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let my_public_key = x25519_dalek::PublicKey::from(&my_secret_key);
        let my_idx = OsRng.next_u32();

        let their_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let their_public_key = x25519_dalek::PublicKey::from(&their_secret_key);
        let their_idx = OsRng.next_u32();

        // Generate ML-DSA keypairs for both parties
        let my_mldsa_keypair = MlDsaKeyPair::generate().expect("Failed to generate ML-DSA keypair");
        let their_mldsa_keypair =
            MlDsaKeyPair::generate().expect("Failed to generate ML-DSA keypair");

        // Extract public keys for peer verification
        let my_mldsa_public = my_mldsa_keypair.public_key().clone();
        let their_mldsa_public = their_mldsa_keypair.public_key().clone();

        // Create PQ-only handshake states with ML-DSA keys
        let mut my_hybrid_state = HybridHandshakeState::new(OperatingMode::PqOnly);
        my_hybrid_state.mldsa_keypair = Some(my_mldsa_keypair);
        my_hybrid_state.peer_mldsa_public_key = Some(their_mldsa_public);

        let mut their_hybrid_state = HybridHandshakeState::new(OperatingMode::PqOnly);
        their_hybrid_state.mldsa_keypair = Some(their_mldsa_keypair);
        their_hybrid_state.peer_mldsa_public_key = Some(my_mldsa_public);

        let my_tun = Tunn::new_hybrid(
            my_secret_key,
            their_public_key,
            None,
            None,
            my_idx,
            None,
            my_hybrid_state,
        );

        let their_tun = Tunn::new_hybrid(
            their_secret_key,
            my_public_key,
            None,
            None,
            their_idx,
            None,
            their_hybrid_state,
        );

        (my_tun, their_tun)
    }

    #[test]
    fn pqonly_tunnel_creation() {
        let (my_tun, their_tun) = create_two_pqonly_tuns();
        assert!(my_tun.is_hybrid());
        assert!(their_tun.is_hybrid());
        assert_eq!(my_tun.mode(), OperatingMode::PqOnly);
        assert_eq!(their_tun.mode(), OperatingMode::PqOnly);
        // Verify ML-DSA auth is ready
        assert!(my_tun.is_pq_auth_ready());
        assert!(their_tun.is_pq_auth_ready());
    }

    #[test]
    fn pqonly_handshake_init() {
        let (mut my_tun, _their_tun) = create_two_pqonly_tuns();
        let init = create_pqonly_handshake_init(&mut my_tun);

        // Should be a PQ-auth init (includes ML-DSA signature)
        assert_eq!(init.len(), HANDSHAKE_INIT_PQ_AUTH_SZ);

        let packet = Tunn::parse_incoming_packet(&init).unwrap();
        assert!(matches!(packet, Packet::HandshakeInitPqAuth(_)));
    }

    #[test]
    fn pqonly_full_handshake() {
        let (mut my_tun, mut their_tun) = create_two_pqonly_tuns();

        // Initiator sends PQ-auth handshake init (with ML-DSA signature)
        let init = create_pqonly_handshake_init(&mut my_tun);
        assert_eq!(
            init.len(),
            HANDSHAKE_INIT_PQ_AUTH_SZ,
            "Init should include ML-DSA signature"
        );

        // Responder verifies signature and returns PQ-auth response
        let resp = create_pqonly_handshake_response(&mut their_tun, &init);
        assert_eq!(
            resp.len(),
            HANDSHAKE_RESP_PQ_AUTH_SZ,
            "Response should include ML-DSA signature"
        );

        // Initiator verifies responder's signature and completes handshake
        let keepalive = parse_pqonly_handshake_resp(&mut my_tun, &resp);

        // Responder receives keepalive - handshake complete
        parse_pqonly_keepalive(&mut their_tun, &keepalive);
    }

    #[test]
    fn pqonly_one_ip_packet() {
        let (mut my_tun, mut their_tun) = create_two_pqonly_tuns();

        // Complete PQ-auth handshake
        let init = create_pqonly_handshake_init(&mut my_tun);
        let resp = create_pqonly_handshake_response(&mut their_tun, &init);
        let keepalive = parse_pqonly_handshake_resp(&mut my_tun, &resp);
        parse_pqonly_keepalive(&mut their_tun, &keepalive);

        // Now send data over the PQ-authenticated tunnel
        let mut my_dst = [0u8; 1024];
        let mut their_dst = [0u8; 1024];
        let sent_packet_buf = create_ipv4_udp_packet();

        let data = my_tun.encapsulate(&sent_packet_buf, &mut my_dst);
        assert!(matches!(data, TunnResult::WriteToNetwork(_)));
        let data = if let TunnResult::WriteToNetwork(sent) = data {
            sent
        } else {
            unreachable!();
        };

        let data = their_tun.decapsulate(None, data, &mut their_dst);
        assert!(matches!(data, TunnResult::WriteToTunnelV4(..)));
        let recv_packet_buf = if let TunnResult::WriteToTunnelV4(recv, _addr) = data {
            recv
        } else {
            unreachable!();
        };
        assert_eq!(sent_packet_buf, recv_packet_buf);
    }

    #[test]
    fn pqonly_wrong_signature_rejected() {
        // Create two tunnels but give them mismatched ML-DSA keys
        let my_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let my_public_key = x25519_dalek::PublicKey::from(&my_secret_key);
        let my_idx = OsRng.next_u32();

        let their_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let their_public_key = x25519_dalek::PublicKey::from(&their_secret_key);
        let their_idx = OsRng.next_u32();

        // Generate ML-DSA keypairs
        let my_mldsa_keypair = MlDsaKeyPair::generate().expect("Failed to generate ML-DSA keypair");
        let their_mldsa_keypair =
            MlDsaKeyPair::generate().expect("Failed to generate ML-DSA keypair");

        // Generate a WRONG key for peer verification (attacker's key)
        let wrong_mldsa_keypair =
            MlDsaKeyPair::generate().expect("Failed to generate ML-DSA keypair");
        let wrong_mldsa_public = wrong_mldsa_keypair.public_key().clone();

        // My tunnel has correct keys
        let mut my_hybrid_state = HybridHandshakeState::new(OperatingMode::PqOnly);
        my_hybrid_state.mldsa_keypair = Some(my_mldsa_keypair);
        my_hybrid_state.peer_mldsa_public_key = Some(their_mldsa_keypair.public_key().clone());

        // Their tunnel has WRONG peer public key (won't match my signature)
        let mut their_hybrid_state = HybridHandshakeState::new(OperatingMode::PqOnly);
        their_hybrid_state.mldsa_keypair = Some(their_mldsa_keypair);
        their_hybrid_state.peer_mldsa_public_key = Some(wrong_mldsa_public); // WRONG!

        let mut my_tun = Tunn::new_hybrid(
            my_secret_key,
            their_public_key,
            None,
            None,
            my_idx,
            None,
            my_hybrid_state,
        );

        let mut their_tun = Tunn::new_hybrid(
            their_secret_key,
            my_public_key,
            None,
            None,
            their_idx,
            None,
            their_hybrid_state,
        );

        // Initiator sends PQ-auth handshake init
        let init = create_pqonly_handshake_init(&mut my_tun);
        assert_eq!(init.len(), HANDSHAKE_INIT_PQ_AUTH_SZ);

        // Responder should REJECT due to signature verification failure
        let mut dst = vec![0u8; PQONLY_BUF_SIZE];
        let result = their_tun.decapsulate(None, &init, &mut dst);

        // Should fail with InvalidPacket error
        assert!(
            matches!(result, TunnResult::Err(WireGuardError::InvalidPacket)),
            "Expected InvalidPacket error for wrong signature, got {:?}",
            result
        );
    }
}
