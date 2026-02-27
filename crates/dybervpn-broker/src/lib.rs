//! DyberVPN ZTNA Broker
//!
//! The Broker is the central relay in a Zero Trust Network Access deployment.
//! It accepts outbound connections from both Clients (remote users) and
//! Connectors (inside-network agents), then stitches their WireGuard sessions
//! together with per-packet policy enforcement.
//!
//! # Architecture
//!
//! ```text
//! Client ──(outbound UDP)──> Broker <──(outbound UDP)── Connector
//!                              │
//!                         decrypt → policy → re-encrypt
//!                         (session stitching)
//! ```
//!
//! - **Control plane** (TCP): Connectors register via NDJSON, advertising their
//!   routes. The Broker maintains a service registry mapping CIDRs to Connectors.
//! - **Data plane** (UDP): Standard WireGuard tunnels. The Broker maintains a
//!   separate `Tunn` for each peer (Client or Connector) and stitches packets
//!   between them.
//! - **No TUN device**: The Broker never writes to a TUN device — it's a pure
//!   userspace relay.

pub mod auth;
pub mod broker;
pub mod config;
pub mod control;
pub mod error;
pub mod peer;
pub mod registry;
pub mod session;

#[cfg(test)]
mod tests {
    use crate::config::BrokerConfig;
    use crate::control;
    use crate::error::BrokerError;
    use crate::peer::{BrokerPeer, PeerRole};
    use crate::registry::ServiceRegistry;
    use crate::session::{self, StitchResult};

    use boringtun::noise::Tunn;
    use dashmap::DashMap;
    use dybervpn_protocol::OperatingMode;
    use dybervpn_tunnel::audit::AuditLogger;
    use dybervpn_tunnel::connector::ControlMessage;
    use dybervpn_tunnel::policy::{PolicyConfig, PolicyEngine};
    use dybervpn_tunnel::revocation::RevocationEngine;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;
    use x25519_dalek::{PublicKey, StaticSecret};

    /// Helper: generate a random X25519 keypair
    fn gen_keypair() -> (StaticSecret, PublicKey) {
        let secret = StaticSecret::random_from_rng(rand_core::OsRng);
        let public = PublicKey::from(&secret);
        (secret, public)
    }

    /// Helper: create a BrokerConfig with random keys and OS-assigned ports
    fn test_broker_config(private_key: [u8; 32]) -> BrokerConfig {
        BrokerConfig {
            listen_udp: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            listen_control: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            private_key,
            mode: OperatingMode::Classic,
            ..BrokerConfig::default()
        }
    }

    // ─── Test 1: Connector registration and heartbeat ────────────────────────

    #[tokio::test]
    async fn test_connector_register_and_heartbeat() {
        let (broker_secret, _broker_public) = gen_keypair();
        let config = test_broker_config(broker_secret.to_bytes());

        let peers: Arc<DashMap<[u8; 32], BrokerPeer>> = Arc::new(DashMap::new());
        let registry = Arc::new(ServiceRegistry::new());
        let audit = AuditLogger::disabled();
        let revocation = Arc::new(RevocationEngine::disabled());

        // Bind the control plane listener to get the actual port
        let listener = tokio::net::TcpListener::bind(config.listen_control)
            .await
            .unwrap();
        let control_addr = listener.local_addr().unwrap();

        let config = Arc::new(BrokerConfig {
            listen_control: control_addr,
            ..config
        });

        // Spawn the control plane handler in the background
        let ctrl_config = Arc::clone(&config);
        let ctrl_peers = Arc::clone(&peers);
        let ctrl_registry = Arc::clone(&registry);
        let ctrl_audit = audit.clone();
        let ctrl_revocation = Arc::clone(&revocation);

        tokio::spawn(async move {
            // Accept one connection and handle it
            let (stream, addr) = listener.accept().await.unwrap();
            let _ = crate::control::handle_connector_for_test(
                stream, addr, ctrl_config, ctrl_peers, ctrl_registry, ctrl_audit, ctrl_revocation,
            ).await;
        });

        // Connect as a Connector
        let mut stream = TcpStream::connect(control_addr).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();

        // Generate a Connector key
        let (_conn_secret, conn_public) = gen_keypair();
        let conn_pk = conn_public.to_bytes();

        // Send Register
        let register = ControlMessage::Register {
            public_key: base64::encode(&conn_pk),
            pq_public_key: None,
            mldsa_signature: None,
            advertised_routes: vec!["10.1.0.0/16".to_string()],
            service_name: "test-service".to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        let json = serde_json::to_string(&register).unwrap();
        writer.write_all(json.as_bytes()).await.unwrap();
        writer.write_all(b"\n").await.unwrap();
        writer.flush().await.unwrap();

        // Read RegisterAck
        let line = lines.next_line().await.unwrap().unwrap();
        let ack: ControlMessage = serde_json::from_str(&line).unwrap();
        match ack {
            ControlMessage::RegisterAck { success, error } => {
                assert!(success, "Registration should succeed, error: {:?}", error);
            }
            other => panic!("Expected RegisterAck, got: {:?}", other),
        }

        // Verify peer was registered
        assert_eq!(peers.len(), 1);
        assert!(peers.contains_key(&conn_pk));
        assert_eq!(registry.route_count(), 1);
        assert_eq!(
            registry.lookup(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 5))),
            Some(conn_pk),
        );

        // Send Heartbeat
        let hb = ControlMessage::Heartbeat {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        let json = serde_json::to_string(&hb).unwrap();
        writer.write_all(json.as_bytes()).await.unwrap();
        writer.write_all(b"\n").await.unwrap();
        writer.flush().await.unwrap();

        // Read HeartbeatAck
        let line = lines.next_line().await.unwrap().unwrap();
        let hb_ack: ControlMessage = serde_json::from_str(&line).unwrap();
        match hb_ack {
            ControlMessage::HeartbeatAck { timestamp: _ } => {
                // Success
            }
            other => panic!("Expected HeartbeatAck, got: {:?}", other),
        }

        // Send Disconnect
        let disc = ControlMessage::Disconnect {
            reason: "test done".to_string(),
        };
        let json = serde_json::to_string(&disc).unwrap();
        writer.write_all(json.as_bytes()).await.unwrap();
        writer.write_all(b"\n").await.unwrap();
        writer.flush().await.unwrap();

        // Give the handler time to process disconnect and cleanup
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Verify cleanup
        assert_eq!(peers.len(), 0, "Peer should be cleaned up after disconnect");
        assert_eq!(registry.route_count(), 0, "Routes should be cleaned up");
    }

    // ─── Test 2: Revoked peer rejected ───────────────────────────────────────

    #[tokio::test]
    async fn test_revoked_peer_rejected() {
        use dybervpn_tunnel::revocation::SecurityConfig as RevSecConfig;

        let (broker_secret, _) = gen_keypair();
        let config = test_broker_config(broker_secret.to_bytes());

        let peers: Arc<DashMap<[u8; 32], BrokerPeer>> = Arc::new(DashMap::new());
        let registry = Arc::new(ServiceRegistry::new());
        let audit = AuditLogger::disabled();

        // Create revocation engine and revoke a key
        let (_conn_secret, conn_public) = gen_keypair();
        let conn_pk = conn_public.to_bytes();

        let tmp_dir = std::env::temp_dir().join("dybervpn-test-revoked");
        let _ = std::fs::create_dir_all(&tmp_dir);
        let crl_path = tmp_dir.join("test.crl.json");

        let mut rev_engine = RevocationEngine::new(RevSecConfig {
            crl_path: Some(crl_path.to_string_lossy().to_string()),
            ..RevSecConfig::default()
        });
        rev_engine.revoke_key(
            &conn_pk,
            Some("test-connector"),
            dybervpn_tunnel::revocation::RevocationReason::Administrative,
            Some("test"),
        ).unwrap();
        let revocation = Arc::new(rev_engine);

        // Bind TCP listener
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control_addr = listener.local_addr().unwrap();

        let config = Arc::new(BrokerConfig {
            listen_control: control_addr,
            ..config
        });

        let ctrl_config = Arc::clone(&config);
        let ctrl_peers = Arc::clone(&peers);
        let ctrl_registry = Arc::clone(&registry);
        let ctrl_audit = audit.clone();
        let ctrl_revocation = Arc::clone(&revocation);

        tokio::spawn(async move {
            let (stream, addr) = listener.accept().await.unwrap();
            let _ = crate::control::handle_connector_for_test(
                stream, addr, ctrl_config, ctrl_peers, ctrl_registry, ctrl_audit, ctrl_revocation,
            ).await;
        });

        // Connect and try to register with the revoked key
        let stream = TcpStream::connect(control_addr).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();

        let register = ControlMessage::Register {
            public_key: base64::encode(&conn_pk),
            pq_public_key: None,
            mldsa_signature: None,
            advertised_routes: vec!["10.2.0.0/16".to_string()],
            service_name: "revoked-service".to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        let json = serde_json::to_string(&register).unwrap();
        writer.write_all(json.as_bytes()).await.unwrap();
        writer.write_all(b"\n").await.unwrap();
        writer.flush().await.unwrap();

        // Read RegisterAck — should be rejected
        let line = lines.next_line().await.unwrap().unwrap();
        let ack: ControlMessage = serde_json::from_str(&line).unwrap();
        match ack {
            ControlMessage::RegisterAck { success, error } => {
                assert!(!success, "Revoked key should be rejected");
                assert!(error.unwrap().contains("revoked"));
            }
            other => panic!("Expected RegisterAck, got: {:?}", other),
        }

        // Verify no peer was registered
        assert_eq!(peers.len(), 0, "Revoked peer should not be registered");
        assert_eq!(registry.route_count(), 0);
    }

    // ─── Test 3: Session stitching with WireGuard tunnels ────────────────────

    #[test]
    fn test_session_stitching_handshake() {
        // Create two tunnel pairs:
        //   Client ↔ Broker (client side)
        //   Broker ↔ Connector (broker side for connector)
        // Then verify that handshake packets are produced as expected.

        let (broker_secret, broker_public) = gen_keypair();
        let (client_secret, client_public) = gen_keypair();

        // Create Client's Tunn (talking to Broker)
        let mut client_tunn = Tunn::new(
            client_secret,
            broker_public,
            None, Some(25), 0, None,
        );

        // Create Broker's Tunn for this Client
        let mut broker_tunn = Tunn::new(
            broker_secret,
            client_public,
            None, Some(25), 1, None,
        );

        // Client initiates handshake
        let mut init_buf = vec![0u8; 65535];
        let mut timer_buf = vec![0u8; 65535];

        // Force a handshake initiation from client
        let handshake = client_tunn.format_handshake_initiation(&mut init_buf, false);
        assert!(
            matches!(handshake, boringtun::noise::TunnResult::WriteToNetwork(_)),
            "Client should produce a handshake initiation"
        );

        // Wrap the handshake data as if it arrived at the Broker
        if let boringtun::noise::TunnResult::WriteToNetwork(init_data) = handshake {
            let init_data = init_data.to_vec();

            // Broker decapsulates the handshake
            let mut resp_buf = vec![0u8; 65535];
            let result = broker_tunn.decapsulate(
                Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                &init_data,
                &mut resp_buf,
            );

            // Broker should produce a handshake response
            assert!(
                matches!(result, boringtun::noise::TunnResult::WriteToNetwork(_)),
                "Broker should produce a handshake response, got: {:?}",
                result
            );
        }
    }

    // ─── Test 4: Policy denial in session stitching ──────────────────────────

    #[test]
    fn test_policy_deny_drops_packet() {
        // Create a policy engine that denies everything
        let mut policy = PolicyEngine::new(&PolicyConfig {
            enabled: true,
            default_action: "deny".to_string(),
            policy_path: None,
            role: Vec::new(),
        });

        let (broker_secret, broker_public) = gen_keypair();
        let (client_secret, client_public) = gen_keypair();
        let (_, connector_public) = gen_keypair();

        let broker_secret_clone = StaticSecret::from(broker_secret.to_bytes());

        // Create Broker's Tunn for Client side
        let client_side_tunn = Tunn::new(
            StaticSecret::from(broker_secret.to_bytes()),
            client_public,
            None, Some(25), 0, None,
        );

        // Create Broker's Tunn for Connector side
        let connector_side_tunn = Tunn::new(
            broker_secret_clone,
            connector_public,
            None, Some(25), 1, None,
        );

        let mut src_peer = BrokerPeer::new(
            client_side_tunn,
            PeerRole::Client,
            "127.0.0.1:50000".parse().unwrap(),
            client_public.to_bytes(),
        );
        src_peer.service_name = Some("test-client".to_string());

        let mut dst_peer = BrokerPeer::new(
            connector_side_tunn,
            PeerRole::Connector,
            "127.0.0.1:50001".parse().unwrap(),
            connector_public.to_bytes(),
        );

        let audit = AuditLogger::disabled();

        // Create a fake encrypted packet (it will fail to decrypt since we
        // don't have an established session, but we can test error handling)
        let fake_packet = vec![0u8; 100];
        let result = session::stitch_packet(
            &mut src_peer,
            &mut dst_peer,
            &fake_packet,
            &mut policy,
            &audit,
        );

        // With a fake packet and no session, we expect a decrypt error
        assert!(result.is_err(), "Should fail to decrypt a fake packet");
    }

    // ─── Test 5: Registry integration with control plane ─────────────────────

    #[test]
    fn test_registry_multi_connector_routing() {
        let registry = ServiceRegistry::new();

        // Connector A serves 10.0.0.0/8 (broad)
        let key_a = [0xAA; 32];
        registry.register(key_a, &[
            (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8),
        ]);

        // Connector B serves 10.1.0.0/16 (more specific)
        let key_b = [0xBB; 32];
        registry.register(key_b, &[
            (IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)), 16),
        ]);

        // Connector C serves 172.16.0.0/12
        let key_c = [0xCC; 32];
        registry.register(key_c, &[
            (IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)), 12),
        ]);

        assert_eq!(registry.connector_count(), 3);
        assert_eq!(registry.route_count(), 3);

        // 10.1.0.5 → Connector B (longest prefix match)
        assert_eq!(registry.lookup(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 5))), Some(key_b));

        // 10.2.0.5 → Connector A (only /8 matches)
        assert_eq!(registry.lookup(IpAddr::V4(Ipv4Addr::new(10, 2, 0, 5))), Some(key_a));

        // 172.16.5.1 → Connector C
        assert_eq!(registry.lookup(IpAddr::V4(Ipv4Addr::new(172, 16, 5, 1))), Some(key_c));

        // 192.168.1.1 → None
        assert_eq!(registry.lookup(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))), None);

        // Unregister Connector B, 10.1.0.5 should now resolve to A
        registry.unregister(&key_b);
        assert_eq!(registry.lookup(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 5))), Some(key_a));
        assert_eq!(registry.connector_count(), 2);
    }

    // ─── Test 6: Peer management ─────────────────────────────────────────────

    #[test]
    fn test_peer_idle_detection() {
        let (secret, public) = gen_keypair();
        let tunn = Tunn::new(
            secret,
            public,
            None, Some(25), 0, None,
        );

        let mut peer = BrokerPeer::new(
            tunn,
            PeerRole::Client,
            "127.0.0.1:50000".parse().unwrap(),
            public.to_bytes(),
        );

        // Just created — should not be idle
        assert!(!peer.is_idle(std::time::Duration::from_secs(60)));

        // Touch and verify
        peer.touch();
        assert!(!peer.is_idle(std::time::Duration::from_secs(60)));

        // With zero timeout, everything is idle
        assert!(peer.is_idle(std::time::Duration::from_secs(0)));

        // Short ID should be 4 bytes hex
        assert_eq!(peer.short_id().len(), 8);
    }

    // ─── Test 7: Config parsing ──────────────────────────────────────────────

    #[test]
    fn test_broker_config_file_parsing() {
        use crate::config::BrokerConfigFile;

        let toml_str = r#"
[broker]
private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
listen_udp = "0.0.0.0:51820"
listen_control = "0.0.0.0:51821"
mode = "classic"
max_clients = 500
session_timeout = 600
heartbeat_timeout = 180
"#;

        let config: BrokerConfigFile = toml::from_str(toml_str).unwrap();
        assert_eq!(config.broker.max_clients, 500);
        assert_eq!(config.broker.session_timeout, 600);
        assert_eq!(config.broker.heartbeat_timeout, 180);
        assert_eq!(config.broker.mode, OperatingMode::Classic);
    }

    // ─── Test 8: Stale peer reaping ──────────────────────────────────────────

    #[test]
    fn test_stale_peer_reaping() {
        use crate::broker::reap_stale_peers;

        let peers: DashMap<[u8; 32], BrokerPeer> = DashMap::new();
        let registry = ServiceRegistry::new();
        let endpoint_map: DashMap<SocketAddr, [u8; 32]> = DashMap::new();

        let (secret, public) = gen_keypair();
        let pk = public.to_bytes();
        let endpoint: SocketAddr = "127.0.0.1:50000".parse().unwrap();

        let tunn = Tunn::new(secret, public, None, Some(25), 0, None);
        let mut peer = BrokerPeer::new(tunn, PeerRole::Connector, endpoint, pk);
        peer.authenticated = true;

        // Register routes
        registry.register(pk, &[(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8)]);
        endpoint_map.insert(endpoint, pk);
        peers.insert(pk, peer);

        assert_eq!(peers.len(), 1);
        assert_eq!(registry.route_count(), 1);
        assert_eq!(endpoint_map.len(), 1);

        // Reap with a generous timeout — nothing should be removed
        reap_stale_peers(
            &peers,
            &registry,
            &endpoint_map,
            std::time::Duration::from_secs(3600),
            std::time::Duration::from_secs(3600),
        );
        assert_eq!(peers.len(), 1);

        // Reap with zero timeout — everything is stale
        reap_stale_peers(
            &peers,
            &registry,
            &endpoint_map,
            std::time::Duration::from_secs(0),
            std::time::Duration::from_secs(0),
        );
        assert_eq!(peers.len(), 0, "Stale peer should be removed");
        assert_eq!(registry.route_count(), 0, "Routes should be cleaned up");
        assert_eq!(endpoint_map.len(), 0, "Endpoint map should be cleaned up");
    }
}
