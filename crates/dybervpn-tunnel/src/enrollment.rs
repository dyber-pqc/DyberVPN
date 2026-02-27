//! Enrollment API — lightweight HTTP endpoint for automated peer provisioning.
//!
//! Instead of running `dybervpn add-peer` manually for each client, the server
//! can expose an enrollment endpoint. Clients POST their public keys and receive
//! a complete configuration in response.
//!
//! Security: The enrollment endpoint is protected by a pre-shared enrollment token
//! (PSK). In production, this should be replaced with certificate-based auth or
//! LDAP/SAML/OIDC integration (Phase 3).
//!
//! Usage:
//!   Server config:
//!     [enrollment]
//!     enabled = true
//!     listen = "0.0.0.0:8443"
//!     token = "your-secret-enrollment-token"
//!
//!   Client request:
//!     curl -X POST https://server:8443/enroll \
//!       -H "Authorization: Bearer your-secret-enrollment-token" \
//!       -H "Content-Type: application/json" \
//!       -d '{"name": "laptop", "public_key": "base64...", "pq_public_key": "base64..."}'

use std::collections::HashMap;
use std::io::{Read, Write, BufRead, BufReader};
use std::net::{TcpListener, TcpStream, SocketAddr, IpAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use serde::{Serialize, Deserialize};

/// Enrollment request from client
#[derive(Debug, Deserialize)]
pub struct EnrollRequest {
    /// Client name (human-readable identifier)
    pub name: String,
    /// Client's X25519 public key (base64)
    pub public_key: String,
    /// Client's ML-KEM-768 public key (base64, required for hybrid/pq-only)
    #[serde(default)]
    pub pq_public_key: Option<String>,
    /// Client's ML-DSA-65 public key (base64, required for pq-only)
    #[serde(default)]
    pub mldsa_public_key: Option<String>,
}

/// Enrollment response to client
#[derive(Debug, Serialize, Deserialize)]
pub struct EnrollResponse {
    /// Whether enrollment succeeded
    pub success: bool,
    /// Assigned VPN IP address
    pub assigned_ip: String,
    /// Server's X25519 public key (base64)
    pub server_public_key: String,
    /// Server's ML-KEM-768 public key (base64)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_pq_public_key: Option<String>,
    /// Complete TOML client config
    pub client_config: String,
    /// Operating mode
    pub mode: String,
    /// Error message (if success=false)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Enrollment server configuration
#[derive(Debug, Clone)]
pub struct EnrollmentConfig {
    /// Listen address for the enrollment API
    pub listen_addr: SocketAddr,
    /// Pre-shared enrollment token
    pub token: String,
    /// Path to server config file (to append new peers)
    pub server_config_path: PathBuf,
    /// Server endpoint (IP:port) for client configs
    pub server_endpoint: String,
    /// Reload flag to signal the daemon to reload after enrollment
    pub reload_flag: Arc<AtomicBool>,
}

/// Enrollment server — runs in a separate thread
pub struct EnrollmentServer {
    config: EnrollmentConfig,
    shutdown: Arc<AtomicBool>,
    /// Track enrolled client names to prevent duplicates
    enrolled_names: Vec<String>,
}

impl EnrollmentServer {
    /// Create a new enrollment server
    pub fn new(config: EnrollmentConfig, shutdown: Arc<AtomicBool>) -> Self {
        Self {
            config,
            shutdown,
            enrolled_names: Vec::new(),
        }
    }

    /// Run the enrollment server (blocking — call from a dedicated thread)
    pub fn run(&mut self) {
        let listener = match TcpListener::bind(self.config.listen_addr) {
            Ok(l) => {
                tracing::info!(
                    "Enrollment API listening on {}",
                    self.config.listen_addr
                );
                l
            }
            Err(e) => {
                tracing::error!("Failed to bind enrollment API: {}", e);
                return;
            }
        };

        // Set non-blocking so we can check the shutdown flag
        listener.set_nonblocking(true).ok();

        while !self.shutdown.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, addr)) => {
                    tracing::debug!("Enrollment connection from {}", addr);
                    if let Err(e) = self.handle_connection(stream, addr) {
                        tracing::warn!("Enrollment request error from {}: {}", addr, e);
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    continue;
                }
                Err(e) => {
                    tracing::warn!("Enrollment accept error: {}", e);
                }
            }
        }

        tracing::info!("Enrollment API shutting down");
    }

    /// Handle a single HTTP connection
    fn handle_connection(&mut self, mut stream: TcpStream, addr: SocketAddr) -> Result<(), String> {
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .map_err(|e| format!("set timeout: {}", e))?;

        let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);

        // Read request line
        let mut request_line = String::new();
        reader.read_line(&mut request_line).map_err(|e| e.to_string())?;
        let request_line = request_line.trim().to_string();

        // Parse headers
        let mut headers: HashMap<String, String> = HashMap::new();
        let mut content_length: usize = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).map_err(|e| e.to_string())?;
            let line = line.trim().to_string();
            if line.is_empty() {
                break;
            }
            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim().to_lowercase();
                let value = value.trim().to_string();
                if key == "content-length" {
                    content_length = value.parse().unwrap_or(0);
                }
                headers.insert(key, value);
            }
        }

        // Route request
        if request_line.starts_with("POST /enroll") {
            self.handle_enroll(&mut reader, &mut stream, &headers, content_length, addr)
        } else if request_line.starts_with("GET /status") {
            self.handle_status(&mut stream, &headers)
        } else if request_line.starts_with("GET /health") {
            self.send_response(&mut stream, 200, r#"{"status":"ok"}"#)
        } else {
            self.send_response(&mut stream, 404, r#"{"error":"not found"}"#)
        }
    }

    /// Handle POST /enroll
    fn handle_enroll(
        &mut self,
        reader: &mut BufReader<TcpStream>,
        stream: &mut TcpStream,
        headers: &HashMap<String, String>,
        content_length: usize,
        addr: SocketAddr,
    ) -> Result<(), String> {
        // Check authorization token
        let auth = headers.get("authorization").cloned().unwrap_or_default();
        let expected = format!("Bearer {}", self.config.token);
        if auth != expected {
            tracing::warn!("Enrollment auth failed from {}", addr);
            return self.send_response(stream, 401, r#"{"success":false,"error":"unauthorized"}"#);
        }

        // Read body
        if content_length == 0 || content_length > 1_000_000 {
            return self.send_response(stream, 400, r#"{"success":false,"error":"invalid content length"}"#);
        }

        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body).map_err(|e| e.to_string())?;

        // Parse request
        let request: EnrollRequest = match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(e) => {
                return self.send_response(
                    stream,
                    400,
                    &format!(r#"{{"success":false,"error":"invalid JSON: {}"}}"#, e),
                );
            }
        };

        // Validate
        if request.name.is_empty() || request.name.len() > 64 {
            return self.send_response(stream, 400, r#"{"success":false,"error":"name must be 1-64 chars"}"#);
        }
        if request.public_key.is_empty() {
            return self.send_response(stream, 400, r#"{"success":false,"error":"public_key required"}"#);
        }

        // Check for duplicate name
        if self.enrolled_names.contains(&request.name) {
            return self.send_response(stream, 409, 
                &format!(r#"{{"success":false,"error":"peer '{}' already enrolled"}}"#, request.name));
        }

        tracing::info!("Enrollment request: name='{}' from {}", request.name, addr);

        // Read server config to determine mode and next IP
        let server_config_str = std::fs::read_to_string(&self.config.server_config_path)
            .map_err(|e| format!("read config: {}", e))?;

        let server_config: dybervpn_protocol::Config = toml::from_str(&server_config_str)
            .map_err(|e| format!("parse config: {}", e))?;

        // Calculate next available IP
        let (server_ip, prefix) = parse_cidr_simple(&server_config.interface.address)
            .ok_or("invalid server address")?;

        let server_octets = match server_ip {
            IpAddr::V4(v4) => v4.octets(),
            _ => return Err("only IPv4 supported".into()),
        };

        let existing_ips: Vec<u8> = server_config.peer.iter()
            .filter_map(|p| {
                parse_cidr_simple(&p.allowed_ips)
                    .and_then(|(ip, _)| match ip {
                        IpAddr::V4(v4) => Some(v4.octets()[3]),
                        _ => None,
                    })
            })
            .collect();

        let mut next_octet = server_octets[3] + 1;
        while existing_ips.contains(&next_octet) || next_octet == 0 || next_octet == 255 {
            next_octet += 1;
            if next_octet >= 255 {
                return self.send_response(stream, 507, r#"{"success":false,"error":"no free IPs"}"#);
            }
        }

        let client_ip = format!(
            "{}.{}.{}.{}",
            server_octets[0], server_octets[1], server_octets[2], next_octet
        );
        let subnet = format!(
            "{}.{}.{}.0/{}",
            server_octets[0], server_octets[1], server_octets[2], prefix
        );

        // Derive server public keys
        let server_priv_bytes = base64::decode(&server_config.interface.private_key)
            .map_err(|_| "invalid server private key")?;
        let mut sk_arr = [0u8; 32];
        if server_priv_bytes.len() != 32 { return Err("bad server key len".into()); }
        sk_arr.copy_from_slice(&server_priv_bytes);
        let server_secret = x25519_dalek::StaticSecret::from(sk_arr);
        let server_public = x25519_dalek::PublicKey::from(&server_secret);
        let server_public_b64 = base64::encode(server_public.as_bytes());

        let server_pq_public_b64 = server_config.interface.pq_private_key.as_ref()
            .and_then(|pq_priv| {
                let bytes = base64::decode(pq_priv).ok()?;
                if bytes.len() >= 2400 {
                    Some(base64::encode(&bytes[bytes.len() - 1184..]))
                } else {
                    None
                }
            });

        // Build [[peer]] block for server config
        let mode_str = format!("{:?}", server_config.interface.mode).to_lowercase();
        let mut peer_block = format!(
            "\n# Peer: {} (enrolled {} from {})\n[[peer]]\npublic_key = \"{}\"\n",
            request.name,
            chrono::Utc::now().format("%Y-%m-%d %H:%M"),
            addr.ip(),
            request.public_key,
        );

        if let Some(ref pq_pk) = request.pq_public_key {
            peer_block.push_str(&format!("pq_public_key = \"{}\"\n", pq_pk));
        }
        if let Some(ref mldsa_pk) = request.mldsa_public_key {
            peer_block.push_str(&format!("mldsa_public_key = \"{}\"\n", mldsa_pk));
        }
        peer_block.push_str(&format!("allowed_ips = \"{}/32\"\n", client_ip));
        peer_block.push_str("persistent_keepalive = 25\n");

        // Append to server config
        std::fs::OpenOptions::new()
            .append(true)
            .open(&self.config.server_config_path)
            .and_then(|mut f| f.write_all(peer_block.as_bytes()))
            .map_err(|e| format!("write config: {}", e))?;

        // Build client config
        let mut client_config = format!(
            "# DyberVPN Client Configuration — {}\n\
             # Enrolled: {}\n\
             # Server: {}\n\n\
             [interface]\n\
             name = \"dvpn0\"\n\
             address = \"{}/{}\"\n\
             mode = \"{}\"\n\
             # IMPORTANT: Add your private keys below\n\
             # private_key = \"YOUR_X25519_PRIVATE_KEY\"\n",
            request.name,
            chrono::Utc::now().to_rfc3339(),
            self.config.server_endpoint,
            client_ip,
            prefix,
            mode_str,
        );

        if server_config.interface.mode.uses_pq_kex() {
            client_config.push_str("# pq_private_key = \"YOUR_MLKEM_PRIVATE_KEY\"\n");
        }

        client_config.push_str(&format!(
            "\n[[peer]]\npublic_key = \"{}\"\n",
            server_public_b64,
        ));

        if let Some(ref pq_pk) = server_pq_public_b64 {
            client_config.push_str(&format!("pq_public_key = \"{}\"\n", pq_pk));
        }

        client_config.push_str(&format!(
            "allowed_ips = \"{}\"\nendpoint = \"{}\"\npersistent_keepalive = 25\n",
            subnet,
            self.config.server_endpoint,
        ));

        // Signal daemon to reload
        self.config.reload_flag.store(true, Ordering::Relaxed);
        self.enrolled_names.push(request.name.clone());

        // Build response
        let response = EnrollResponse {
            success: true,
            assigned_ip: client_ip.clone(),
            server_public_key: server_public_b64,
            server_pq_public_key: server_pq_public_b64,
            client_config,
            mode: mode_str,
            error: None,
        };

        let json = serde_json::to_string_pretty(&response)
            .map_err(|e| format!("serialize: {}", e))?;

        tracing::info!(
            "Enrolled peer '{}' with IP {} (requested from {})",
            request.name,
            client_ip,
            addr
        );

        self.send_response(stream, 200, &json)
    }

    /// Handle GET /status
    fn handle_status(
        &self,
        stream: &mut TcpStream,
        headers: &HashMap<String, String>,
    ) -> Result<(), String> {
        // Require auth
        let auth = headers.get("authorization").cloned().unwrap_or_default();
        let expected = format!("Bearer {}", self.config.token);
        if auth != expected {
            return self.send_response(stream, 401, r#"{"error":"unauthorized"}"#);
        }

        let status = serde_json::json!({
            "enrolled_peers": self.enrolled_names.len(),
            "peer_names": self.enrolled_names,
        });

        self.send_response(stream, 200, &status.to_string())
    }

    /// Send an HTTP response
    fn send_response(&self, stream: &mut TcpStream, status: u16, body: &str) -> Result<(), String> {
        let status_text = match status {
            200 => "OK",
            400 => "Bad Request",
            401 => "Unauthorized",
            404 => "Not Found",
            409 => "Conflict",
            507 => "Insufficient Storage",
            _ => "Error",
        };

        let response = format!(
            "HTTP/1.1 {} {}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {}",
            status, status_text, body.len(), body
        );

        stream.write_all(response.as_bytes()).map_err(|e| e.to_string())?;
        stream.flush().map_err(|e| e.to_string())?;

        Ok(())
    }
}

/// Simple CIDR parser (doesn't pull in full anyhow)
fn parse_cidr_simple(s: &str) -> Option<(IpAddr, u8)> {
    // Handle comma-separated (take first)
    let s = s.split(',').next()?.trim();
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 {
        return None;
    }
    let ip: IpAddr = parts[0].parse().ok()?;
    let prefix: u8 = parts[1].parse().ok()?;
    Some((ip, prefix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_parse_cidr_simple() {
        let (ip, prefix) = parse_cidr_simple("10.200.200.1/24").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(10, 200, 200, 1)));
        assert_eq!(prefix, 24);
    }

    #[test]
    fn test_parse_cidr_with_comma() {
        let (ip, prefix) = parse_cidr_simple("10.200.200.2/32, 10.200.200.0/24").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(10, 200, 200, 2)));
        assert_eq!(prefix, 32);
    }

    #[test]
    fn test_enroll_request_deserialize() {
        let json = r#"{"name":"laptop","public_key":"abc123","pq_public_key":"def456"}"#;
        let req: EnrollRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "laptop");
        assert_eq!(req.public_key, "abc123");
        assert_eq!(req.pq_public_key, Some("def456".to_string()));
    }

    // =========================================================================
    // Integration tests — full enrollment server HTTP round-trip
    // =========================================================================

    /// Create a temp server config and EnrollmentConfig for tests.
    /// Returns (config, config_path) where config_path is a temp file.
    fn create_test_enrollment_config(token: &str) -> (EnrollmentConfig, std::path::PathBuf) {
        // Generate a real X25519 private key
        let server_secret = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let server_private_b64 = base64::encode(server_secret.to_bytes());

        // Write a minimal valid server config
        let config_content = format!(
            "[interface]\n\
             private_key = \"{}\"\n\
             listen_port = 51820\n\
             address = \"10.200.200.1/24\"\n\
             mode = \"classic\"\n",
            server_private_b64,
        );

        let dir = std::env::temp_dir().join(format!("dybervpn-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("server.toml");
        std::fs::write(&config_path, &config_content).unwrap();

        // Bind to port 0 to get a random available port
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener); // Free the port for the enrollment server

        let config = EnrollmentConfig {
            listen_addr: addr,
            token: token.to_string(),
            server_config_path: config_path.clone(),
            server_endpoint: "10.200.200.1:51820".to_string(),
            reload_flag: Arc::new(AtomicBool::new(false)),
        };

        (config, config_path)
    }

    /// Send a raw HTTP request to the enrollment server
    fn http_request(addr: SocketAddr, method: &str, path: &str, token: Option<&str>, body: Option<&str>) -> (u16, String) {
        let mut stream = TcpStream::connect(addr).expect("connect to enrollment server");
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok();

        let body_bytes = body.unwrap_or("");
        let mut request = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\n",
            method, path, addr, body_bytes.len(),
        );
        if let Some(t) = token {
            request.push_str(&format!("Authorization: Bearer {}\r\n", t));
        }
        request.push_str("Content-Type: application/json\r\n\r\n");
        request.push_str(body_bytes);

        stream.write_all(request.as_bytes()).expect("send request");
        stream.flush().ok();

        let mut response = String::new();
        stream.read_to_string(&mut response).ok();

        // Parse status code
        let status = response.lines().next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0u16);

        // Extract body (after \r\n\r\n)
        let body = response.split("\r\n\r\n")
            .nth(1)
            .unwrap_or("")
            .to_string();

        (status, body)
    }

    #[test]
    fn test_enrollment_server_health_check() {
        let token = "test-token-health";
        let (config, config_path) = create_test_enrollment_config(token);
        let addr = config.listen_addr;
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = Arc::clone(&shutdown);

        // Start server in background thread
        let handle = std::thread::spawn(move || {
            let mut server = EnrollmentServer::new(config, shutdown_clone);
            server.run();
        });

        // Give server time to bind
        std::thread::sleep(std::time::Duration::from_millis(300));

        // Test GET /health (no auth required)
        let (status, body) = http_request(addr, "GET", "/health", None, None);
        assert_eq!(status, 200, "health check should return 200");
        assert!(body.contains("ok"), "health check body: {}", body);

        // Test 404 for unknown path
        let (status, _body) = http_request(addr, "GET", "/nonexistent", None, None);
        assert_eq!(status, 404);

        // Shutdown
        shutdown.store(true, Ordering::Relaxed);
        handle.join().ok();
        let _ = std::fs::remove_dir_all(config_path.parent().unwrap());
    }

    #[test]
    fn test_enrollment_server_auth_required() {
        let token = "test-token-auth";
        let (config, config_path) = create_test_enrollment_config(token);
        let addr = config.listen_addr;
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = Arc::clone(&shutdown);

        let handle = std::thread::spawn(move || {
            let mut server = EnrollmentServer::new(config, shutdown_clone);
            server.run();
        });

        std::thread::sleep(std::time::Duration::from_millis(300));

        // POST /enroll without auth → 401
        let body = r#"{"name":"laptop","public_key":"dGVzdA=="}"#;
        let (status, resp) = http_request(addr, "POST", "/enroll", None, Some(body));
        assert_eq!(status, 401, "no auth should be 401, got body: {}", resp);

        // POST /enroll with wrong token → 401
        let (status, _) = http_request(addr, "POST", "/enroll", Some("wrong-token"), Some(body));
        assert_eq!(status, 401);

        // GET /status without auth → 401
        let (status, _) = http_request(addr, "GET", "/status", None, None);
        assert_eq!(status, 401);

        shutdown.store(true, Ordering::Relaxed);
        handle.join().ok();
        let _ = std::fs::remove_dir_all(config_path.parent().unwrap());
    }

    #[test]
    fn test_enrollment_server_full_enroll() {
        let token = "test-token-enroll";
        let (config, config_path) = create_test_enrollment_config(token);
        let addr = config.listen_addr;
        let reload_flag = Arc::clone(&config.reload_flag);
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = Arc::clone(&shutdown);

        let handle = std::thread::spawn(move || {
            let mut server = EnrollmentServer::new(config, shutdown_clone);
            server.run();
        });

        std::thread::sleep(std::time::Duration::from_millis(300));

        // Generate a real client keypair
        let client_secret = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let client_public = x25519_dalek::PublicKey::from(&client_secret);
        let client_public_b64 = base64::encode(client_public.as_bytes());

        // Enroll a peer
        let enroll_body = format!(
            r#"{{"name":"test-laptop","public_key":"{}"}}"#,
            client_public_b64,
        );
        let (status, resp_body) = http_request(addr, "POST", "/enroll", Some(token), Some(&enroll_body));
        assert_eq!(status, 200, "enrollment should succeed, got: {}", resp_body);

        let resp: EnrollResponse = serde_json::from_str(&resp_body)
            .expect("enrollment response should be valid JSON");
        assert!(resp.success, "enrollment should be successful");
        assert_eq!(resp.assigned_ip, "10.200.200.2", "first client gets .2");
        assert!(!resp.server_public_key.is_empty(), "server public key should be present");
        assert_eq!(resp.mode, "classic");
        assert!(resp.client_config.contains("test-laptop"), "config should contain peer name");
        assert!(resp.client_config.contains("10.200.200.2"), "config should contain assigned IP");

        // Verify reload flag was set
        assert!(reload_flag.load(Ordering::Relaxed), "reload flag should be set after enrollment");

        // Verify peer was appended to server config file
        let updated_config = std::fs::read_to_string(&config_path).unwrap();
        assert!(updated_config.contains(&client_public_b64), "server config should contain client key");
        assert!(updated_config.contains("test-laptop"), "server config should contain peer name");
        assert!(updated_config.contains("10.200.200.2/32"), "server config should contain assigned IP");

        // Enroll a second peer — should get .3
        let client2_secret = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let client2_public = x25519_dalek::PublicKey::from(&client2_secret);
        let client2_public_b64 = base64::encode(client2_public.as_bytes());
        let enroll_body2 = format!(
            r#"{{"name":"test-phone","public_key":"{}"}}"#,
            client2_public_b64,
        );
        let (status2, resp_body2) = http_request(addr, "POST", "/enroll", Some(token), Some(&enroll_body2));
        assert_eq!(status2, 200);
        let resp2: EnrollResponse = serde_json::from_str(&resp_body2).unwrap();
        assert_eq!(resp2.assigned_ip, "10.200.200.3", "second client gets .3");

        // Duplicate name → 409
        let (status_dup, _) = http_request(addr, "POST", "/enroll", Some(token), Some(&enroll_body));
        assert_eq!(status_dup, 409, "duplicate name should be 409");

        // GET /status should show 2 enrolled peers
        let (status_s, status_body) = http_request(addr, "GET", "/status", Some(token), None);
        assert_eq!(status_s, 200);
        assert!(status_body.contains("\"enrolled_peers\":2"), "status: {}", status_body);

        shutdown.store(true, Ordering::Relaxed);
        handle.join().ok();
        let _ = std::fs::remove_dir_all(config_path.parent().unwrap());
    }

    #[test]
    fn test_enrollment_server_validation() {
        let token = "test-token-validate";
        let (config, config_path) = create_test_enrollment_config(token);
        let addr = config.listen_addr;
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = Arc::clone(&shutdown);

        let handle = std::thread::spawn(move || {
            let mut server = EnrollmentServer::new(config, shutdown_clone);
            server.run();
        });

        std::thread::sleep(std::time::Duration::from_millis(300));

        // Empty name → 400
        let (status, _) = http_request(addr, "POST", "/enroll", Some(token),
            Some(r#"{"name":"","public_key":"dGVzdA=="}"#));
        assert_eq!(status, 400);

        // Missing public_key → 400
        let (status, _) = http_request(addr, "POST", "/enroll", Some(token),
            Some(r#"{"name":"test","public_key":""}"#));
        assert_eq!(status, 400);

        // Invalid JSON → 400
        let (status, _) = http_request(addr, "POST", "/enroll", Some(token),
            Some(r#"not json at all"#));
        assert_eq!(status, 400);

        shutdown.store(true, Ordering::Relaxed);
        handle.join().ok();
        let _ = std::fs::remove_dir_all(config_path.parent().unwrap());
    }
}
