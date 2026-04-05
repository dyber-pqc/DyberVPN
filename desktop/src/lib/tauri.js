// DyberVPN — Tauri API helpers with demo fallback
// Copyright 2026 Dyber, Inc.

// ─── Tauri window API (lazy init, no top-level await) ─────
let appWindow = null;
let _windowInitialized = false;

export function getAppWindow() {
  if (!_windowInitialized) {
    _windowInitialized = true;
    try {
      const mod = window.__TAURI_INTERNALS__;
      if (mod) {
        import("@tauri-apps/api/window").then(m => { appWindow = m.getCurrentWindow(); }).catch(() => {});
      }
    } catch (_) {}
  }
  return appWindow;
}
// Kick off init immediately
getAppWindow();

// ─── Tauri invoke wrapper with demo fallback ──────────────
function getTauriInvoke() {
  try { return window.__TAURI_INTERNALS__?.invoke || null; } catch (_) { return null; }
}

export async function invoke(cmd, args = {}) {
  const ti = getTauriInvoke();
  if (ti) {
    try { return await ti(cmd, args); }
    catch (e) { console.warn("Tauri invoke failed:", cmd, e); throw e; }
  }
  if (cmd === "import_config") {
    return { name: args.path?.split(/[\\/]/).pop()?.replace(".toml", "") || "Imported", endpoint: "10.200.200.1:51820", mode: "hybrid" };
  }
  if (cmd === "connect_tunnel") { await new Promise(r => setTimeout(r, 1800)); return null; }
  if (cmd === "disconnect_tunnel") { await new Promise(r => setTimeout(r, 500)); return null; }
  if (cmd === "generate_keys") {
    await new Promise(r => setTimeout(r, 600));
    const b64 = (len) => {
      const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
      let s = ""; for (let i = 0; i < len; i++) s += chars[Math.floor(Math.random() * 64)];
      return s + "=";
    };
    const mode = args.mode || "hybrid";
    let out = "";
    if (mode === "hybrid" || mode === "classic") {
      out += `[classical]\n`;
      out += `private_key = ${b64(43)}\n`;
      out += `public_key  = ${b64(43)}\n`;
    }
    if (mode === "hybrid" || mode === "pqonly") {
      out += `\n[ml-kem-768]\n`;
      out += `pq_private_key = ${b64(86)}\n`;
      out += `pq_public_key  = ${b64(86)}\n`;
    }
    if (mode === "pqonly" || mode === "hybrid") {
      out += `\n[ml-dsa-65]\n`;
      out += `signing_private_key = ${b64(120)}\n`;
      out += `signing_public_key  = ${b64(86)}\n`;
    }
    return out;
  }
  if (cmd === "get_status") {
    // Demo: simulate traffic growth
    if (!window._demoTraffic) window._demoTraffic = { rx: 0, tx: 0, start: Date.now() };
    window._demoTraffic.rx += Math.floor(Math.random() * 5000 + 1000);
    window._demoTraffic.tx += Math.floor(Math.random() * 3000 + 500);
    return {
      connected: true,
      rx: window._demoTraffic.rx,
      tx: window._demoTraffic.tx,
      uptime_secs: Math.floor((Date.now() - window._demoTraffic.start) / 1000),
      latency_ms: Math.floor(Math.random() * 15 + 5),
      interface_name: "dvpn0",
    };
  }
  if (cmd === "get_peers") {
    return [{
      index: 0,
      public_key: "aB3x9kQw2mN7pL4jR8vY5tHs6wE1dFg0",
      pq_public_key: "7Fj2kL9mNx4pQr5tBv8wAy3zCd6eGh0i",
      allowed_ips: "10.200.200.0/24",
      endpoint: "10.200.200.1:51820",
      keepalive: 25,
    }];
  }
  if (cmd === "ping_endpoint") {
    await new Promise(r => setTimeout(r, 100));
    return Math.floor(Math.random() * 20 + 5);
  }
  if (cmd === "enroll_device") {
    await new Promise(r => setTimeout(r, 2000));
    const ip = `10.200.200.${Math.floor(Math.random() * 200 + 10)}`;
    return `Enrolled successfully!\n\n  Name:        ${args.name}\n  Assigned IP: ${ip}\n  Config:      ${args.outputDir}/${args.name}.toml\n  Mode:        ${args.mode}`;
  }
  if (cmd === "revoke_peer") {
    await new Promise(r => setTimeout(r, 500));
    return `Key revoked for peer '${args.peer}'`;
  }
  if (cmd === "suspend_peer") {
    await new Promise(r => setTimeout(r, 500));
    return `Key suspended for peer '${args.peer}'`;
  }
  if (cmd === "reinstate_peer") {
    await new Promise(r => setTimeout(r, 500));
    return `Key reinstated for peer '${args.peer}'`;
  }
  if (cmd === "list_revoked") {
    return JSON.stringify([
      { peer_name: "old-laptop", public_key_fingerprint: "aB3x9kQw", reason: "device_lost", revoked_at: "2026-02-20T10:30:00Z", revoked_by: "admin@company.com", expires_at: null },
      { peer_name: "temp-contractor", public_key_fingerprint: "7Fj2kL9m", reason: "employee_departed", revoked_at: "2026-02-25T14:00:00Z", revoked_by: "admin@company.com", expires_at: "2026-03-04T14:00:00Z" },
    ]);
  }
  if (cmd === "check_server_health") {
    await new Promise(r => setTimeout(r, 300));
    return JSON.stringify({ status: "ok" });
  }
  if (cmd === "read_audit_log") {
    return JSON.stringify([
      { timestamp: "2026-02-26T10:30:00Z", event_id: 1, category: "connection", event_type: "PeerConnected", outcome: "success", peer_name: "alice-laptop", source_ip: "10.200.200.2", message: "Peer connected via hybrid handshake" },
      { timestamp: "2026-02-26T10:30:01Z", event_id: 2, category: "handshake", event_type: "HandshakeCompleted", outcome: "success", peer_name: "alice-laptop", message: "ML-KEM-768 + X25519 hybrid handshake completed in 42ms" },
      { timestamp: "2026-02-26T10:35:00Z", event_id: 3, category: "policy", event_type: "PacketAllowed", outcome: "success", peer_name: "alice-laptop", source_ip: "10.200.200.2", dest_ip: "10.0.0.50", dest_port: 443, protocol: "tcp", policy_rule: "allow-https" },
      { timestamp: "2026-02-26T10:35:12Z", event_id: 4, category: "policy", event_type: "PacketDenied", outcome: "denied", peer_name: "bob-phone", source_ip: "10.200.200.5", dest_ip: "10.0.0.100", dest_port: 22, protocol: "tcp", policy_rule: "deny-ssh", message: "SSH access denied by policy" },
      { timestamp: "2026-02-26T11:00:00Z", event_id: 5, category: "key_management", event_type: "KeyRotationCompleted", outcome: "success", peer_name: "alice-laptop", message: "Session key rotated successfully" },
      { timestamp: "2026-02-26T11:15:00Z", event_id: 6, category: "enrollment", event_type: "EnrollmentApproved", outcome: "success", peer_name: "charlie-desktop", source_ip: "192.168.1.50", message: "Device enrolled with hybrid mode" },
      { timestamp: "2026-02-26T11:30:00Z", event_id: 7, category: "system", event_type: "ConfigReloaded", outcome: "success", message: "Configuration reloaded: 3 peers added, 0 removed, 5 total" },
      { timestamp: "2026-02-26T12:00:00Z", event_id: 8, category: "connection", event_type: "PeerDisconnected", outcome: "success", peer_name: "bob-phone", message: "Peer disconnected (idle timeout)" },
    ]);
  }
  if (cmd === "get_policy_config") {
    return JSON.stringify({
      policy: {
        enabled: true,
        default_action: "deny",
        role: [
          { name: "admin", peers: ["alice-laptop", "admin-workstation"], rule: [
            { action: "allow", network: "0.0.0.0/0", protocol: "any", description: "Full access" },
          ]},
          { name: "developer", peers: ["bob-phone", "charlie-desktop"], rule: [
            { action: "allow", network: "10.0.0.0/24", ports: "80,443,8080-8090", protocol: "tcp", description: "HTTP/HTTPS to dev servers" },
            { action: "allow", network: "10.0.1.0/24", ports: "5432,6379", protocol: "tcp", description: "Database access" },
            { action: "deny", network: "10.0.0.0/8", protocol: "any", description: "Deny other internal" },
          ]},
          { name: "guest", peers: [], rule: [
            { action: "allow", network: "0.0.0.0/0", ports: "443", protocol: "tcp", description: "HTTPS only" },
          ]},
        ],
      },
      security: {
        key_max_age_hours: 720,
        session_max_age_hours: 24,
        check_interval_secs: 300,
        auto_disconnect_revoked: true,
      },
    });
  }
  if (cmd === "run_posture_check") {
    await new Promise(r => setTimeout(r, 1500));
    return JSON.stringify({
      score: 85,
      compliant: true,
      threshold: 60,
      checks: [
        { name: "OS Version", category: "operating_system", passed: true, weight: 20, detail: "Windows 10.26200 — supported" },
        { name: "Firewall", category: "security", passed: true, weight: 25, detail: "Windows Firewall: all profiles enabled" },
        { name: "Disk Encryption", category: "encryption", passed: false, weight: 25, detail: "BitLocker C: not protected" },
        { name: "Antivirus", category: "security", passed: true, weight: 15, detail: "Windows Defender: AV=true, RealTime=true" },
        { name: "Screen Lock", category: "security", passed: true, weight: 15, detail: "Screen lock: using system defaults" },
      ],
      timestamp: new Date().toISOString(),
    });
  }
  if (cmd === "get_metrics") {
    return JSON.stringify({
      available: false,
      message: "Metrics server not running. Start the DyberVPN daemon with --metrics flag.",
    });
  }
  return null;
}

// ─── Tauri event listener with demo fallback ────────────

/**
 * Subscribe to a Tauri event. Returns a Promise<unlisten> if Tauri is
 * available, or null if in demo mode (caller should fall back to polling).
 */
export function listen(eventName, callback) {
  if (!window.__TAURI_INTERNALS__) {
    return null; // Demo mode — caller handles fallback
  }

  return (async () => {
    try {
      const mod = await import("@tauri-apps/api/event");
      return await mod.listen(eventName, callback);
    } catch (_) {
      return () => {}; // noop unlisten if import fails
    }
  })();
}
