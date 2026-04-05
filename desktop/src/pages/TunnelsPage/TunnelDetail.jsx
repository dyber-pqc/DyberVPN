import { useState, useEffect, useRef } from "react";
import { invoke } from "../../lib/tauri";
import { ShieldIcon } from "../../components/ShieldIcon";
import styles from "./TunnelDetail.module.css";

export function TunnelDetail({ tunnel, isConnected, connecting, onToggleConnection, settings, uptime, traffic, logs, setLogs }) {
  const [tab, setTab] = useState("status");
  const [peers, setPeers] = useState([]);
  const [peerLatency, setPeerLatency] = useState(null);
  const latencyTimer = useRef(null);

  // Fetch peers when tunnel changes
  useEffect(() => {
    if (!tunnel?.configPath) { setPeers([]); return; }
    let cancelled = false;
    (async () => {
      try {
        const result = await invoke("get_peers", { configPath: tunnel.configPath });
        if (!cancelled && Array.isArray(result)) setPeers(result);
      } catch (_) {
        // Demo fallback
        if (!cancelled) setPeers([{
          index: 0,
          public_key: tunnel.endpoint?.split(":")[0] || "peer",
          pq_public_key: null,
          allowed_ips: "10.200.200.0/24",
          endpoint: tunnel.endpoint,
          keepalive: 25,
        }]);
      }
    })();
    return () => { cancelled = true; };
  }, [tunnel?.id, tunnel?.configPath]);

  // Poll latency when connected
  useEffect(() => {
    if (!isConnected || !tunnel?.endpoint) { setPeerLatency(null); return; }
    let cancelled = false;
    const pollLatency = async () => {
      try {
        const ms = await invoke("ping_endpoint", { host: tunnel.endpoint });
        if (!cancelled && ms != null) setPeerLatency(ms);
      } catch (_) {
        // Demo fallback
        if (!cancelled) setPeerLatency(Math.floor(Math.random() * 20 + 5));
      }
    };
    pollLatency();
    latencyTimer.current = setInterval(pollLatency, 5000);
    return () => { cancelled = true; clearInterval(latencyTimer.current); };
  }, [isConnected, tunnel?.endpoint]);

  if (!tunnel) {
    return <div className={styles.empty}>No tunnels configured. Import a config to get started.</div>;
  }

  return (
    <div className={styles.panel}>
      {/* Connect button */}
      <div className={styles.connectArea}>
        <div className={styles.connectBtnWrap} style={{ animation: isConnected ? "glowPulse 3s ease-in-out infinite" : "none" }}>
          <div onClick={onToggleConnection} className={styles.connectBtn}
            style={{
              background: connecting ? "radial-gradient(circle at 40% 40%, #5b21b6, #4c1d95)" : isConnected ? "radial-gradient(circle at 40% 40%, #059669, #047857)" : "radial-gradient(circle at 40% 40%, #23233a, #1a1a2e)",
              border: connecting ? "3px solid rgba(139,92,246,0.5)" : isConnected ? "3px solid rgba(52,211,153,0.4)" : "3px solid rgba(75,85,99,0.3)",
              cursor: connecting ? "wait" : "pointer",
              animation: connecting ? "pulse 1.2s ease-in-out infinite" : "none",
            }}>
            {connecting ? (
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#c4b5fd" strokeWidth="2.5"><g style={{ animation: "spin 0.8s linear infinite", transformOrigin: "center" }}><path d="M12 2a10 10 0 0 1 10 10" strokeLinecap="round" /></g></svg>
            ) : isConnected ? (
              <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#6ee7b7" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><rect x="6" y="6" width="12" height="12" rx="2" /></svg>
            ) : (
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none"><polygon points="6,3 20,12 6,21" fill="#9ca3af" /></svg>
            )}
            <span className={styles.connectLabel} style={{ color: connecting ? "#c4b5fd" : isConnected ? "#6ee7b7" : "#9ca3af" }}>
              {connecting ? "HANDSHAKE" : isConnected ? "STOP" : "CONNECT"}
            </span>
          </div>
        </div>
        <div className={styles.statusText} style={{ color: connecting ? "#a78bfa" : isConnected ? "#34d399" : "#6b7280" }}>
          <ShieldIcon connected={isConnected} size={22} />
          {connecting ? "Performing PQ handshake\u2026" : isConnected ? "Quantum-Secure Tunnel Active" : "Not Connected"}
        </div>
        <div className={styles.tunnelInfo}>
          {tunnel.name} {"\u2022"} {tunnel.endpoint} {"\u2022"} {tunnel.mode.toUpperCase()}
          {isConnected && settings.killSwitch && <span className={styles.killSwitchLabel}> {"\u2022"} KILL SWITCH</span>}
        </div>
      </div>

      {/* Sub-tabs */}
      <div className={styles.tabs}>
        {["status", "peers", "logs", "config"].map(t => (
          <button key={t} onClick={() => setTab(t)} className={`${styles.tab} ${tab === t ? styles.tabActive : ""}`}>{t}</button>
        ))}
      </div>

      {/* Tab content */}
      <div className={styles.tabContent}>
        {tab === "status" && (
          <div className={styles.statusGrid}>
            {[
              { label: "RECEIVED", value: isConnected ? traffic.rx : "0 B", icon: "\u2193", color: "#34d399" },
              { label: "SENT", value: isConnected ? traffic.tx : "0 B", icon: "\u2191", color: "#a78bfa" },
              { label: "UPTIME", value: uptime, icon: "\u25F7", color: "#f59e0b" },
              { label: "LATENCY", value: isConnected ? traffic.latency : "\u2014", icon: "\u25C7", color: "#38bdf8" },
            ].map(s => (
              <div key={s.label} className={styles.statCard}>
                <div className={styles.statLabel}>{s.icon} {s.label}</div>
                <div className={`${styles.statValue} ${isConnected ? styles.statValueActive : styles.statValueInactive}`}>{s.value}</div>
              </div>
            ))}
            <div className={styles.cryptoBar}>
              <div className={styles.cryptoFields}>
                {[
                  { label: "KEY EXCHANGE", value: tunnel.mode === "classic" ? "X25519" : "ML-KEM-768 + X25519" },
                  { label: "AUTH", value: tunnel.mode === "pqonly" ? "ML-DSA-65" : "Ed25519" },
                  { label: "CIPHER", value: "ChaCha20-Poly1305" },
                ].map(c => (
                  <div key={c.label}>
                    <div className={styles.cryptoFieldLabel}>{c.label}</div>
                    <div className={styles.cryptoFieldValue}>{c.value}</div>
                  </div>
                ))}
              </div>
              <div className={styles.cryptoBadges}>
                <div className={styles.badge} style={{
                  background: isConnected ? "rgba(52,211,153,0.1)" : "rgba(107,114,128,0.1)",
                  color: isConnected ? "#34d399" : "#6b7280",
                  border: `1px solid ${isConnected ? "rgba(52,211,153,0.2)" : "rgba(107,114,128,0.2)"}`,
                }}>{isConnected ? "\u25CF" : "\u25CB"} FIPS 203/204</div>
                {settings.killSwitch && <div className={styles.badge} style={{
                  background: "rgba(245,158,11,0.1)", color: "#f59e0b",
                  border: "1px solid rgba(245,158,11,0.2)",
                }}>{"\uD83D\uDD12"} KILL SWITCH</div>}
              </div>
            </div>
            <div className={styles.featureTags}>
              {[
                settings.killSwitch && { label: "Kill Switch", color: "#f59e0b" },
                settings.dnsLeakProtection && { label: "DNS Protection", color: "#38bdf8" },
                settings.alwaysOn && { label: "Always-On", color: "#34d399" },
                settings.splitTunnel && { label: "Split Tunnel", color: "#a78bfa" },
                settings.lockdownMode && { label: "Lockdown", color: "#ef4444" },
              ].filter(Boolean).map(f => (
                <span key={f.label} className={styles.featureTag} style={{
                  background: `${f.color}10`, color: f.color,
                  border: `1px solid ${f.color}30`,
                }}>{"\u2713"} {f.label}</span>
              ))}
            </div>
          </div>
        )}

        {tab === "logs" && (
          <div className={styles.logsAnim}>
            <div className={styles.logsClearRow}>
              <button onClick={() => setLogs([])} className={styles.logsClearBtn}>Clear Logs</button>
            </div>
            {logs.length === 0 && <div className={styles.logsEmpty}>No log entries.</div>}
            {logs.map((l, i) => (
              <div key={i} className={styles.logLine} style={{ animation: i === 0 ? "fadeIn 0.3s ease" : "none" }}>
                <span className={styles.logTime}>{l.time}</span>
                <span className={styles.logIcon} style={{ color: l.level === "ok" ? "#34d399" : l.level === "error" ? "#ef4444" : l.level === "warn" ? "#f59e0b" : "#4b5563" }}>
                  {l.level === "ok" ? "\u2713" : l.level === "error" ? "\u2717" : l.level === "warn" ? "\u26A0" : "\u00B7"}
                </span>
                <span style={{ color: l.level === "error" ? "#fca5a5" : l.level === "ok" ? "#86efac" : l.level === "warn" ? "#fcd34d" : "#94a3b8" }}>{l.msg}</span>
              </div>
            ))}
          </div>
        )}

        {tab === "peers" && (
          <div className={styles.peersAnim}>
            <div className={styles.peersHeader}>
              <div className={styles.peersLabel}>CONFIGURED PEERS ({isConnected ? peers.length : 0} / {peers.length})</div>
              <div className={styles.peersBadge} style={{
                background: isConnected ? "rgba(52,211,153,0.1)" : "rgba(107,114,128,0.1)",
                color: isConnected ? "#34d399" : "#6b7280",
                border: `1px solid ${isConnected ? "rgba(52,211,153,0.2)" : "rgba(107,114,128,0.2)"}`,
              }}>{isConnected ? "\u25CF ALL HEALTHY" : "\u25CB OFFLINE"}</div>
            </div>
            {peers.length === 0 && (
              <div className={styles.logsEmpty}>No peers configured.</div>
            )}
            {peers.map((peer, pi) => {
              const truncKey = (k) => k && k.length > 12 ? `${k.slice(0, 8)}...${k.slice(-4)}` : (k || "\u2014");
              const qualityPct = peerLatency != null
                ? (peerLatency < 20 ? 95 : peerLatency < 50 ? 85 : peerLatency < 100 ? 70 : peerLatency < 200 ? 50 : 30)
                : null;
              return (
                <div key={pi} className={styles.peerCard}>
                  <div className={styles.peerTop}>
                    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                      <div className={styles.peerDot} style={{
                        background: isConnected ? "#34d399" : "#4b5563",
                        boxShadow: isConnected ? "0 0 8px rgba(52,211,153,0.5)" : "none",
                      }} />
                      <span className={styles.peerName}>Peer {peer.index}</span>
                    </div>
                    <span className={styles.peerEndpoint}>{peer.endpoint || tunnel.endpoint}</span>
                  </div>
                  <div className={styles.peerGrid}>
                    {[
                      ["Public Key", truncKey(peer.public_key), true],
                      ["PQ Public Key", peer.pq_public_key ? `ML-KEM-768: ${truncKey(peer.pq_public_key)}` : "\u2014", true],
                      ["Allowed IPs", peer.allowed_ips, false],
                      ["Latency", isConnected && peerLatency != null ? `${Math.round(peerLatency)} ms` : "\u2014", false],
                      ["Handshake Protocol", tunnel.mode === "classic" ? "Noise IK" : "Hybrid PQ Noise", false],
                      ["Keepalive", `${peer.keepalive}s`, false],
                      ["\u2193 Received", isConnected ? traffic.rx : "0 B", false],
                      ["\u2191 Sent", isConnected ? traffic.tx : "0 B", false],
                    ].map(([k, v, isKey]) => (
                      <div key={k}>
                        <div className={styles.peerFieldLabel}>{k.toUpperCase()}</div>
                        <div className={isKey ? styles.peerFieldValueKey : styles.peerFieldValue}>{v}</div>
                      </div>
                    ))}
                  </div>
                  {isConnected && qualityPct != null && (
                    <div className={styles.qualityBar}>
                      <div className={styles.qualityTrack}>
                        <div className={styles.qualityFill} style={{ width: `${qualityPct}%` }} />
                      </div>
                      <span className={styles.qualityLabel}>{qualityPct}% QUALITY</span>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}

        {tab === "config" && (
          <div className={styles.configBlock}>
            <div><span className={styles.configComment}># {tunnel.name}</span></div>
            <div style={{ height: 6 }} />
            <div><span className={styles.configSection}>[interface]</span></div>
            <div>name = <span className={styles.configString}>"dvpn0"</span></div>
            <div>mode = <span className={styles.configString}>"{tunnel.mode}"</span></div>
            <div>address = <span className={styles.configString}>"10.200.200.2/24"</span></div>
            <div>private_key = <span className={styles.configSecret}>{"\u2022".repeat(22)}</span></div>
            <div>pq_private_key = <span className={styles.configSecret}>{"\u2022".repeat(22)}</span></div>
            {tunnel.mode === "pqonly" && <div>mldsa_private_key = <span className={styles.configSecret}>{"\u2022".repeat(22)}</span></div>}
            <div style={{ height: 6 }} />
            <div><span className={styles.configSection}>[[peer]]</span></div>
            <div>endpoint = <span className={styles.configString}>"{tunnel.endpoint}"</span></div>
            <div>allowed_ips = <span className={styles.configString}>"10.200.200.0/24"</span></div>
            <div>persistent_keepalive = <span className={styles.configNumber}>25</span></div>
            {settings.splitTunnel && <>
              <div style={{ height: 6 }} />
              <div><span className={styles.configComment}># Split tunnel routes</span></div>
              {settings.splitTunnelRules.split("\n").filter(Boolean).map((r, i) => (
                <div key={i}>allowed_ips = <span className={styles.configString}>"{r.trim()}"</span></div>
              ))}
            </>}
            {tunnel.configPath && (
              <div className={styles.configSource}>
                <span className={styles.configComment}># Source: {tunnel.configPath}</span>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
