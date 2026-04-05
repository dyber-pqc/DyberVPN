import { useState } from "react";
import { invoke } from "../../lib/tauri";
import { Icon } from "../../components/Icon";
import { Toggle } from "../../components/Toggle/Toggle";
import { SettingRow } from "../../components/SettingRow/SettingRow";
import { Select } from "../../components/Select/Select";
import { NumInput } from "../../components/NumInput/NumInput";
import { ConfirmModal } from "../../components/ConfirmModal/ConfirmModal";
import { EnrollModal } from "../../components/EnrollModal/EnrollModal";
import { KeyLifecycleModal } from "../../components/KeyLifecycleModal/KeyLifecycleModal";
import styles from "./SettingsPage.module.css";

const TABS = [
  { id: "security", label: "Security", icon: "shield" },
  { id: "network", label: "Network", icon: "globe" },
  { id: "crypto", label: "Cryptography", icon: "lock" },
  { id: "compliance", label: "Compliance", icon: "clipboard" },
  { id: "fleet", label: "Fleet", icon: "building" },
  { id: "app", label: "Application", icon: "gear" },
];

export function SettingsPage({ settings, updateSetting, auditLog, setAuditLog, addToast, tunnels, setTunnels }) {
  const [settingsTab, setSettingsTab] = useState("security");
  const [copied, setCopied] = useState(false);

  // Fleet state
  const [showEnrollModal, setShowEnrollModal] = useState(false);
  const [showKeyModal, setShowKeyModal] = useState(null); // "revoke" | "suspend" | null
  const [showUnenrollConfirm, setShowUnenrollConfirm] = useState(false);
  const [revokedKeys, setRevokedKeys] = useState([]);
  const [serverHealth, setServerHealth] = useState(null);
  const [loadingRevoked, setLoadingRevoked] = useState(false);
  const [policyConfig, setPolicyConfig] = useState(null);
  const [fleetAuditLog, setFleetAuditLog] = useState(null);
  const [postureResult, setPostureResult] = useState(null);
  const [loadingPosture, setLoadingPosture] = useState(false);
  const [metricsData, setMetricsData] = useState(null);

  const ts = () => new Date().toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });

  // Fleet handlers
  const handleEnroll = async ({ server, token, name, mode }) => {
    const outputDir = ".";
    const result = await invoke("enroll_device", { server, token, name, mode, outputDir });
    const ipMatch = result.match(/Assigned IP:\s*(\S+)/);
    const configMatch = result.match(/Config:\s*(.+)/);
    const assignedIp = ipMatch ? ipMatch[1] : "unknown";
    const configPath = configMatch ? configMatch[1].trim() : "";

    updateSetting("fleetEnrolled", true);
    updateSetting("fleetServerUrl", server);
    updateSetting("fleetDeviceName", name);
    updateSetting("fleetAssignedIp", assignedIp);
    updateSetting("fleetMode", mode);
    updateSetting("fleetConfigPath", configPath);
    updateSetting("fleetEnrolledAt", new Date().toISOString());

    if (configPath && setTunnels) {
      setTunnels(prev => [...prev, {
        id: `fleet-${Date.now()}`,
        name: `Fleet: ${name}`,
        endpoint: server.replace(/^https?:\/\//, "").replace(/:\d+$/, "") + ":51820",
        mode,
        status: "disconnected",
        configPath,
      }]);
    }

    addToast?.("success", `Enrolled as "${name}" with IP ${assignedIp}`);
    setShowEnrollModal(false);
    setAuditLog(prev => [{ time: ts(), event: "fleet_enroll", detail: `Enrolled with ${server} as ${name}`, severity: "info" }, ...prev]);
  };

  const handleUnenroll = () => {
    updateSetting("fleetEnrolled", false);
    updateSetting("fleetServerUrl", "");
    updateSetting("fleetDeviceName", "");
    updateSetting("fleetAssignedIp", "");
    updateSetting("fleetMode", "");
    updateSetting("fleetConfigPath", "");
    updateSetting("fleetEnrolledAt", "");
    setRevokedKeys([]);
    setServerHealth(null);
    setShowUnenrollConfirm(false);
    addToast?.("info", "Device unenrolled from fleet");
    setAuditLog(prev => [{ time: ts(), event: "fleet_unenroll", detail: "Device removed from fleet", severity: "warn" }, ...prev]);
  };

  const handleHealthCheck = async () => {
    try {
      const result = await invoke("check_server_health", { serverUrl: settings.fleetServerUrl });
      const data = JSON.parse(result);
      setServerHealth(data.status === "ok" ? "ok" : "error");
      addToast?.(data.status === "ok" ? "success" : "warn", `Server health: ${data.status}`);
    } catch (e) {
      setServerHealth("error");
      addToast?.("error", `Health check failed: ${e}`);
    }
  };

  const handleLoadRevoked = async () => {
    setLoadingRevoked(true);
    try {
      const result = await invoke("list_revoked", { configPath: settings.fleetConfigPath });
      setRevokedKeys(JSON.parse(result));
    } catch (e) {
      addToast?.("error", `Failed to load CRL: ${e}`);
    }
    setLoadingRevoked(false);
  };

  const handleKeyAction = async ({ action, peer, reason, expires, revokedBy }) => {
    if (action === "revoke") {
      await invoke("revoke_peer", { configPath: settings.fleetConfigPath, peer, reason: reason || "administrative", revokedBy: revokedBy || "" });
      addToast?.("success", `Key revoked for "${peer}"`);
    } else {
      await invoke("suspend_peer", { configPath: settings.fleetConfigPath, peer, expires: expires || "7d", revokedBy: revokedBy || "" });
      addToast?.("success", `Key suspended for "${peer}"`);
    }
    setShowKeyModal(null);
    handleLoadRevoked();
    setAuditLog(prev => [{ time: ts(), event: action === "revoke" ? "key_revoke" : "key_suspend", detail: `${action}: ${peer}`, severity: "warn" }, ...prev]);
  };

  const handleReinstate = async (peer) => {
    try {
      await invoke("reinstate_peer", { configPath: settings.fleetConfigPath, peer });
      addToast?.("success", `Key reinstated for "${peer}"`);
      handleLoadRevoked();
      setAuditLog(prev => [{ time: ts(), event: "key_reinstate", detail: `Reinstated: ${peer}`, severity: "info" }, ...prev]);
    } catch (e) {
      addToast?.("error", `Reinstate failed: ${e}`);
    }
  };

  const handleImportPolicy = async () => {
    try {
      const path = await invoke("pick_config_file");
      if (!path) return;
      const config = await invoke("import_config", { path });
      if (setTunnels) {
        setTunnels(prev => [...prev, {
          id: `policy-${Date.now()}`,
          name: config?.name || path.split(/[\\/]/).pop().replace(".toml", ""),
          endpoint: config?.endpoint || "--",
          mode: config?.mode || "hybrid",
          status: "disconnected",
          configPath: path,
        }]);
      }
      addToast?.("success", `Policy imported: ${path.split(/[\\/]/).pop()}`);
    } catch (e) {
      addToast?.("error", `Import failed: ${e}`);
    }
  };

  const handleLoadPolicy = async () => {
    try {
      const result = await invoke("get_policy_config", { configPath: settings.fleetConfigPath });
      setPolicyConfig(JSON.parse(result));
    } catch (e) {
      addToast?.("error", `Failed to load policy: ${e}`);
    }
  };

  const handleLoadAuditLog = async () => {
    try {
      const result = await invoke("read_audit_log", { configPath: settings.fleetConfigPath, maxEntries: 100 });
      setFleetAuditLog(JSON.parse(result));
    } catch (e) {
      addToast?.("error", `Failed to load audit log: ${e}`);
    }
  };

  const handlePostureCheck = async () => {
    setLoadingPosture(true);
    try {
      const result = await invoke("run_posture_check");
      setPostureResult(JSON.parse(result));
      addToast?.(JSON.parse(result).compliant ? "success" : "warn", `Posture score: ${JSON.parse(result).score}/100`);
    } catch (e) {
      addToast?.("error", `Posture check failed: ${e}`);
    }
    setLoadingPosture(false);
  };

  const handleLoadMetrics = async () => {
    try {
      const result = await invoke("get_metrics", {});
      setMetricsData(JSON.parse(result));
    } catch (e) {
      addToast?.("error", `Failed to load metrics: ${e}`);
    }
  };

  const exportAuditLog = (format) => {
    let content = "";
    if (format === "json") {
      content = JSON.stringify(auditLog.map(e => ({ timestamp: e.time, event: e.event, detail: e.detail, severity: e.severity })), null, 2);
    } else {
      content = auditLog.map(e => `<${e.severity === "warn" ? "4" : e.severity === "error" ? "3" : "6"}>1 ${e.time} dybervpn-client - - - ${e.event}: ${e.detail}`).join("\n");
    }
    navigator.clipboard.writeText(content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className={styles.page}>
      {/* Sidebar */}
      <div className={styles.sidebar}>
        <div className={styles.sidebarTitle}>SETTINGS</div>
        {TABS.map(t => (
          <div key={t.id} onClick={() => setSettingsTab(t.id)}
            className={`${styles.tabItem} ${settingsTab === t.id ? styles.tabItemActive : ""}`}>
            <span className={styles.tabIcon}><Icon name={t.icon} size={14} /></span>{t.label}
          </div>
        ))}
      </div>

      {/* Content */}
      <div className={styles.content}>

        {/* SECURITY */}
        {settingsTab === "security" && (
          <div className={styles.sectionAnim}>
            <h3 className={styles.sectionTitle}>Security</h3>
            <p className={styles.sectionDesc}>Network protection and leak prevention settings</p>
            <div className={styles.card}>
              <SettingRow icon="lock" label="Kill Switch" desc="Block all network traffic if the VPN tunnel drops unexpectedly. Prevents data leaks during connection interruptions.">
                <Toggle value={settings.killSwitch} onChange={v => updateSetting("killSwitch", v)} />
              </SettingRow>
              <SettingRow icon="globe" label="DNS Leak Protection" desc="Route all DNS queries through the encrypted tunnel. Prevents your ISP from seeing which domains you visit.">
                <Toggle value={settings.dnsLeakProtection} onChange={v => updateSetting("dnsLeakProtection", v)} />
              </SettingRow>
              <SettingRow icon="refresh" label="Always-On VPN" desc="Automatically reconnect if the tunnel is interrupted. Ensures continuous protection without manual intervention.">
                <Toggle value={settings.alwaysOn} onChange={v => updateSetting("alwaysOn", v)} />
              </SettingRow>
              <SettingRow icon="zap" label="Auto-Connect on Launch" desc="Establish the last active tunnel immediately when DyberVPN starts.">
                <Toggle value={settings.autoConnect} onChange={v => updateSetting("autoConnect", v)} />
              </SettingRow>
              <SettingRow icon="shield" label="Lockdown Mode" desc="Prevent non-admin users from modifying settings or disconnecting tunnels. For managed enterprise deployments." last>
                <Toggle value={settings.lockdownMode} onChange={v => updateSetting("lockdownMode", v)} />
              </SettingRow>
            </div>
            {settings.lockdownMode && (
              <div className={styles.lockdownWarn}>
                <span className={styles.lockdownWarnIcon}><Icon name="shield" size={18} color="#f59e0b" /></span>
                <div>
                  <div className={styles.lockdownWarnTitle}>Lockdown Mode Active</div>
                  <div className={styles.lockdownWarnText}>
                    Settings and tunnel controls are locked. Users cannot modify security policies, disconnect active tunnels, or change cryptographic configurations. This mode is designed for fleet-managed deployments where an administrator controls the VPN policy.
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* NETWORK */}
        {settingsTab === "network" && (
          <div className={styles.sectionAnim}>
            <h3 className={styles.sectionTitle}>Network</h3>
            <p className={styles.sectionDesc}>Tunnel networking and split tunneling configuration</p>
            <div className={styles.card}>
              <SettingRow icon="ruler" label="MTU" desc="Maximum Transmission Unit size. Lower values improve compatibility; higher values improve throughput.">
                <NumInput value={settings.mtu} onChange={v => updateSetting("mtu", v)} min={1280} max={1500} />
              </SettingRow>
              <SettingRow icon="plug" label="Listen Port" desc="UDP port for WireGuard protocol traffic.">
                <NumInput value={settings.listenPort} onChange={v => updateSetting("listenPort", v)} min={1024} max={65535} />
              </SettingRow>
              <SettingRow icon="heart" label="Persistent Keepalive" desc="Interval in seconds to send keepalive packets. Keeps NAT mappings alive." last>
                <NumInput value={settings.keepalive} onChange={v => updateSetting("keepalive", v)} min={0} max={300} suffix="sec" />
              </SettingRow>
            </div>
            <div className={styles.card}>
              <SettingRow icon="shuffle" label="Split Tunneling" desc="Route only specific subnets through the VPN tunnel. All other traffic uses your normal connection.">
                <Toggle value={settings.splitTunnel} onChange={v => updateSetting("splitTunnel", v)} />
              </SettingRow>
              {settings.splitTunnel && (
                <div className={styles.splitTunnelBox}>
                  <div className={styles.splitTunnelLabel}>ROUTED SUBNETS (CIDR notation, one per line)</div>
                  <textarea value={settings.splitTunnelRules} onChange={e => updateSetting("splitTunnelRules", e.target.value)}
                    rows={5} className={styles.splitTunnelTextarea} />
                  <div className={styles.splitTunnelHint}>Only traffic destined for these subnets will traverse the VPN tunnel. All other traffic exits directly.</div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* CRYPTOGRAPHY */}
        {settingsTab === "crypto" && (
          <div className={styles.sectionAnim}>
            <h3 className={styles.sectionTitle}>Cryptography</h3>
            <p className={styles.sectionDesc}>Post-quantum cryptographic backend and algorithm configuration</p>
            <div className={styles.card}>
              <SettingRow icon="gear" label="Crypto Backend" desc="Hardware accelerated (QUAC 100) or pure software. Auto will detect hardware at startup.">
                <Select value={settings.cryptoBackend} onChange={v => updateSetting("cryptoBackend", v)} options={[
                  { value: "auto", label: "Auto Detect" }, { value: "software", label: "Software Only" }, { value: "quac100", label: "QUAC 100 HW" },
                ]} />
              </SettingRow>
              <SettingRow icon="key" label="Default Mode" desc="Cryptographic mode for new tunnel configurations.">
                <Select value={settings.preferredMode} onChange={v => updateSetting("preferredMode", v)} options={[
                  { value: "hybrid", label: "Hybrid (recommended)" }, { value: "pqonly", label: "PQ-Only (CNSA 2.0)" }, { value: "classic", label: "Classic (WireGuard)" },
                ]} />
              </SettingRow>
              <SettingRow icon="refresh" label="Key Rotation Interval" desc="How often session keys are renegotiated. Lower = more secure, slightly more overhead." last>
                <NumInput value={settings.keyRotationInterval} onChange={v => updateSetting("keyRotationInterval", v)} min={30} max={3600} suffix="sec" />
              </SettingRow>
            </div>
            <div className={styles.sectionLabel}>ACTIVE ALGORITHM SUITE</div>
            <div className={styles.algoGrid}>
              {[
                { label: "Key Exchange", algo: settings.preferredMode === "classic" ? "X25519 (Curve25519)" : "ML-KEM-768 + X25519", fips: settings.preferredMode !== "classic" ? "FIPS 203" : "\u2014", level: settings.preferredMode !== "classic" ? "NIST Level 3" : "128-bit classical", color: "#a78bfa" },
                { label: "Authentication", algo: settings.preferredMode === "pqonly" ? "ML-DSA-65" : "Ed25519", fips: settings.preferredMode === "pqonly" ? "FIPS 204" : "\u2014", level: settings.preferredMode === "pqonly" ? "NIST Level 3" : "128-bit classical", color: "#34d399" },
                { label: "Symmetric Cipher", algo: "ChaCha20-Poly1305", fips: "\u2014", level: "256-bit (quantum-safe)", color: "#38bdf8" },
                { label: "Key Derivation", algo: "HKDF-SHA256", fips: "FIPS 198-1", level: "256-bit", color: "#f59e0b" },
              ].map(a => (
                <div key={a.label} className={styles.algoCard}>
                  <div className={styles.algoLabel}>{a.label.toUpperCase()}</div>
                  <div className={styles.algoName} style={{ color: a.color }}>{a.algo}</div>
                  <div className={styles.algoLevel}>{a.level} {a.fips !== "\u2014" && `\u2022 ${a.fips}`}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* COMPLIANCE */}
        {settingsTab === "compliance" && (
          <div className={styles.sectionAnim}>
            <h3 className={styles.sectionTitle}>Compliance</h3>
            <p className={styles.sectionDesc}>CNSA 2.0 alignment, FIPS status, and audit trail</p>
            <div className={styles.sectionLabel}>CNSA 2.0 ALIGNMENT</div>
            <div className={styles.card}>
              {[
                { req: "Key Exchange: ML-KEM (FIPS 203)", status: settings.preferredMode !== "classic" ? "pass" : "warn", detail: settings.preferredMode !== "classic" ? "ML-KEM-768 active (Level 3). Upgrade to ML-KEM-1024 for Level 5." : "Classical X25519 only \u2014 not quantum resistant" },
                { req: "Digital Signature: ML-DSA (FIPS 204)", status: settings.preferredMode === "pqonly" ? "pass" : "warn", detail: settings.preferredMode === "pqonly" ? "ML-DSA-65 active for authentication" : "Ed25519 classical auth \u2014 switch to PQ-Only for ML-DSA" },
                { req: "Symmetric Encryption: AES-256 or equivalent", status: "pass", detail: "ChaCha20-Poly1305 (256-bit) \u2014 quantum resistant symmetric cipher" },
                { req: "Hashing: SHA-384 or SHA-512", status: "info", detail: "HKDF-SHA256 in use. SHA-384/512 upgrade planned for CNSA 2.0 strict." },
                { req: "No hybrid/transitional cryptography", status: settings.preferredMode === "pqonly" ? "pass" : "info", detail: settings.preferredMode === "pqonly" ? "PQ-Only mode: no classical fallback" : "Hybrid mode uses classical + PQ (CNSA 2.0 considers hybrid transitional)" },
              ].map((c, i, arr) => (
                <div key={i} className={`${styles.cnsaItem} ${i === arr.length - 1 ? styles.cnsaItemLast : ""}`}>
                  <span className={styles.cnsaIcon}>
                    {c.status === "pass" ? <Icon name="shield" size={14} color="#34d399" /> : c.status === "warn" ? <Icon name="shield" size={14} color="#f59e0b" /> : <Icon name="info" size={14} color="#38bdf8" />}
                  </span>
                  <div style={{ flex: 1 }}>
                    <div className={`${styles.cnsaReq} ${styles[`cnsaReq${c.status.charAt(0).toUpperCase() + c.status.slice(1)}`]}`}>{c.req}</div>
                    <div className={styles.cnsaDetail}>{c.detail}</div>
                  </div>
                </div>
              ))}
            </div>
            <div className={styles.sectionLabel}>FIPS 140-3 STATUS</div>
            <div className={styles.fipsCard}>
              <span className={styles.fipsIcon}><Icon name="construction" size={20} color="#f59e0b" /></span>
              <div>
                <div className={styles.fipsTitle}>FIPS 140-3 Validation In Progress</div>
                <div className={styles.fipsText}>
                  The DyberVPN cryptographic module is undergoing FIPS 140-3 Level 3 validation. Software backend uses aws-lc-rs which has an active FIPS submission. Target: CMVP certificate by Q4 2026.
                </div>
                <div className={styles.fipsMeta}>
                  <div><span className={styles.fipsMetaKey}>Module: </span><span className={styles.fipsMetaVal}>dybervpn-crypto v0.1.1</span></div>
                  <div><span className={styles.fipsMetaKey}>Backend: </span><span className={styles.fipsMetaVal}>aws-lc-rs (FIPS pending)</span></div>
                  <div><span className={styles.fipsMetaKey}>Level: </span><span className={styles.fipsMetaVal}>3 (targeted)</span></div>
                </div>
              </div>
            </div>
            <div className={styles.auditHeader}>
              <div className={styles.sectionLabel}>AUDIT LOG ({auditLog.length} events)</div>
              <div className={styles.auditActions}>
                <button onClick={() => exportAuditLog("json")} className={`${styles.auditBtn} ${copied ? styles.auditBtnCopied : ""}`}>
                  {copied ? "\u2713 Copied" : "Copy JSON"}
                </button>
                <button onClick={() => exportAuditLog("syslog")} className={styles.auditBtn}>Copy Syslog</button>
                <button onClick={() => setAuditLog([])} className={styles.auditBtn}>Clear</button>
              </div>
            </div>
            <div className={styles.auditList}>
              {auditLog.length === 0 ? (
                <div className={styles.auditEmpty}>No audit events recorded</div>
              ) : auditLog.map((e, i) => (
                <div key={i} className={styles.auditRow}>
                  <span className={styles.auditTime}>{e.time}</span>
                  <span className={styles.auditSev} style={{ color: e.severity === "warn" ? "#f59e0b" : e.severity === "error" ? "#ef4444" : "#4b5563" }}>
                    {e.severity === "warn" ? "\u26A0" : e.severity === "error" ? "\u2717" : "\u00B7"}
                  </span>
                  <span className={styles.auditEvent}>{e.event}</span>
                  <span className={styles.auditDetail}>{e.detail}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* FLEET */}
        {settingsTab === "fleet" && (
          <div className={styles.sectionAnim}>
            <h3 className={styles.sectionTitle}>Fleet Management</h3>
            <p className={styles.sectionDesc}>Centralized device enrollment and policy management for enterprise deployments</p>

            {/* Enrollment status — dynamic based on enrollment state */}
            {!settings.fleetEnrolled ? (
              <div className={styles.enrollCard}>
                <div className={styles.enrollIcon}><Icon name="building" size={28} color="#6b7280" /></div>
                <div className={styles.enrollTitle}>Not Enrolled</div>
                <div className={styles.enrollDesc}>
                  This device is running in standalone mode. Connect to a DyberVPN Management Server to enable centralized policy distribution, fleet monitoring, certificate-based authentication, and automated key rotation.
                </div>
                <div className={styles.enrollActions}>
                  <button className={styles.enrollBtn} onClick={() => setShowEnrollModal(true)}>Enroll Device</button>
                  <button className={styles.enrollBtnSecondary} onClick={handleImportPolicy}>Import Policy File</button>
                </div>
              </div>
            ) : (
              <>
                {/* Enrolled status card */}
                <div className={styles.enrolledCard}>
                  <div className={styles.enrolledHeader}>
                    <div className={styles.enrolledIcon}><Icon name="shield" size={24} color="#34d399" /></div>
                    <div>
                      <div className={styles.enrolledTitle}>
                        <span className={styles.enrolledDot} /> Enrolled
                      </div>
                      <div className={styles.enrolledServer}>{settings.fleetServerUrl}</div>
                    </div>
                  </div>
                  <div className={styles.enrolledDetails}>
                    <div className={styles.enrolledRow}><span>Device Name</span><span>{settings.fleetDeviceName}</span></div>
                    <div className={styles.enrolledRow}><span>Assigned IP</span><span>{settings.fleetAssignedIp}</span></div>
                    <div className={styles.enrolledRow}><span>Mode</span><span>{settings.fleetMode}</span></div>
                    <div className={styles.enrolledRow}>
                      <span>Server Health</span>
                      <span className={serverHealth === "ok" ? styles.healthOk : serverHealth === "error" ? styles.healthError : ""}>
                        {serverHealth === "ok" ? "Healthy" : serverHealth === "error" ? "Unreachable" : "Not checked"}
                      </span>
                    </div>
                    <div className={styles.enrolledRow}><span>Enrolled</span><span>{settings.fleetEnrolledAt ? new Date(settings.fleetEnrolledAt).toLocaleDateString() : "\u2014"}</span></div>
                    <div className={styles.enrolledRow}><span>Config</span><span>{settings.fleetConfigPath?.split(/[\\/]/).pop() || "\u2014"}</span></div>
                  </div>
                  <div className={styles.enrollActions}>
                    <button className={styles.healthBtn} onClick={handleHealthCheck}>Check Health</button>
                    <button className={styles.enrollBtnSecondary} onClick={handleImportPolicy}>Import Policy</button>
                    <button className={styles.enrollBtnSecondary} onClick={() => setShowUnenrollConfirm(true)}>Unenroll</button>
                  </div>
                </div>

                {/* Key lifecycle management */}
                <div className={styles.sectionLabel}>KEY LIFECYCLE MANAGEMENT</div>
                <div className={styles.card}>
                  <SettingRow icon="key" label="Revoke Peer Key" desc="Permanently revoke a peer's key. The peer will be disconnected and cannot reconnect until reinstated.">
                    <button className={styles.dangerBtn} onClick={() => setShowKeyModal("revoke")}>Revoke</button>
                  </SettingRow>
                  <SettingRow icon="clock" label="Suspend Peer Key" desc="Temporarily suspend a peer's access. The suspension expires automatically after the chosen duration.">
                    <button className={styles.warnBtn} onClick={() => setShowKeyModal("suspend")}>Suspend</button>
                  </SettingRow>
                  <SettingRow icon="refresh" label="Reinstate Peer Key" desc="Re-enable a previously revoked or suspended key. View the revocation list below to reinstate.">
                    <button className={styles.successBtn} onClick={handleLoadRevoked}>{loadingRevoked ? "Loading..." : "View CRL"}</button>
                  </SettingRow>
                </div>

                {/* Revoked keys table */}
                {revokedKeys.length > 0 && (
                  <>
                    <div className={styles.sectionLabel}>REVOKED / SUSPENDED KEYS ({revokedKeys.length})</div>
                    <div className={styles.revokedList}>
                      {revokedKeys.map((entry, i) => (
                        <div key={i} className={styles.revokedRow}>
                          <span className={styles.revokedName}>{entry.peer_name || entry.name || "unknown"}</span>
                          <span className={`${styles.revokedStatus} ${entry.expires_at ? styles.revokedStatusSuspended : styles.revokedStatusRevoked}`}>
                            {entry.expires_at ? "suspended" : "revoked"}
                          </span>
                          <span className={styles.revokedReason}>{entry.reason || "\u2014"}</span>
                          <span className={styles.revokedDate}>{entry.revoked_at ? new Date(entry.revoked_at).toLocaleDateString() : "\u2014"}</span>
                          <button className={styles.reinstateBtn} onClick={() => handleReinstate(entry.peer_name || entry.name)}>Reinstate</button>
                        </div>
                      ))}
                    </div>
                  </>
                )}
              </>
            )}

            {/* Policy Engine — always visible when enrolled */}
            {settings.fleetEnrolled && (
              <>
                <div className={styles.sectionLabel}>
                  POLICY ENGINE
                  {!policyConfig && <button className={styles.inlineBtn} onClick={handleLoadPolicy}>Load Policy</button>}
                </div>
                {policyConfig ? (
                  <div className={styles.card}>
                    <SettingRow icon="satellite" label="Policy Enforcement" desc={`Default action: ${policyConfig.policy?.default_action || "deny"}`}>
                      <span className={styles.diagValue} style={{ color: policyConfig.policy?.enabled ? "#34d399" : "#ef4444" }}>
                        {policyConfig.policy?.enabled ? "Enabled" : "Disabled"}
                      </span>
                    </SettingRow>
                    {(policyConfig.policy?.role || []).map((role, i, arr) => (
                      <SettingRow key={role.name} icon="user" label={role.name} desc={`${(role.peers || []).length} peer(s), ${(role.rule || []).length} rule(s)`} last={i === arr.length - 1}>
                        <span className={styles.diagValue} style={{ color: "#a78bfa" }}>
                          {(role.rule || []).map(r => r.action).filter((v, j, a) => a.indexOf(v) === j).join("/")}
                        </span>
                      </SettingRow>
                    ))}
                  </div>
                ) : (
                  <div className={styles.card}>
                    <SettingRow icon="satellite" label="Policy Engine" desc="Per-peer role-based access control with CIDR rules, port filtering, and hot-reload." last>
                      <button className={styles.successBtn} onClick={handleLoadPolicy}>Load</button>
                    </SettingRow>
                  </div>
                )}

                {/* Security / Key Rotation Config */}
                {policyConfig?.security && (
                  <>
                    <div className={styles.sectionLabel}>KEY ROTATION & SESSION SECURITY</div>
                    <div className={styles.card}>
                      <SettingRow icon="refresh" label="Key Max Age" desc="Force key rotation after this period.">
                        <span className={styles.diagValue} style={{ color: "#f59e0b" }}>{policyConfig.security.key_max_age_hours || 720}h</span>
                      </SettingRow>
                      <SettingRow icon="clock" label="Session Max Age" desc="Force re-handshake after this period.">
                        <span className={styles.diagValue} style={{ color: "#f59e0b" }}>{policyConfig.security.session_max_age_hours || 24}h</span>
                      </SettingRow>
                      <SettingRow icon="shield" label="CRL Check Interval" desc="How often to scan for revoked/expired peers.">
                        <span className={styles.diagValue} style={{ color: "#6b7280" }}>{policyConfig.security.check_interval_secs || 300}s</span>
                      </SettingRow>
                      <SettingRow icon="lock" label="Auto-Disconnect Revoked" desc="Immediately drop sessions for revoked keys." last>
                        <span className={styles.diagValue} style={{ color: policyConfig.security.auto_disconnect_revoked !== false ? "#34d399" : "#ef4444" }}>
                          {policyConfig.security.auto_disconnect_revoked !== false ? "Enabled" : "Disabled"}
                        </span>
                      </SettingRow>
                    </div>
                  </>
                )}
              </>
            )}

            {/* SIEM / Audit Log Viewer — enrolled only */}
            {settings.fleetEnrolled && (
              <>
                <div className={styles.sectionLabel}>
                  SIEM / AUDIT LOG
                  {!fleetAuditLog && <button className={styles.inlineBtn} onClick={handleLoadAuditLog}>Load Audit Log</button>}
                  {fleetAuditLog && <button className={styles.inlineBtn} onClick={handleLoadAuditLog}>Refresh</button>}
                </div>
                {fleetAuditLog && fleetAuditLog.length > 0 ? (
                  <div className={styles.auditList}>
                    {fleetAuditLog.map((e, i) => (
                      <div key={i} className={styles.auditRow}>
                        <span className={styles.auditTime}>{e.timestamp ? new Date(e.timestamp).toLocaleTimeString("en-US", { hour12: false }) : "\u2014"}</span>
                        <span className={styles.auditSev} style={{ color: e.outcome === "denied" || e.outcome === "failure" ? "#ef4444" : e.outcome === "error" ? "#f59e0b" : "#4b5563" }}>
                          {e.outcome === "denied" ? "\u2717" : e.outcome === "failure" || e.outcome === "error" ? "\u26A0" : "\u00B7"}
                        </span>
                        <span className={styles.auditEvent}>{e.event_type || e.event || "\u2014"}</span>
                        <span className={styles.auditDetail}>{e.message || e.detail || `${e.peer_name || ""}${e.dest_ip ? ` \u2192 ${e.dest_ip}:${e.dest_port}` : ""}`}</span>
                      </div>
                    ))}
                  </div>
                ) : fleetAuditLog ? (
                  <div className={styles.card}><div className={styles.auditEmpty}>No audit events recorded</div></div>
                ) : (
                  <div className={styles.card}>
                    <SettingRow icon="edit" label="Structured Audit Log" desc="NDJSON log with connections, handshakes, policy decisions, key management, and enrollment events." last>
                      <button className={styles.successBtn} onClick={handleLoadAuditLog}>Load</button>
                    </SettingRow>
                  </div>
                )}
              </>
            )}

            {/* Zero Trust Posture — always visible */}
            <div className={styles.sectionLabel}>
              ZERO TRUST POSTURE
              <button className={styles.inlineBtn} onClick={handlePostureCheck}>{loadingPosture ? "Checking..." : "Run Check"}</button>
            </div>
            {postureResult ? (
              <>
                <div className={postureResult.compliant ? styles.postureCardPass : styles.postureCardFail}>
                  <div className={styles.postureHeader}>
                    <div className={styles.postureScore}>
                      <span className={styles.postureScoreNum}>{postureResult.score}</span>
                      <span className={styles.postureScoreMax}>/100</span>
                    </div>
                    <div>
                      <div className={styles.postureVerdict} style={{ color: postureResult.compliant ? "#34d399" : "#ef4444" }}>
                        {postureResult.compliant ? "Compliant" : "Non-Compliant"}
                      </div>
                      <div className={styles.postureThreshold}>Threshold: {postureResult.threshold}</div>
                    </div>
                  </div>
                </div>
                <div className={styles.card}>
                  {postureResult.checks.map((check, i) => (
                    <SettingRow key={check.name} icon={check.passed ? "shield" : "info"} label={check.name} desc={check.detail} last={i === postureResult.checks.length - 1}>
                      <span className={styles.diagValue} style={{ color: check.passed ? "#34d399" : "#ef4444" }}>
                        {check.passed ? "Pass" : "Fail"} ({check.weight}pts)
                      </span>
                    </SettingRow>
                  ))}
                </div>
              </>
            ) : (
              <div className={styles.card}>
                <SettingRow icon="shield" label="Device Posture" desc="OS version, firewall, disk encryption, antivirus, and screen lock compliance checks." last>
                  <button className={styles.successBtn} onClick={handlePostureCheck}>{loadingPosture ? "..." : "Check"}</button>
                </SettingRow>
              </div>
            )}

            {/* Fleet Dashboard / Metrics — enrolled only */}
            {settings.fleetEnrolled && (
              <>
                <div className={styles.sectionLabel}>
                  FLEET DASHBOARD
                  <button className={styles.inlineBtn} onClick={handleLoadMetrics}>Query Metrics</button>
                </div>
                {metricsData ? (
                  metricsData.available ? (
                    <div className={styles.card}>
                      <SettingRow icon="chart" label="Prometheus Metrics" desc="Live metrics from the running DyberVPN daemon." last>
                        <span className={styles.diagValue} style={{ color: "#34d399" }}>Connected</span>
                      </SettingRow>
                    </div>
                  ) : (
                    <div className={styles.metricsOffline}>
                      <span className={styles.metricsOfflineIcon}><Icon name="chart" size={18} color="#6b7280" /></span>
                      <div>
                        <div className={styles.metricsOfflineTitle}>Metrics Server Offline</div>
                        <div className={styles.metricsOfflineText}>{metricsData.message}</div>
                        <div className={styles.metricsOfflineHint}>Run: <code>dybervpn up -c config.toml --metrics 127.0.0.1:9090</code></div>
                      </div>
                    </div>
                  )
                ) : (
                  <div className={styles.card}>
                    <SettingRow icon="chart" label="Prometheus Metrics" desc="Handshakes, throughput, errors, active sessions. Connect to a running daemon's /metrics endpoint." last>
                      <button className={styles.successBtn} onClick={handleLoadMetrics}>Connect</button>
                    </SettingRow>
                  </div>
                )}
              </>
            )}

            {/* Fleet capabilities grid */}
            <div className={styles.sectionLabel}>{settings.fleetEnrolled ? "FLEET CAPABILITIES" : "FLEET CAPABILITIES (requires enrollment)"}</div>
            <div className={styles.fleetGrid}>
              {[
                { icon: "scroll", title: "Certificate Auth", desc: "PQ certificate-based authentication with ML-DSA-65 digital signatures. No shared secrets in PQ-Only mode.", tag: "Active", active: settings.preferredMode === "pqonly", partial: settings.preferredMode !== "pqonly" },
                { icon: "satellite", title: "Policy Push", desc: "Per-peer role-based access control with CIDR rules, port filtering, and hot-reload. PolicyEngine enforces zero-trust network segmentation.", tag: "Active", active: true },
                { icon: "chart", title: "Fleet Dashboard", desc: "Prometheus-compatible metrics (handshakes, throughput, errors, sessions) with /metrics endpoint for Grafana integration.", tag: "Planned", active: false },
                { icon: "refresh", title: "Auto Key Rotation", desc: "Session re-keying, key age enforcement, and manual revoke/suspend/reinstate via CRL. Configurable max age and check intervals.", tag: "Partial", active: false, partial: true },
                { icon: "edit", title: "SIEM Integration", desc: "NDJSON structured audit logging with 25+ event types. Covers connections, handshakes, policy decisions, key management, and enrollment.", tag: "Active", active: true },
                { icon: "shield", title: "Zero Trust Posture", desc: "Device health checks, OS version verification, and endpoint compliance scoring before tunnel establishment.", tag: "Planned", active: false },
              ].map(f => (
                <div key={f.title} className={styles.fleetCard}>
                  <div className={styles.fleetCardHeader}>
                    <div className={styles.fleetCardLeft}>
                      <span className={styles.fleetCardIcon}><Icon name={f.icon} size={14} /></span>
                      <span className={styles.fleetCardTitle}>{f.title}</span>
                    </div>
                    <span className={f.active ? styles.fleetCardTagActive : f.partial ? styles.fleetCardTagPartial : styles.fleetCardTag}>{f.active ? "Active" : f.tag}</span>
                  </div>
                  <div className={styles.fleetCardDesc}>{f.desc}</div>
                </div>
              ))}
            </div>
            <div className={styles.ossCallout}>
              <span className={styles.ossIcon}><Icon name="unlock" size={18} color="#34d399" /></span>
              <div>
                <div className={styles.ossTitle}>Open Source Advantage</div>
                <div className={styles.ossText}>
                  Unlike proprietary alternatives, DyberVPN's core — including the post-quantum handshake, tunnel implementation, and cryptographic backend — is fully open source (Apache 2.0). Your security team can audit every line. No black-box protocols. No vendor lock-in. The fleet management server will also be open source.
                </div>
              </div>
            </div>

            {/* Fleet modals */}
            {showEnrollModal && (
              <EnrollModal onConfirm={handleEnroll} onCancel={() => setShowEnrollModal(false)} />
            )}
            {showKeyModal && (
              <KeyLifecycleModal action={showKeyModal} onConfirm={handleKeyAction} onCancel={() => setShowKeyModal(null)} />
            )}
            {showUnenrollConfirm && (
              <ConfirmModal
                title="Unenroll Device"
                message="Remove this device from fleet management? The enrollment configuration will be cleared. You can re-enroll at any time."
                confirmLabel="Unenroll"
                onConfirm={handleUnenroll}
                onCancel={() => setShowUnenrollConfirm(false)}
              />
            )}
          </div>
        )}

        {/* APPLICATION */}
        {settingsTab === "app" && (
          <div className={styles.sectionAnim}>
            <h3 className={styles.sectionTitle}>Application</h3>
            <p className={styles.sectionDesc}>Desktop client preferences and update settings</p>
            <div className={styles.card}>
              <SettingRow icon="bell" label="System Tray" desc="Keep DyberVPN running in the system tray when the window is closed.">
                <Toggle value={settings.systemTray} onChange={v => updateSetting("systemTray", v)} />
              </SettingRow>
              <SettingRow icon="rocket" label="Start Minimized" desc="Launch DyberVPN minimized to the system tray on startup.">
                <Toggle value={settings.startMinimized} onChange={v => updateSetting("startMinimized", v)} />
              </SettingRow>
              <SettingRow icon="download" label="Auto-Update" desc="Automatically download and install new versions of DyberVPN.">
                <Toggle value={settings.autoUpdate} onChange={v => updateSetting("autoUpdate", v)} />
              </SettingRow>
              <SettingRow icon="shuffle" label="Update Channel" desc="Stable releases are recommended. Beta channel provides early access to new features.">
                <Select value={settings.updateChannel} onChange={v => updateSetting("updateChannel", v)} width={120} options={[
                  { value: "stable", label: "Stable" }, { value: "beta", label: "Beta" }, { value: "nightly", label: "Nightly" },
                ]} />
              </SettingRow>
              <SettingRow icon="clipboard" label="Log Level" desc="Controls verbosity of application logs.">
                <Select value={settings.logLevel} onChange={v => updateSetting("logLevel", v)} width={120} options={[
                  { value: "error", label: "Error" }, { value: "warn", label: "Warning" }, { value: "info", label: "Info" }, { value: "debug", label: "Debug" }, { value: "trace", label: "Trace" },
                ]} />
              </SettingRow>
              <SettingRow icon="folder" label="Config Directory" last>
                <span className={styles.diagValue} style={{ color: "#6b7280" }}>/etc/dybervpn/</span>
              </SettingRow>
            </div>
            <div className={styles.sectionLabel}>DIAGNOSTICS</div>
            <div className={styles.card}>
              <SettingRow icon="monitor" label="Platform" desc={navigator.platform || "Unknown"}>
                <span className={styles.diagValue} style={{ color: "#6b7280" }}>{navigator.userAgent.includes("Windows") ? "Windows" : navigator.userAgent.includes("Mac") ? "macOS" : "Linux"}</span>
              </SettingRow>
              <SettingRow icon="wrench" label="Crypto Backend">
                <span className={styles.diagValue} style={{ color: "#34d399" }}>Software (ml-kem + ml-dsa)</span>
              </SettingRow>
              <SettingRow icon="hexagon" label="QUAC 100 Hardware">
                <span className={styles.diagValue} style={{ color: "#f59e0b" }}>Not Detected</span>
              </SettingRow>
              <SettingRow icon="dice" label="Entropy Source" last>
                <span className={styles.diagValue} style={{ color: "#6b7280" }}>OS (urandom / BCryptGenRandom)</span>
              </SettingRow>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
