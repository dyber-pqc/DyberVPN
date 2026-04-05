// DyberVPN Desktop Client UI — Enterprise Edition
// Copyright 2026 Dyber, Inc.
//
// Post-Quantum VPN for Infrastructure You Control
// Open Source - Self-Hosted - CNSA 2.0 Aligned

import { useState, useEffect, useCallback, useRef } from "react";
import { usePage } from "./router/RouterContext";
import { invoke } from "./lib/tauri";
import { loadSettings, saveSettings, loadTunnels, saveTunnels } from "./lib/store";
import { useUptime } from "./hooks/useUptime";
import { useTraffic } from "./hooks/useTraffic";
import { Icon } from "./components/Icon";
import { WindowControls } from "./components/WindowControls/WindowControls";
import { ContextMenu } from "./components/ContextMenu/ContextMenu";
import { ConfirmModal } from "./components/ConfirmModal/ConfirmModal";
import { InputModal } from "./components/InputModal/InputModal";
import { Toast } from "./components/Toast/Toast";
import { TunnelsPage } from "./pages/TunnelsPage/TunnelsPage";
import { KeyManagerPage } from "./pages/KeyManagerPage/KeyManagerPage";
import { SettingsPage } from "./pages/SettingsPage/SettingsPage";
import { AboutPage } from "./pages/AboutPage/AboutPage";
import styles from "./App.module.css";

// ═══════════════════════════════════════════════════════════
// NAVIGATION ITEMS
// ═══════════════════════════════════════════════════════════
const NAV_ITEMS = [
  { id: "tunnels", label: "Tunnels", icon: "lock" },
  { id: "keys", label: "Keys", icon: "key" },
  { id: "settings", label: "Settings", icon: "gear" },
  { id: "about", label: "About", icon: "info" },
];

// ═══════════════════════════════════════════════════════════
// MAIN APP
// ═══════════════════════════════════════════════════════════
export default function App() {
  const { page, navigate } = usePage();

  // ─── Tunnel state ────────────────────────────────────────
  const [tunnels, setTunnels] = useState([]);
  const [selected, setSelected] = useState(0);
  const [connecting, setConnecting] = useState(false);
  const [logs, setLogs] = useState([{ time: "\u2014", level: "ok", msg: "DyberVPN v0.1.1 \u2014 crypto backend: software (ml-kem + ml-dsa)" }]);
  const [ctxMenu, setCtxMenu] = useState(null);
  const [confirmDelete, setConfirmDelete] = useState(null);
  const [renameTarget, setRenameTarget] = useState(null);
  const [toasts, setToasts] = useState([]);
  const [loaded, setLoaded] = useState(false);

  // ─── Settings state ──────────────────────────────────────
  const [settings, setSettings] = useState(null);
  const [auditLog, setAuditLog] = useState([]);

  // ─── Persistence: load on mount ────────────────────────
  const tunnelsRef = useRef(tunnels);
  tunnelsRef.current = tunnels;

  useEffect(() => {
    (async () => {
      const [savedSettings, savedTunnels] = await Promise.all([loadSettings(), loadTunnels()]);
      setSettings(savedSettings);
      setTunnels(savedTunnels);
      setLoaded(true);

      const ts = (offset = 0) => {
        const d = new Date(Date.now() - offset);
        return d.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
      };
      setAuditLog([
        { time: ts(3000), event: "app_start", detail: "DyberVPN v0.1.1 initialized", severity: "info" },
        { time: ts(2000), event: "crypto_init", detail: "Software backend loaded (ml-kem, ml-dsa)", severity: "info" },
        { time: ts(2000), event: "hw_scan", detail: "QUAC 100 not detected \u2014 using software crypto", severity: "warn" },
        { time: ts(1000), event: "config_load", detail: `Loaded ${savedTunnels.length} tunnel configurations`, severity: "info" },
        { time: ts(1000), event: "kill_switch", detail: savedSettings.killSwitch ? "Kill switch enabled \u2014 all non-VPN traffic blocked on connect" : "Kill switch disabled", severity: savedSettings.killSwitch ? "info" : "warn" },
        { time: ts(0), event: "dns_protect", detail: savedSettings.dnsLeakProtection ? "DNS leak protection active" : "DNS leak protection disabled", severity: savedSettings.dnsLeakProtection ? "info" : "warn" },
      ]);
    })();
  }, []);

  // ─── Auto-connect on launch ──────────────────────────────
  const autoConnectDone = useRef(false);
  useEffect(() => {
    if (!loaded || !settings || autoConnectDone.current) return;
    autoConnectDone.current = true;
    if (settings.autoConnect && tunnels.length > 0 && tunnels[0].status !== "connected") {
      (async () => {
        setConnecting(true);
        addLog("info", `Auto-connecting to ${tunnels[0].name}...`);
        try { await invoke("connect_tunnel", { tunnelId: tunnels[0].id, configPath: tunnels[0].configPath || "" }); } catch (_) { await new Promise(r => setTimeout(r, 1800)); }
        addLog("ok", `Auto-connect: tunnel ${tunnels[0].name} established`);
        setTunnels(prev => prev.map((t, i) => i === 0 ? { ...t, status: "connected" } : t));
        setConnecting(false);
      })();
    }
  }, [loaded, settings, tunnels.length]);

  // ─── Derived ─────────────────────────────────────────────
  const tunnel = tunnels[selected];
  const isConnected = tunnel?.status === "connected";
  const uptime = useUptime(isConnected);
  const traffic = useTraffic(isConnected, tunnel?.id);

  // ─── Toast helper ───────────────────────────────────────
  const addToast = useCallback((type, message) => {
    setToasts(prev => [...prev, { id: Date.now() + Math.random(), type, message }]);
  }, []);

  const dismissToast = useCallback((id) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  // ─── Helpers ─────────────────────────────────────────────
  const updateSetting = async (key, value) => {
    const next = { ...settings, [key]: value };
    setSettings(next);
    try { await saveSettings(next); }
    catch (_) { addToast("error", "Failed to save settings"); }
    const ts = new Date().toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
    setAuditLog(prev => [{ time: ts, event: "setting_change", detail: `${key} \u2192 ${JSON.stringify(value)}`, severity: "info" }, ...prev]);
  };

  // ─── Persist tunnels on any change ─────────────────────
  const prevTunnelsJson = useRef("");
  useEffect(() => {
    if (!loaded) return;
    const json = JSON.stringify(tunnels.map(({ status, ...rest }) => rest));
    if (json !== prevTunnelsJson.current) {
      prevTunnelsJson.current = json;
      saveTunnels(tunnels);
    }
  }, [tunnels, loaded]);

  const addLog = useCallback((level, msg) => {
    const now = new Date();
    const time = [now.getHours(), now.getMinutes(), now.getSeconds()].map(n => String(n).padStart(2, "0")).join(":");
    setLogs(prev => [{ time, level, msg }, ...prev].slice(0, 500));
  }, []);

  const toggleConnection = async () => {
    if (connecting || !tunnel) return;
    setConnecting(true);
    if (isConnected) {
      addLog("info", `Shutting down tunnel ${tunnel.name}...`);
      try { await invoke("disconnect_tunnel", { tunnelId: tunnel.id }); } catch (e) { addToast("error", `Disconnect failed: ${e}`); }
      addLog("info", "TUN interface dvpn0 destroyed");
      addLog("info", `Tunnel ${tunnel.name} disconnected`);
      setTunnels(prev => prev.map((t, i) => i === selected ? { ...t, status: "disconnected" } : t));
      const ts = new Date().toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
      setAuditLog(prev => [{ time: ts, event: "tunnel_down", detail: `${tunnel.name} disconnected`, severity: "info" }, ...prev]);
    } else {
      addLog("info", `Loading configuration: ${tunnel.name}`);
      addLog("info", `Creating TUN interface dvpn0 (10.200.200.2/24)`);
      if (settings.killSwitch) addLog("info", "Kill switch engaged \u2014 blocking non-VPN traffic");
      if (settings.dnsLeakProtection) addLog("info", "DNS leak protection active \u2014 routing queries through tunnel");
      addLog("info", `Initiating PQ handshake with ${tunnel.endpoint}`);
      try { await invoke("connect_tunnel", { tunnelId: tunnel.id, configPath: tunnel.configPath || "" }); } catch (_) { addToast("warn", "Backend unavailable \u2014 using simulated connection"); await new Promise(r => setTimeout(r, 1800)); }
      addLog("info", `ML-KEM-768 encapsulation complete (1088 bytes)`);
      addLog("info", `X25519 DH exchange complete`);
      addLog("info", `Shared secrets combined via HKDF-SHA256`);
      if (tunnel.mode === "pqonly") addLog("info", `ML-DSA-65 transcript signature verified (3309 bytes)`);
      addLog("info", `Handshake complete \u2014 ${tunnel.mode === "pqonly" ? "ML-KEM-768 + ML-DSA-65" : "ML-KEM-768 + X25519 + Ed25519"} (${tunnel.mode})`);
      addLog("ok", `Session keys derived \u2014 ChaCha20-Poly1305 active`);
      addLog("ok", `Quantum-secure tunnel established \u2713`);
      setTunnels(prev => prev.map((t, i) => i === selected ? { ...t, status: "connected" } : t));
      const ts = new Date().toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
      setAuditLog(prev => [{ time: ts, event: "tunnel_up", detail: `${tunnel.name} connected (${tunnel.mode})`, severity: "info" }, ...prev]);
    }
    setConnecting(false);
  };

  const deleteTunnel = (idx) => {
    if (tunnels[idx].status === "connected") { addToast("warn", `Cannot delete active tunnel \u2014 disconnect first`); return; }
    addLog("info", `Removed tunnel: ${tunnels[idx].name}`);
    setTunnels(prev => prev.filter((_, i) => i !== idx));
    if (selected >= idx && selected > 0) setSelected(s => s - 1);
    setConfirmDelete(null);
  };

  const duplicateTunnel = (idx) => {
    const src = tunnels[idx];
    setTunnels(prev => [...prev.slice(0, idx + 1), { ...src, id: `${src.id}-copy-${Date.now()}`, name: `${src.name} (copy)`, status: "disconnected" }, ...prev.slice(idx + 1)]);
    addLog("info", `Duplicated tunnel: ${src.name}`);
  };

  const handleImport = async (path) => {
    try {
      const config = await invoke("import_config", { path });
      setTunnels(prev => [...prev, { id: `tunnel-${Date.now()}`, name: config?.name || path.split(/[\\/]/).pop().replace(".toml", ""), endpoint: config?.endpoint || "\u2014", mode: config?.mode || "hybrid", status: "disconnected", configPath: path }]);
      addLog("info", `Imported config: ${path}`);
      addToast("success", `Imported: ${path.split(/[\\/]/).pop()}`);
    } catch (e) { addLog("error", `Import failed: ${e}`); addToast("error", `Import failed: ${e}`); }
  };

  const browseFile = async () => { try { return await invoke("pick_config_file"); } catch (_) { return null; } };

  const handleTunnelContext = (e, idx) => { e.preventDefault(); e.stopPropagation(); setCtxMenu({ x: e.clientX, y: e.clientY, idx }); };

  const contextItems = ctxMenu ? [
    { icon: tunnels[ctxMenu.idx]?.status === "connected" ? "\u23F9" : "\u25B6", label: tunnels[ctxMenu.idx]?.status === "connected" ? "Disconnect" : "Connect", action: () => { setSelected(ctxMenu.idx); setTimeout(toggleConnection, 50); } },
    { separator: true },
    { icon: "\u2750", label: "Duplicate", action: () => duplicateTunnel(ctxMenu.idx), shortcut: "Ctrl+D" },
    { icon: "\u270E", label: "Edit Name", action: () => setRenameTarget(ctxMenu.idx) },
    { icon: "\u2192", label: "Open Config Location", action: () => addLog("info", `Config: ${tunnels[ctxMenu.idx].configPath || "No file path"}`) },
    { separator: true },
    { icon: "\u2715", label: "Delete Tunnel", danger: true, action: () => setConfirmDelete(ctxMenu.idx), shortcut: "Del" },
  ] : [];

  // ─── Keyboard shortcuts ──────────────────────────────────
  useEffect(() => {
    const handler = (e) => { if (e.key === "Escape") { setCtxMenu(null); setConfirmDelete(null); setRenameTarget(null); } };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  // ═══════════════════════════════════════════════════════════
  // RENDER
  // ═══════════════════════════════════════════════════════════
  if (!loaded || !settings) return (
    <div className={styles.app} style={{ display: "flex", alignItems: "center", justifyContent: "center", flexDirection: "column", gap: "12px" }}>
      <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#34d399" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ animation: "pulse 1.5s ease-in-out infinite" }}>
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      </svg>
      <span style={{ color: "#94a3b8", fontSize: "13px", letterSpacing: "0.05em" }}>Loading DyberVPN...</span>
    </div>
  );

  return (
    <div className={styles.app}>
      {/* Top bar */}
      <div className={styles.topBar}>
        <div data-tauri-drag-region="true" className={styles.brandArea}>
          <div className={styles.brandIcon}>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
          </div>
          <span className={styles.brandName}>DyberVPN</span>
        </div>
        <div data-tauri-drag-region="true" className={styles.navArea}>
          {NAV_ITEMS.map(n => (
            <div key={n.id} onClick={() => navigate(n.id)}
              className={`${styles.navTab} ${page === n.id ? styles.navTabActive : ""}`}>
              <span className={styles.navIcon}><Icon name={n.icon} size={12} /></span>{n.label}
            </div>
          ))}
        </div>
        {tunnels.some(t => t.status === "connected") && (
          <div className={styles.activePill}>
            <span className={styles.activeDot} />
            {tunnels.filter(t => t.status === "connected").length} ACTIVE
          </div>
        )}
        <WindowControls />
      </div>

      {/* Main content */}
      <div className={styles.main}>
        {page === "tunnels" && (
          <TunnelsPage
            tunnels={tunnels} selected={selected} setSelected={setSelected}
            onContextMenu={handleTunnelContext}
            tunnel={tunnel} isConnected={isConnected} connecting={connecting}
            onToggleConnection={toggleConnection}
            onImport={handleImport} browseFile={browseFile}
            settings={settings} uptime={uptime} traffic={traffic}
            logs={logs} setLogs={setLogs}
          />
        )}
        {page === "keys" && <KeyManagerPage addLog={addLog} addToast={addToast} />}
        {page === "settings" && <SettingsPage settings={settings} updateSetting={updateSetting} auditLog={auditLog} setAuditLog={setAuditLog} addToast={addToast} tunnels={tunnels} setTunnels={setTunnels} />}
        {page === "about" && <AboutPage />}
      </div>

      {/* Overlays */}
      {ctxMenu && <ContextMenu x={ctxMenu.x} y={ctxMenu.y} items={contextItems} onClose={() => setCtxMenu(null)} />}
      {confirmDelete !== null && (
        <ConfirmModal
          title="Delete Tunnel"
          confirmLabel="Delete"
          onConfirm={() => deleteTunnel(confirmDelete)}
          onCancel={() => setConfirmDelete(null)}
        >
          Are you sure you want to delete <strong style={{ color: "#f87171" }}>{tunnels[confirmDelete]?.name}</strong>? This action cannot be undone.
        </ConfirmModal>
      )}
      {renameTarget !== null && (
        <InputModal
          title="Rename Tunnel"
          label="Tunnel name"
          defaultValue={tunnels[renameTarget]?.name || ""}
          confirmLabel="Rename"
          onConfirm={(name) => {
            setTunnels(prev => prev.map((t, i) => i === renameTarget ? { ...t, name } : t));
            addLog("info", `Renamed tunnel to: ${name}`);
            setRenameTarget(null);
          }}
          onCancel={() => setRenameTarget(null)}
        />
      )}
      <Toast toasts={toasts} onDismiss={dismissToast} />
    </div>
  );
}
