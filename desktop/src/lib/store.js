// DyberVPN — Persistent store wrapper
// Copyright 2026 Dyber, Inc.
//
// Uses @tauri-apps/plugin-store in Tauri, falls back to localStorage in browser.

let _store = null;

async function getStore() {
  if (_store) return _store;
  try {
    if (window.__TAURI_INTERNALS__) {
      const { load } = await import("@tauri-apps/plugin-store");
      _store = await load("dybervpn-settings.json", { autoSave: true });
      return _store;
    }
  } catch (_) {}
  // Fallback: localStorage wrapper with same API shape
  _store = {
    get: async (key) => {
      try { const v = localStorage.getItem(`dybervpn:${key}`); return v ? JSON.parse(v) : undefined; }
      catch (_) { return undefined; }
    },
    set: async (key, value) => {
      localStorage.setItem(`dybervpn:${key}`, JSON.stringify(value));
    },
    save: async () => {},
  };
  return _store;
}

// ─── Settings ────────────────────────────────────────────

const DEFAULT_SETTINGS = {
  killSwitch: true, dnsLeakProtection: true, splitTunnel: false,
  splitTunnelRules: "10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16",
  alwaysOn: true, autoConnect: false, lockdownMode: false,
  mtu: "1420", listenPort: "51820", keepalive: "25",
  cryptoBackend: "auto", preferredMode: "hybrid", keyRotationInterval: "120",
  logLevel: "info", exportFormat: "syslog", autoUpdate: true,
  updateChannel: "stable", startMinimized: false, systemTray: true,
  // Fleet enrollment state
  fleetEnrolled: false, fleetServerUrl: "", fleetDeviceName: "",
  fleetAssignedIp: "", fleetMode: "", fleetConfigPath: "", fleetEnrolledAt: "",
};

export async function loadSettings() {
  try {
    const store = await getStore();
    const saved = await store.get("settings");
    if (saved && typeof saved === "object") {
      return { ...DEFAULT_SETTINGS, ...saved };
    }
  } catch (_) {}
  return { ...DEFAULT_SETTINGS };
}

export async function saveSettings(settings) {
  try {
    const store = await getStore();
    await store.set("settings", settings);
    await store.save();
  } catch (_) {}
}

// ─── Tunnels ─────────────────────────────────────────────

const DEFAULT_TUNNELS = [
  { id: "production-dc", name: "Production DC", endpoint: "10.200.200.1:51820", mode: "hybrid", status: "disconnected", configPath: "/etc/dybervpn/prod.toml" },
  { id: "dev-staging", name: "Dev Staging", endpoint: "10.200.201.1:51820", mode: "pqonly", status: "disconnected", configPath: "/etc/dybervpn/staging.toml" },
  { id: "office-gw", name: "Office Gateway", endpoint: "10.200.202.1:51820", mode: "hybrid", status: "disconnected", configPath: "/etc/dybervpn/office.toml" },
];

export async function loadTunnels() {
  try {
    const store = await getStore();
    const saved = await store.get("tunnels");
    if (Array.isArray(saved) && saved.length > 0) {
      // Always reset status to disconnected on load (process isn't running after restart)
      return saved.map(t => ({ ...t, status: "disconnected" }));
    }
  } catch (_) {}
  return DEFAULT_TUNNELS.map(t => ({ ...t }));
}

export async function saveTunnels(tunnels) {
  try {
    const store = await getStore();
    // Strip runtime-only fields before saving
    const toSave = tunnels.map(({ status, ...rest }) => rest);
    await store.set("tunnels", toSave);
    await store.save();
  } catch (_) {}
}
