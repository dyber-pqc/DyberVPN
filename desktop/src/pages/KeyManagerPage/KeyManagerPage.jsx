import { useState } from "react";
import { invoke } from "../../lib/tauri";
import { Icon } from "../../components/Icon";
import { ModeTag } from "../../components/ModeTag/ModeTag";
import styles from "./KeyManagerPage.module.css";

const MODES = [
  { mode: "hybrid", label: "Hybrid", desc: "ML-KEM-768 + X25519 + Ed25519 + ML-DSA-65", color: "#a78bfa", icon: "\u2B21", detail: "Recommended for production. Defense-in-depth with classical and post-quantum." },
  { mode: "pqonly", label: "PQ-Only", desc: "ML-KEM-768 + ML-DSA-65", color: "#34d399", icon: "\u25C8", detail: "Maximum quantum resistance. CNSA 2.0 strict compliance." },
  { mode: "classic", label: "Classic", desc: "X25519 + Ed25519 (WireGuard compatible)", color: "#9ca3af", icon: "\u25CB", detail: "Standard WireGuard keys. Not quantum-resistant." },
];

function parseKeyOutput(output) {
  const sections = [];
  let current = null;
  for (const line of output.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    if (t.startsWith("[") && t.endsWith("]")) {
      if (current) sections.push(current);
      current = { header: t.slice(1, -1), lines: [] };
    } else if (current) {
      const eq = t.indexOf("=");
      if (eq > 0) {
        const key = t.slice(0, eq).trim();
        const value = t.slice(eq + 1).trim();
        current.lines.push({ key, value, isPrivate: key.toLowerCase().includes("private") || key.toLowerCase().includes("secret") });
      }
    }
  }
  if (current) sections.push(current);
  return sections;
}

function modeColor(m) {
  return MODES.find(x => x.mode === m)?.color || "#6b7280";
}

export function KeyManagerPage({ addLog, addToast }) {
  const [generating, setGenerating] = useState(null);
  const [keyHistory, setKeyHistory] = useState([]);
  const [copied, setCopied] = useState(null);

  const generate = async (mode) => {
    if (generating) return;
    setGenerating(mode);
    addLog("info", `Generating ${mode} key pair via dybervpn genkey -m ${mode}...`);
    try {
      const output = await invoke("generate_keys", { mode });
      setKeyHistory(prev => [{ id: `key-${Date.now()}`, mode, output: output || "(no output)", timestamp: new Date().toLocaleString(), expanded: true }, ...prev]);
      addLog("ok", `${mode} key pair generated successfully`);
      addToast?.("success", `${mode} key pair generated`);
    } catch (e) { addLog("error", `Key generation failed: ${e}`); addToast?.("error", `Key generation failed: ${e}`); }
    setGenerating(null);
  };

  const copyText = async (text, id) => {
    try { await navigator.clipboard.writeText(text); setCopied(id); setTimeout(() => setCopied(null), 2000); } catch (_) {}
  };

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <div>
          <h2 className={styles.title}>Key Manager</h2>
          <div className={styles.subtitle}>Generate post-quantum cryptographic key pairs for tunnel configuration</div>
        </div>
        {keyHistory.length > 0 && (
          <button onClick={() => { if (confirm("Clear all generated keys from history?")) setKeyHistory([]); }} className={styles.clearBtn}>Clear History</button>
        )}
      </div>

      <div className={styles.modeGrid}>
        {MODES.map(k => (
          <div key={k.mode} onClick={() => generate(k.mode)}
            className={`${styles.modeCard} ${generating && generating !== k.mode ? styles.modeCardDisabled : ""}`}
            style={{ cursor: generating ? "wait" : "pointer", borderColor: undefined }}
            onMouseEnter={e => { if (!generating) { e.currentTarget.style.borderColor = k.color; } }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = "rgba(255,255,255,0.08)"; }}
          >
            <div className={styles.modeCardHeader}>
              <span className={styles.modeCardIcon} style={{ color: k.color }}>{k.icon}</span>
              <span className={styles.modeCardLabel} style={{ color: k.color }}>{k.label}</span>
              {generating === k.mode && (
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={k.color} strokeWidth="2.5" className={styles.spinner}>
                  <path d="M12 2a10 10 0 0 1 10 10" strokeLinecap="round" />
                </svg>
              )}
            </div>
            <div className={styles.modeCardDesc}>{k.desc}</div>
            <div className={styles.modeCardDetail}>{k.detail}</div>
          </div>
        ))}
      </div>

      {keyHistory.length === 0 ? (
        <div className={styles.empty}>
          <div className={styles.emptyIcon}><Icon name="key" size={32} color="#6b7280" /></div>
          <div className={styles.emptyTitle}>No keys generated yet</div>
          <div className={styles.emptyDesc}>Click a key type above to generate a new key pair</div>
        </div>
      ) : (
        <div>
          <div className={styles.historyLabel}>GENERATED KEYS ({keyHistory.length})</div>
          {keyHistory.map(entry => {
            const sections = parseKeyOutput(entry.output);
            const mc = modeColor(entry.mode);
            return (
              <div key={entry.id} className={styles.keyEntry}
                style={{
                  border: `1px solid ${entry.expanded ? mc + "30" : "rgba(255,255,255,0.06)"}`,
                  background: entry.expanded ? mc + "05" : "rgba(255,255,255,0.015)",
                }}
              >
                <div onClick={() => setKeyHistory(prev => prev.map(k => k.id === entry.id ? { ...k, expanded: !k.expanded } : k))} className={styles.keyEntryHeader}>
                  <span className={styles.expandArrow} style={{ transform: entry.expanded ? "rotate(90deg)" : "rotate(0deg)" }}>{"\u25B6"}</span>
                  <ModeTag mode={entry.mode} />
                  <span className={styles.keyLabel}>{entry.mode === "hybrid" ? "Hybrid" : entry.mode === "pqonly" ? "PQ-Only" : "Classic"} Key Pair</span>
                  <span className={styles.keyTimestamp}>{entry.timestamp}</span>
                  <button onClick={(e) => { e.stopPropagation(); copyText(entry.output, entry.id + "-all"); }}
                    className={`${styles.copyAllBtn} ${copied === entry.id + "-all" ? styles.copyAllBtnCopied : ""}`}>
                    {copied === entry.id + "-all" ? "\u2713 Copied" : "Copy All"}
                  </button>
                  <button onClick={(e) => { e.stopPropagation(); setKeyHistory(prev => prev.filter(k => k.id !== entry.id)); }}
                    className={styles.removeBtn} title="Remove">{"\u2715"}</button>
                </div>
                {entry.expanded && (
                  <div className={styles.keyBody}>
                    {sections.map((section, si) => (
                      <div key={si} className={styles.keySection} style={{ marginBottom: si < sections.length - 1 ? 12 : 0 }}>
                        <div className={styles.keySectionHeader} style={{ color: mc }}>{section.header}</div>
                        {section.lines.map((line, li) => (
                          <div key={li} className={styles.keyLine} style={{ marginBottom: li < section.lines.length - 1 ? 8 : 0 }}>
                            <span className={styles.keyLineLabel}>{line.key}</span>
                            <div className={`${styles.keyLineValue} ${line.isPrivate ? styles.keyLinePrivate : styles.keyLinePublic}`}>
                              {line.isPrivate && <span className={styles.privateWarning}>{"\u26A0"}</span>}
                              <span className={`${styles.keyText} ${line.isPrivate ? styles.keyTextPrivate : styles.keyTextPublic}`}>{line.value}</span>
                              <button onClick={() => copyText(line.value, entry.id + "-" + line.key)}
                                className={`${styles.copyKeyBtn} ${copied === entry.id + "-" + line.key ? styles.copyKeyBtnCopied : ""}`}>
                                {copied === entry.id + "-" + line.key ? "\u2713" : "\u2398"}
                              </button>
                            </div>
                          </div>
                        ))}
                      </div>
                    ))}
                    <div className={styles.warningBox}>
                      <span className={styles.warningIcon}>{"\u26A0"}</span>
                      <span className={styles.warningText}>Private keys are shown once and not stored. Copy them to your config files now. Never share private keys.</span>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      <div className={styles.cliBox}>
        <div className={styles.cliTitle}>CLI EQUIVALENT</div>
        <div className={styles.cliContent}>
          <div><span className={styles.cliComment}># Generate hybrid keys (recommended)</span></div>
          <div><span className={styles.cliPrompt}>$</span> dybervpn genkey -m hybrid</div>
          <div style={{ height: 4 }} />
          <div><span className={styles.cliComment}># Extract public key from private key</span></div>
          <div><span className={styles.cliPrompt}>$</span> dybervpn pubkey {'<'} private.key</div>
        </div>
      </div>
    </div>
  );
}
