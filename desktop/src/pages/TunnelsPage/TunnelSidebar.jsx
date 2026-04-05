import { useState } from "react";
import { StatusDot } from "../../components/StatusDot/StatusDot";
import { ModeTag } from "../../components/ModeTag/ModeTag";
import styles from "./TunnelSidebar.module.css";

export function TunnelSidebar({ tunnels, selected, setSelected, onContextMenu, onImport, browseFile }) {
  const [showImport, setShowImport] = useState(false);
  const [importPath, setImportPath] = useState("");

  const handleImport = () => {
    const p = importPath.trim();
    if (!p) return;
    onImport(p);
    setShowImport(false);
    setImportPath("");
  };

  const handleBrowse = async () => {
    const fp = await browseFile();
    if (fp) setImportPath(fp);
  };

  return (
    <div className={styles.sidebar}>
      <div className={styles.list}>
        <div className={styles.listTitle}>TUNNELS ({tunnels.length})</div>
        {tunnels.map((t, i) => (
          <div key={t.id} onClick={() => setSelected(i)} onContextMenu={(e) => onContextMenu(e, i)}
            className={`${styles.tunnelItem} ${selected === i ? styles.tunnelItemActive : ""}`}>
            <div className={styles.tunnelItemTop}>
              <div className={styles.tunnelItemLeft}>
                <StatusDot status={t.status} />
                <span className={`${styles.tunnelName} ${selected === i ? styles.tunnelNameActive : ""}`}>{t.name}</span>
              </div>
              <ModeTag mode={t.mode} />
            </div>
            <div className={styles.tunnelEndpoint}>{t.endpoint}</div>
          </div>
        ))}
        {showImport ? (
          <div className={styles.importBox}>
            <div className={styles.importLabel}>Config file path:</div>
            <div className={styles.importRow}>
              <input type="text" value={importPath} onChange={e => setImportPath(e.target.value)}
                onKeyDown={e => e.key === "Enter" && handleImport()}
                placeholder="/etc/dybervpn/client.toml" className={styles.importInput} />
              <button onClick={handleBrowse} className={styles.browseBtn}>{"\u2026"}</button>
            </div>
            <div className={styles.importActions}>
              <button onClick={handleImport} className={styles.importBtn}>Import</button>
              <button onClick={() => { setShowImport(false); setImportPath(""); }} className={styles.cancelBtn}>Cancel</button>
            </div>
          </div>
        ) : (
          <button onClick={() => setShowImport(true)} className={styles.addBtn}>+ Import Config</button>
        )}
      </div>
      <div className={styles.footer}>Right-click tunnel for options</div>
    </div>
  );
}
