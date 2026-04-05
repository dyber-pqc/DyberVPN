import { LatticeCanvas } from "../../components/LatticeCanvas/LatticeCanvas";
import { TunnelSidebar } from "./TunnelSidebar";
import { TunnelDetail } from "./TunnelDetail";
import styles from "./TunnelsPage.module.css";

export function TunnelsPage({
  tunnels, selected, setSelected, onContextMenu,
  tunnel, isConnected, connecting, onToggleConnection,
  onImport, browseFile, settings, uptime, traffic, logs, setLogs,
}) {
  return (
    <div className={styles.page}>
      <TunnelSidebar
        tunnels={tunnels}
        selected={selected}
        setSelected={setSelected}
        onContextMenu={onContextMenu}
        onImport={onImport}
        browseFile={browseFile}
      />
      <div style={{ flex: 1, display: "flex", flexDirection: "column", position: "relative", overflow: "hidden" }}>
        <LatticeCanvas connected={isConnected} />
        <TunnelDetail
          tunnel={tunnel}
          isConnected={isConnected}
          connecting={connecting}
          onToggleConnection={onToggleConnection}
          settings={settings}
          uptime={uptime}
          traffic={traffic}
          logs={logs}
          setLogs={setLogs}
        />
      </div>
    </div>
  );
}
