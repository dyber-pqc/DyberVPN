import { getAppWindow } from "../../lib/tauri";
import styles from "./WindowControls.module.css";

export function WindowControls() {
  return (
    <div className={styles.controls}>
      <button onClick={() => getAppWindow()?.minimize()} title="Minimize" className={styles.btn}>
        <svg width="11" height="11" viewBox="0 0 11 11">
          <line x1="1" y1="5.5" x2="10" y2="5.5" stroke="#6b7280" strokeWidth="1.2" />
        </svg>
      </button>
      <button onClick={() => getAppWindow()?.toggleMaximize()} title="Maximize" className={styles.btn}>
        <svg width="11" height="11" viewBox="0 0 11 11">
          <rect x="1.5" y="1.5" width="8" height="8" rx="1.2" stroke="#6b7280" strokeWidth="1.2" fill="none" />
        </svg>
      </button>
      <button onClick={() => getAppWindow()?.close()} title="Close" className={styles.closeBtn}>
        <svg width="11" height="11" viewBox="0 0 11 11">
          <line x1="2" y1="2" x2="9" y2="9" stroke="#6b7280" strokeWidth="1.3" />
          <line x1="9" y1="2" x2="2" y2="9" stroke="#6b7280" strokeWidth="1.3" />
        </svg>
      </button>
    </div>
  );
}
