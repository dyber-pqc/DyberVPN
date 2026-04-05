import { useEffect } from "react";
import styles from "./Toast.module.css";

const ICONS = {
  success: "\u2713",
  error: "\u2715",
  warn: "\u26A0",
  info: "\u2139",
};

export function Toast({ toasts, onDismiss }) {
  return (
    <div className={styles.container}>
      {toasts.map(t => (
        <ToastItem key={t.id} toast={t} onDismiss={onDismiss} />
      ))}
    </div>
  );
}

function ToastItem({ toast, onDismiss }) {
  useEffect(() => {
    const ms = toast.type === "error" ? 6000 : 4000;
    const timer = setTimeout(() => onDismiss(toast.id), ms);
    return () => clearTimeout(timer);
  }, [toast.id, toast.type, onDismiss]);

  return (
    <div className={`${styles.toast} ${styles[toast.type] || styles.info}`}>
      <span className={styles.icon}>{ICONS[toast.type] || ICONS.info}</span>
      <span className={styles.msg}>{toast.message}</span>
      <button className={styles.close} onClick={() => onDismiss(toast.id)}>{"\u2715"}</button>
    </div>
  );
}
