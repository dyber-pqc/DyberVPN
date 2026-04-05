import styles from "./StatusDot.module.css";

export function StatusDot({ status }) {
  const on = status === "connected";
  return <span className={`${styles.dot} ${on ? styles.connected : ""}`} />;
}
