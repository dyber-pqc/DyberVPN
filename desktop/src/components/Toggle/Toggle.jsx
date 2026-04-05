import styles from "./Toggle.module.css";

export function Toggle({ value, onChange, disabled, size = "md" }) {
  const w = size === "sm" ? 32 : 38;
  const h = size === "sm" ? 18 : 22;
  const dot = size === "sm" ? 14 : 18;
  return (
    <div
      onClick={() => !disabled && onChange(!value)}
      className={`${styles.track} ${disabled ? styles.disabled : ""}`}
      style={{
        width: w, height: h,
        background: value ? "linear-gradient(135deg, #7c3aed, #a855f7)" : "rgba(75,85,99,0.4)",
        border: `1px solid ${value ? "rgba(139,92,246,0.5)" : "rgba(75,85,99,0.5)"}`,
      }}
    >
      <div
        className={styles.dot}
        style={{
          width: dot, height: dot,
          background: value ? "#fff" : "#9ca3af",
          transform: `translateX(${value ? w - dot - 6 : 0}px)`,
        }}
      />
    </div>
  );
}
