import styles from "./NumInput.module.css";

export function NumInput({ value, onChange, min, max, suffix, width = 80 }) {
  return (
    <div className={styles.wrapper}>
      <input
        type="number" value={value} min={min} max={max}
        onChange={e => onChange(e.target.value)}
        className={styles.input}
        style={{ width }}
      />
      {suffix && <span className={styles.suffix}>{suffix}</span>}
    </div>
  );
}
