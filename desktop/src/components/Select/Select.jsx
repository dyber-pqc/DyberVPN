import styles from "./Select.module.css";

export function Select({ value, onChange, options, width = 160 }) {
  return (
    <select
      value={value}
      onChange={e => onChange(e.target.value)}
      className={styles.select}
      style={{ width }}
    >
      {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
    </select>
  );
}
