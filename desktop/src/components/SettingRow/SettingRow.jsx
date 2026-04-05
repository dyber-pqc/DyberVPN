import { Icon } from "../Icon";
import styles from "./SettingRow.module.css";

export function SettingRow({ icon, label, desc, children, danger, last }) {
  const iconEl = typeof icon === "string" ? <Icon name={icon} size={15} /> : icon;
  return (
    <div className={`${styles.row} ${last ? styles.last : ""}`}>
      <div className={styles.left}>
        {iconEl && <span className={styles.icon}>{iconEl}</span>}
        <div className={styles.content}>
          <div className={`${styles.label} ${danger ? styles.labelDanger : ""}`}>{label}</div>
          {desc && <div className={styles.desc}>{desc}</div>}
        </div>
      </div>
      <div className={styles.right}>{children}</div>
    </div>
  );
}
