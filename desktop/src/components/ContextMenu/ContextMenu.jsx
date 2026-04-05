import { useEffect } from "react";
import styles from "./ContextMenu.module.css";

export function ContextMenu({ x, y, items, onClose }) {
  useEffect(() => {
    const handler = () => onClose();
    window.addEventListener("click", handler);
    window.addEventListener("contextmenu", handler);
    return () => {
      window.removeEventListener("click", handler);
      window.removeEventListener("contextmenu", handler);
    };
  }, [onClose]);

  return (
    <div className={styles.menu} style={{ left: x, top: y }}>
      {items.map((item, i) => item.separator ? (
        <div key={i} className={styles.separator} />
      ) : (
        <div
          key={i}
          onClick={(e) => { e.stopPropagation(); item.action(); onClose(); }}
          className={`${styles.item} ${item.danger ? styles.itemDanger : ""}`}
        >
          <span className={styles.itemIcon}>{item.icon}</span>
          <span>{item.label}</span>
          {item.shortcut && <span className={styles.shortcut}>{item.shortcut}</span>}
        </div>
      ))}
    </div>
  );
}
