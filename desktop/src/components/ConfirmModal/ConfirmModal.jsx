import styles from "./ConfirmModal.module.css";

export function ConfirmModal({ title, children, confirmLabel = "Delete", onConfirm, onCancel }) {
  return (
    <div className={styles.overlay} onClick={onCancel}>
      <div className={styles.dialog} onClick={e => e.stopPropagation()}>
        <div className={styles.title}>{title}</div>
        <div className={styles.message}>{children}</div>
        <div className={styles.actions}>
          <button onClick={onCancel} className={styles.cancelBtn}>Cancel</button>
          <button onClick={onConfirm} className={styles.confirmBtn}>{confirmLabel}</button>
        </div>
      </div>
    </div>
  );
}
