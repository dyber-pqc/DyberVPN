import { useState, useEffect, useRef } from "react";
import styles from "./InputModal.module.css";

export function InputModal({ title, label, defaultValue = "", confirmLabel = "Save", onConfirm, onCancel }) {
  const [value, setValue] = useState(defaultValue);
  const inputRef = useRef(null);

  useEffect(() => {
    inputRef.current?.focus();
    inputRef.current?.select();
  }, []);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (value.trim()) onConfirm(value.trim());
  };

  return (
    <div className={styles.overlay} onClick={onCancel}>
      <form className={styles.dialog} onClick={e => e.stopPropagation()} onSubmit={handleSubmit}>
        <div className={styles.title}>{title}</div>
        {label && <label className={styles.label}>{label}</label>}
        <input
          ref={inputRef}
          type="text"
          value={value}
          onChange={e => setValue(e.target.value)}
          className={styles.input}
          spellCheck={false}
        />
        <div className={styles.actions}>
          <button type="button" onClick={onCancel} className={styles.cancelBtn}>Cancel</button>
          <button type="submit" disabled={!value.trim()} className={styles.confirmBtn}>{confirmLabel}</button>
        </div>
      </form>
    </div>
  );
}
