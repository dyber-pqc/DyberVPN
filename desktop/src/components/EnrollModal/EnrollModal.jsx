import { useState, useEffect, useRef } from "react";
import { Select } from "../Select/Select";
import styles from "./EnrollModal.module.css";

export function EnrollModal({ onConfirm, onCancel }) {
  const [server, setServer] = useState("");
  const [token, setToken] = useState("");
  const [name, setName] = useState("");
  const [mode, setMode] = useState("hybrid");
  const [showToken, setShowToken] = useState(false);
  const [enrolling, setEnrolling] = useState(false);
  const [error, setError] = useState(null);
  const serverRef = useRef(null);

  useEffect(() => { serverRef.current?.focus(); }, []);

  const valid = server.trim() && token.trim() && name.trim();

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!valid || enrolling) return;
    setEnrolling(true);
    setError(null);
    try {
      await onConfirm({ server: server.trim(), token: token.trim(), name: name.trim(), mode });
    } catch (err) {
      setError(String(err));
      setEnrolling(false);
    }
  };

  return (
    <div className={styles.overlay} onClick={onCancel}>
      <form className={styles.dialog} onClick={e => e.stopPropagation()} onSubmit={handleSubmit}>
        <div className={styles.title}>Enroll Device</div>
        <p className={styles.desc}>Connect to a DyberVPN Management Server for centralized policy distribution and fleet monitoring.</p>

        <label className={styles.label}>Server URL</label>
        <input
          ref={serverRef}
          type="text"
          value={server}
          onChange={e => setServer(e.target.value)}
          className={styles.input}
          placeholder="http://10.200.200.1:8443"
          spellCheck={false}
          disabled={enrolling}
        />

        <label className={styles.label}>Enrollment Token</label>
        <div className={styles.tokenRow}>
          <input
            type={showToken ? "text" : "password"}
            value={token}
            onChange={e => setToken(e.target.value)}
            className={styles.tokenInput}
            placeholder="Bearer token from your admin"
            spellCheck={false}
            disabled={enrolling}
          />
          <button type="button" className={styles.toggleBtn} onClick={() => setShowToken(v => !v)} tabIndex={-1}>
            {showToken ? "Hide" : "Show"}
          </button>
        </div>

        <label className={styles.label}>Device Name</label>
        <input
          type="text"
          value={name}
          onChange={e => setName(e.target.value)}
          className={styles.input}
          placeholder="my-laptop"
          spellCheck={false}
          disabled={enrolling}
        />

        <label className={styles.label}>Cryptographic Mode</label>
        <div className={styles.selectWrap}>
          <Select value={mode} onChange={setMode} options={[
            { value: "hybrid", label: "Hybrid (recommended)" },
            { value: "pqonly", label: "PQ-Only (CNSA 2.0)" },
            { value: "classic", label: "Classic (WireGuard)" },
          ]} />
        </div>

        {error && <div className={styles.error}>{error}</div>}

        <div className={styles.actions}>
          <button type="button" onClick={onCancel} className={styles.cancelBtn} disabled={enrolling}>Cancel</button>
          <button type="submit" disabled={!valid || enrolling} className={styles.confirmBtn}>
            {enrolling ? "Enrolling..." : "Enroll"}
          </button>
        </div>
      </form>
    </div>
  );
}
