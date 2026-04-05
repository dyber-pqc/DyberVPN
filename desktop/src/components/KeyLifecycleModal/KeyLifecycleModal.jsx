import { useState, useEffect, useRef } from "react";
import { Select } from "../Select/Select";
import styles from "./KeyLifecycleModal.module.css";

const REASONS = [
  { value: "employee_departed", label: "Employee Departed" },
  { value: "key_compromised", label: "Key Compromised" },
  { value: "device_lost", label: "Device Lost" },
  { value: "key_superseded", label: "Key Superseded" },
  { value: "policy_violation", label: "Policy Violation" },
  { value: "administrative", label: "Administrative" },
];

const DURATIONS = [
  { value: "24h", label: "24 Hours" },
  { value: "7d", label: "7 Days" },
  { value: "2w", label: "2 Weeks" },
  { value: "30d", label: "30 Days" },
];

export function KeyLifecycleModal({ action, onConfirm, onCancel }) {
  const [peer, setPeer] = useState("");
  const [reason, setReason] = useState("administrative");
  const [expires, setExpires] = useState("7d");
  const [revokedBy, setRevokedBy] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const peerRef = useRef(null);

  useEffect(() => { peerRef.current?.focus(); }, []);

  const isRevoke = action === "revoke";
  const valid = peer.trim();

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!valid || submitting) return;
    setSubmitting(true);
    try {
      await onConfirm({
        action,
        peer: peer.trim(),
        reason: isRevoke ? reason : undefined,
        expires: !isRevoke ? expires : undefined,
        revokedBy: revokedBy.trim(),
      });
    } catch (_) {
      setSubmitting(false);
    }
  };

  return (
    <div className={styles.overlay} onClick={onCancel}>
      <form className={styles.dialog} onClick={e => e.stopPropagation()} onSubmit={handleSubmit}>
        <div className={isRevoke ? styles.titleRevoke : styles.titleSuspend}>
          {isRevoke ? "Revoke Peer Key" : "Suspend Peer Key"}
        </div>
        <p className={styles.desc}>
          {isRevoke
            ? "Permanently revoke a peer's key. The peer will be disconnected and cannot reconnect until reinstated."
            : "Temporarily suspend a peer's access. The suspension expires automatically after the chosen duration."}
        </p>

        <label className={styles.label}>Peer Name or Identifier</label>
        <input
          ref={peerRef}
          type="text"
          value={peer}
          onChange={e => setPeer(e.target.value)}
          className={styles.input}
          placeholder="alice-laptop"
          spellCheck={false}
          disabled={submitting}
        />

        {isRevoke ? (
          <>
            <label className={styles.label}>Reason</label>
            <div className={styles.selectWrap}>
              <Select value={reason} onChange={setReason} options={REASONS} />
            </div>
          </>
        ) : (
          <>
            <label className={styles.label}>Duration</label>
            <div className={styles.selectWrap}>
              <Select value={expires} onChange={setExpires} options={DURATIONS} />
            </div>
          </>
        )}

        <label className={styles.label}>Performed By (optional)</label>
        <input
          type="text"
          value={revokedBy}
          onChange={e => setRevokedBy(e.target.value)}
          className={styles.input}
          placeholder="admin@company.com"
          spellCheck={false}
          disabled={submitting}
        />

        <div className={styles.actions}>
          <button type="button" onClick={onCancel} className={styles.cancelBtn} disabled={submitting}>Cancel</button>
          <button type="submit" disabled={!valid || submitting}
            className={isRevoke ? styles.revokeBtn : styles.suspendBtn}>
            {submitting ? "Processing..." : isRevoke ? "Revoke Key" : "Suspend Key"}
          </button>
        </div>
      </form>
    </div>
  );
}
