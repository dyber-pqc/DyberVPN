import styles from "./AboutPage.module.css";

export function AboutPage() {
  return (
    <div className={styles.page}>
      <div className={styles.logo}>
        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
      </div>
      <div className={styles.title}>DyberVPN</div>
      <div className={styles.subtitle}>POST-QUANTUM VPN</div>
      <div className={styles.badge}>OPEN SOURCE</div>
      <div className={styles.desc}>
        Self-hosted, post-quantum VPN built with NIST-standardized algorithms. WireGuard-compatible protocol with hardware acceleration support. Fully auditable — no black-box cryptography.
      </div>
      <div className={styles.grid}>
        {[
          ["Version", "0.1.1"],
          ["License", "Apache 2.0 + BSD-3"],
          ["Key Exchange", "ML-KEM-768 (FIPS 203)"],
          ["Authentication", "ML-DSA-65 (FIPS 204)"],
          ["Data Cipher", "ChaCha20-Poly1305"],
          ["Artifact Signing", "ML-DSA-65 (.sig.mldsa)"],
          ["Compliance", "CNSA 2.0 aligned"],
          ["HW Acceleration", "QUAC 100 (optional)"],
        ].map(([k, v]) => (
          <div key={k} className={styles.gridRow}>
            <span className={styles.gridKey}>{k}</span>
            <span className={styles.gridVal}>{v}</span>
          </div>
        ))}
      </div>
      <div className={styles.links}>
        <a href="https://github.com/dyber-pqc/DyberVPN" target="_blank" rel="noopener noreferrer" className={styles.linkBtn}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="#94a3b8"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
          Source Code
        </a>
        <a href="https://dyber.org" target="_blank" rel="noopener noreferrer" className={`${styles.linkBtn} ${styles.linkBtnPrimary}`}>
          dyber.org
        </a>
      </div>
      <div className={styles.copyright}>&copy; 2026 Dyber, Inc.</div>
    </div>
  );
}
