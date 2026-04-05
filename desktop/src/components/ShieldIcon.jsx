export function ShieldIcon({ connected, size = 20 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
      stroke={connected ? "#34d399" : "#6b7280"} strokeWidth="2"
      strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      {connected && <path d="M9 12l2 2 4-4" stroke="#34d399" strokeWidth="2.5" />}
    </svg>
  );
}
