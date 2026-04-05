import { useState, useEffect, useRef } from "react";

export function useUptime(running) {
  const [seconds, setSeconds] = useState(0);
  const iv = useRef(null);
  useEffect(() => {
    if (running) {
      setSeconds(0);
      iv.current = setInterval(() => setSeconds(s => s + 1), 1000);
    } else {
      setSeconds(0);
      if (iv.current) clearInterval(iv.current);
    }
    return () => { if (iv.current) clearInterval(iv.current); };
  }, [running]);
  if (!running) return "\u2014";
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  return h > 0 ? `${h}h ${m}m ${s}s` : m > 0 ? `${m}m ${s}s` : `${s}s`;
}
