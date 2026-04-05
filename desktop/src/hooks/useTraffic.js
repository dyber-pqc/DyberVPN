import { useState, useEffect, useRef } from "react";
import { invoke, listen } from "../lib/tauri";

export function useTraffic(connected, tunnelId) {
  const [rx, setRx] = useState(0);
  const [tx, setTx] = useState(0);
  const [latency, setLatency] = useState(null);
  const prevId = useRef(tunnelId);

  useEffect(() => {
    // Reset counters when tunnel changes or disconnects
    if (!connected || tunnelId !== prevId.current) {
      setRx(0);
      setTx(0);
      setLatency(null);
      prevId.current = tunnelId;
    }
    if (!connected || !tunnelId) return;

    let cancelled = false;

    // Try event-based approach (returns null in demo mode)
    const unlistenPromise = listen("tunnel-stats", (event) => {
      if (cancelled) return;
      const stats = event?.payload?.tunnels?.[tunnelId];
      if (stats) {
        setRx(stats.rx);
        setTx(stats.tx);
        if (stats.latency_ms != null) {
          setLatency(stats.latency_ms);
        }
      }
    });

    // If listen() returned null (demo mode), fall back to polling
    if (unlistenPromise === null) {
      const poll = async () => {
        try {
          const status = await invoke("get_status", { tunnelId });
          if (!cancelled && status) {
            setRx(status.rx);
            setTx(status.tx);
            if (status.latency_ms != null) {
              setLatency(status.latency_ms);
            }
          }
        } catch (_) {
          // Demo fallback: increment with fake data when backend unavailable
          if (!cancelled) {
            setRx(r => r + Math.floor(Math.random() * 5000 + 1000));
            setTx(t => t + Math.floor(Math.random() * 3000 + 500));
          }
        }
      };
      poll();
      const iv = setInterval(poll, 2000);
      return () => { cancelled = true; clearInterval(iv); };
    }

    // Cleanup for event-based path
    return () => {
      cancelled = true;
      if (unlistenPromise && typeof unlistenPromise.then === "function") {
        unlistenPromise.then((unlisten) => {
          if (typeof unlisten === "function") unlisten();
        });
      }
    };
  }, [connected, tunnelId]);

  const fmt = (b) => {
    if (b === 0) return "0 B";
    if (b < 1024) return `${b} B`;
    if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`;
    if (b < 1073741824) return `${(b / 1048576).toFixed(1)} MB`;
    return `${(b / 1073741824).toFixed(2)} GB`;
  };

  const fmtLatency = (ms) => {
    if (ms == null) return "\u2014";
    if (ms < 1) return "< 1 ms";
    return `${Math.round(ms)} ms`;
  };

  return { rx: fmt(rx), tx: fmt(tx), latency: fmtLatency(latency) };
}
