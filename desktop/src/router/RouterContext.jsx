// DyberVPN — Lightweight custom router
// Copyright 2026 Dyber, Inc.

import { createContext, useContext, useState, useCallback } from "react";

const RouterContext = createContext(null);

export function RouterProvider({ defaultPage = "tunnels", children }) {
  const [page, setPage] = useState(defaultPage);
  const navigate = useCallback((target) => {
    if (typeof target === "string") setPage(target);
  }, []);
  return (
    <RouterContext.Provider value={{ page, navigate }}>
      {children}
    </RouterContext.Provider>
  );
}

export function usePage() {
  const ctx = useContext(RouterContext);
  if (!ctx) throw new Error("usePage must be used within RouterProvider");
  return ctx;
}
