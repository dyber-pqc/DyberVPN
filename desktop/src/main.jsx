// DyberVPN Desktop Client
// Copyright 2026 Dyber, Inc.

import React from "react";
import ReactDOM from "react-dom/client";
import { RouterProvider } from "./router/RouterContext";
import { ErrorBoundary } from "./components/ErrorBoundary";
import App from "./App";
import "./global.css";

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <ErrorBoundary>
      <RouterProvider defaultPage="tunnels">
        <App />
      </RouterProvider>
    </ErrorBoundary>
  </React.StrictMode>
);
