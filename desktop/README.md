# DyberVPN Desktop Client

Native desktop client for DyberVPN — Post-Quantum VPN for Infrastructure You Control.

Built with [Tauri](https://tauri.app/) (Rust backend + React frontend).

## Screenshots

*Coming soon*

## Requirements

- [Node.js](https://nodejs.org/) 18+
- [Rust](https://rustup.rs/) 1.75+
- [DyberVPN CLI](https://github.com/dyber-pqc/DyberVPN) installed at `/usr/local/bin/dybervpn`

### Platform-specific

**Windows:**
- Microsoft Visual Studio C++ Build Tools
- WebView2 (comes with Windows 10/11)

**macOS:**
- Xcode Command Line Tools

**Linux:**
- `libwebkit2gtk-4.1-dev`, `libappindicator3-dev`, `librsvg2-dev`, `patchelf`

```bash
# Ubuntu/Debian
sudo apt install libwebkit2gtk-4.1-dev build-essential curl wget file \
  libxdo-dev libssl-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev
```

## Development

```bash
# Install dependencies
npm install

# Run in development mode (hot-reload)
npm run tauri dev

# Build for production
npm run tauri build
```

## Architecture

```
dybervpn-app/
├── src/                  # React frontend
│   ├── main.jsx          # Entry point
│   └── App.jsx           # Main UI
├── src-tauri/            # Rust backend
│   ├── src/main.rs       # Tauri commands (wraps dybervpn CLI)
│   ├── Cargo.toml
│   └── tauri.conf.json   # App configuration
├── index.html
├── vite.config.js
└── package.json
```

### How it works

The Tauri backend spawns the `dybervpn` CLI binary as child processes:

| UI Action | CLI Command |
|-----------|-------------|
| Import Config | Reads and parses TOML file |
| Connect | `dybervpn up -c <config> -f` |
| Disconnect | `dybervpn down <interface>` |
| Status | `dybervpn status` |
| Generate Keys | `dybervpn genkey -m <mode>` |
| Validate | `dybervpn check -c <config>` |

## Building Installers

```bash
# Build for current platform
npm run tauri build

# Output locations:
# Windows: src-tauri/target/release/bundle/nsis/DyberVPN_0.1.0_x64-setup.exe
# macOS:   src-tauri/target/release/bundle/dmg/DyberVPN_0.1.0_x64.dmg
# Linux:   src-tauri/target/release/bundle/deb/dybervpn_0.1.0_amd64.deb
```

## License

Apache 2.0 — Copyright 2026 Dyber, Inc.
