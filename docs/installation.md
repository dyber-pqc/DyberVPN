# Installation Guide

## Requirements

### Supported Platforms

| Platform | Status | Notes |
|----------|--------|-------|
| Linux (x86_64) | ✅ Fully supported | Primary platform |
| Linux (aarch64) | ✅ Supported | ARM64 builds available |
| macOS | 🧪 Experimental | Community testing |
| Windows | ❌ Not yet | Planned |

### System Requirements

- **OS**: Linux kernel 3.10+ (Ubuntu 20.04+, Debian 11+, RHEL 8+)
- **Architecture**: x86_64 or aarch64
- **RAM**: 64 MB minimum
- **Disk**: 50 MB for binary
- **Permissions**: Root or CAP_NET_ADMIN capability

## Installation Methods

### 1. Pre-built Binaries (Recommended)

Download the latest release:

```bash
# Get the latest version
VERSION=$(curl -s https://api.github.com/repos/dyber-pqc/DyberVPN/releases/latest | grep tag_name | cut -d '"' -f 4)

# Download for your platform
curl -LO "https://github.com/dyber-pqc/DyberVPN/releases/download/${VERSION}/dybervpn-${VERSION#v}-x86_64-unknown-linux-gnu.tar.gz"

# Verify checksum
curl -LO "https://github.com/dyber-pqc/DyberVPN/releases/download/${VERSION}/SHA256SUMS.txt"
sha256sum -c SHA256SUMS.txt

# Extract and install
tar -xzf dybervpn-*.tar.gz
sudo mv dybervpn /usr/local/bin/
sudo chmod +x /usr/local/bin/dybervpn

# Verify installation
dybervpn version
```

### 2. Docker

```bash
# Pull the image
docker pull ghcr.io/dyber-pqc/dybervpn:latest

# Run with configuration
docker run -d \
  --name dybervpn \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  -v /path/to/config.toml:/etc/dybervpn/config.toml:ro \
  -p 51820:51820/udp \
  ghcr.io/dyber-pqc/dybervpn:latest
```

### 3. Build from Source

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Clone the repository
git clone https://github.com/dyber-pqc/DyberVPN.git
cd DyberVPN

# Build release binary
cargo build --release

# Install
sudo cp target/release/dybervpn /usr/local/bin/
```

### 4. Package Managers

Coming soon:
- Debian/Ubuntu: `apt install dybervpn`
- Fedora/RHEL: `dnf install dybervpn`
- Arch: `pacman -S dybervpn`

## Post-Installation

### Set Capabilities (Alternative to Root)

```bash
sudo setcap cap_net_admin+ep /usr/local/bin/dybervpn
```

### Create Directories

```bash
sudo mkdir -p /etc/dybervpn
sudo mkdir -p /var/run/dybervpn
```

### Generate Keys

```bash
# Hybrid mode (default)
dybervpn genkey -m hybrid > /etc/dybervpn/keys.txt

# PQ-only mode (maximum quantum resistance)
dybervpn genkey -m pqonly > /etc/dybervpn/keys.txt
```

### Verify Installation

```bash
dybervpn version
dybervpn benchmark -i 50
```

## Uninstallation

```bash
# Stop any running tunnels
sudo dybervpn down dvpn0

# Remove binary
sudo rm /usr/local/bin/dybervpn

# Remove configuration (optional)
sudo rm -rf /etc/dybervpn

# Remove Docker image (if used)
docker rmi ghcr.io/dyber-pqc/dybervpn:latest
```

## Next Steps

- [Configuration Guide](configuration.md)
- [Quick Start Tutorial](quickstart.md)
- [CLI Reference](cli-reference.md)

---

*Copyright 2026 Dyber, Inc.*
