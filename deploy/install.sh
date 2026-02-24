#!/bin/bash
# DyberVPN Installation Script
# Post-Quantum VPN for Infrastructure You Control

set -e

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/dybervpn"
SYSTEMD_DIR="/etc/systemd/system"
REPO_URL="https://github.com/dyberinc/dybervpn"

echo "================================"
echo "DyberVPN Installer"
echo "Post-Quantum VPN"
echo "================================"
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo)"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "Cannot detect OS"
    exit 1
fi

echo "Detected OS: $OS"
echo

# Install dependencies
echo "Installing dependencies..."
case $OS in
    ubuntu|debian)
        apt-get update
        apt-get install -y curl build-essential
        ;;
    fedora|centos|rhel)
        dnf install -y curl gcc
        ;;
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac

# Check for Rust
if ! command -v cargo &> /dev/null; then
    echo "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

# Clone and build
echo
echo "Building DyberVPN..."
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

git clone "$REPO_URL" dybervpn
cd dybervpn

cargo build --release -p dybervpn-cli

# Install binary
echo
echo "Installing binary..."
install -m 755 target/release/dybervpn "$INSTALL_DIR/dybervpn"

# Create config directory
mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

# Install systemd service
if [ -d "$SYSTEMD_DIR" ]; then
    echo "Installing systemd service..."
    cp deploy/dybervpn.service "$SYSTEMD_DIR/"
    systemctl daemon-reload
fi

# Cleanup
rm -rf "$TEMP_DIR"

echo
echo "================================"
echo "Installation complete!"
echo "================================"
echo
echo "Next steps:"
echo "  1. Generate keys:     dybervpn init --server > /etc/dybervpn/config.toml"
echo "  2. Edit config:       nano /etc/dybervpn/config.toml"
echo "  3. Start service:     systemctl enable --now dybervpn"
echo
echo "For client setup:       dybervpn init --client <SERVER_IP>"
echo
echo "Version info:           dybervpn version"
echo
