#!/bin/bash
# DyberVPN Installation Script
# Post-Quantum VPN for Infrastructure You Control

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Defaults
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/dybervpn"
SYSTEMD_DIR="/etc/systemd/system"

echo -e "${GREEN}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║           DyberVPN Installation Script                    ║"
echo "║        Post-Quantum VPN with ML-KEM-768 + X25519          ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (use sudo)${NC}"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
else
    OS=$(uname -s)
fi

echo -e "${YELLOW}Detected OS: $OS${NC}"

# Check for pre-built binary or build from source
if [ -f "./target/release/dybervpn" ]; then
    BINARY="./target/release/dybervpn"
    echo -e "${GREEN}Found pre-built binary${NC}"
elif [ -f "./dybervpn" ]; then
    BINARY="./dybervpn"
    echo -e "${GREEN}Found binary in current directory${NC}"
else
    echo -e "${YELLOW}No binary found. Building from source...${NC}"
    
    # Check for Rust
    if ! command -v cargo &> /dev/null; then
        echo -e "${RED}Rust not found. Installing Rust...${NC}"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
    fi
    
    # Build
    echo "Building DyberVPN (this may take a few minutes)..."
    cargo build --release
    BINARY="./target/release/dybervpn"
fi

# Install binary
echo -e "${GREEN}Installing binary to $INSTALL_DIR${NC}"
install -m 755 "$BINARY" "$INSTALL_DIR/dybervpn"

# Create config directory
echo -e "${GREEN}Creating config directory at $CONFIG_DIR${NC}"
mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

# Install systemd service
if [ -d "$SYSTEMD_DIR" ]; then
    echo -e "${GREEN}Installing systemd service${NC}"
    cp deploy/dybervpn.service "$SYSTEMD_DIR/"
    systemctl daemon-reload
fi

# Create example config if none exists
if [ ! -f "$CONFIG_DIR/config.toml" ]; then
    echo -e "${GREEN}Creating example configuration${NC}"
    cat > "$CONFIG_DIR/config.toml.example" << 'EOF'
# DyberVPN Server Configuration Example
# Copy to config.toml and customize

[interface]
name = "dvpn0"
# Generate with: dybervpn genkey -m hybrid
private_key = "YOUR_PRIVATE_KEY_HERE"
pq_private_key = "YOUR_PQ_PRIVATE_KEY_HERE"
listen_port = 51820
address = "10.0.0.1/24"
mode = "hybrid"  # hybrid, pq-only, or classic

# Add peers below
# [[peer]]
# public_key = "PEER_PUBLIC_KEY"
# pq_public_key = "PEER_PQ_PUBLIC_KEY"
# allowed_ips = "10.0.0.2/32"
# endpoint = "peer.example.com:51820"  # optional for clients
# persistent_keepalive = 25
EOF
fi

# Verify installation
echo ""
echo -e "${GREEN}Verifying installation...${NC}"
dybervpn version

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║           Installation Complete!                         ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Next steps:"
echo "  1. Generate keys:      dybervpn genkey -m hybrid > keys.txt"
echo "  2. Create config:      cp $CONFIG_DIR/config.toml.example $CONFIG_DIR/config.toml"
echo "  3. Edit config:        nano $CONFIG_DIR/config.toml"
echo "  4. Start manually:     dybervpn up -c $CONFIG_DIR/config.toml"
echo "  5. Or enable service:  systemctl enable --now dybervpn"
echo ""
echo -e "${YELLOW}For more info: https://github.com/dyber-pqc/DyberVPN${NC}"
