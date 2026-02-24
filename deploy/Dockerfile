# DyberVPN Docker Image
# Post-Quantum VPN for Infrastructure You Control

FROM rust:1.75-bookworm AS builder

WORKDIR /build

# Copy source
COPY . .

# Build release binary
RUN cargo build --release -p dybervpn-cli

# Runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    iproute2 \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# Copy binary
COPY --from=builder /build/target/release/dybervpn /usr/local/bin/dybervpn

# Create config directory
RUN mkdir -p /etc/dybervpn

# Default config location
VOLUME /etc/dybervpn

# WireGuard-compatible port
EXPOSE 51820/udp

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD dybervpn status dvpn0 || exit 1

# Run in foreground
ENTRYPOINT ["dybervpn"]
CMD ["up", "/etc/dybervpn/config.toml", "--foreground"]
