# DyberVPN Docker Image
# Post-Quantum VPN with ML-KEM-768 + X25519

# Build stage
FROM rust:1.77-slim-bookworm AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy source
COPY . .

# Build release binary
RUN cargo build --release --bin dybervpn

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    iproute2 \
    iptables \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /build/target/release/dybervpn /usr/local/bin/dybervpn

# Create config directory
RUN mkdir -p /etc/dybervpn

# Set capabilities for network operations
RUN setcap cap_net_admin+ep /usr/local/bin/dybervpn || true

EXPOSE 51820/udp

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD dybervpn status dvpn0 || exit 1

ENTRYPOINT ["/usr/local/bin/dybervpn"]
CMD ["up", "-c", "/etc/dybervpn/config.toml", "-f"]
