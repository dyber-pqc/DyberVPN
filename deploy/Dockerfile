# DyberVPN Docker Image
# Post-Quantum VPN with ML-KEM-768 + ML-DSA-65

# Build stage
FROM rust:1-slim-bookworm AS builder

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
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /build/target/release/dybervpn /usr/local/bin/dybervpn

# Create config and run directories
RUN mkdir -p /etc/dybervpn /var/run/dybervpn

# Note: Use --cap-add=NET_ADMIN when running the container for TUN access

EXPOSE 51820/udp
EXPOSE 51821/tcp

ENTRYPOINT ["/usr/local/bin/dybervpn"]
CMD ["up", "-c", "/etc/dybervpn/config.toml", "-f"]
