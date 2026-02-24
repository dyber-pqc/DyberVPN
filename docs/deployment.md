# Deployment Guide

This guide covers various deployment options for DyberVPN.

## Table of Contents

1. [systemd Service](#systemd-service)
2. [Docker](#docker)
3. [Docker Compose](#docker-compose)
4. [Kubernetes](#kubernetes)
5. [Cloud Deployments](#cloud-deployments)

## systemd Service

### Installation

```bash
# Copy service file
sudo cp deploy/dybervpn.service /etc/systemd/system/

# Create configuration directory
sudo mkdir -p /etc/dybervpn

# Copy your configuration
sudo cp your-config.toml /etc/dybervpn/config.toml

# Reload systemd
sudo systemctl daemon-reload

# Enable and start
sudo systemctl enable dybervpn
sudo systemctl start dybervpn
```

### Service File

```ini
# /etc/systemd/system/dybervpn.service

[Unit]
Description=DyberVPN Post-Quantum VPN
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/dybervpn up -c /etc/dybervpn/config.toml -f
ExecStop=/usr/local/bin/dybervpn down dvpn0
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/run/dybervpn

# Capabilities
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
```

### Management

```bash
# Status
sudo systemctl status dybervpn

# Logs
sudo journalctl -u dybervpn -f

# Restart
sudo systemctl restart dybervpn

# Stop
sudo systemctl stop dybervpn
```

## Docker

### Pull Image

```bash
docker pull ghcr.io/dyber-pqc/dybervpn:latest
```

### Run Container

```bash
docker run -d \
  --name dybervpn \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  --sysctl net.ipv4.ip_forward=1 \
  -v /path/to/config.toml:/etc/dybervpn/config.toml:ro \
  -p 51820:51820/udp \
  --restart unless-stopped \
  ghcr.io/dyber-pqc/dybervpn:latest
```

### Custom Commands

```bash
# Generate keys
docker run --rm ghcr.io/dyber-pqc/dybervpn:latest genkey -m hybrid

# Check configuration
docker run --rm \
  -v /path/to/config.toml:/etc/dybervpn/config.toml:ro \
  ghcr.io/dyber-pqc/dybervpn:latest check -c /etc/dybervpn/config.toml

# Run benchmarks
docker run --rm ghcr.io/dyber-pqc/dybervpn:latest benchmark -i 100
```

### Build Custom Image

```bash
# Clone repository
git clone https://github.com/dyber-pqc/DyberVPN.git
cd DyberVPN

# Build image
docker build -t my-dybervpn:latest -f deploy/Dockerfile .
```

## Docker Compose

### Basic Setup

```yaml
# docker-compose.yml
version: '3.8'

services:
  dybervpn:
    image: ghcr.io/dyber-pqc/dybervpn:latest
    container_name: dybervpn
    cap_add:
      - NET_ADMIN
      - NET_RAW
    sysctls:
      - net.ipv4.ip_forward=1
    volumes:
      - ./config.toml:/etc/dybervpn/config.toml:ro
    ports:
      - "51820:51820/udp"
    restart: unless-stopped
```

### Start

```bash
docker-compose up -d
```

### With Multiple Interfaces

```yaml
version: '3.8'

services:
  dybervpn-site1:
    image: ghcr.io/dyber-pqc/dybervpn:latest
    container_name: dybervpn-site1
    cap_add:
      - NET_ADMIN
      - NET_RAW
    sysctls:
      - net.ipv4.ip_forward=1
    volumes:
      - ./site1.toml:/etc/dybervpn/config.toml:ro
    ports:
      - "51820:51820/udp"
    restart: unless-stopped

  dybervpn-site2:
    image: ghcr.io/dyber-pqc/dybervpn:latest
    container_name: dybervpn-site2
    cap_add:
      - NET_ADMIN
      - NET_RAW
    sysctls:
      - net.ipv4.ip_forward=1
    volumes:
      - ./site2.toml:/etc/dybervpn/config.toml:ro
    ports:
      - "51821:51820/udp"
    restart: unless-stopped
```

## Kubernetes

### ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: dybervpn-config
data:
  config.toml: |
    [interface]
    name = "dvpn0"
    listen_port = 51820
    address = "10.200.200.1/24"
    mode = "hybrid"
    private_key = "${PRIVATE_KEY}"
    pq_private_key = "${PQ_PRIVATE_KEY}"
    
    [[peer]]
    public_key = "${PEER_PUBLIC_KEY}"
    pq_public_key = "${PEER_PQ_PUBLIC_KEY}"
    allowed_ips = "10.200.200.2/32"
```

### Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: dybervpn-keys
type: Opaque
stringData:
  private_key: "BASE64_PRIVATE_KEY"
  pq_private_key: "BASE64_PQ_PRIVATE_KEY"
```

### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: dybervpn
spec:
  replicas: 1
  selector:
    matchLabels:
      app: dybervpn
  template:
    metadata:
      labels:
        app: dybervpn
    spec:
      containers:
      - name: dybervpn
        image: ghcr.io/dyber-pqc/dybervpn:latest
        ports:
        - containerPort: 51820
          protocol: UDP
        securityContext:
          capabilities:
            add:
            - NET_ADMIN
            - NET_RAW
        volumeMounts:
        - name: config
          mountPath: /etc/dybervpn
          readOnly: true
      volumes:
      - name: config
        configMap:
          name: dybervpn-config
```

### Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: dybervpn
spec:
  type: LoadBalancer
  ports:
  - port: 51820
    targetPort: 51820
    protocol: UDP
  selector:
    app: dybervpn
```

## Cloud Deployments

### AWS EC2

```bash
# Launch instance
aws ec2 run-instances \
  --image-id ami-0c55b159cbfafe1f0 \
  --instance-type t3.micro \
  --key-name your-key \
  --security-group-ids sg-xxxxxx \
  --user-data file://user-data.sh

# user-data.sh
#!/bin/bash
curl -LO https://github.com/dyber-pqc/DyberVPN/releases/latest/download/dybervpn-linux-x86_64.tar.gz
tar -xzf dybervpn-linux-x86_64.tar.gz
mv dybervpn /usr/local/bin/
# Configure and start...
```

### Google Cloud

```bash
gcloud compute instances create dybervpn-server \
  --machine-type=e2-micro \
  --image-family=ubuntu-2404-lts \
  --image-project=ubuntu-os-cloud \
  --tags=dybervpn \
  --metadata-from-file=startup-script=startup.sh
```

### Azure

```bash
az vm create \
  --resource-group myResourceGroup \
  --name dybervpn-server \
  --image Ubuntu2204 \
  --size Standard_B1s \
  --admin-username azureuser \
  --custom-data cloud-init.yaml
```

## Firewall Configuration

### iptables

```bash
# Allow UDP traffic
iptables -A INPUT -p udp --dport 51820 -j ACCEPT

# Allow forwarding (for routing)
iptables -A FORWARD -i dvpn0 -j ACCEPT
iptables -A FORWARD -o dvpn0 -j ACCEPT

# NAT (if routing to internet)
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

### ufw

```bash
ufw allow 51820/udp
ufw allow in on dvpn0
ufw allow out on dvpn0
```

### firewalld

```bash
firewall-cmd --permanent --add-port=51820/udp
firewall-cmd --permanent --add-interface=dvpn0 --zone=trusted
firewall-cmd --reload
```

## Monitoring

### Prometheus Metrics

DyberVPN exposes Prometheus metrics on `/metrics` (when enabled):

```
# Handshake metrics
dybervpn_handshakes_total{mode="hybrid"} 42
dybervpn_handshake_duration_seconds{quantile="0.99"} 0.003

# Traffic metrics
dybervpn_bytes_received_total 1234567
dybervpn_bytes_sent_total 7654321

# Peer metrics
dybervpn_peers_active 5
```

### Logging

```bash
# journalctl (systemd)
journalctl -u dybervpn -f

# Docker logs
docker logs -f dybervpn

# Verbose mode
dybervpn up -c config.toml -f -v
```

---

*Copyright 2026 Dyber, Inc.*
