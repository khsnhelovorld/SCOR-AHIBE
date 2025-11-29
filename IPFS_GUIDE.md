## IPFS Deployment Guide

This document provides comprehensive guidance for running SCOR-AHIBE with
different IPFS topologies, from local development to production deployments.

### Table of Contents

1. [Quick Start with IPFS Desktop](#1-quick-start-with-ipfs-desktop)
2. [Topology Overview](#2-topology-overview)
3. [Local Development Setup](#3-local-development-setup)
4. [Basic Pinning Operations](#4-basic-pinning-operations)
5. [Switching Between Local Node and Public Gateway](#5-switching-between-local-node-and-public-gateway)
6. [Configuration Reference](#6-configuration-reference)
7. [Migrating to Production](#7-migrating-to-production)
8. [Security Considerations](#8-security-considerations)
9. [Troubleshooting](#9-troubleshooting)
10. [Future Public Node Deployment](#10-future-public-node-deployment)

---

### 1. Quick Start with IPFS Desktop

**IPFS Desktop** is the easiest way to get started with IPFS for development.

#### Installation

1. Download IPFS Desktop from: https://docs.ipfs.tech/install/ipfs-desktop/
2. Install and launch the application
3. IPFS Desktop automatically:
   - Initializes your IPFS node
   - Starts the daemon in the background
   - Provides a system tray icon for status monitoring
   - Opens the Web UI for file management

#### Verify Installation

```bash
# Check if IPFS API is accessible
curl -X POST http://127.0.0.1:5001/api/v0/id

# Or using the IPFS CLI
ipfs id
```

#### Configure SCOR-AHIBE for Desktop

```powershell
# Windows PowerShell
$env:IPFS_HOST="127.0.0.1"
$env:IPFS_PORT="5001"

# Or use environment file
# Add to .env:
# IPFS_HOST=127.0.0.1
# IPFS_PORT=5001
```

**Note**: IPFS Desktop runs the API on `localhost:5001` by default. No additional configuration is needed for local development.

---

### 2. Topology Overview

| Topology | When to Use | Pros | Cons |
|----------|-------------|------|------|
| **IPFS Desktop** | Development, demos, learning | Zero setup, GUI management, automatic updates | Content unavailable when laptop sleeps; not externally reachable |
| **Local `ipfs daemon`** | CI/CD, servers, headless systems | Lightweight, scriptable, full control | Manual management required |
| **Private IPFS node/cluster** | Enterprise, controlled data plane | Full control, custom pinning policies, SLAs | Infrastructure overhead, operational complexity |
| **Public gateway** | Read-only verification, untrusted clients | No infrastructure needed, globally accessible | Rate limits, caching delays, no upload capability |

---

### 3. Local Development Setup

#### Option A: IPFS Desktop (Recommended for Development)

1. Install IPFS Desktop (see Quick Start above)
2. Launch the application
3. Configure SCOR-AHIBE:

```powershell
$env:IPFS_HOST="127.0.0.1"
$env:IPFS_PORT="5001"
```

#### Option B: Command-Line IPFS Daemon

```bash
# Install IPFS (using package manager or download)
# macOS: brew install ipfs
# Ubuntu: snap install ipfs
# Windows: Download from https://dist.ipfs.io

# Initialize IPFS (first time only)
ipfs init

# Start the daemon
ipfs daemon

# The daemon exposes:
# - API: http://127.0.0.1:5001
# - Gateway: http://127.0.0.1:8080
# - Swarm: 4001/tcp, 4001/udp
```

#### Verify Setup

```bash
# Test upload
echo "Hello SCOR-AHIBE" | ipfs add
# Returns: added QmXXX...

# Test download
ipfs cat QmXXX...
```

---

### 4. Basic Pinning Operations

Pinning ensures content remains available on your node and isn't garbage collected.

#### Pin Content After Upload

```bash
# Upload and pin (automatic with SCOR-AHIBE when IPFS_PIN_AFTER_ADD=true)
ipfs add --pin=true myfile.json

# Pin existing content
ipfs pin add QmYourContentCID

# List pinned content
ipfs pin ls

# Unpin content (will be garbage collected)
ipfs pin rm QmYourContentCID
```

#### SCOR-AHIBE Auto-Pinning

The Java application automatically pins uploaded content when:

```bash
# Enable pinning (default is true)
$env:IPFS_PIN_AFTER_ADD="true"

# Disable pinning (for cluster-managed pinning)
$env:IPFS_PIN_AFTER_ADD="false"
```

#### Verify Content is Pinned

```bash
# Check if specific CID is pinned
ipfs pin ls --type=recursive | grep QmYourCID

# Get pin status
ipfs pin ls QmYourCID
```

---

### 5. Switching Between Local Node and Public Gateway

SCOR-AHIBE supports both local IPFS nodes and public gateways for different use cases.

#### Local Node Configuration (Full Functionality)

```powershell
# For uploads and downloads
$env:IPFS_HOST="127.0.0.1"
$env:IPFS_PORT="5001"

# Clear gateway fallback
$env:IPFS_GATEWAY_URL=""
```

#### Public Gateway Configuration (Read-Only)

```powershell
# Gateway for read operations (uploads will fail)
$env:IPFS_GATEWAY_URL="https://ipfs.io/ipfs/"

# Alternative gateways:
# $env:IPFS_GATEWAY_URL="https://cloudflare-ipfs.com/ipfs/"
# $env:IPFS_GATEWAY_URL="https://dweb.link/ipfs/"
# $env:IPFS_GATEWAY_URL="https://gateway.pinata.cloud/ipfs/"
```

#### Hybrid Configuration (Recommended for Production)

```powershell
# Primary: Local/private node for uploads
$env:IPFS_HOST="your-ipfs-server.example.com"
$env:IPFS_PORT="5001"

# Fallback: Public gateway for reads when primary fails
$env:IPFS_GATEWAY_URL="https://ipfs.io/ipfs/"
```

#### Testing Gateway Access

```bash
# Test public gateway access
curl https://ipfs.io/ipfs/QmYourCID

# Test with SCOR-AHIBE
./gradlew runVerifier -PappArgs="holder:test@example.com,2025-01-01"
```

---

### 6. Configuration Reference

All IPFS configuration is done via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `IPFS_HOST` | `127.0.0.1` | IPFS API hostname |
| `IPFS_PORT` | `5001` | IPFS API port |
| `IPFS_URL` | - | Full URL override (e.g., `http://ipfs.example.com:5001`) |
| `IPFS_GATEWAY_URL` | - | Read-only fallback gateway (e.g., `https://ipfs.io/ipfs/`) |
| `IPFS_PIN_AFTER_ADD` | `true` | Pin content after upload |
| `IPFS_MAX_RETRIES` | `3` | Number of retry attempts |
| `IPFS_RETRY_BACKOFF_MS` | `200` | Initial retry backoff (doubles each attempt) |
| `IPFS_API_BEARER_TOKEN` | - | Bearer token for authenticated APIs |
| `IPFS_API_BASIC_AUTH` | - | Basic auth credentials (`user:pass`) |
| `IPFS_API_BASIC_USER` | - | Basic auth username |
| `IPFS_API_BASIC_PASS` | - | Basic auth password |
| `IPFS_TLS_INSECURE` | `false` | Skip TLS certificate verification (dev only!) |
| `IPFS_CLIENT_CERT_P12` | - | Path to client certificate (PKCS12) |
| `IPFS_CLIENT_CERT_PASSWORD` | - | Client certificate password |
| `IPFS_CA_CERT_PATH` | - | Custom CA certificate path |

#### Example .env File

```bash
# .env file for SCOR-AHIBE

# IPFS Configuration
IPFS_HOST=127.0.0.1
IPFS_PORT=5001
IPFS_PIN_AFTER_ADD=true
IPFS_GATEWAY_URL=https://ipfs.io/ipfs/
IPFS_MAX_RETRIES=3
IPFS_RETRY_BACKOFF_MS=200

# Blockchain Configuration
ETH_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com
PRIVATE_KEY=your_private_key_here

# Security
DELEGATE_KEY_SECRET=your-strong-passphrase-here
```

---

### 7. Migrating to Production

#### Step 1: Provision Infrastructure

- Dedicated VM or container with public IP
- Install `kubo` (go-ipfs) or use managed IPFS service
- Minimum specs: 2 CPU, 4GB RAM, 100GB SSD

#### Step 2: Configure Secure Access

```bash
# Bind API to specific interface (not 0.0.0.0!)
ipfs config Addresses.API "/ip4/10.0.0.1/tcp/5001"

# Or use reverse proxy with TLS
# nginx.conf example in docs/nginx-ipfs.conf
```

#### Step 3: Enable Authentication

```bash
# Option A: Bearer token via reverse proxy
$env:IPFS_API_BEARER_TOKEN="your-secret-token"

# Option B: Basic auth via reverse proxy  
$env:IPFS_API_BASIC_USER="ipfs-user"
$env:IPFS_API_BASIC_PASS="secure-password"

# Option C: mTLS for enterprise
$env:IPFS_CLIENT_CERT_P12="/path/to/client.p12"
$env:IPFS_CLIENT_CERT_PASSWORD="cert-password"
$env:IPFS_CA_CERT_PATH="/path/to/ca.crt"
```

#### Step 4: Set Up Pinning

For high availability, pin content on multiple nodes:

```bash
# On primary node
ipfs pin add QmYourCiphertextCID

# On replica nodes
ipfs pin add QmYourCiphertextCID

# Or use IPFS Cluster for automated replication
# https://cluster.ipfs.io/
```

---

### 8. Security Considerations

#### API Security

- **Never expose `/api/v0` to the public internet without authentication**
- Use reverse proxy (nginx, caddy) with TLS termination
- Implement rate limiting to prevent abuse
- Use firewall rules to restrict access

#### Content Security

- Ciphertext files contain encrypted data only (no plaintext secrets)
- Each holder has exactly one ciphertext file (SCOR-AHIBE principle)
- Treat CIDs as sensitive metadata (reveals revocation patterns)
- Consider using private IPFS networks for highly sensitive deployments

#### Key Management

- Always set `DELEGATE_KEY_SECRET` for encrypted key exports
- Use strong passphrases (16+ characters, mixed case, numbers, symbols)
- Rotate keys periodically
- Never commit secrets to version control

#### Private IPFS Networks with Swarm Keys

For enterprise deployments requiring complete isolation, you can create a private IPFS network using a swarm key. Only nodes with the same swarm key can communicate.

##### Generating a Swarm Key

```bash
# Method 1: Using go-ipfs-swarm-key-gen (recommended)
go install github.com/Kubuxu/go-ipfs-swarm-key-gen/ipfs-swarm-key-gen@latest
ipfs-swarm-key-gen > ~/.ipfs/swarm.key

# Method 2: Using OpenSSL (alternative)
echo -e "/key/swarm/psk/1.0.0/\n/base16/\n$(openssl rand -hex 32)" > ~/.ipfs/swarm.key

# Method 3: Using Python
python3 -c "import secrets; print('/key/swarm/psk/1.0.0/\n/base16/\n' + secrets.token_hex(32))" > ~/.ipfs/swarm.key
```

##### Distributing the Swarm Key

1. **Secure Transfer**: Copy the `swarm.key` file to each node using SCP, rsync, or secure configuration management (Ansible, Terraform)

```bash
# Copy to remote node
scp ~/.ipfs/swarm.key user@remote-node:~/.ipfs/swarm.key

# Set proper permissions
chmod 600 ~/.ipfs/swarm.key
```

2. **Key Placement**: The file must be at `~/.ipfs/swarm.key` (Linux/macOS) or `%USERPROFILE%\.ipfs\swarm.key` (Windows)

##### Configuring Private Network Nodes

```bash
# Remove default bootstrap peers
ipfs bootstrap rm --all

# Add only your private network peers
ipfs bootstrap add /ip4/192.168.1.10/tcp/4001/p2p/QmPeerID1...
ipfs bootstrap add /ip4/192.168.1.11/tcp/4001/p2p/QmPeerID2...

# Configure IPFS to reject public network connections
ipfs config --json Swarm.DisableBandwidthMetrics false
ipfs config --json Swarm.ResourceMgr.Enabled true
```

##### Verifying Private Network

```bash
# Start IPFS daemon (should show "Swarm key present")
ipfs daemon
# Look for: "Swarm is limited to private network of peers with the swarm key"

# Verify connected peers are only your nodes
ipfs swarm peers

# Test isolation: Public CIDs should be unreachable
ipfs cat QmPublicCID  # Should timeout or fail
```

##### Docker Deployment with Swarm Key

```yaml
# docker-compose.yml
version: '3.8'
services:
  ipfs-node:
    image: ipfs/kubo:latest
    volumes:
      - ipfs_data:/data/ipfs
      - ./swarm.key:/data/ipfs/swarm.key:ro
    environment:
      - IPFS_SWARM_KEY_FILE=/data/ipfs/swarm.key
      - LIBP2P_FORCE_PNET=1  # Enforce private network
    ports:
      - "5001:5001"
      - "4001:4001"
    command: >
      sh -c "ipfs bootstrap rm --all &&
             ipfs bootstrap add /ip4/192.168.1.10/tcp/4001/p2p/QmPeer1 &&
             ipfs daemon"
```

##### Kubernetes Secret for Swarm Key

```yaml
# swarm-key-secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: ipfs-swarm-key
type: Opaque
stringData:
  swarm.key: |
    /key/swarm/psk/1.0.0/
    /base16/
    <your-64-character-hex-key-here>
```

```yaml
# ipfs-deployment.yaml (volume mount)
spec:
  containers:
  - name: ipfs
    volumeMounts:
    - name: swarm-key
      mountPath: /data/ipfs/swarm.key
      subPath: swarm.key
      readOnly: true
  volumes:
  - name: swarm-key
    secret:
      secretName: ipfs-swarm-key
```

##### Security Best Practices for Swarm Keys

| Practice | Recommendation |
|----------|----------------|
| Key Generation | Use cryptographically secure random generator |
| Key Storage | Encrypt at rest using secrets manager (Vault, AWS Secrets) |
| Key Rotation | Rotate annually or after any security incident |
| Access Control | Limit key access to infrastructure admins only |
| Audit | Log all swarm key access and distribution events |
| Backup | Securely backup keys with offline storage |

---

### 9. Troubleshooting

#### IPFS Connection Refused

```bash
# Check if daemon is running
ps aux | grep ipfs
# or on Windows
tasklist | findstr ipfs

# Start daemon
ipfs daemon

# Check API binding
ipfs config Addresses.API
```

#### Circuit Breaker Open

If you see "Circuit breaker is OPEN" errors:

```java
// The service automatically recovers after 30 seconds
// Manual reset if needed:
ipfsService.resetCircuitBreaker();
```

#### Content Not Found (404)

```bash
# Verify content exists locally
ipfs pin ls | grep QmYourCID

# Try fetching from network
ipfs get QmYourCID

# Check peer connections
ipfs swarm peers
```

#### Slow Downloads

```bash
# Enable QUIC for faster transfers
ipfs config --json Swarm.Transports.Network.QUIC true

# Add direct peers for faster discovery
ipfs bootstrap add /ip4/104.236.179.241/tcp/4001/p2p/QmPeer...
```

---

### 10. Future Public Node Deployment

> **Note**: This section is for planning purposes. Implementation requires additional infrastructure.

#### Recommended Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Load Balancer (TLS)                      │
└─────────────────────────────────────────────────────────────┘
                              │
         ┌────────────────────┼────────────────────┐
         │                    │                    │
┌────────▼────────┐  ┌────────▼────────┐  ┌────────▼────────┐
│   IPFS Node 1   │  │   IPFS Node 2   │  │   IPFS Node 3   │
│  (Primary Pin)  │  │    (Replica)    │  │    (Replica)    │
└─────────────────┘  └─────────────────┘  └─────────────────┘
         │                    │                    │
         └────────────────────┼────────────────────┘
                              │
                    ┌─────────▼─────────┐
                    │   IPFS Cluster    │
                    │   (Pin Manager)   │
                    └───────────────────┘
```

#### Key Components

1. **Load Balancer**: SSL termination, health checks, geographic routing
2. **IPFS Nodes**: Kubo instances with swarm connectivity
3. **IPFS Cluster**: Automatic pin replication and management
4. **Monitoring**: Prometheus + Grafana for metrics
5. **Backup**: Regular snapshots of pinned content

#### Estimated Resources

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| Nodes | 3 | 5+ |
| CPU/node | 4 cores | 8 cores |
| RAM/node | 8 GB | 16 GB |
| Storage/node | 500 GB SSD | 1 TB NVMe |
| Network | 1 Gbps | 10 Gbps |

#### Migration Checklist

- [ ] Provision infrastructure
- [ ] Install and configure IPFS nodes
- [ ] Set up IPFS Cluster
- [ ] Configure TLS/mTLS
- [ ] Implement authentication
- [ ] Set up monitoring
- [ ] Migrate existing pins
- [ ] Update client configurations
- [ ] Performance testing
- [ ] Documentation update

---

### Ciphertext Caching

The `VerifierService` uses direct IPFS fetching with circuit breaker protection:

- **Circuit Breaker**: Prevents cascading failures when IPFS is unavailable
- **Retry Logic**: Exponential backoff for transient failures
- **Gateway Fallback**: Falls back to public gateways when local node is down

---

### Code Integration

Java applications integrate with IPFS via these environment variables:

```java
// Automatic configuration from environment
IPFSService ipfs = new IPFSService(
    System.getenv("IPFS_HOST"),
    Integer.parseInt(System.getenv("IPFS_PORT"))
);

// Circuit breaker status
if (!ipfs.isCircuitClosed()) {
    // Handle degraded mode
}
```

SCOR-AHIBE Principle:
- Each holder has exactly one ciphertext file on IPFS
- Direct CID lookup with O(1) complexity
- No aggregation or shared data files
