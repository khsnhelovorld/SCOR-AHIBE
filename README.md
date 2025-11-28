# SCOR-AHIBE

**Self-Certifying Off-chain Revocation for Attribute-based Hierarchical Identity-Based Encryption**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-21+-orange.svg)](https://openjdk.java.net/)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.20-363636.svg)](https://soliditylang.org/)
[![IPFS](https://img.shields.io/badge/IPFS-Compatible-65C2CB.svg)](https://ipfs.tech/)
[![Ethereum](https://img.shields.io/badge/Ethereum-Sepolia-3C3C3D.svg)](https://sepolia.dev/)

> A novel credential revocation mechanism achieving **O(1) on-chain storage** per holder with **off-chain verifiability** through AHIBE encryption and IPFS storage.

---

## Overview

### What is SCOR-AHIBE?

SCOR-AHIBE is a reference implementation for efficient, verifiable credential revocation in decentralized identity systems. It combines:

- **AHIBE (Attribute-based Hierarchical IBE)** for time-bound credential encryption
- **Blockchain** for immutable revocation anchoring with O(1) storage
- **IPFS** for scalable off-chain ciphertext storage
- **Merkle Trees** for batch revocation aggregation

### Problem Statement

Traditional revocation mechanisms face scalability challenges:
- **CRLs (Certificate Revocation Lists)**: Linear growth, expensive distribution
- **OCSP**: Centralized, privacy-leaking queries
- **On-chain lists**: Expensive gas costs for large holder sets

### Our Solution

SCOR-AHIBE achieves:
| Metric | Traditional | SCOR-AHIBE |
|--------|------------|------------|
| On-chain storage | O(n) | **O(1)** per holder |
| Verification | Online query | **Off-chain** (time comparison) |
| Batch revocation | N transactions | **1 transaction** |
| Privacy | Leaks query patterns | **Encrypted** ciphertext |

### Target Users

- **Researchers** exploring IBE-based revocation schemes
- **Developers** building decentralized identity systems
- **Organizations** requiring scalable credential management

### Academic Reference

This implementation accompanies the research paper:
> *"SCOR-AHIBE: Efficient Verifiable Revocation for Attribute-based Hierarchical Identity-Based Encryption"* (2025)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          SCOR-AHIBE System                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌──────────────────────┐ │
│  │   PKG   │───▶│ Issuer  │───▶│ Holder  │    │      Verifier        │ │
│  │ (Setup) │    │(Revoke) │    │(Delegate│    │  (Check + Decrypt)   │ │
│  └─────────┘    └────┬────┘    └─────────┘    └──────────┬───────────┘ │
│                      │                                    │             │
│                      ▼                                    ▼             │
│              ┌───────────────┐                ┌───────────────────────┐ │
│              │     IPFS      │◀──────────────▶│     Blockchain        │ │
│              │  (Ciphertext) │                │  (Pointer + Epoch)    │ │
│              └───────────────┘                └───────────────────────┘ │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Components

| Component | Technology | Role |
|-----------|-----------|------|
| **PKG** | Java + BLS12-381 | Generate master keys and public parameters |
| **Issuer** | Java | Issue credentials, publish revocations |
| **Holder** | Java | Derive epoch-specific delegate keys |
| **Verifier** | Java | Check revocation status, decrypt certificates |
| **Smart Contract** | Solidity | Store revocation pointers (O(1) per holder) |
| **Storage** | IPFS | Store encrypted ciphertexts off-chain |

### Workflow

1. **Revocation**: Issuer encrypts session key for `(HolderID, Epoch)` → uploads to IPFS → publishes pointer to blockchain
2. **Verification**: Verifier queries blockchain → compares epochs → downloads from IPFS if needed → decrypts with delegate key

---

## Features

### Core Features
- [x] **BLS12-381 Pairing** - ~128-bit security with native library support
- [x] **AHIBE Encryption** - Hierarchical key derivation (Holder → Epoch)
- [x] **Off-chain Storage** - IPFS with automatic pinning
- [x] **O(1) On-chain** - Static key per holder (not per epoch)
- [x] **Batch Revocation** - Merkle tree aggregation for multiple holders
- [x] **Un-Revoke Support** - Version tracking with ACTIVE/REVOKED status

### Production Features
- [x] **AES-256-GCM** encrypted key export
- [x] **Circuit Breaker** for IPFS resilience
- [x] **LRU Cache** for aggregated indices (5 min TTL)
- [x] **Compact JSON** format (30-40% smaller)
- [x] **CSV Benchmark** export for analysis

### Verification Logic

| Condition | Result |
|-----------|--------|
| No record found | ✅ VALID |
| `T_check < T_rev` | ✅ VALID (before revocation) |
| `T_check ≥ T_rev` AND `Status = ACTIVE` | ✅ VALID (un-revoked) |
| `T_check ≥ T_rev` AND `Status = REVOKED` | ❌ REVOKED |

---

## Requirements

| Requirement | Version | Purpose |
|-------------|---------|---------|
| **Java JDK** | 21+ | Core application |
| **Node.js** | 18+ | Hardhat, scripts |
| **IPFS** | Any | Ciphertext storage |
| **Gradle** | 8.x | Java build |
| **npm** | 9+ | JS dependencies |

### Optional
- **IPFS Desktop** - Easiest IPFS setup for development
- **Sepolia ETH** - For testnet deployment ([Faucet](https://sepoliafaucet.com/))

---

## Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/your-repo/SCOR-AHIBE.git
cd SCOR-AHIBE
npm install
./gradlew build
```

### 2. Start IPFS

Launch **IPFS Desktop** or run:
```bash
ipfs daemon
```

### 3. Local Test (5 commands)

```powershell
# Terminal 1: Start local blockchain
npx hardhat node

# Terminal 2: Deploy & test
npm run hardhat:deploy:local
./gradlew run
$env:RECORD_PATH="app/outbox/holder_alice_example_com__2025-10-30.json"
npm run hardhat:publish:local
npm run hardhat:check:local
```

### 4. Sepolia Testnet

See **[SEPOLIA-QUICKSTART.md](SEPOLIA-QUICKSTART.md)** for full testnet guide.

---

## Usage

### Full Usage Guide

See **[Usage.md](Usage.md)** for comprehensive scenarios including:
- Single revocation flow
- Holder/Verifier separation
- Batch revocation
- Un-revoke mechanism
- Performance benchmarking
- Compact JSON format

### Quick Reference

| Task | Command |
|------|---------|
| Build | `./gradlew build` |
| Test (Java) | `./gradlew test` |
| Test (Solidity) | `npm run hardhat:test` |
| Full Demo | `./gradlew run` |
| Benchmark | `./gradlew runDemo -PappArgs="<holder>,<epoch>,<iterations>"` |
| Holder Key Gen | `./gradlew runHolder -PappArgs="<holder>,<epoch>"` |
| Verify | `./gradlew runVerifier -PappArgs="<keyPath>,<holder>,<epoch>"` |
| Batch Publish | `./gradlew runBatchPublisher -PappArgs="<csvFile>"` |
| Deploy Sepolia | `npm run hardhat:deploy:sepolia` |
| Publish to Chain | `npm run hardhat:publish:sepolia` |
| Check Status | `npm run hardhat:check:sepolia` |

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `IPFS_HOST` | `127.0.0.1` | IPFS API host |
| `IPFS_PORT` | `5001` | IPFS API port |
| `IPFS_GATEWAY_URL` | - | Public gateway fallback |
| `ETH_RPC_URL` | `http://127.0.0.1:8545` | Ethereum RPC endpoint |
| `NETWORK` | `hardhat` | Network name |
| `DELEGATE_KEY_SECRET` | - | Passphrase for key encryption |
| `OUTPUT_FORMAT` | `standard` | `compact` for smaller JSON |
| `CHECK_HOLDER_ID` | `holder:alice@example.com` | Holder to check |
| `CHECK_EPOCH` | `2025-10-30` | Epoch to check |

### Example `.env`

```bash
# Blockchain
SEPOLIA_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com
PRIVATE_KEY=your_private_key_here

# IPFS
IPFS_HOST=127.0.0.1
IPFS_PORT=5001

# Security
DELEGATE_KEY_SECRET=your-secure-passphrase
```

---

## Project Structure

```
SCOR-AHIBE/
├── app/src/main/java/com/project/ahibe/
│   ├── core/                    # Business logic
│   │   ├── IssuerService.java   # Revocation publishing
│   │   ├── HolderService.java   # Key derivation
│   │   ├── VerifierService.java # Status verification
│   │   └── BatchRevocationService.java
│   ├── crypto/                  # Cryptographic operations
│   │   ├── AhibeService.java    # High-level AHIBE API
│   │   ├── bls12/               # BLS12-381 implementation
│   │   └── HashingUtils.java    # Merkle tree operations
│   ├── eth/                     # Blockchain integration
│   │   ├── RevocationListClient.java
│   │   └── Web3jConnectionPool.java
│   ├── ipfs/                    # IPFS integration
│   │   ├── IPFSService.java
│   │   └── CircuitBreaker.java
│   ├── io/                      # Serialization
│   │   └── AggregatedRevocationIndex.java
│   ├── App.java                 # Main demo application
│   ├── DemoApp.java             # Benchmark runner
│   ├── HolderApp.java           # Standalone holder
│   ├── VerifierApp.java         # Standalone verifier
│   └── BatchPublisherApp.java   # Batch operations
├── contracts/
│   └── RevocationList.sol       # Smart contract
├── scripts/
│   ├── deploy.js                # Contract deployment
│   ├── publishRevocation.js     # Publish to chain
│   └── checkRevocation.js       # Query status
├── test/
│   └── RevocationList.test.js   # Contract tests
├── SEPOLIA-QUICKSTART.md        # Testnet guide
├── IPFS_GUIDE.md                # IPFS configuration
└── Usage.md                     # Detailed usage scenarios
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [SEPOLIA-QUICKSTART.md](SEPOLIA-QUICKSTART.md) | Quick start for Sepolia testnet |
| [Usage.md](Usage.md) | Comprehensive usage scenarios |
| [IPFS_GUIDE.md](IPFS_GUIDE.md) | IPFS setup and configuration |

---

## License

This project is licensed under the **MIT License** - see [LICENSE](LICENSE) for details.

---

## Acknowledgments

- [supranational/blst](https://github.com/supranational/blst) - BLS12-381 native library
- [BouncyCastle](https://www.bouncycastle.org/) - Java cryptography
- [Web3j](https://github.com/web3j/web3j) - Ethereum Java client
- [Hardhat](https://hardhat.org/) - Ethereum development environment
- [IPFS](https://ipfs.tech/) - Decentralized storage

---

## Citation

```bibtex
@inproceedings{scorahibe2025,
  title     = {SCOR-AHIBE: Efficient Verifiable Revocation for 
               Attribute-based Hierarchical Identity-Based Encryption},
  author    = {[Authors]},
  booktitle = {[Conference]},
  year      = {2025}
}
```
