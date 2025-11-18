# SCOR-AHIBE Quick Demo Guide

## Mô hình AHIBE với Holder → Verifier Flow

Hệ thống implement **Attribute-based Hierarchical Identity-Based Encryption (AHIBE)** cho revocation system:

```
PKG → Issuer → Holder (Root Key) → Derive → Delegate Keys (per epoch) → Verifier
```

## Prerequisites

1. **IPFS Desktop** đã cài và đang chạy (hoặc `ipfs daemon`)
2. **Node.js 18+** và dependencies đã cài: `npm install`
3. **JDK 21+** đã cài

## Demo Steps

### 1. Start Local Blockchain

```bash
# Terminal 1
npx hardhat node


**⚠️ QUAN TRỌNG:** 
- Để terminal này CHẠY và KHÔNG đóng nó
- Hardhat node phải chạy TRƯỚC khi deploy/publish
- Nếu restart Hardhat node, contract state sẽ bị mất → cần redeploy và republish

### CÁC LỆNH BÊN DƯỚI CHẠY TRÊN CÙNG 1 TERMINAL
### 2. Deploy Smart Contract

```bash
npm run hardhat:deploy:local
```

✓ Tạo file `deployments/hardhat.json` với contract address.

### 3. Issuer: Generate Revocation Certificate

```bash
# Deploy contract (Ghi lại Gas used từ Terminal 1)
npm run hardhat:deploy:local

# Tạo data và Publish lên Chain (Ghi lại Gas used từ Terminal 1)
$env:RECORD_PATH="app/outbox/holder_alice_example_com__2025-10-30.json"
npm run hardhat:publish

# Chạy Benchmark Java
$env:NETWORK="hardhat"; $env:ETH_RPC_URL="http://127.0.0.1:8545"; $env:IPFS_HOST="127.0.0.1"; $env:IPFS_PORT="5001"
./gradlew runDemo -PappArgs="holder:alice@example.com,2025-10-30"
```
## Architecture Diagram

```
┌──────────┐
│   PKG    │ (Private Key Generator)
└────┬─────┘
     │ masterKey
     ▼
┌──────────┐
│  Issuer  │
└────┬─────┘
     │ rootKey(holder:alice)
     ▼
┌──────────┐         Revocation Certificate
│  Holder  │         ┌─────────────────────┐
│  Alice   │         │  Encrypted for      │
└────┬─────┘         │  holder:alice ||    │
     │               │  2025-10-30         │
     │ derive        └──────────┬──────────┘
     ▼                          │ Upload
┌──────────────┐                ▼
│ Delegate Key │           ┌────────┐
│ (2025-10-30) │           │  IPFS  │ ← CID
└──────┬───────┘           └────────┘
       │ send to                │
       ▼                        │ CID stored
  ┌──────────┐                 ▼
  │ Verifier │ ──query──→ ┌──────────────┐
  └──────────┘            │ Blockchain   │
       │                  │ Smart        │
       │ ←──── CID ────── │ Contract     │
       │                  └──────────────┘
       ▼ download
  ┌────────┐
  │  IPFS  │
  └────┬───┘
       │ ciphertext
       ▼
  ┌──────────────────┐
  │ Decrypt with     │
  │ delegate key     │
  └──────────────────┘
       │
       ▼
  ✓ REVOKED / NOT REVOKED
```