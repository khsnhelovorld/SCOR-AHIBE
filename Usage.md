# SCOR-AHIBE Usage Guide

Complete usage scenarios for SCOR-AHIBE on local and testnet environments.

---

## Table of Contents

1. [Setup & Deploy](#1-setup--deploy)
2. [Single Revocation](#2-single-revocation)
3. [Holder & Verifier Flow](#3-holder--verifier-flow)
4. [Un-Revoke Mechanism](#4-un-revoke-mechanism)
5. [Performance Benchmark](#5-performance-benchmark)
6. [Encrypted Key Export](#6-encrypted-key-export)
7. [Multi-Network Deploy](#7-multi-network-deploy)
8. [IPFS Gateway Fallback](#8-ipfs-gateway-fallback)
9. [Command Reference](#command-reference)

---

## 1. Setup & Deploy

```powershell
# Install dependencies
npm install
./gradlew build

# Run tests
./gradlew test              # Java tests
npm run hardhat:test        # Solidity tests

# Deploy to Sepolia
npm run hardhat:deploy:sepolia
# Output: Contract deployed to: 0x... (save this address)
```

---

## 2. Single Revocation

### Step 1: Set Environment

```powershell
$env:IPFS_HOST="127.0.0.1"
$env:IPFS_PORT="5001"
$env:NETWORK="sepolia"
$env:ETH_RPC_URL="https://ethereum-sepolia-rpc.publicnode.com"
$env:DELEGATE_KEY_SECRET="my-secure-passphrase-123"
```

### Step 2: Generate Revocation Certificate

```powershell
./gradlew run
# Output: app/outbox/holder_alice_example_com__2025-10-30.json
```

### Step 3: Publish to Blockchain

```powershell
$env:RECORD_PATH="app/outbox/holder_alice_example_com__2025-10-30.json"
npm run hardhat:publish:sepolia
```

### Step 4: Verify Status

```powershell
npm run hardhat:check:sepolia
```

---

## 3. Holder & Verifier Flow

Simulate separate Holder and Verifier entities.

### Holder: Generate Delegate Key

```powershell
$env:DELEGATE_KEY_SECRET="my-secure-passphrase-123"
./gradlew runHolder -PappArgs="holder:alice@example.com,2025-10-30"
# Output: app/outbox/delegate_key_holder_alice_example.com_2025-10-30.key
```

### Verifier: Check Revocation Status

```powershell
$env:DELEGATE_KEY_SECRET="my-secure-passphrase-123"
./gradlew runVerifier -PappArgs="outbox/delegate_key_holder_alice_example.com_2025-10-30.key,holder:alice@example.com,2025-10-30"
```

**Important:** Both Holder and Verifier must use the **same `DELEGATE_KEY_SECRET`**.

---

## 4. Un-Revoke Mechanism

Re-activate a previously revoked holder.

### Check Current Status

```powershell
npm run hardhat:check:sepolia
# Shows: Status: REVOKED (1), Version: N
```

### Un-Revoke via Console

```powershell
npx hardhat console --network sepolia
```

In the console:
```javascript
const address = "0x47e00EdB9fd5366eE44Ac103B6260fe06b9577B8"  // Your contract
const contract = await ethers.getContractAt("RevocationList", address)
const key = ethers.keccak256(ethers.toUtf8Bytes("holder:alice@example.com"))
const tx = await contract.unrevoke(key)
await tx.wait()
console.log("Un-revoked!")
.exit
```

### Verify Un-Revoke

```powershell
npm run hardhat:check:sepolia
# Shows: Status: ACTIVE (0), Version: N+1
```

### Re-Revoke (After Un-Revoke)

```powershell
$env:RECORD_PATH="app/outbox/holder_alice_example_com__2025-10-30.json"
npm run hardhat:publish:sepolia
```

### Status Summary

| Condition | Result |
|-----------|--------|
| `T_check < T_rev` | ✅ VALID (before revocation) |
| `T_check >= T_rev` AND `Status = REVOKED` | ❌ REVOKED |
| `T_check >= T_rev` AND `Status = ACTIVE` | ✅ VALID (un-revoked) |

---

## 5. Performance Benchmark

Run cryptographic operation benchmarks.

### Default (1000 iterations)

```powershell
./gradlew runDemo -PappArgs="holder:alice@example.com,2025-10-30"
```

### Custom Iterations

```powershell
./gradlew runDemo -PappArgs="holder:alice@example.com,2025-10-30,500"
```

### Results

CSV exported to: `benchmark_results/benchmark_<holder>_<epoch>_<timestamp>.csv`

**Metrics captured:**
- Delegate key generation time
- Blockchain query time
- IPFS fetch time
- Decryption time

---

## 6. Encrypted Key Export

Secure delegate key transfer between machines.

### Demo Mode (Insecure)

```powershell
$env:DELEGATE_KEY_SECRET=""
./gradlew runHolder -PappArgs="holder:test@example.com,2025-12-01"
# Warning: Keys stored in memory only, lost when app exits
```

### Production Mode (Encrypted)

```powershell
$env:DELEGATE_KEY_SECRET="my-secure-passphrase-123"
./gradlew runHolder -PappArgs="holder:test@example.com,2025-12-01"
# Output: AES-256-GCM encrypted key file
```

### Comparison

| Aspect | No Passphrase | With Passphrase |
|--------|--------------|-----------------|
| Storage | JVM memory | Encrypted file |
| Persistence | Lost on exit | Permanent |
| Transfer | Not possible | ✅ Secure file transfer |
| Security | ❌ Insecure | ✅ AES-256-GCM + PBKDF2 |

### Key Transfer

1. Set same `DELEGATE_KEY_SECRET` on both machines
2. Transfer `.key` file (encrypted, safe over insecure channels)
3. Import on target machine with same passphrase

---

## 7. Multi-Network Deploy

### Local Hardhat Node

```powershell
# Terminal 1
npx hardhat node

# Terminal 2
npm run hardhat:deploy:local
```

### Sepolia Testnet

```powershell
npm run hardhat:deploy:sepolia
```

### Network Configuration

Set in `.env`:
```bash
SEPOLIA_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com
PRIVATE_KEY=your_private_key
```

---

## 8. IPFS Gateway Fallback

Verify without running local IPFS node.

### Local IPFS (Full functionality)

```powershell
$env:IPFS_HOST="127.0.0.1"
$env:IPFS_PORT="5001"
./gradlew runDemo -PappArgs="holder:alice@example.com,2025-10-30,100"
```

### Public Gateway (Read-only)

```powershell
$env:IPFS_GATEWAY_URL="https://ipfs.io/ipfs/"
$env:NETWORK="sepolia"
$env:ETH_RPC_URL="https://ethereum-sepolia-rpc.publicnode.com"
$env:DELEGATE_KEY_SECRET="my-secure-passphrase-123"

./gradlew runVerifier -PappArgs="delegate_key.key,holder:alice@example.com,2025-10-30"
```

**Note:** Public gateways are read-only. Uploads require a local IPFS node.

---

## Command Reference

| Purpose | Command |
|---------|---------|
| Build project | `./gradlew build` |
| Java tests | `./gradlew test` |
| Solidity tests | `npm run hardhat:test` |
| Deploy (local) | `npm run hardhat:deploy:local` |
| Deploy (Sepolia) | `npm run hardhat:deploy:sepolia` |
| Full demo | `./gradlew run` |
| Benchmark | `./gradlew runDemo -PappArgs="<holder>,<epoch>,<iterations>"` |
| Holder key gen | `./gradlew runHolder -PappArgs="<holder>,<epoch>"` |
| Verifier check | `./gradlew runVerifier -PappArgs="<keyPath>,<holder>,<epoch>"` |
| Publish to chain | `npm run hardhat:publish:sepolia` |
| Check on chain | `npm run hardhat:check:sepolia` |

### Check Specific Holder

```powershell
$env:CHECK_HOLDER_ID="holder:user1@example.com"
$env:CHECK_EPOCH="2025-11-01"
npm run hardhat:check:sepolia
```
