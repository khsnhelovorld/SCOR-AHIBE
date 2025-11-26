# SCOR-AHIBE

SCOR-AHIBE (Self-Certifying Off-chain Revocation for Attribute-based Hierarchical Identity-Based Encryption) is an experimental reference implementation that accompanies our research on verifiable revocation for AHIBE credentials. The system instantiates the full end-to-end workflow—from PKG bootstrap and cryptographic encapsulation to IPFS persistence and on-chain pointer management—allowing practitioners to reproduce the protocol, benchmark cryptographic costs, and validate the static-key revocation model described in the paper.

## Requirements

- JDK 21+
- Node.js 18+
- IPFS node (local or remote)

## IPFS Setup

### Local IPFS Node (Recommended)

1. Install IPFS from https://docs.ipfs.tech/install/
2. Initialize and start IPFS node:
   ```bash
   ipfs init
   ipfs daemon
   ```
   IPFS API runs at `http://127.0.0.1:5001` by default.

**Note**: If using IPFS Desktop, skip step 2 and just open the application.

### Remote IPFS Node

If using a remote IPFS node, set environment variables:
```bash
# Windows PowerShell
$env:IPFS_HOST="your-ipfs-host"
$env:IPFS_PORT="5001"

# Linux/Mac
export IPFS_HOST="your-ipfs-host"
export IPFS_PORT="5001"
```

## Installation

### Install Dependencies

```bash
# Install Node.js dependencies
npm install

# Java dependencies are managed by Gradle (no manual installation needed)
```

## Usage

### Option 1: Hardhat Local Network

#### Step 1: Start Services

```bash
# Terminal 1: Start IPFS daemon
ipfs daemon

# Terminal 2: Start Hardhat local network
npx hardhat node
```

#### Step 2: Deploy Smart Contract

```bash
# Terminal 3: Deploy to local network
npm run hardhat:deploy:local
```

This creates `deployments/localhost.json` with the contract address.

#### Step 3: Configure Environment

```bash
# Windows PowerShell
$env:IPFS_HOST="127.0.0.1"
$env:IPFS_PORT="5001"
$env:ETH_RPC_URL="http://127.0.0.1:8545"
```

#### Step 4: Generate and Publish Revocation Certificate

```bash
# Generate revocation certificate and upload to IPFS
./gradlew run

# Publish CID to blockchain
$env:RECORD_PATH="app/outbox/<filename>.json"
npm run hardhat:publish
```

### Option 2: Sepolia Testnet

#### Step 1: Configure Environment

```bash
# Copy environment template
cp env.example .env
```

Edit `.env` and set:
```
SEPOLIA_RPC_URL=https://rpc.sepolia.org
PRIVATE_KEY=your_private_key_here
IPFS_HOST=127.0.0.1
IPFS_PORT=5001
ETH_RPC_URL=https://rpc.sepolia.org
```

**Important**: Use a test account with Sepolia ETH for gas fees. Never commit real private keys.

#### Step 2: Start IPFS

```bash
# Terminal 1: Start IPFS daemon
ipfs daemon
```

#### Step 3: Deploy Smart Contract

```bash
# Deploy to Sepolia testnet
npm run hardhat:deploy:sepolia
```

This creates `deployments/sepolia.json` with the contract address.

#### Step 4: Generate and Publish Revocation Certificate

```bash
# Set IPFS / RPC configuration (if not in .env)
$env:IPFS_HOST="127.0.0.1"
$env:IPFS_PORT="5001"
$env:ETH_RPC_URL="https://ethereum-sepolia-rpc.publicnode.com"
$env:NETWORK="sepolia" # Required when running runDemo/Verifier flows

# Generate revocation certificate and upload to IPFS using default sample IDs (holder:alice@example.com, epoch 2025-10-30)
./gradlew run

# Publish CID to blockchain
$env:RECORD_PATH="app/outbox/<filename>.json"
npm run hardhat:publish:sepolia

# Benchmark / verify full flow once the record exists on-chain
./gradlew runDemo -PappArgs="holder:alice@example.com,2025-10-30"
```

### Revocation Flow (Static Key + Epoch)

The current contract and off-chain services follow the static-key architecture illustrated in the design update:

1. **Issuer / Publisher**
   - Uses AHIBE to encrypt with the pair `(holderId, epoch)`.
   - Uploads ciphertext to IPFS and receives a CID.
   - Publishes on-chain with `key = keccak256(holderId)` (static per holder) and payload `{epoch, cid}`.
2. **Verifier**
   - Derives the same static key from `holderId` and fetches the record.
   - Compares the requested `T_check` (epoch provided to `VerifierApp`/`runDemo`) against the stored `T_rev`.
   - Only if `T_check >= T_rev` does it download the IPFS payload and decapsulate to confirm revocation.

Because the mapping key is static, you must ensure the **same `holderId` string** is reused for:

- Java generation (`run`/`runDemo`/`HolderApp`)
- Publishing (`RECORD_PATH` file name reflects the holder/epoch)
- Verification (`VerifierApp` or `runDemo` arguments, or `npm run hardhat:check*` scripts)

If you change the identifiers, regenerate the record and republish before running the verifier.

## Basic Commands

```bash
# Java
./gradlew test          # Run JUnit tests
./gradlew run           # Run main application

# Hardhat
npm run hardhat:compile # Compile contracts
npm run hardhat:test    # Run contract tests
```

## Project Structure

- **Java (Gradle)**: AHIBE DIP10 implementation using jPBC, PKG/Issuer/Holder/Verifier services
- **Solidity (Hardhat)**: `RevocationList` smart contract storing IPFS CIDs
- **IPFS Integration**: Off-chain storage for revocation certificates
- **Bridge Scripts**: Deploy and publish scripts for on-chain operations

## License

Educational project for demonstrating SCOR-AHIBE architecture.
