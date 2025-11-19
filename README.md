# SCOR-AHIBE

Implementation of SCOR-AHIBE architecture demonstrating off-chain revocation certificate storage with on-chain pointer management.

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
# Set IPFS configuration (if not in .env)
$env:IPFS_HOST="127.0.0.1"
$env:IPFS_PORT="5001"
$env:ETH_RPC_URL="https://rpc.sepolia.org"

# Generate revocation certificate and upload to IPFS
./gradlew run

# Publish CID to blockchain
$env:RECORD_PATH="app/outbox/<filename>.json"
npm run hardhat:publish:sepolia
```

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
