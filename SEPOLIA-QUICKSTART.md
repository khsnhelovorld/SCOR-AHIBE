# Quick Start - Sepolia Testnet

```powershell
# Đảm bảo IPFS đang chạy (IPFS Desktop hoặc ipfs daemon)

# Deploy contract
npm run hardhat:deploy:sepolia

# Publish revocation
$env:RECORD_PATH="app/outbox/holder_alice_example_com__2025-10-30.json"
npm run hardhat:publish:sepolia

# Run Java demo
$env:NETWORK="sepolia"; $env:ETH_RPC_URL="https://ethereum-sepolia-rpc.publicnode.com"; $env:IPFS_HOST="127.0.0.1"; $env:IPFS_PORT="5001"
./gradlew runDemo -PappArgs="holder:alice@example.com,2025-10-30"

# Verify
npm run hardhat:check:sepolia
```