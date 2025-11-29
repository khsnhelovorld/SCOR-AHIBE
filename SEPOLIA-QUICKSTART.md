# Sepolia Testnet Quick Start

Deploy and test SCOR-AHIBE on Ethereum Sepolia testnet in under 10 minutes.

## Prerequisites

- **Node.js 18+** and **npm**
- **JDK 21+** with Gradle
- **IPFS Desktop** running ([Download](https://docs.ipfs.tech/install/ipfs-desktop/))
- **Sepolia ETH** ([Faucet](https://sepoliafaucet.com/))
- **RPC URL** from [Alchemy](https://www.alchemy.com/) or [Infura](https://www.infura.io/)

## Quick Start (10 commands)

```powershell
# 1. Setup
cp env.example .env                    # Edit with your PRIVATE_KEY and RPC URL
npm install && ./gradlew build

# 2. Deploy contract
npm run hardhat:deploy:sepolia

# 3. Set environment
$env:IPFS_HOST="127.0.0.1"; $env:IPFS_PORT="5001"
$env:NETWORK="sepolia"; $env:ETH_RPC_URL="https://ethereum-sepolia-rpc.publicnode.com"
$env:DELEGATE_KEY_SECRET="your-secure-passphrase"

# 4. Generate revocation certificate
./gradlew run

# 5. Publish to blockchain
$env:RECORD_PATH="app/outbox/holder_alice_example_com__2025-10-30.json"
npm run hardhat:publish:sepolia

# 6. Check status
npm run hardhat:check:sepolia
```

**Expected output:**
```
✓ RESULT: Revocation record found!
  Status: REVOKED (1)
  Version: 1
```

---

## Full Workflow

### 1. Environment Configuration

Create `.env` file:
```bash
SEPOLIA_RPC_URL=https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY
PRIVATE_KEY=your_wallet_private_key_without_0x
```

### 2. Holder Key Generation

```powershell
$env:DELEGATE_KEY_SECRET="your-secure-passphrase"
./gradlew runHolder -PappArgs="holder:alice@example.com,2025-10-30"
# Output: app/outbox/delegate_key_holder_alice_example.com_2025-10-30.key
```

### 3. Verifier Check

```powershell
./gradlew runVerifier -PappArgs="outbox/delegate_key_holder_alice_example.com_2025-10-30.key,holder:alice@example.com,2025-10-30"
```

### 4. Un-Revoke

```powershell
npx hardhat console --network sepolia
```
```javascript
const c = await ethers.getContractAt("RevocationList", "<CONTRACT_ADDRESS>")
const k = ethers.keccak256(ethers.toUtf8Bytes("holder:alice@example.com"))
await (await c.unrevoke(k)).wait()
.exit
```
```powershell
npm run hardhat:check:sepolia
# Output: Status: ACTIVE (0) - un-revoked!
```

### 5. Benchmark

```powershell
./gradlew runDemo -PappArgs="holder:alice@example.com,2025-10-30,100"
# Results: benchmark_results/benchmark_*.csv

./gradlew runDemo -PappArgs="holder:alice@example.com,2025-10-30"
# 1000 times
```

---

## Verification Logic

| Condition | Result |
|-----------|--------|
| No record | ✅ VALID |
| `T_check < T_rev` | ✅ VALID (before revocation) |
| `T_check ≥ T_rev` AND `Status = ACTIVE` | ✅ VALID (un-revoked) |
| `T_check ≥ T_rev` AND `Status = REVOKED` | ❌ REVOKED |

---

## Check Other Holders

```powershell
$env:CHECK_HOLDER_ID="holder:user1@example.com"
$env:CHECK_EPOCH="2025-11-01"
npm run hardhat:check:sepolia
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `IPFS node not available` | Ensure IPFS Desktop is running |
| `Gas estimation failed` | Check Sepolia ETH balance |
| `Credential not revoked` | Verify record is published and epoch matches |
| `Key import failed` | Use same `DELEGATE_KEY_SECRET` for export/import |
| `AlreadyPublished` | Holder already revoked; un-revoke first to re-revoke |

---

## Smart Contract

**Deployed on Sepolia**: Check `deployments/sepolia.json` for your contract address.

### Key Functions

```solidity
// Publish revocation (1 holder = 1 IPFS file)
function publish(bytes32 key, uint256 epoch, string ptr)

// Un-revoke holder
function unrevoke(bytes32 key)

// Check status
function getRevocationInfo(bytes32 key) returns (epoch, ptr, version, status)

// Batch operations (transaction-level batching, each holder still has 1 file)
function publishBatch(bytes32[] keys, uint256[] epochs, string[] ptrs)
function batchCheckRevocation(bytes32[] keys)
```

---

## Security Notes

1. **Never commit** `.env` or private keys
2. **Use `DELEGATE_KEY_SECRET`** for encrypted key files
3. **Verify contract address** before publishing
4. Native BLS12-381 provides ~128-bit security

---

## Next Steps

- See [Usage.md](Usage.md) for all scenarios
- See [IPFS_GUIDE.md](IPFS_GUIDE.md) for production IPFS setup
