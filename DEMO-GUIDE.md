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

## Demo Steps (5 phút)

### 1. Start Local Blockchain

```bash
# Terminal 1
npx hardhat node
# OR using npm script:
npm run hardhat:node
```

**⚠️ QUAN TRỌNG:** 
- Để terminal này CHẠY và KHÔNG đóng nó
- Hardhat node phải chạy TRƯỚC khi deploy/publish
- Nếu restart Hardhat node, contract state sẽ bị mất → cần redeploy và republish
- Hardhat node chạy trên port 8545 (http://127.0.0.1:8545)

### 2. Deploy Smart Contract

```bash
# Terminal 2
npm run hardhat:deploy:local
```

✓ Tạo file `deployments/hardhat.json` với contract address.

### 3. Issuer: Generate Revocation Certificate

```bash
# Set IPFS config (Windows PowerShell)
$env:IPFS_HOST="127.0.0.1"
$env:IPFS_PORT="5001"

# Run Issuer app
./gradlew run
```

**Issuer sẽ:**
- Generate revocation certificate cho `holder:alice@example.com` epoch `2025-10-30`
- Upload ciphertext lên IPFS → nhận CID
- Save metadata vào `app/outbox/holder_alice_example_com__2025-10-30.json`

**Output:** 
```
✓ Revocation certificate uploaded to IPFS.
  IPFS CID: QmXXXXXXXXXX...
```

### 4. Publish CID to Blockchain

```bash
$env:RECORD_PATH="app/outbox/holder_alice_example_com__2025-10-30.json"
npm run hardhat:publish
```

✓ CID được lưu lên smart contract.

### 5. Run Complete Demo (Holder → Verifier)

**RECOMMENDED: Chạy DemoApp để demo toàn bộ flow trong 1 JVM:**

```bash
# Set environment variables
$env:NETWORK="hardhat"
$env:ETH_RPC_URL="http://127.0.0.1:8545"
$env:IPFS_HOST="127.0.0.1"
$env:IPFS_PORT="5001"

# Run complete demo
./gradlew runDemo -PappArgs="holder:alice@example.com,2025-10-30"
```

**Demo sẽ chạy 2 phần:**
1. **Holder Part**: Generate delegate key → lưu vào memory
2. **[Press Enter]**: User nhấn Enter để tiếp tục
3. **Verifier Part**: Import key từ memory → verify revocation

**Output mẫu:**
```
╔════════════════════════════════════════════════════════════════╗
║              DEMO APPLICATION - Complete Flow                  ║
║         Holder → Delegate Key → Verifier (Same JVM)           ║
╚════════════════════════════════════════════════════════════════╝

═══════════════════════════════════════
PART 1: HOLDER - Generate Delegate Key
═══════════════════════════════════════

[1/5] Initializing AHIBE cryptographic service...
      ✓ AHIBE service initialized

[2/5] Bootstrapping PKG and obtaining public parameters...
      ✓ PKG bootstrapped

[3/5] Requesting root key from Issuer...
      ✓ Root key received from Issuer

[4/5] Deriving epoch-specific delegate key...
      ✓ Delegate key derived for epoch: 2025-10-30

[5/5] Exporting delegate key...
      ✓ Delegate key exported (in-memory storage)

Press Enter to continue to Verifier part...

═══════════════════════════════════════
PART 2: VERIFIER - Verify Revocation Status
═══════════════════════════════════════

[1/6] Importing delegate key from Holder...
      ✓ Delegate key imported from in-memory storage

[2/6] Connecting to IPFS node...
      ✓ IPFS node is available

[3/6] Connecting to blockchain network...
      ✓ Connected to network: hardhat

[4/6] Querying blockchain for revocation record...
      ✓ Found revocation CID: QmXXXX...

[5/6] Downloading revocation certificate from IPFS...
      ✓ Downloaded ciphertext (492 bytes)

[6/6] Decrypting and verifying with delegate key...
      ✓ Decryption successful!

╔════════════════════════════════════════════════════════════════╗
║                   VERIFICATION RESULT: REVOKED                 ║
╚════════════════════════════════════════════════════════════════╝

Status:        REVOKED
Holder:        holder:alice@example.com
Epoch:         2025-10-30
CID:           QmXXXX...
Verification:  SUCCESS
```

---

### Alternative: Run Holder and Verifier Separately (Advanced)

**Chỉ dành cho testing riêng từng component. Không được recommended vì in-memory storage!**

#### 5a. Holder: Derive & Export Delegate Key

#### 5a. Holder: Derive & Export Delegate Key

```bash
# Chạy trong cùng terminal session với Verifier
./gradlew runHolder -PappArgs="holder:alice@example.com,2025-10-30"
```

**Holder sẽ:**
- Nhận root key từ Issuer (SK_H)
- Derive delegate key cho epoch 2025-10-30 (SK_{H||T})
- Export ra file: `outbox/delegate_key_holder_alice_example_com_2025-10-30.key`

**⚠️ LƯU Ý DEMO MODE:**
- Keys được lưu trong **in-memory storage** (không serialize ra disk)
- **PHẢI chạy Holder và Verifier trong CÙNG 1 terminal session**
- Nếu tắt terminal, keys sẽ mất → phải generate lại
- Trong production, cần implement proper key marshalling/serialization

### 6. Verifier: Verify Revocation Status

#### 5b. Verifier: Verify Revocation Status

```bash
# QUAN TRỌNG: Chạy NGAY trong cùng terminal session với Holder (bước 5a)
# KHÔNG tắt terminal giữa bước 5a và 5b

# Set environment
$env:NETWORK="hardhat"
$env:ETH_RPC_URL="http://127.0.0.1:8545"
$env:IPFS_HOST="127.0.0.1"
$env:IPFS_PORT="5001"

# Run Verifier app
./gradlew runVerifier -PappArgs="outbox/delegate_key_holder_alice_example_com_2025-10-30.key,holder:alice@example.com,2025-10-30"
```

**Verifier sẽ:**
1. Import delegate key từ in-memory storage (same session)
2. Query blockchain → lấy CID
3. Download ciphertext từ IPFS
4. Decrypt bằng delegate key
5. ✓ Kết quả: **REVOKED**

## Expected Final Output

```
╔════════════════════════════════════════════════════════════════╗
║                   VERIFICATION RESULT: REVOKED                 ║
╚════════════════════════════════════════════════════════════════╝

Status:        REVOKED
Holder:        holder:alice@example.com
Epoch:         2025-10-30
CID:           QmXXXXXXXXXX...
Verification:  SUCCESS - Delegate key successfully decrypted the certificate
```

## Key Concepts Demonstrated

1. ✅ **Hierarchical Key Derivation**: Holder derive epoch keys từ root key
2. ✅ **Selective Decryption**: Delegate key chỉ decrypt được specific holder+epoch
3. ✅ **Off-chain Storage**: Ciphertext stored on IPFS (cheaper than on-chain)
4. ✅ **On-chain Pointer**: Blockchain stores CID (immutable, verifiable)
5. ✅ **Privacy**: Verifier không cần toàn bộ root key, chỉ cần delegate key

## Testing Different Scenarios

### Test: Không có revocation
```bash
# Trong cùng terminal session, thử verify cho epoch khác (không có revocation)
./gradlew runVerifier -PappArgs="outbox/delegate_key_holder_alice_example_com_2025-10-30.key,holder:alice@example.com,2025-10-31"

# Result: NOT REVOKED
```

### Test: Delegate key cho holder khác
```bash
# Trong cùng terminal session, generate delegate key cho holder khác
./gradlew runHolder -PappArgs="holder:bob@example.com,2025-10-30"

# Ngay sau đó, verify với Bob's key cho Alice's revocation
./gradlew runVerifier -PappArgs="outbox/delegate_key_holder_bob_example_com_2025-10-30.key,holder:alice@example.com,2025-10-30"

# Result: Decryption fails (wrong key)
```

### Test: Simplified Demo Flow (All in One Session)
```bash
# Chạy tất cả trong 1 terminal session:

# 1. Generate revocation certificate
./gradlew run

# 2. Publish to blockchain
$env:RECORD_PATH="app/outbox/holder_alice_example_com__2025-10-30.json"
npm run hardhat:publish

# 3. Holder derive delegate key
./gradlew runHolder -PappArgs="holder:alice@example.com,2025-10-30"

# 4. Verifier verify (NGAY sau bước 3)
$env:NETWORK="hardhat"
$env:ETH_RPC_URL="http://127.0.0.1:8545"
$env:IPFS_HOST="127.0.0.1"
$env:IPFS_PORT="5001"
./gradlew runVerifier -PappArgs="outbox/delegate_key_holder_alice_example_com_2025-10-30.key,holder:alice@example.com,2025-10-30"
```

## Troubleshooting

**Verifier shows "NOT REVOKED" when revocation was published:**
```
❌ No revocation record found on blockchain
```

**Nguyên nhân:**
1. Hardhat node đã bị restart → contract state bị mất
2. Hardhat node không chạy khi verifier query
3. Deploy/publish sử dụng network khác với verifier

**Giải pháp:**
1. **Kiểm tra Hardhat node có đang chạy:**
   ```bash
   # Check if port 8545 is accessible
   npm run hardhat:check
   ```
   
2. **Nếu node không chạy hoặc đã restart:**
   ```bash
   # Start Hardhat node (keep it running!)
   npm run hardhat:node
   
   # Redeploy contract
   npm run hardhat:deploy:local
   
   # Republish revocation
   $env:RECORD_PATH="app/outbox/holder_alice_example_com__2025-10-30.json"
   npm run hardhat:publish
   ```

3. **Verify contract state:**
   ```bash
   npm run hardhat:check
   ```
   Expected output: `✓ RESULT: Revocation record found!`

**Key not found in storage:**
```
Error: Key not found in storage. Token: delegate_key_...
Note: In demo mode, keys must be generated in the same session.
```
**Giải pháp:** Chạy lại Holder và Verifier trong cùng 1 terminal session, KHÔNG tắt terminal giữa chừng.

**IPFS not available:**
```bash
# Check IPFS daemon
ipfs id

# Start IPFS daemon
ipfs daemon
```

**Blockchain connection failed:**
```bash
# Ensure hardhat node is running in Terminal 1
# Check it's listening on http://127.0.0.1:8545

# Start Hardhat node if not running:
npm run hardhat:node

# Verify connection:
npm run hardhat:check
```

**Contract not found error:**
```
No contract code found at address 0x...
The Hardhat node may have been restarted (contract state lost)
```

**Giải pháp:**
- Hardhat node sử dụng in-memory state → nếu restart sẽ mất tất cả
- Phải giữ Hardhat node chạy từ khi deploy đến khi verify
- Nếu đã restart, cần redeploy contract và republish revocation

**Build errors:**
```bash
./gradlew clean build
```

## Demo Mode vs Production

### Current Implementation (Demo Mode)

**KeySerializer sử dụng in-memory storage:**
- ✅ Đơn giản, dễ hiểu
- ✅ Hoạt động tốt cho demo/học tập
- ✅ Không cần lo về serialization complexity
- ❌ Keys chỉ tồn tại trong session hiện tại
- ❌ Không thể transfer keys giữa processes khác nhau
- ❌ Không thể transfer keys giữa máy khác nhau

### Production Requirements

Để production, cần implement:
1. **Proper Key Marshalling**: Serialize JPBC Element objects thủ công
2. **Secure Key Storage**: Encrypt keys trước khi lưu ra disk
3. **Key Transfer Protocol**: Secure channel (TLS, encrypted email, etc.)
4. **Key Expiration**: Time-based key lifecycle management
5. **Audit Logging**: Track key generation và usage

**Tham khảo:** Xem comments trong `KeySerializer.java` để biết cách implement proper serialization.

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