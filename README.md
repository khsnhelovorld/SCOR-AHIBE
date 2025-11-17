# SCOR-AHIBE

Tổng hợp mã nguồn minh họa kiến trúc SCOR-AHIBE:

- **Java (Gradle)**: triển khai AHIBE DIP10 bằng jPBC, dịch vụ PKG/Issuer/Holder/Verifier, cùng bộ test JUnit.
- **Solidity (Hardhat)**: hợp đồng `RevocationList` append-only lưu <ins>chuỗi con trỏ</ins> (ví dụ IPFS CID) thay vì blob ciphertext.
- **IPFS Integration**: Upload và download revocation certificates từ IPFS để lưu trữ off-chain.
- **Bridge scripts**: CLI deploy/publish bằng Hardhat, JSON outbox dùng để chuyển dữ liệu từ Java sang on-chain + IPFS.

## Yêu cầu môi trường

- JDK 21+
- Node.js 18+ (đã kiểm thử với v22.16.0)
- IPFS node (local hoặc remote) - xem phần [Setup IPFS](#setup-ipfs)
- PowerShell/Bash

## Setup IPFS

### Option 1: Local IPFS Node (Recommended)

1. **Install IPFS**: Download và cài đặt IPFS từ https://docs.ipfs.tech/install/

// Nếu dùng IPFS Desktop thì không cần chạy mục 2. **Initialize và start IPFS node**:
2. **Initialize và start IPFS node**:
   ```bash
   ipfs init
   ipfs daemon
   ```
   IPFS API sẽ chạy tại `http://127.0.0.1:5001` (mặc định)

3. **Configure environment variables**:
   ```bash
   # Windows PowerShell
   $env:IPFS_HOST="127.0.0.1"
   $env:IPFS_PORT="5001"
   
   # Linux/Mac
   export IPFS_HOST=127.0.0.1
   export IPFS_PORT=5001
   ```
   
   Hoặc sử dụng URL format:
   ```bash
   export IPFS_URL=http://127.0.0.1:5001
   ```

### Option 2: Remote IPFS Node

Nếu bạn có IPFS node chạy ở địa chỉ khác:
```bash
export IPFS_URL=http://your-ipfs-node:5001
```
## Setup Blockchain Testnet

1. **Copy environment template**: (Nếu chạy local thì không cần)
   ```bash
   cp env.example .env
   ```

2. **Configure testnet** (chọn một trong các testnet):
   - **Sepolia (Ethereum)**: Set `SEPOLIA_RPC_URL` và `PRIVATE_KEY` trong `.env`
   - **Mumbai (Polygon)**: Set `MUMBAI_RPC_URL` và `PRIVATE_KEY` trong `.env`
   - **Local Hardhat**: Không cần config, chạy `npx hardhat node` trước

3. **Get testnet tokens**: 
   - Sepolia: [https://sepoliafaucet.com/](https://sepoliafaucet.com/)
   - Mumbai: [https://faucet.polygon.technology/](https://faucet.polygon.technology/)

4. **Install dependencies**:
   ```bash
   npm install
   ```

## Lệnh quan trọng

```bash
# Java side
./gradlew test               # chạy toàn bộ test JUnit
./gradlew run                # chạy ứng dụng với IPFS integration

# Hardhat side
npx hardhat compile
npx hardhat test

# Deploy to testnet
npm run hardhat:deploy:sepolia    # Deploy to Sepolia
npm run hardhat:deploy:mumbai      # Deploy to Mumbai
npm run hardhat:deploy:local       # Deploy to local Hardhat network

# Publish revocation to testnet
# Publish revocation to testnet (set RECORD_PATH env var)
# PowerShell
$env:RECORD_PATH="app/outbox/<file>.json"; npm run hardhat:publish:sepolia

# Bash
RECORD_PATH=app/outbox/<file>.json npm run hardhat:publish:sepolia
```

## Luồng demo Off-chain → On-chain với IPFS

### Demo Flow: Holder → Verifier với Delegate Key

**Mô hình AHIBE hoàn chỉnh:**
1. **PKG** → Generate master key và public parameters
2. **Issuer** → Nhận master key, issue root key cho Holder
3. **Holder** → Nhận root key, derive epoch-specific delegate key
4. **Holder** → Export delegate key và gửi cho Verifier
5. **Verifier** → Import delegate key, query blockchain, download từ IPFS, decrypt và verify

#### Prerequisites

```bash
# Terminal 1: Start IPFS daemon (nếu dùng local node hoặc sử dụng IPFS Desktop)
ipfs daemon

# Terminal 2: Start local blockchain (nếu dùng Hardhat local network)
npx hardhat node
```

#### Bước 1: Deploy Smart Contract

```bash
# Deploy to local hardhat network
npm run hardhat:deploy:local

# Hoặc deploy to testnet
npm run hardhat:deploy:sepolia    # hoặc mumbai
```

Script sẽ tạo file `deployments/<network>.json` với địa chỉ contract.

#### Bước 2: Issuer tạo và publish Revocation Certificate

```bash
# Set IPFS configuration (Windows PowerShell)
$env:IPFS_HOST="127.0.0.1"
$env:IPFS_PORT="5001"

# Set blockchain RPC (nếu dùng testnet, local hardhat thì không cần)
$env:ETH_RPC_URL="https://rpc.sepolia.org"  # hoặc Mumbai RPC

# Run Java application để tạo revocation certificate
./gradlew run
```

Lệnh này sẽ:
- PKG bootstrap: tạo public parameters và master key
- Issuer issue root key cho `holder:alice@example.com`
- Issuer tạo revocation certificate (ciphertext) cho epoch `2025-10-30`
- **Upload ciphertext lên IPFS → nhận CID**
- Ghi JSON vào `outbox/` với `storagePointer` là IPFS CID thật

**Output example:**
```
Revocation certificate uploaded to IPFS.
IPFS CID: QmU4GgaZZftoNGGuDKh3yUt79QEHNcG4dJrdtvjzMRG5c9
Saved to: app/outbox/holder_alice_example_com__2025-10-30.json
```

#### Bước 3: Publish CID lên Blockchain

```bash
# Publish CID to blockchain (Windows PowerShell)
$env:RECORD_PATH="app/outbox/holder_alice_example_com__2025-10-30.json"
npm run hardhat:publish

# Hoặc với testnet
$env:RECORD_PATH="app/outbox/holder_alice_example_com__2025-10-30.json"
npm run hardhat:publish:sepolia
```

Script sẽ:
- Đọc JSON từ `outbox/`
- Tính `key = keccak256(holderId || epoch)`
- Gọi `RevocationList.publish(key, CID)` để lưu CID lên blockchain

**Output example:**
```
Publishing revocation record to RevocationList...
Contract address: 0x5FbDB2315678afecb367f032d93F642f64180aa3
Transaction hash: 0x1234567890abcdef...
✅ Revocation published successfully!
```

#### Bước 4: Holder tạo và export Delegate Key

```bash
# QUAN TRỌNG: Chạy trong cùng terminal session với Verifier (Bước 5)
# Holder derives epoch-specific delegate key và export ra file
./gradlew runHolder -PappArgs="holder:alice@example.com,2025-10-30"
```

Lệnh này sẽ:
- Holder nhận root key từ Issuer (simulated)
- Holder derive delegate key cho epoch `2025-10-30` sử dụng AHIBE hierarchical delegation
- Export delegate key: `outbox/delegate_key_holder_alice_example_com_2025-10-30.key`

**⚠️ DEMO MODE - In-Memory Key Storage:**
- Keys được lưu trong **in-memory storage** (không serialize ra disk)
- **PHẢI chạy Holder (Bước 4) và Verifier (Bước 5) trong CÙNG 1 terminal session**
- Nếu tắt terminal giữa chừng, keys sẽ mất → phải generate lại
- Đây là implementation đơn giản cho demo/học tập
- Trong production, cần implement proper key marshalling/serialization

**Output example:**
```
╔════════════════════════════════════════════════════════════════╗
║            HOLDER APPLICATION - AHIBE Key Derivation          ║
╚════════════════════════════════════════════════════════════════╝

Holder ID: holder:alice@example.com
Epoch:     2025-10-30

[1/5] Initializing AHIBE cryptographic service...
      ✓ AHIBE service initialized (160-bit security, depth 3)

[2/5] Bootstrapping PKG and obtaining public parameters...
      ✓ PKG bootstrapped, public parameters obtained

[3/5] Requesting root key from Issuer...
      ✓ Root key (SK_H) received from Issuer
      ℹ In production, this key would be transmitted via secure channel

[4/5] Deriving epoch-specific delegate key...
      ✓ Delegate key (SK_{H||T}) derived for epoch: 2025-10-30
      ℹ This demonstrates AHIBE hierarchical key derivation

[5/5] Exporting delegate key to file...
      ⚠ Demo Mode: Key stored in memory with token: delegate_key_holder_alice_example.com_2025-10-30
      ℹ In production, implement proper key serialization/marshalling
      ✓ Delegate key exported to: D:\...\outbox\delegate_key_holder_alice_example_com_2025-10-30.key

╔════════════════════════════════════════════════════════════════╗
║                    SUCCESS - Key Generated                     ║
╚════════════════════════════════════════════════════════════════╝
```

#### Bước 5: Verifier verify Revocation Status

```bash
# QUAN TRỌNG: Chạy NGAY trong cùng terminal session với Holder (Bước 4)
# KHÔNG tắt terminal giữa Bước 4 và Bước 5

# Set environment variables (Windows PowerShell)
$env:NETWORK="hardhat"                # hoặc "sepolia", "mumbai"
$env:ETH_RPC_URL="http://127.0.0.1:8545"  # hoặc testnet RPC URL
$env:IPFS_HOST="127.0.0.1"
$env:IPFS_PORT="5001"

# Run Verifier application
./gradlew runVerifier -PappArgs="outbox/delegate_key_holder_alice_example_com_2025-10-30.key,holder:alice@example.com,2025-10-30"
```

Verifier sẽ thực hiện:
1. ✓ Import delegate key từ in-memory storage (cùng session với Holder)
2. ✓ Connect to IPFS node
3. ✓ Connect to blockchain network
4. ✓ Query smart contract để lấy CID
5. ✓ Download revocation certificate từ IPFS sử dụng CID
6. ✓ Decrypt ciphertext bằng delegate key
7. ✓ Hiển thị kết quả: **REVOKED** hoặc **NOT REVOKED**

**Output example (REVOKED):**
```
╔════════════════════════════════════════════════════════════════╗
║         VERIFIER APPLICATION - Revocation Status Check        ║
╚════════════════════════════════════════════════════════════════╝

Delegate Key: outbox/delegate_key_holder_alice_example_com_2025-10-30.key
Holder ID:    holder:alice@example.com
Epoch:        2025-10-30

[1/7] Initializing AHIBE cryptographic service...
      ✓ AHIBE service initialized

[2/7] Obtaining public parameters from PKG...
      ✓ Public parameters obtained

[3/7] Importing delegate key from Holder...
      ✓ Delegate key imported successfully
      ℹ This key can only decrypt revocations for: holder:alice@example.com || 2025-10-30

[4/7] Connecting to IPFS node...
      Using IPFS at 127.0.0.1:5001
      ✓ IPFS node is available and responding

[5/7] Connecting to blockchain network...
      ✓ Connected to network: hardhat
      ✓ Using contract at: 0x5FbDB2315678afecb367f032d93F642f64180aa3

[6/7] Querying blockchain for revocation record...
      ✓ Found revocation CID on blockchain: QmU4GgaZZftoNGGuDKh3yUt79QEHNcG4dJrdtvjzMRG5c9

[7/7] Downloading and decrypting revocation certificate...
      ✓ Downloaded ciphertext from IPFS (800 bytes)
      ⏳ Decrypting with delegate key...
      ✓ Successfully decrypted revocation certificate
      ℹ Session key (first 16 bytes): 0a1cfde5e32293c1821d133c0327ee74...

╔════════════════════════════════════════════════════════════════╗
║                   VERIFICATION RESULT: REVOKED                 ║
╚════════════════════════════════════════════════════════════════╝

Status:        REVOKED
Holder:        holder:alice@example.com
Epoch:         2025-10-30
CID:           QmU4GgaZZftoNGGuDKh3yUt79QEHNcG4dJrdtvjzMRG5c9
Verification:  SUCCESS - Delegate key successfully decrypted the certificate

Interpretation:
  • A revocation certificate exists on blockchain for this holder+epoch
  • The certificate was successfully downloaded from IPFS
  • The delegate key correctly decrypted the certificate
  • This proves the holder's credential for this epoch is REVOKED
```

**Output example (NOT REVOKED):**
```
[6/7] Querying blockchain for revocation record...
      ℹ No revocation record found on blockchain

╔════════════════════════════════════════════════════════════════╗
║                  VERIFICATION RESULT: NOT REVOKED              ║
╚════════════════════════════════════════════════════════════════╝

Status:    NOT REVOKED
Holder:    holder:alice@example.com
Epoch:     2025-10-30
Reason:    No revocation certificate found on blockchain
```

### Manual Verification (Optional)

Verify thủ công từ blockchain console:

```bash
npx hardhat console --network hardhat  # hoặc sepolia, mumbai

> const deploy = require("./deployments/hardhat.json");
> const rl = await ethers.getContractAt("RevocationList", deploy.address);
> const key = ethers.keccak256(ethers.concat([
    ethers.toUtf8Bytes("holder:alice@example.com"), 
    ethers.toUtf8Bytes("2025-10-30")
  ]));
> const info = await rl.getRevocationInfo(key);
> console.log("CID:", info.cid);
> console.log("Timestamp:", new Date(Number(info.timestamp) * 1000));
```

## Kiến trúc AHIBE Hierarchy

```
Level 0: PKG (Master Key)
         │
         ├─► masterKey (generated by PKG)
         │
Level 1: Holder Identity
         │
         ├─► rootKey for "holder:alice@example.com"
         │   (issued by Issuer using masterKey)
         │
Level 2: Epoch (Time-based delegation)
         │
         ├─► delegateKey for "holder:alice@example.com || 2025-10-30"
         │   (derived by Holder from rootKey)
         │
         └─► delegateKey for "holder:alice@example.com || 2025-10-31"
             (can be derived independently for different epochs)
```

### Key Properties

1. **Hierarchical Key Derivation**: Holder can derive epoch-specific keys from root key without contacting Issuer
2. **Forward Security**: Compromise of epoch key for 2025-10-30 doesn't affect 2025-10-31
3. **Identity-Based**: Keys are bound to specific identities (Holder ID + Epoch)
4. **Selective Decryption**: Each delegate key can only decrypt revocations for its specific holder+epoch

## Cấu trúc thư mục chính

```
SCOR-AHIBE/
 ├─ app/                       # Java Gradle module
 │   ├─ src/main/java/com/project/ahibe/
 │   │   ├─ App.java           # Main application (Issuer flow)
 │   │   ├─ HolderApp.java    # Holder application (derive & export delegate key)
 │   │   ├─ VerifierApp.java  # Verifier application (verify revocation status)
 │   │   ├─ crypto/            # AhibeService (AHIBE cryptographic operations)
 │   │   ├─ core/              # PKG / Issuer / Holder / Verifier services
 │   │   ├─ eth/               # Blockchain client (RevocationListClient)
 │   │   ├─ io/                # JSON export, storage fetchers, KeySerializer
 │   │   └─ ipfs/              # IPFS service and storage fetcher
 │   ├─ outbox/                # Generated files (JSON records, delegate keys)
 │   └─ build.gradle           # Gradle tasks: run, runHolder, runVerifier
 ├─ contracts/
 │   └─ RevocationList.sol     # Smart contract for storing revocation CIDs
 ├─ scripts/
 │   ├─ deploy.js              # Deploy contract and save metadata
 │   └─ publishRevocation.js   # Publish CID to blockchain
 ├─ test/
 │   └─ RevocationList.test.js # Smart contract tests
 ├─ deployments/               # Deployment metadata per network
 ├─ libs/jars/                 # jPBC library JARs
 ├─ package.json               # NPM scripts for Hardhat
 └─ README.md                  # This file
```

## Kiến trúc

### Components Overview

**Java Applications:**
- **App.java**: Main Issuer application - generates revocation certificates, uploads to IPFS, saves metadata
- **HolderApp.java**: Holder application - derives epoch-specific delegate keys and exports to file
- **VerifierApp.java**: Verifier application - imports delegate key, queries blockchain, downloads from IPFS, decrypts and verifies

**Core Services:**

```bash
# Deploy to testnet
npm run hardhat:deploy:sepolia    # hoặc mumbai, hoặc local
**Core Services:**
- **AhibeService**: AHIBE cryptographic operations (setup, keyGen, delegate, encaps/decaps)
- **PkgService**: Private Key Generator - bootstraps the system with master key
- **IssuerService**: Issues root keys to holders and creates revocation certificates
- **HolderService**: Derives epoch-specific delegate keys from root keys
- **VerifierService**: Verifies revocation status by decrypting certificates
- **IPFSService**: Upload and download content from IPFS
- **RevocationListClient**: Query smart contract for revocation CIDs
- **KeySerializer**: Export/import delegate keys to/from files

### Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                     ISSUER FLOW (App.java)                      │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ├─► 1. Generate Revocation Certificate
                            │      (ciphertext for holder:alice || 2025-10-30)
                            │
                            ├─► 2. Upload to IPFS
                            │      → Receive CID
                            │
                            └─► 3. Save metadata to outbox/
                                   (JSON with CID, holder, epoch)

┌─────────────────────────────────────────────────────────────────┐
│                 HOLDER FLOW (HolderApp.java)                    │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ├─► 1. Receive root key from Issuer
                            │      (SK_H for holder:alice@example.com)
                            │
                            ├─► 2. Derive epoch-specific delegate key
                            │      (SK_{H||T} for 2025-10-30)
                            │
                            └─► 3. Export delegate key to file
                                   → Send to Verifier (secure channel)

┌─────────────────────────────────────────────────────────────────┐
│               VERIFIER FLOW (VerifierApp.java)                  │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ├─► 1. Import delegate key from Holder
                            │
                            ├─► 2. Query blockchain for CID
                            │      (RevocationList smart contract)
                            │
                            ├─► 3. Download ciphertext from IPFS
                            │      (using CID)
                            │
                            ├─► 4. Decrypt with delegate key
                            │
                            └─► 5. Determine: REVOKED or NOT REVOKED
```

## Ghi chú

- Tất cả thư viện jPBC được vendor trong `libs/jars` để tránh phụ thuộc Maven Central.
- `package.json` khoá Hardhat `^2.17.2` + `@nomicfoundation/hardhat-toolbox ^4` nhằm giữ tương thích ethers v6.
- IPFS integration sử dụng HTTP API client với OkHttp.
- `RevocationRecordWriter` tạo JSON gồm `storagePointer` (IPFS CID); script publish sẽ từ chối nếu trường này trống.
- **KeySerializer** sử dụng Java serialization để export/import AHIBE keys một cách an toàn.
- Đảm bảo IPFS node đang chạy và accessible trước khi chạy ứng dụng.
- Delegate key files (`.key`) chứa cryptographic material nhạy cảm - **không chia sẻ công khai**.
- Trong production, truyền delegate key qua kênh bảo mật (encrypted email, secure file transfer, etc.)

## Troubleshooting

### IPFS Connection Issues

```bash
# Check IPFS daemon is running
ipfs id

# Test IPFS API
curl http://127.0.0.1:5001/api/v0/version
```

### Blockchain Connection Issues

```bash
# Test RPC connection
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
  http://127.0.0.1:8545
```

### Build Issues

```bash
# Clean and rebuild
./gradlew clean build

# Compile contracts
npx hardhat clean
npx hardhat compile
```

### Key Storage Issues (Demo Mode)

```
Error: Key not found in storage. Token: delegate_key_...
Note: In demo mode, keys must be generated in the same session.
```

**Nguyên nhân**: KeySerializer sử dụng in-memory storage cho demo

**Giải pháp**:
1. Chạy Holder và Verifier trong **CÙNG 1 terminal session**
2. **KHÔNG tắt terminal** giữa bước generate key (Holder) và verify (Verifier)
3. Nếu đã tắt terminal, chạy lại từ đầu: `./gradlew runHolder` → `./gradlew runVerifier`

**Lưu ý**: Đây là implementation đơn giản cho demo/học tập. Trong production, cần implement proper key marshalling/serialization.

## Demo Mode vs Production

### Current Implementation (Demo Mode)

**KeySerializer** hiện tại sử dụng **in-memory storage**:

✅ **Ưu điểm**:
- Đơn giản, dễ hiểu
- Không cần lo về JPBC serialization complexity
- Hoạt động tốt cho demo/học tập trong single session

❌ **Hạn chế**:
- Keys chỉ tồn tại trong JVM session hiện tại
- PHẢI chạy Holder và Verifier trong cùng 1 terminal session
- Không thể transfer keys giữa processes/machines khác nhau
- Không phù hợp cho production deployment

### Production Requirements

Để deploy production, cần implement:

1. **Proper Key Marshalling**
   - Serialize JPBC Element objects (k0, k1, k2[], hId[]) thành byte arrays
   - Encode/decode bằng Base64 hoặc custom format
   - Handle pairing parameters reconstruction

2. **Secure Key Storage**
   - Encrypt keys before writing to disk (AES-256-GCM)
   - Use secure key derivation (PBKDF2, Argon2)
   - Store in secure location (encrypted filesystem, HSM)

3. **Key Transfer Protocol**
   - Establish secure channel (TLS/mTLS)
   - Use encrypted messaging (PGP, S/MIME)
   - Implement key agreement protocol (ECDH)

4. **Key Lifecycle Management**
   - Time-based key expiration
   - Key rotation policies
   - Revocation mechanism for compromised keys

5. **Audit & Monitoring**
   - Log all key operations (generate, export, import, use)
   - Detect anomalous key usage patterns
   - Compliance with security standards (FIPS 140-2, etc.)

**Tham khảo**: Xem comments trong source code `KeySerializer.java` để biết cách implement proper JPBC Element serialization.

## Security Considerations

1. **Master Key Protection**: PKG's master key must be stored securely (HSM, secure enclave)
2. **Root Key Distribution**: Holder root keys should be transmitted via secure channels
3. **Delegate Key Scope**: Each delegate key is limited to specific holder+epoch combination
4. **IPFS Content Addressing**: CIDs ensure content integrity (cannot be tampered)
5. **Blockchain Immutability**: Once published, revocation records cannot be altered
6. **Forward Security**: Compromise of epoch key doesn't affect other epochs

## License

Educational project for demonstrating SCOR-AHIBE architecture.

---