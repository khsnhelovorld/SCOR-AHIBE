# SCOR-AHIBE Playground

Tổng hợp mã nguồn minh họa kiến trúc SCOR-AHIBE:

- **Java (Gradle)**: triển khai AHIBE DIP10 bằng jPBC, dịch vụ PKG/Issuer/Holder/Verifier, cùng bộ test JUnit.
- **Solidity (Hardhat)**: hợp đồng `RevocationList` append-only lưu <ins>chuỗi con trỏ</ins> (ví dụ IPFS CID) thay vì blob ciphertext.
- **Bridge scripts**: CLI deploy/publish bằng Hardhat, JSON outbox dùng để chuyển dữ liệu từ Java sang on-chain + IPFS (hoặc hệ lưu trữ khác).

## Yêu cầu môi trường

- JDK 21+
- Node.js 18+ (đã kiểm thử với v22.16.0)
- PowerShell/Bash

## Lệnh quan trọng

```bash
# Java side
./gradlew test               # chạy toàn bộ test JUnit
./gradlew run --args=''      # (tuỳ chọn) nếu muốn cấu hình application plugin

# Hardhat side (chạy trên terminal khác)
npx hardhat compile
npx hardhat test
npm run hardhat:deploy:local        # deploy RevocationList lên mạng Hardhat cục bộ
npm run hardhat:publish -- <file>   # đọc JSON outbox và publish lên contract
```

## Luồng demo Off-chain → On-chain

1. **Sinh dữ liệu AHIBE & blob off-chain**
   ```bash
   ./gradlew run
   ```
   Lệnh này:
   - PKG bootstrap (`PkgService`)
   - Issuer cấp `SK_H` rồi tạo bản ghi thu hồi cho `holder:alice@example.com` tại epoch `2025-10-30`
   - Holder delegate ra `SK_{H||T}`
   - Verifier decaps kiểm chứng bản ghi
   - Lưu ciphertext vào `storage/<CID>.bin` (CID giả lập bằng SHA-256 trong ví dụ) và ghi JSON vào `outbox/` (sessionKey Base64, ciphertext Hex, `storagePointer`)
   > Trong thực tế bạn nên upload file `storage/<CID>.bin` lên IPFS/Arweave... và thay thế `storagePointer` trong JSON bằng CID thật sự.

2. **Triển khai contract cục bộ**
   ```bash
   npx hardhat node          # (tuỳ chọn) nếu muốn mạng riêng
   npm run hardhat:deploy:local
   ```
   Script tạo file `deployments/hardhat.json` với địa chỉ contract.

3. **Publish bản ghi thu hồi (lưu pointer on-chain)**
   ```bash
   npm run hardhat:publish -- outbox/<file>.json
   ```
   Script tự tính `key = keccak256(holderId || epoch)` và gọi `RevocationList.publish(key, storagePointer)`. Nếu chưa upload ciphertext lên IPFS, lệnh sẽ dừng vì thiếu `storagePointer`.

4. **Xác minh**
   ```bash
   npx hardhat console --network hardhat
   > const deploy = require("./deployments/hardhat.json");
   > const rl = await ethers.getContractAt("RevocationList", deploy.address);
   > await rl.getRevocationInfo(<key>); // trả về CID/URL off-chain
   ```
   Hoặc chạy lại `./gradlew run` sau khi publish: ứng dụng sẽ tự kết nối `http://127.0.0.1:8545` (có thể override bằng biến môi trường `ETH_RPC_URL`) và kiểm tra pointer on-chain, sau đó đọc blob từ `storage/` (giả lập IPFS) để decaps.

## Cấu trúc thư mục chính

```
Code/
 ├─ app/                       # Java Gradle module
 │   └─ src/main/java/com/project/ahibe
 │       ├─ crypto/            # AhibeService
 │       ├─ core/              # PKG / Issuer / Holder / Verifier services
 │       └─ io/                # JSON export helpers
 ├─ contracts/RevocationList.sol
 ├─ scripts/deploy.js          # Hardhat deploy + lưu metadata
 ├─ scripts/publishRevocation.js
 ├─ test/RevocationList.test.js
 ├─ outbox/                    # JSON được Java sinh ra (gitignore)
 └─ storage/                   # Blob ciphertext off-chain (gitignore)
```

## Ghi chú

- Tất cả thư viện jPBC được vendor trong `libs/jars` để tránh phụ thuộc Maven Central.
- `package.json` khoá Hardhat `^2.17.2` + `@nomicfoundation/hardhat-toolbox ^4` nhằm giữ tương thích ethers v6.
- `RevocationRecordWriter` tạo JSON gồm `storagePointer`; script publish sẽ từ chối nếu trường này trống. Hãy upload blob lên IPFS trước khi gọi script.
- `storage/` chỉ phục vụ demo (giả lập IPFS). Trong môi trường thật, hãy thay `LocalFileStorageFetcher` bằng client IPFS/Arweave tương ứng.
