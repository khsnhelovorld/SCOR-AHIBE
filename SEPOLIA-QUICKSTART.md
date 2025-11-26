# Quick Start - Sepolia Testnet

Hướng dẫn dưới đây giả định bạn **vừa clone repo**, đã có `.env` chứa `SEPOLIA_RPC_URL`, `ETH_RPC_URL`, `PRIVATE_KEY`, `IPFS_HOST`, `IPFS_PORT` (hoặc IPFS URL) và muốn benchmark bằng `runDemo` trên mạng Sepolia.

```powershell
# 0. Cài dependencies một lần sau khi clone
npm install
./gradlew build

# 1. Đảm bảo IPFS Desktop đang chạy hoặc mở terminal khác: ipfs daemon

# 2. Deploy smart contract lên Sepolia (ghi deployments/sepolia.json)
npm run hardhat:deploy:sepolia

# 3. Sinh revocation record cho holder/epoch mong muốn bằng ứng dụng Java mặc định
#    (Ứng dụng App sẽ generate + upload lên IPFS và ghi file outbox)
$env:IPFS_HOST="127.0.0.1"
$env:IPFS_PORT="5001"
$env:NETWORK="sepolia"
$env:ETH_RPC_URL="https://ethereum-sepolia-rpc.publicnode.com"
./gradlew run

#    Lệnh trên sẽ tạo file app/outbox/holder_alice_example_com__2025-10-30.json
#    (mặc định holder:alice@example.com, epoch 2025-10-30). Nếu cần ID khác,
#    sử dụng `./gradlew runHolder` + `./gradlew runVerifier` hoặc chỉnh sửa tham số trong App.java.

# 4. Publish CID + epoch lên contract vừa deploy
$env:RECORD_PATH="app/outbox/holder_alice_example_com__2025-10-30.json"
npm run hardhat:publish:sepolia

# 5. Benchmark / demo toàn bộ luồng (Verifier đọc record trên Sepolia)
$env:NETWORK="sepolia"
$env:ETH_RPC_URL="https://ethereum-sepolia-rpc.publicnode.com"
./gradlew runDemo -PappArgs="holder:alice@example.com,2025-10-30"

# 6. (Tùy chọn) Kiểm tra lại contract state bằng script Hardhat
npm run hardhat:check:sepolia
```

Ghi chú:
- Nếu bạn thay `holderId` hoặc `epoch`, hãy chạy lại bước 3 và 4 với file `RECORD_PATH` mới.
- `runDemo` sẽ báo lỗi “Credential not revoked” nếu bạn quên publish hoặc dùng epoch chưa có bản ghi trên chain.
- Khi thay RPC/provider, cập nhật lại `.env` hoặc biến môi trường tương ứng trước khi chạy lệnh.