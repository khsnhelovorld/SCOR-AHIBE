const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  const [issuer] = await hre.ethers.getSigners();

  const recordPath =
    process.argv[2] !== undefined ? process.argv[2] : path.join(__dirname, "..", "outbox", "revocation-holder_alice_example_com__2025-10-30.json");
  const deploymentFile =
    process.env.REVOCATION_DEPLOYMENT ??
    path.join(__dirname, "..", "deployments", `${hre.network.name}.json`);

  const record = JSON.parse(fs.readFileSync(recordPath, "utf8"));
  const deployment = JSON.parse(fs.readFileSync(deploymentFile, "utf8"));

  const contract = await hre.ethers.getContractAt("RevocationList", deployment.address, issuer);

  const key = hre.ethers.keccak256(
    hre.ethers.concat([
      hre.ethers.toUtf8Bytes(record.holderId),
      hre.ethers.toUtf8Bytes(record.epoch),
    ])
  );

  console.log(`Publishing revocation for ${record.holderId} @ ${record.epoch}`);
  if (!record.storagePointer) {
    throw new Error("storagePointer missing in record JSON. Upload ciphertext to IPFS and set storagePointer.");
  }
  const tx = await contract.publish(key, record.storagePointer);
  await tx.wait();
  console.log(`Transaction hash: ${tx.hash}`);
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });

