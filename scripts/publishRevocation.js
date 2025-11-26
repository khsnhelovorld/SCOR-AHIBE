const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  const [issuer] = await hre.ethers.getSigners();
  console.log(`Deploying from account: ${issuer.address}`);
  console.log(`Network: ${hre.network.name}`);

  const recordPath =
    process.env.REVOCATION_RECORD ??
    process.env.RECORD_PATH ??
    path.join(__dirname, "..", "outbox", "revocation-holder_alice_example_com__2025-10-30.json");
  const deploymentFile =
    process.env.REVOCATION_DEPLOYMENT ??
    path.join(__dirname, "..", "deployments", `${hre.network.name}.json`);

  if (!fs.existsSync(recordPath)) {
    throw new Error(`Record file not found: ${recordPath}. Set RECORD_PATH or REVOCATION_RECORD env var to override.`);
  }
  if (!fs.existsSync(deploymentFile)) {
    throw new Error(`Deployment file not found: ${deploymentFile}. Please deploy the contract first.`);
  }

  const record = JSON.parse(fs.readFileSync(recordPath, "utf8"));
  const deployment = JSON.parse(fs.readFileSync(deploymentFile, "utf8"));

  const contract = await hre.ethers.getContractAt("RevocationList", deployment.address, issuer);

  // Use static key: keccak256(holderId) only
  const key = hre.ethers.keccak256(hre.ethers.toUtf8Bytes(record.holderId));

  // Convert epoch string (YYYY-MM-DD) to days since epoch (1970-01-01)
  const epochDate = new Date(record.epoch + "T00:00:00Z");
  const epochDays = Math.floor(epochDate.getTime() / (1000 * 60 * 60 * 24));

  console.log(`Publishing revocation for ${record.holderId} @ ${record.epoch}`);
  console.log(`Contract address: ${deployment.address}`);
  console.log(`Static key (keccak256 of holderId): ${key}`);
  console.log(`Epoch (days since 1970-01-01): ${epochDays}`);
  if (!record.storagePointer) {
    throw new Error("storagePointer missing in record JSON. Upload ciphertext to IPFS and set storagePointer.");
  }
  console.log(`IPFS CID: ${record.storagePointer}`);
  
  const tx = await contract.publish(key, epochDays, record.storagePointer);
  console.log(`Transaction submitted: ${tx.hash}`);
  console.log("Waiting for confirmation...");
  await tx.wait();
  console.log(`Transaction confirmed! Hash: ${tx.hash}`);
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });

