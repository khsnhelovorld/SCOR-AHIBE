const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

/**
 * Publish revocation record to the smart contract.
 * 
 * SCOR-AHIBE: 1 on-chain key = 1 off-chain file.
 * Each holder has exactly one IPFS file (direct CID pointer).
 * No aggregation or Merkle proofs.
 */
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

  const payload = JSON.parse(fs.readFileSync(recordPath, "utf8"));
  const deployment = JSON.parse(fs.readFileSync(deploymentFile, "utf8"));

  const contract = await hre.ethers.getContractAt("RevocationList", deployment.address, issuer);

  // SCOR-AHIBE: Only single record publishing (no aggregation)
  await publishSingle(contract, deployment.address, payload, issuer.address);
}

async function publishSingle(contract, contractAddress, record, issuerAddress) {
  ensure(record.holderId, "holderId missing in record JSON");
  ensure(record.epoch, "epoch missing in record JSON");
  ensure(record.storagePointer, "storagePointer missing in record JSON");

  const key = hre.ethers.keccak256(hre.ethers.toUtf8Bytes(record.holderId));
  const epochDays = formatEpochDays(record.epoch);

  console.log(`Publishing revocation for ${record.holderId} @ ${record.epoch}`);
  console.log(`Contract: ${contractAddress}`);
  console.log(`IPFS CID: ${record.storagePointer}`);

  // SCOR-AHIBE simplified contract: publish(key, epochDays, storagePointer)
  const tx = await contract.publish(key, epochDays, record.storagePointer);
  console.log(` → tx: ${tx.hash}`);
  await tx.wait();
  console.log("   ✓ Confirmed");
}

function formatEpochDays(epochStr) {
  const epochDate = new Date(epochStr + "T00:00:00Z");
  return Math.floor(epochDate.getTime() / (1000 * 60 * 60 * 24));
}

function ensure(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
