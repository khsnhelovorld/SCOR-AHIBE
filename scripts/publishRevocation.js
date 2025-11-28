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

  const payload = JSON.parse(fs.readFileSync(recordPath, "utf8"));
  const deployment = JSON.parse(fs.readFileSync(deploymentFile, "utf8"));

  const contract = await hre.ethers.getContractAt("RevocationList", deployment.address, issuer);

  if (Array.isArray(payload.entries)) {
    await publishAggregated(contract, deployment.address, payload, issuer.address);
  } else {
    await publishSingle(contract, deployment.address, payload, issuer.address);
  }
}

async function publishSingle(contract, contractAddress, record, issuerAddress) {
  ensure(record.holderId, "holderId missing in record JSON");
  ensure(record.epoch, "epoch missing in record JSON");
  ensure(record.storagePointer, "storagePointer missing in record JSON");

  const key = hre.ethers.keccak256(hre.ethers.toUtf8Bytes(record.holderId));
  const epochDays = formatEpochDays(record.epoch);
  const leafHash = normalizeLeafHash(record.leafHash);

  console.log(`Publishing revocation for ${record.holderId} @ ${record.epoch}`);
  console.log(`Contract: ${contractAddress} | Pointer: ${record.storagePointer}`);
  console.log(`Leaf hash: ${leafHash}`);

  const tx = await contract.publish(key, epochDays, record.storagePointer, leafHash, !!record.aggregated);
  console.log(` → tx: ${tx.hash}`);
  await tx.wait();
  console.log("   ✓ Confirmed");
}

async function publishAggregated(contract, contractAddress, indexJson, issuerAddress) {
  const pointer = indexJson.storagePointer || process.env.AGGREGATED_POINTER;
  if (!pointer) {
    throw new Error("Aggregated index missing storagePointer. Set AGGREGATED_POINTER env var or update index file with pointer.");
  }
  console.log(`Detected aggregated index ${indexJson.indexId} (${indexJson.entries.length} entries)`);

  let counter = 0;
  for (const entry of indexJson.entries) {
    const key = hre.ethers.keccak256(hre.ethers.toUtf8Bytes(entry.holderId));
    const epochDays = formatEpochDays(entry.epoch);
    const leafHash = normalizeLeafHash(entry.leafHashHex || entry.leafHash);

    console.log(`→ Entry: ${entry.holderId} @ ${entry.epoch}`);
    const tx = await contract.publish(key, epochDays, pointer, leafHash, true);
    console.log(`   tx: ${tx.hash}`);
    await tx.wait();
    counter += 1;
  }
  console.log(`✓ Published ${counter} aggregated entries on ${contractAddress}`);
}

function formatEpochDays(epochStr) {
  const epochDate = new Date(epochStr + "T00:00:00Z");
  return Math.floor(epochDate.getTime() / (1000 * 60 * 60 * 24));
}

function normalizeLeafHash(value) {
  if (!value) {
    return hre.ethers.ZeroHash;
  }
  if (!value.startsWith("0x")) {
    throw new Error("Leaf hash must be hex-prefixed (0x...)");
  }
  return hre.ethers.zeroPadValue(value, 32);
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

