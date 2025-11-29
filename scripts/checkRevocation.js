const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

/**
 * Check revocation status from the smart contract.
 * 
 * SCOR-AHIBE: 1 on-chain key = 1 off-chain file.
 * Direct CID lookup with O(1) complexity.
 * No aggregation or Merkle proofs.
 */
async function main() {
  const [issuer] = await hre.ethers.getSigners();
  console.log(`Checking from account: ${issuer.address}`);
  console.log(`Network: ${hre.network.name}`);

  const deploymentFile = path.join(__dirname, "..", "deployments", `${hre.network.name}.json`);
  
  if (!fs.existsSync(deploymentFile)) {
    throw new Error(`Deployment file not found: ${deploymentFile}. Please deploy the contract first.`);
  }

  const deployment = JSON.parse(fs.readFileSync(deploymentFile, "utf8"));
  const contractAddress = deployment.address;

  console.log(`Contract address: ${contractAddress}`);
  
  // Check if contract exists
  const code = await hre.ethers.provider.getCode(contractAddress);
  if (code === "0x") {
    console.error("❌ ERROR: No contract code at this address. The Hardhat node may have been restarted.");
    console.error("   Solution: Restart Hardhat node and redeploy the contract.");
    process.exit(1);
  }
  console.log("✓ Contract code exists at address");

  const contract = await hre.ethers.getContractAt("RevocationList", contractAddress, issuer);

  // Test with the expected holder ID and check epoch
  const holderId = process.env.CHECK_HOLDER_ID || "holder:alice@example.com";
  const checkEpoch = process.env.CHECK_EPOCH || "2025-10-30"; // T_check

  // Use static key: keccak256(holderId) only
  const key = hre.ethers.keccak256(hre.ethers.toUtf8Bytes(holderId));

  console.log(`\nChecking revocation for:`);
  console.log(`  Holder ID: ${holderId}`);
  console.log(`  Check Epoch (T_check): ${checkEpoch}`);
  console.log(`  Static Key (keccak256 of holderId): ${key}`);

  try {
    // SCOR-AHIBE simplified: getRevocationInfo returns (epoch, ptr, version, status)
    const result = await contract.getRevocationInfo(key);
    const revEpochDays = result[0];
    const cid = result[1];
    const version = result[2] !== undefined ? result[2] : 0n;
    const status = result[3] !== undefined ? Number(result[3]) : 1; // Default REVOKED for old contracts
    
    // Status enum: 0 = ACTIVE, 1 = REVOKED
    const STATUS_ACTIVE = 0;
    const STATUS_REVOKED = 1;
    const statusText = status === STATUS_ACTIVE ? "ACTIVE" : "REVOKED";
    
    if (revEpochDays === 0n && (cid === "" || cid === null)) {
      console.log("\n✓ RESULT: No revocation record found");
      console.log("  → Credential is VALID (never revoked)");
    } else {
      // Convert check epoch to days
      const checkEpochDate = new Date(checkEpoch + "T00:00:00Z");
      const checkEpochDays = Math.floor(checkEpochDate.getTime() / (1000 * 60 * 60 * 24));
      
      // Convert revEpochDays (BigInt) to number for comparison
      const revEpochDaysNum = Number(revEpochDays);
      const versionNum = Number(version);
      
      console.log(`\n✓ RESULT: Revocation record found!`);
      console.log(`  Revocation Epoch (T_rev): ${revEpochDaysNum} days since 1970-01-01`);
      console.log(`  Check Epoch (T_check): ${checkEpochDays} days since 1970-01-01`);
      console.log(`  IPFS CID: ${cid}`);
      console.log(`  Version: ${versionNum}`);
      console.log(`  Status: ${statusText} (${status})`);
      
      // First check status - if ACTIVE, holder was un-revoked
      if (status === STATUS_ACTIVE) {
        console.log(`\n✓ VALID: Holder was UN-REVOKED (status: ACTIVE, version: ${versionNum})`);
        console.log("  → Credential is VALID (holder was previously revoked but has been un-revoked)");
        return;
      }
      
      // Time comparison logic (only if status is REVOKED)
      if (checkEpochDays < revEpochDaysNum) {
        console.log(`\n✓ VALID: Check epoch (${checkEpochDays}) is BEFORE revocation epoch (${revEpochDaysNum})`);
        console.log("  → Credential is VALID (check time occurred before revocation)");
      } else {
        console.log(`\n⚠ REVOKED: Check epoch (${checkEpochDays}) is AT OR AFTER revocation epoch (${revEpochDaysNum})`);
        console.log(`  Status: ${statusText} | Version: ${versionNum}`);
        console.log("  → Credential is REVOKED");
        console.log("  → Download from IPFS and decrypt with AHIBE for final confirmation");
        console.log(`  → IPFS CID: ${cid}`);
      }
    }
  } catch (error) {
    console.error("\n❌ ERROR querying contract:");
    console.error(error.message);
    process.exit(1);
  }
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
