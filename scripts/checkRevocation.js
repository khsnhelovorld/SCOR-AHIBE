const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

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
  const holderId = "holder:alice@example.com";
  const checkEpoch = "2025-10-30"; // T_check

  // Use static key: keccak256(holderId) only
  const key = hre.ethers.keccak256(hre.ethers.toUtf8Bytes(holderId));

  console.log(`\nChecking revocation for:`);
  console.log(`  Holder ID: ${holderId}`);
  console.log(`  Check Epoch (T_check): ${checkEpoch}`);
  console.log(`  Static Key (keccak256 of holderId): ${key}`);

  try {
    const [revEpochDays, cid] = await contract.getRevocationInfo(key);
    
    if (revEpochDays === 0n && (cid === "" || cid === null)) {
      console.log("\n✓ RESULT: No revocation record found");
      console.log("  → Credential is VALID (never revoked)");
    } else {
      // Convert check epoch to days
      const checkEpochDate = new Date(checkEpoch + "T00:00:00Z");
      const checkEpochDays = Math.floor(checkEpochDate.getTime() / (1000 * 60 * 60 * 24));
      
      // Convert revEpochDays (BigInt) to number for comparison
      const revEpochDaysNum = Number(revEpochDays);
      
      console.log(`\n✓ RESULT: Revocation record found!`);
      console.log(`  Revocation Epoch (T_rev): ${revEpochDaysNum} days since 1970-01-01`);
      console.log(`  Check Epoch (T_check): ${checkEpochDays} days since 1970-01-01`);
      console.log(`  IPFS CID: ${cid}`);
      
      // Time comparison logic
      if (checkEpochDays < revEpochDaysNum) {
        console.log(`\n✓ VALID: Check epoch (${checkEpochDays}) is BEFORE revocation epoch (${revEpochDaysNum})`);
        console.log("  → Credential is VALID (check time occurred before revocation)");
      } else {
        console.log(`\n⚠ POTENTIALLY REVOKED: Check epoch (${checkEpochDays}) is AT OR AFTER revocation epoch (${revEpochDaysNum})`);
        console.log("  → Credential may be REVOKED");
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

