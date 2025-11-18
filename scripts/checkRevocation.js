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

  // Test with the expected holder ID and epoch
  const holderId = "holder:alice@example.com";
  const epoch = "2025-10-30";

  const key = hre.ethers.keccak256(
    hre.ethers.concat([
      hre.ethers.toUtf8Bytes(holderId),
      hre.ethers.toUtf8Bytes(epoch),
    ])
  );

  console.log(`\nChecking revocation for:`);
  console.log(`  Holder ID: ${holderId}`);
  console.log(`  Epoch: ${epoch}`);
  console.log(`  Key (bytes32): ${key}`);

  try {
    const cid = await contract.getRevocationInfo(key);
    
    if (cid === "" || cid === null) {
      console.log("\n❌ RESULT: No revocation record found (empty string returned)");
      console.log("\nThis means either:");
      console.log("  1. The Hardhat node was restarted after publishing (state lost)");
      console.log("  2. The transaction was not confirmed properly");
      console.log("  3. The key computation is different between publish and query");
      
      console.log("\nTo fix:");
      console.log("  1. Ensure Hardhat node is still running from when you published");
      console.log("  2. Or republish the revocation:");
      console.log(`     $env:RECORD_PATH="app/outbox/holder_alice_example_com__2025-10-30.json"`);
      console.log(`     npm run hardhat:publish`);
    } else {
      console.log(`\n✓ RESULT: Revocation record found!`);
      console.log(`  IPFS CID: ${cid}`);
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

