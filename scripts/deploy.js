const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  const RevocationList = await hre.ethers.getContractFactory("RevocationList");
  const contract = await RevocationList.deploy();
  await contract.waitForDeployment();

  const address = contract.target;
  console.log(`RevocationList deployed to: ${address}`);

  const deploymentsDir = path.join(__dirname, "..", "deployments");
  fs.mkdirSync(deploymentsDir, { recursive: true });

  const metadata = {
    address,
    network: hre.network.name,
    deployedAt: new Date().toISOString(),
  };

  const file = path.join(deploymentsDir, `${hre.network.name}.json`);
  fs.writeFileSync(file, JSON.stringify(metadata, null, 2));
  console.log(`Saved deployment metadata to ${file}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

