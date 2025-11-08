const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("RevocationList", function () {
  async function deployFixture() {
    const [issuer, stranger] = await ethers.getSigners();
    const RevocationList = await ethers.getContractFactory("RevocationList", issuer);
    const contract = await RevocationList.deploy();
    await contract.waitForDeployment();

    return { contract, issuer, stranger };
  }

  it("stores and retrieves AHIBE ciphertext", async function () {
    const { contract } = await deployFixture();
    const key = ethers.keccak256(ethers.toUtf8Bytes("holder|epoch"));
    const pointer = "ipfs://cid-1234";

    await expect(contract.publish(key, pointer))
      .to.emit(contract, "RevocationPublished")
      .withArgs(key, pointer);

    expect(await contract.getRevocationInfo(key)).to.equal(pointer);
  });

  it("prevents duplicate publications", async function () {
    const { contract } = await deployFixture();
    const key = ethers.keccak256(ethers.toUtf8Bytes("holder|epoch"));
    const pointer = "ipfs://cid-deadbeef";

    await contract.publish(key, pointer);
    await expect(contract.publish(key, pointer)).to.be.revertedWithCustomError(
      contract,
      "AlreadyPublished"
    );
  });

  it("restricts publish to owner", async function () {
    const { contract, stranger } = await deployFixture();
    const key = ethers.keccak256(ethers.toUtf8Bytes("holder|epoch"));
    const pointer = "ipfs://cid-beef";

    await expect(
      contract.connect(stranger).publish(key, pointer)
    ).to.be.revertedWithCustomError(contract, "NotOwner");
  });
});

