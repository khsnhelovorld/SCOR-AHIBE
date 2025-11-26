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

  it("stores and retrieves revocation record with epoch and pointer", async function () {
    const { contract } = await deployFixture();
    // Static key: keccak256(holderId) only
    const key = ethers.keccak256(ethers.toUtf8Bytes("holder:alice@example.com"));
    const epoch = 20000; // days since 1970-01-01
    const pointer = "ipfs://cid-1234";

    await expect(contract.publish(key, epoch, pointer))
      .to.emit(contract, "RevocationPublished")
      .withArgs(key, epoch, pointer);

    const [retrievedEpoch, retrievedPtr] = await contract.getRevocationInfo(key);
    expect(retrievedEpoch).to.equal(epoch);
    expect(retrievedPtr).to.equal(pointer);
  });

  it("prevents duplicate publications", async function () {
    const { contract } = await deployFixture();
    const key = ethers.keccak256(ethers.toUtf8Bytes("holder:alice@example.com"));
    const epoch = 20000;
    const pointer = "ipfs://cid-deadbeef";

    await contract.publish(key, epoch, pointer);
    await expect(contract.publish(key, epoch, pointer)).to.be.revertedWithCustomError(
      contract,
      "AlreadyPublished"
    );
  });

  it("restricts publish to owner", async function () {
    const { contract, stranger } = await deployFixture();
    const key = ethers.keccak256(ethers.toUtf8Bytes("holder:alice@example.com"));
    const epoch = 20000;
    const pointer = "ipfs://cid-beef";

    await expect(
      contract.connect(stranger).publish(key, epoch, pointer)
    ).to.be.revertedWithCustomError(contract, "NotOwner");
  });

  it("returns zero epoch and empty pointer for non-existent record", async function () {
    const { contract } = await deployFixture();
    const key = ethers.keccak256(ethers.toUtf8Bytes("holder:nonexistent@example.com"));

    const [epoch, ptr] = await contract.getRevocationInfo(key);
    expect(epoch).to.equal(0);
    expect(ptr).to.equal("");
  });
});

