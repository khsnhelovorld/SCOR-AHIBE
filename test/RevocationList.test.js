const { expect } = require("chai");
const { ethers } = require("hardhat");

/**
 * Tests for RevocationList smart contract.
 * 
 * SCOR-AHIBE: 1 on-chain key = 1 off-chain file.
 * Direct CID lookup with O(1) complexity.
 * No aggregation or Merkle proofs.
 */
describe("RevocationList", function () {
  async function deployFixture() {
    const [issuer, publisher, stranger] = await ethers.getSigners();
    const RevocationList = await ethers.getContractFactory("RevocationList", issuer);
    const contract = await RevocationList.deploy();
    await contract.waitForDeployment();

    return { contract, issuer, publisher, stranger };
  }

  it("stores and retrieves revocation record with epoch and pointer", async function () {
    const { contract } = await deployFixture();
    // Static key: keccak256(holderId) only
    const key = ethers.keccak256(ethers.toUtf8Bytes("holder:alice@example.com"));
    const epoch = 20000; // days since 1970-01-01
    const pointer = "ipfs://cid-1234";

    // SCOR-AHIBE simplified: publish(key, epoch, pointer)
    await expect(contract.publish(key, epoch, pointer))
      .to.emit(contract, "RevocationPublished")
      .withArgs(key, epoch, pointer);

    const [retrievedEpoch, retrievedPtr, version, status] = await contract.getRevocationInfo(key);
    expect(retrievedEpoch).to.equal(epoch);
    expect(retrievedPtr).to.equal(pointer);
    expect(version).to.equal(1); // First publish is version 1
    expect(status).to.equal(1); // REVOKED = 1
  });

  it("prevents duplicate first-time publications", async function () {
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

  it("restricts publish to authorized accounts", async function () {
    const { contract, stranger } = await deployFixture();
    const key = ethers.keccak256(ethers.toUtf8Bytes("holder:alice@example.com"));
    const epoch = 20000;
    const pointer = "ipfs://cid-beef";

    await expect(
      contract.connect(stranger).publish(key, epoch, pointer)
    ).to.be.revertedWithCustomError(contract, "NotAuthorized");
  });

  it("allows owner to add and remove publishers", async function () {
    const { contract, publisher } = await deployFixture();
    await expect(contract.addPublisher(publisher.address))
      .to.emit(contract, "PublisherAdded")
      .withArgs(publisher.address);

    const key = ethers.keccak256(ethers.toUtf8Bytes("holder:bob@example.com"));
    const epoch = 21000;
    const pointer = "ipfs://cid-bulk";

    await expect(contract.connect(publisher).publish(key, epoch, pointer))
      .to.emit(contract, "RevocationPublished");

    await expect(contract.removePublisher(publisher.address))
      .to.emit(contract, "PublisherRemoved")
      .withArgs(publisher.address);

    const key2 = ethers.keccak256(ethers.toUtf8Bytes("holder:bob2@example.com"));
    await expect(contract.connect(publisher).publish(key2, epoch, pointer))
      .to.be.revertedWithCustomError(contract, "NotAuthorized");
  });

  it("supports ownership transfer", async function () {
    const { contract, issuer, publisher } = await deployFixture();

    await expect(contract.transferOwnership(publisher.address))
      .to.emit(contract, "OwnershipTransferred")
      .withArgs(await issuer.getAddress(), publisher.address);

    await expect(contract.addPublisher(issuer.address))
      .to.be.revertedWithCustomError(contract, "NotOwner");

    await expect(contract.connect(publisher).addPublisher(issuer.address))
      .to.emit(contract, "PublisherAdded")
      .withArgs(issuer.address);
  });

  it("returns zero epoch and empty pointer for non-existent record", async function () {
    const { contract } = await deployFixture();
    const key = ethers.keccak256(ethers.toUtf8Bytes("holder:nonexistent@example.com"));

    const [epoch, ptr, version, status] = await contract.getRevocationInfo(key);
    expect(epoch).to.equal(0);
    expect(ptr).to.equal("");
    expect(version).to.equal(0);
    expect(status).to.equal(0); // ACTIVE = 0
  });

  describe("Un-Revoke Mechanism", function () {
    it("allows un-revoking a revoked holder", async function () {
      const { contract } = await deployFixture();
      const key = ethers.keccak256(ethers.toUtf8Bytes("holder:unrevoke@example.com"));
      const epoch = 20000;
      const pointer = "ipfs://cid-unrevoke";

      // First, publish revocation
      await contract.publish(key, epoch, pointer);
      
      // Verify it's revoked
      let [, , version, status] = await contract.getRevocationInfo(key);
      expect(version).to.equal(1);
      expect(status).to.equal(1); // REVOKED
      expect(await contract.isRevoked(key)).to.be.true;

      // Un-revoke
      await expect(contract.unrevoke(key))
        .to.emit(contract, "StatusChanged")
        .withArgs(key, 0, 2); // ACTIVE = 0, version = 2

      // Verify it's now active
      [, , version, status] = await contract.getRevocationInfo(key);
      expect(version).to.equal(2);
      expect(status).to.equal(0); // ACTIVE
      expect(await contract.isRevoked(key)).to.be.false;
    });

    it("prevents un-revoking a non-existent record", async function () {
      const { contract } = await deployFixture();
      const key = ethers.keccak256(ethers.toUtf8Bytes("holder:nonexistent@example.com"));

      await expect(contract.unrevoke(key))
        .to.be.revertedWithCustomError(contract, "NotRevoked");
    });

    it("prevents un-revoking an already active holder", async function () {
      const { contract } = await deployFixture();
      const key = ethers.keccak256(ethers.toUtf8Bytes("holder:double-unrevoke@example.com"));
      const epoch = 20000;
      const pointer = "ipfs://cid-double";

      // Publish and un-revoke
      await contract.publish(key, epoch, pointer);
      await contract.unrevoke(key);

      // Try to un-revoke again
      await expect(contract.unrevoke(key))
        .to.be.revertedWithCustomError(contract, "NotRevoked");
    });

    it("allows re-revoking after un-revoke", async function () {
      const { contract } = await deployFixture();
      const key = ethers.keccak256(ethers.toUtf8Bytes("holder:re-revoke@example.com"));
      const epoch1 = 20000;
      const pointer1 = "ipfs://cid-first";

      // Initial revocation
      await contract.publish(key, epoch1, pointer1);
      expect(await contract.isRevoked(key)).to.be.true;

      // Un-revoke
      await contract.unrevoke(key);
      expect(await contract.isRevoked(key)).to.be.false;

      // Re-revoke with new data
      const epoch2 = 20100;
      const pointer2 = "ipfs://cid-second";
      
      // After un-revoke, publish should work (supersede model)
      await contract.publish(key, epoch2, pointer2);
      
      const [retrievedEpoch, retrievedPtr, version, status] = await contract.getRevocationInfo(key);
      expect(retrievedEpoch).to.equal(epoch2);
      expect(retrievedPtr).to.equal(pointer2);
      expect(version).to.equal(3); // Third version
      expect(status).to.equal(1); // REVOKED
      expect(await contract.isRevoked(key)).to.be.true;
    });
  });

  describe("Batch Operations", function () {
    it("publishes batch correctly with version tracking", async function () {
      const { contract } = await deployFixture();
      const keys = [
        ethers.keccak256(ethers.toUtf8Bytes("holder:batch1@example.com")),
        ethers.keccak256(ethers.toUtf8Bytes("holder:batch2@example.com")),
        ethers.keccak256(ethers.toUtf8Bytes("holder:batch3@example.com"))
      ];
      const epochs = [20000, 20001, 20002];
      // SCOR-AHIBE: Each holder has individual CID (1:1 mapping)
      const pointers = ["ipfs://cid1", "ipfs://cid2", "ipfs://cid3"];

      await contract.publishBatch(keys, epochs, pointers);

      for (let i = 0; i < keys.length; i++) {
        const [epoch, ptr, version, status] = await contract.getRevocationInfo(keys[i]);
        expect(epoch).to.equal(epochs[i]);
        expect(ptr).to.equal(pointers[i]);
        expect(version).to.equal(1);
        expect(status).to.equal(1); // REVOKED
      }
    });

    it("batch check revocation returns correct status", async function () {
      const { contract } = await deployFixture();
      const key1 = ethers.keccak256(ethers.toUtf8Bytes("holder:check1@example.com"));
      const key2 = ethers.keccak256(ethers.toUtf8Bytes("holder:check2@example.com"));
      const key3 = ethers.keccak256(ethers.toUtf8Bytes("holder:check3@example.com")); // Not revoked
      
      await contract.publish(key1, 20000, "ipfs://check1");
      await contract.publish(key2, 20001, "ipfs://check2");

      const results = await contract.batchCheckRevocation([key1, key2, key3]);
      expect(results[0]).to.be.true;  // key1 is revoked
      expect(results[1]).to.be.true;  // key2 is revoked
      expect(results[2]).to.be.false; // key3 doesn't exist

      // Un-revoke key1
      await contract.unrevoke(key1);
      
      const results2 = await contract.batchCheckRevocation([key1, key2, key3]);
      expect(results2[0]).to.be.false; // key1 is now ACTIVE
      expect(results2[1]).to.be.true;  // key2 still revoked
      expect(results2[2]).to.be.false; // key3 still doesn't exist
    });
  });

  describe("Access Control", function () {
    it("Should allow owner to add publisher", async function () {
      const { contract, publisher } = await deployFixture();
      await contract.addPublisher(publisher.address);
      expect(await contract.publishers(publisher.address)).to.be.true;
    });

    it("Should allow publisher to publish", async function () {
      const { contract, publisher } = await deployFixture();
      await contract.addPublisher(publisher.address);
      const key = ethers.keccak256(ethers.toUtf8Bytes("holder:test@example.com"));
      await expect(contract.connect(publisher).publish(key, 20000, "QmTest"))
        .to.emit(contract, "RevocationPublished");
      const info = await contract.getRevocationInfo(key);
      expect(info[0]).to.equal(20000n);
    });

    it("Should reject non-publisher", async function () {
      const { contract, stranger } = await deployFixture();
      const key = ethers.keccak256(ethers.toUtf8Bytes("holder:reject@example.com"));
      await expect(
        contract.connect(stranger).publish(key, 20000, "QmTest")
      ).to.be.revertedWithCustomError(contract, "NotAuthorized");
    });

    it("Should allow owner to publish directly without being a publisher", async function () {
      const { contract, issuer } = await deployFixture();
      const key = ethers.keccak256(ethers.toUtf8Bytes("holder:owner@example.com"));
      await expect(contract.connect(issuer).publish(key, 20000, "QmOwner"))
        .to.emit(contract, "RevocationPublished");
    });

    it("Should reject adding zero address as publisher", async function () {
      const { contract } = await deployFixture();
      await expect(contract.addPublisher(ethers.ZeroAddress))
        .to.be.revertedWithCustomError(contract, "InvalidAddress");
    });

    it("Should reject transferring ownership to zero address", async function () {
      const { contract } = await deployFixture();
      await expect(contract.transferOwnership(ethers.ZeroAddress))
        .to.be.revertedWithCustomError(contract, "InvalidAddress");
    });

    it("Should allow owner to transfer ownership", async function () {
      const { contract, issuer, publisher } = await deployFixture();
      await expect(contract.transferOwnership(publisher.address))
        .to.emit(contract, "OwnershipTransferred")
        .withArgs(await issuer.getAddress(), publisher.address);
      expect(await contract.owner()).to.equal(publisher.address);
    });

    it("Should remove publisher and prevent further publishing", async function () {
      const { contract, publisher } = await deployFixture();
      await contract.addPublisher(publisher.address);
      const key = ethers.keccak256(ethers.toUtf8Bytes("holder:remove@example.com"));
      
      // Publisher can publish
      await contract.connect(publisher).publish(key, 20000, "QmBefore");
      
      // Remove publisher
      await contract.removePublisher(publisher.address);
      expect(await contract.publishers(publisher.address)).to.be.false;
      
      // Publisher cannot publish new records
      const key2 = ethers.keccak256(ethers.toUtf8Bytes("holder:remove2@example.com"));
      await expect(
        contract.connect(publisher).publish(key2, 20001, "QmAfter")
      ).to.be.revertedWithCustomError(contract, "NotAuthorized");
    });

    it("Should allow publisher to unrevoke", async function () {
      const { contract, publisher } = await deployFixture();
      await contract.addPublisher(publisher.address);
      
      const key = ethers.keccak256(ethers.toUtf8Bytes("holder:pub-unrevoke@example.com"));
      
      // Publisher publishes
      await contract.connect(publisher).publish(key, 20000, "QmPubUnrevoke");
      
      // Publisher un-revokes
      await expect(contract.connect(publisher).unrevoke(key))
        .to.emit(contract, "StatusChanged")
        .withArgs(key, 0, 2);
    });

    it("Should reject stranger from un-revoking", async function () {
      const { contract, stranger } = await deployFixture();
      const key = ethers.keccak256(ethers.toUtf8Bytes("holder:stranger-unrevoke@example.com"));
      
      // Owner publishes
      await contract.publish(key, 20000, "QmStranger");
      
      // Stranger tries to un-revoke
      await expect(contract.connect(stranger).unrevoke(key))
        .to.be.revertedWithCustomError(contract, "NotAuthorized");
    });
  });

  describe("SCOR-AHIBE Principle", function () {
    it("Each holder has unique CID (1:1 mapping)", async function () {
      const { contract } = await deployFixture();
      
      // Different holders should have different CIDs
      const key1 = ethers.keccak256(ethers.toUtf8Bytes("holder:user1@example.com"));
      const key2 = ethers.keccak256(ethers.toUtf8Bytes("holder:user2@example.com"));
      
      await contract.publish(key1, 20000, "ipfs://unique-cid-1");
      await contract.publish(key2, 20000, "ipfs://unique-cid-2");
      
      const [, ptr1] = await contract.getRevocationInfo(key1);
      const [, ptr2] = await contract.getRevocationInfo(key2);
      
      expect(ptr1).to.equal("ipfs://unique-cid-1");
      expect(ptr2).to.equal("ipfs://unique-cid-2");
      expect(ptr1).to.not.equal(ptr2);
    });

    it("Direct O(1) lookup for revocation status", async function () {
      const { contract } = await deployFixture();
      const key = ethers.keccak256(ethers.toUtf8Bytes("holder:o1lookup@example.com"));
      
      await contract.publish(key, 20000, "ipfs://direct-cid");
      
      // Single call to get all information
      const [epoch, ptr, version, status] = await contract.getRevocationInfo(key);
      
      expect(epoch).to.equal(20000);
      expect(ptr).to.equal("ipfs://direct-cid");
      expect(version).to.equal(1);
      expect(status).to.equal(1);
    });
  });
});
