const { expect } = require("chai");
const { ethers } = require("hardhat");

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

    const leafHash = ethers.keccak256(ethers.toUtf8Bytes("leaf"));
    await expect(contract.publish(key, epoch, pointer, leafHash, false))
      .to.emit(contract, "RevocationPublished")
      .withArgs(key, epoch, pointer, leafHash, false);

    const [retrievedEpoch, retrievedPtr, retrievedLeaf, aggregated, version, status] = await contract.getRevocationInfo(key);
    expect(retrievedEpoch).to.equal(epoch);
    expect(retrievedPtr).to.equal(pointer);
    expect(retrievedLeaf).to.equal(leafHash);
    expect(aggregated).to.equal(false);
    expect(version).to.equal(1); // First publish is version 1
    expect(status).to.equal(1); // REVOKED = 1
  });

  it("prevents duplicate first-time publications", async function () {
    const { contract } = await deployFixture();
    const key = ethers.keccak256(ethers.toUtf8Bytes("holder:alice@example.com"));
    const epoch = 20000;
    const pointer = "ipfs://cid-deadbeef";

    const leafHash = ethers.keccak256(ethers.toUtf8Bytes("leaf"));
    await contract.publish(key, epoch, pointer, leafHash, true);
    await expect(contract.publish(key, epoch, pointer, leafHash, true)).to.be.revertedWithCustomError(
      contract,
      "AlreadyPublished"
    );
  });

  it("restricts publish to authorized accounts", async function () {
    const { contract, stranger } = await deployFixture();
    const key = ethers.keccak256(ethers.toUtf8Bytes("holder:alice@example.com"));
    const epoch = 20000;
    const pointer = "ipfs://cid-beef";

    const leafHash = ethers.keccak256(ethers.toUtf8Bytes("leaf"));
    await expect(
      contract.connect(stranger).publish(key, epoch, pointer, leafHash, false)
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
    const leafHash = ethers.keccak256(ethers.toUtf8Bytes("leaf2"));

    await expect(contract.connect(publisher).publish(key, epoch, pointer, leafHash, true))
      .to.emit(contract, "RevocationPublished");

    await expect(contract.removePublisher(publisher.address))
      .to.emit(contract, "PublisherRemoved")
      .withArgs(publisher.address);

    await expect(contract.connect(publisher).publish(key, epoch, pointer, leafHash, true))
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

    const [epoch, ptr, leafHash, aggregated, version, status] = await contract.getRevocationInfo(key);
    expect(epoch).to.equal(0);
    expect(ptr).to.equal("");
    expect(leafHash).to.equal(ethers.ZeroHash);
    expect(aggregated).to.equal(false);
    expect(version).to.equal(0);
    expect(status).to.equal(0); // ACTIVE = 0
  });

  describe("Un-Revoke Mechanism", function () {
    it("allows un-revoking a revoked holder", async function () {
      const { contract } = await deployFixture();
      const key = ethers.keccak256(ethers.toUtf8Bytes("holder:unrevoke@example.com"));
      const epoch = 20000;
      const pointer = "ipfs://cid-unrevoke";
      const leafHash = ethers.keccak256(ethers.toUtf8Bytes("unrevoke-leaf"));

      // First, publish revocation
      await contract.publish(key, epoch, pointer, leafHash, false);
      
      // Verify it's revoked
      let [, , , , version, status] = await contract.getRevocationInfo(key);
      expect(version).to.equal(1);
      expect(status).to.equal(1); // REVOKED
      expect(await contract.isRevoked(key)).to.be.true;

      // Un-revoke
      await expect(contract.unrevoke(key))
        .to.emit(contract, "StatusChanged")
        .withArgs(key, 0, 2); // ACTIVE = 0, version = 2

      // Verify it's now active
      [, , , , version, status] = await contract.getRevocationInfo(key);
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
      const leafHash = ethers.keccak256(ethers.toUtf8Bytes("double-leaf"));

      // Publish and un-revoke
      await contract.publish(key, epoch, pointer, leafHash, false);
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
      const leafHash1 = ethers.keccak256(ethers.toUtf8Bytes("first-leaf"));

      // Initial revocation
      await contract.publish(key, epoch1, pointer1, leafHash1, false);
      expect(await contract.isRevoked(key)).to.be.true;

      // Un-revoke
      await contract.unrevoke(key);
      expect(await contract.isRevoked(key)).to.be.false;

      // Re-revoke with new data
      const epoch2 = 20100;
      const pointer2 = "ipfs://cid-second";
      const leafHash2 = ethers.keccak256(ethers.toUtf8Bytes("second-leaf"));
      
      // After un-revoke, publish should work (supersede model)
      await contract.publish(key, epoch2, pointer2, leafHash2, false);
      
      const [retrievedEpoch, retrievedPtr, , , version, status] = await contract.getRevocationInfo(key);
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
      const pointers = ["ipfs://cid1", "ipfs://cid2", "ipfs://cid3"];
      const leafHashes = [
        ethers.keccak256(ethers.toUtf8Bytes("leaf1")),
        ethers.keccak256(ethers.toUtf8Bytes("leaf2")),
        ethers.keccak256(ethers.toUtf8Bytes("leaf3"))
      ];
      const aggregatedFlags = [false, false, false];

      await contract.publishBatch(keys, epochs, pointers, leafHashes, aggregatedFlags);

      for (let i = 0; i < keys.length; i++) {
        const [epoch, ptr, leafHash, aggregated, version, status] = await contract.getRevocationInfo(keys[i]);
        expect(epoch).to.equal(epochs[i]);
        expect(ptr).to.equal(pointers[i]);
        expect(version).to.equal(1);
        expect(status).to.equal(1); // REVOKED
      }
    });

    it("publishes batch aggregated with shared pointer", async function () {
      const { contract } = await deployFixture();
      const keys = [
        ethers.keccak256(ethers.toUtf8Bytes("holder:agg1@example.com")),
        ethers.keccak256(ethers.toUtf8Bytes("holder:agg2@example.com"))
      ];
      const epochs = [20000, 20001];
      const sharedPointer = "ipfs://shared-index-cid";
      const leafHashes = [
        ethers.keccak256(ethers.toUtf8Bytes("agg-leaf1")),
        ethers.keccak256(ethers.toUtf8Bytes("agg-leaf2"))
      ];

      await contract.publishBatchAggregated(keys, epochs, sharedPointer, leafHashes);

      for (let i = 0; i < keys.length; i++) {
        const [epoch, ptr, , aggregated, version, status] = await contract.getRevocationInfo(keys[i]);
        expect(epoch).to.equal(epochs[i]);
        expect(ptr).to.equal(sharedPointer);
        expect(aggregated).to.be.true;
        expect(version).to.equal(1);
        expect(status).to.equal(1); // REVOKED
      }
    });

    it("batch check revocation returns correct status", async function () {
      const { contract } = await deployFixture();
      const key1 = ethers.keccak256(ethers.toUtf8Bytes("holder:check1@example.com"));
      const key2 = ethers.keccak256(ethers.toUtf8Bytes("holder:check2@example.com"));
      const key3 = ethers.keccak256(ethers.toUtf8Bytes("holder:check3@example.com")); // Not revoked
      
      const leafHash = ethers.keccak256(ethers.toUtf8Bytes("check-leaf"));
      await contract.publish(key1, 20000, "ipfs://check1", leafHash, false);
      await contract.publish(key2, 20001, "ipfs://check2", leafHash, false);

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
      const leafHash = ethers.keccak256(ethers.toUtf8Bytes("test-leaf"));
      await expect(contract.connect(publisher).publish(key, 20000, "QmTest", leafHash, false))
        .to.emit(contract, "RevocationPublished");
      const info = await contract.getRevocationInfo(key);
      expect(info[0]).to.equal(20000n);
    });

    it("Should reject non-publisher", async function () {
      const { contract, stranger } = await deployFixture();
      const key = ethers.keccak256(ethers.toUtf8Bytes("holder:reject@example.com"));
      const leafHash = ethers.keccak256(ethers.toUtf8Bytes("reject-leaf"));
      await expect(
        contract.connect(stranger).publish(key, 20000, "QmTest", leafHash, false)
      ).to.be.revertedWithCustomError(contract, "NotAuthorized");
    });

    it("Should allow owner to publish directly without being a publisher", async function () {
      const { contract, issuer } = await deployFixture();
      const key = ethers.keccak256(ethers.toUtf8Bytes("holder:owner@example.com"));
      const leafHash = ethers.keccak256(ethers.toUtf8Bytes("owner-leaf"));
      await expect(contract.connect(issuer).publish(key, 20000, "QmOwner", leafHash, false))
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
      const leafHash = ethers.keccak256(ethers.toUtf8Bytes("remove-leaf"));
      
      // Publisher can publish
      await contract.connect(publisher).publish(key, 20000, "QmBefore", leafHash, false);
      
      // Remove publisher
      await contract.removePublisher(publisher.address);
      expect(await contract.publishers(publisher.address)).to.be.false;
      
      // Publisher cannot publish new records
      const key2 = ethers.keccak256(ethers.toUtf8Bytes("holder:remove2@example.com"));
      await expect(
        contract.connect(publisher).publish(key2, 20001, "QmAfter", leafHash, false)
      ).to.be.revertedWithCustomError(contract, "NotAuthorized");
    });

    it("Should allow publisher to unrevoke", async function () {
      const { contract, publisher } = await deployFixture();
      await contract.addPublisher(publisher.address);
      
      const key = ethers.keccak256(ethers.toUtf8Bytes("holder:pub-unrevoke@example.com"));
      const leafHash = ethers.keccak256(ethers.toUtf8Bytes("pub-unrevoke-leaf"));
      
      // Publisher publishes
      await contract.connect(publisher).publish(key, 20000, "QmPubUnrevoke", leafHash, false);
      
      // Publisher un-revokes
      await expect(contract.connect(publisher).unrevoke(key))
        .to.emit(contract, "StatusChanged")
        .withArgs(key, 0, 2);
    });

    it("Should reject stranger from un-revoking", async function () {
      const { contract, stranger } = await deployFixture();
      const key = ethers.keccak256(ethers.toUtf8Bytes("holder:stranger-unrevoke@example.com"));
      const leafHash = ethers.keccak256(ethers.toUtf8Bytes("stranger-leaf"));
      
      // Owner publishes
      await contract.publish(key, 20000, "QmStranger", leafHash, false);
      
      // Stranger tries to un-revoke
      await expect(contract.connect(stranger).unrevoke(key))
        .to.be.revertedWithCustomError(contract, "NotAuthorized");
    });
  });
});
