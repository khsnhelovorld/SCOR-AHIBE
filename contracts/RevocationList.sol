// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title RevocationList Contract (SCOR-AHIBE)
 * @notice Append-only mapping where Issuer publishes AHIBE-encrypted revocation entries.
 *         Anyone can read records, only the contract owner can add new entries.
 */
contract RevocationList {
    address public owner;

    struct Record {
        uint256 epoch; // Effective revocation epoch (T_rev) - days since 1970-01-01
        string ptr;    // IPFS CID or storage pointer
    }

    mapping(bytes32 => Record) public revocations; // Static key: keccak256(holderId)

    event RevocationPublished(bytes32 indexed key, uint256 epoch, string storagePointer);

    error NotOwner();
    error AlreadyPublished();

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) {
            revert NotOwner();
        }
        _;
    }

    /**
     * @param key keccak256(holderId) - static key based on holder ID only
     * @param epoch Effective revocation epoch (T_rev) - days since 1970-01-01
     * @param storagePointer Off-chain location (e.g. IPFS CID) of the AHIBE ciphertext
     */
    function publish(bytes32 key, uint256 epoch, string calldata storagePointer) external onlyOwner {
        if (revocations[key].epoch != 0) {
            revert AlreadyPublished();
        }

        revocations[key] = Record(epoch, storagePointer);
        emit RevocationPublished(key, epoch, storagePointer);
    }

    function getRevocationInfo(bytes32 key) external view returns (uint256 epoch, string memory ptr) {
        Record memory record = revocations[key];
        return (record.epoch, record.ptr);
    }
}

