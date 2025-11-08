// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title RevocationList Contract (SCOR-AHIBE)
 * @notice Append-only mapping where Issuer publishes AHIBE-encrypted revocation entries.
 *         Anyone can read records, only the contract owner can add new entries.
 */
contract RevocationList {
    address public owner;

    mapping(bytes32 => string) public revocations;

    event RevocationPublished(bytes32 indexed key, string storagePointer);

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
     * @param key keccak256(holderId || epoch)
     * @param storagePointer Off-chain location (e.g. IPFS CID) of the AHIBE ciphertext
     */
    function publish(bytes32 key, string calldata storagePointer) external onlyOwner {
        if (bytes(revocations[key]).length != 0) {
            revert AlreadyPublished();
        }

        revocations[key] = storagePointer;
        emit RevocationPublished(key, storagePointer);
    }

    function getRevocationInfo(bytes32 key) external view returns (string memory) {
        return revocations[key];
    }
}

