// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title RevocationList Contract (SCOR-AHIBE)
 * @notice Append-only mapping where Issuer publishes AHIBE-encrypted revocation entries.
 *         Anyone can read records, only the contract owner can add new entries.
 */
contract RevocationList {
    address public owner;

    mapping(bytes32 => bytes) public revocations;

    event RevocationPublished(bytes32 indexed key, bytes encryptedInfo);

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
     * @param encryptedInfo AHIBE ciphertext produced off-chain
     */
    function publish(bytes32 key, bytes calldata encryptedInfo) external onlyOwner {
        if (revocations[key].length != 0) {
            revert AlreadyPublished();
        }

        revocations[key] = encryptedInfo;
        emit RevocationPublished(key, encryptedInfo);
    }

    function getRevocationInfo(bytes32 key) external view returns (bytes memory) {
        return revocations[key];
    }
}

