// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title RevocationList Contract (SCOR-AHIBE)
 * @notice Append-only mapping where Issuer publishes AHIBE-encrypted revocation entries.
 *         Supports un-revoke mechanism via version tracking and status field.
 *         Anyone can read records, only the contract owner can add/modify entries.
 */
contract RevocationList {
    address public owner;
    mapping(address => bool) public publishers;

    enum Status { ACTIVE, REVOKED }

    struct Record {
        uint256 epoch;       // Effective revocation epoch (T_rev) - days since 1970-01-01
        string ptr;          // IPFS CID or storage pointer (index or ciphertext)
        bytes32 leafHash;    // Integrity hash of the ciphertext or aggregated leaf
        bool aggregated;     // true if ptr references an aggregated index
        uint256 version;     // Version counter for supersede model
        Status status;       // ACTIVE = not revoked, REVOKED = currently revoked
    }

    mapping(bytes32 => Record) public revocations; // Static key: keccak256(holderId)

    event RevocationPublished(bytes32 indexed key, uint256 epoch, string storagePointer, bytes32 leafHash, bool aggregated);
    event StatusChanged(bytes32 indexed key, Status status, uint256 version);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event PublisherAdded(address indexed account);
    event PublisherRemoved(address indexed account);

    error NotOwner();
    error NotAuthorized();
    error InvalidAddress();
    error AlreadyPublished();
    error NotRevoked();

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    modifier onlyOwner() {
        if (msg.sender != owner) {
            revert NotOwner();
        }
        _;
    }

    modifier onlyPublisher() {
        if (msg.sender != owner && !publishers[msg.sender]) {
            revert NotAuthorized();
        }
        _;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) {
            revert InvalidAddress();
        }
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function addPublisher(address account) external onlyOwner {
        if (account == address(0)) {
            revert InvalidAddress();
        }
        publishers[account] = true;
        emit PublisherAdded(account);
    }

    function removePublisher(address account) external onlyOwner {
        publishers[account] = false;
        emit PublisherRemoved(account);
    }

    /**
     * @notice Publish a revocation record (marks holder as REVOKED)
     * @param key keccak256(holderId) - static key based on holder ID only
     * @param epoch Effective revocation epoch (T_rev) - days since 1970-01-01
     * @param storagePointer Off-chain location (e.g. IPFS CID) of the AHIBE ciphertext
     * @param leafHash Integrity hash of the ciphertext
     * @param aggregated true if storagePointer references an aggregated index
     */
    function publish(bytes32 key, uint256 epoch, string calldata storagePointer, bytes32 leafHash, bool aggregated) external onlyPublisher {
        Record storage record = revocations[key];
        
        // Prevent duplicate publish if currently REVOKED
        // Allow publish if: 1) never published (version=0), or 2) un-revoked (status=ACTIVE)
        if (record.version > 0 && record.status == Status.REVOKED) {
            revert AlreadyPublished();
        }
        
        // Increment version (supersede model)
        uint256 newVersion = record.version + 1;
        
        revocations[key] = Record({
            epoch: epoch,
            ptr: storagePointer,
            leafHash: leafHash,
            aggregated: aggregated,
            version: newVersion,
            status: Status.REVOKED
        });
        
        emit RevocationPublished(key, epoch, storagePointer, leafHash, aggregated);
        emit StatusChanged(key, Status.REVOKED, newVersion);
    }

    /**
     * @notice Un-revoke a holder (marks as ACTIVE, keeps record for audit)
     * @param key keccak256(holderId) - static key based on holder ID only
     */
    function unrevoke(bytes32 key) external onlyPublisher {
        Record storage record = revocations[key];
        
        // Must have existing revocation to un-revoke
        if (record.epoch == 0 || record.status == Status.ACTIVE) {
            revert NotRevoked();
        }
        
        record.version++;
        record.status = Status.ACTIVE;
        
        emit StatusChanged(key, Status.ACTIVE, record.version);
    }

    /**
     * @notice Batch publish multiple revocation records in a single transaction
     * @dev Gas efficient for publishing multiple revocations at once
     * @param keys Array of keccak256(holderId) values
     * @param epochs Array of revocation epochs
     * @param storagePointers Array of IPFS CIDs or storage pointers
     * @param leafHashes Array of leaf hashes for Merkle proof validation
     * @param aggregatedFlags Array indicating if each record is aggregated
     */
    function publishBatch(
        bytes32[] calldata keys,
        uint256[] calldata epochs,
        string[] calldata storagePointers,
        bytes32[] calldata leafHashes,
        bool[] calldata aggregatedFlags
    ) external onlyPublisher {
        uint256 length = keys.length;
        require(length > 0, "Empty batch");
        require(
            epochs.length == length && 
            storagePointers.length == length && 
            leafHashes.length == length && 
            aggregatedFlags.length == length,
            "Array length mismatch"
        );
        
        for (uint256 i = 0; i < length; i++) {
            bytes32 key = keys[i];
            Record storage record = revocations[key];
            
            // Skip if currently REVOKED (no duplicate publish)
            if (record.version > 0 && record.status == Status.REVOKED) {
                continue;
            }
            
            uint256 newVersion = record.version + 1;
            
            revocations[key] = Record({
                epoch: epochs[i],
                ptr: storagePointers[i],
                leafHash: leafHashes[i],
                aggregated: aggregatedFlags[i],
                version: newVersion,
                status: Status.REVOKED
            });
            
            emit RevocationPublished(key, epochs[i], storagePointers[i], leafHashes[i], aggregatedFlags[i]);
            emit StatusChanged(key, Status.REVOKED, newVersion);
        }
    }

    /**
     * @notice Batch publish with same storage pointer (for aggregated index)
     * @dev More gas efficient when all records point to the same aggregated index
     * @param keys Array of keccak256(holderId) values
     * @param epochs Array of revocation epochs
     * @param sharedPointer Common IPFS CID for the aggregated index
     * @param leafHashes Array of leaf hashes for Merkle proof validation
     */
    function publishBatchAggregated(
        bytes32[] calldata keys,
        uint256[] calldata epochs,
        string calldata sharedPointer,
        bytes32[] calldata leafHashes
    ) external onlyPublisher {
        uint256 length = keys.length;
        require(length > 0, "Empty batch");
        require(epochs.length == length && leafHashes.length == length, "Array length mismatch");
        
        for (uint256 i = 0; i < length; i++) {
            bytes32 key = keys[i];
            Record storage record = revocations[key];
            
            // Skip if currently REVOKED (no duplicate publish)
            if (record.version > 0 && record.status == Status.REVOKED) {
                continue;
            }
            
            uint256 newVersion = record.version + 1;
            
            revocations[key] = Record({
                epoch: epochs[i],
                ptr: sharedPointer,
                leafHash: leafHashes[i],
                aggregated: true,
                version: newVersion,
                status: Status.REVOKED
            });
            
            emit RevocationPublished(key, epochs[i], sharedPointer, leafHashes[i], true);
            emit StatusChanged(key, Status.REVOKED, newVersion);
        }
    }

    /**
     * @notice Get full revocation record including version and status
     * @param key keccak256(holderId)
     * @return epoch The revocation epoch
     * @return ptr The storage pointer (IPFS CID)
     * @return leafHash The integrity hash
     * @return aggregated Whether this points to an aggregated index
     * @return version The record version (for supersede tracking)
     * @return status The current status (ACTIVE or REVOKED)
     */
    function getRevocationInfo(bytes32 key) external view returns (
        uint256 epoch, 
        string memory ptr, 
        bytes32 leafHash, 
        bool aggregated,
        uint256 version,
        Status status
    ) {
        Record memory record = revocations[key];
        return (record.epoch, record.ptr, record.leafHash, record.aggregated, record.version, record.status);
    }

    /**
     * @notice Get the latest record (alias for getRevocationInfo for clarity)
     * @param key keccak256(holderId)
     */
    function getLatestRecord(bytes32 key) external view returns (
        uint256 epoch,
        string memory ptr,
        bytes32 leafHash,
        bool aggregated,
        uint256 version,
        Status status
    ) {
        Record memory record = revocations[key];
        return (record.epoch, record.ptr, record.leafHash, record.aggregated, record.version, record.status);
    }

    /**
     * @notice Check if a holder is currently revoked
     * @param key keccak256(holderId)
     * @return true if holder has REVOKED status, false otherwise
     */
    function isRevoked(bytes32 key) external view returns (bool) {
        Record memory record = revocations[key];
        return record.epoch != 0 && record.status == Status.REVOKED;
    }

    /**
     * @notice Check if multiple holders have revocation records
     * @param keys Array of keccak256(holderId) values
     * @return Array of booleans indicating if each holder is currently revoked
     */
    function batchCheckRevocation(bytes32[] calldata keys) external view returns (bool[] memory) {
        bool[] memory results = new bool[](keys.length);
        for (uint256 i = 0; i < keys.length; i++) {
            Record memory record = revocations[keys[i]];
            results[i] = record.epoch != 0 && record.status == Status.REVOKED;
        }
        return results;
    }
}
