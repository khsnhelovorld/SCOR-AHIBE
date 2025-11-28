// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title RevocationList Contract (SCOR-AHIBE)
 * @notice Append-only mapping where Issuer publishes AHIBE-encrypted revocation entries.
 *         
 *         SCOR-AHIBE Principle: 1 on-chain key = 1 off-chain file.
 *         - Each holder has exactly one ciphertext file on IPFS
 *         - Direct CID pointer lookup with O(1) complexity
 *         - No aggregation or Merkle proofs
 *         - IPFS CID integrity is sufficient
 *         
 *         Supports un-revoke mechanism via version tracking and status field.
 *         Anyone can read records, only the contract owner can add/modify entries.
 */
contract RevocationList {
    address public owner;
    mapping(address => bool) public publishers;

    enum Status { ACTIVE, REVOKED }

    struct Record {
        uint256 epoch;       // Effective revocation epoch (T_rev) - days since 1970-01-01
        string ptr;          // IPFS CID - direct pointer to single ciphertext file
        uint256 version;     // Version counter for supersede model
        Status status;       // ACTIVE = not revoked, REVOKED = currently revoked
    }

    mapping(bytes32 => Record) public revocations; // Static key: keccak256(holderId)

    event RevocationPublished(bytes32 indexed key, uint256 epoch, string storagePointer);
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
     * @dev SCOR-AHIBE: Each holder has exactly one IPFS file (1:1 mapping)
     * @param key keccak256(holderId) - static key based on holder ID only
     * @param epoch Effective revocation epoch (T_rev) - days since 1970-01-01
     * @param storagePointer IPFS CID pointing to the holder's ciphertext file
     */
    function publish(bytes32 key, uint256 epoch, string calldata storagePointer) external onlyPublisher {
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
            version: newVersion,
            status: Status.REVOKED
        });
        
        emit RevocationPublished(key, epoch, storagePointer);
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
     *      SCOR-AHIBE: Each holder still gets their own individual IPFS file
     * @param keys Array of keccak256(holderId) values
     * @param epochs Array of revocation epochs
     * @param storagePointers Array of IPFS CIDs (one per holder)
     */
    function publishBatch(
        bytes32[] calldata keys,
        uint256[] calldata epochs,
        string[] calldata storagePointers
    ) external onlyPublisher {
        uint256 length = keys.length;
        require(length > 0, "Empty batch");
        require(
            epochs.length == length && 
            storagePointers.length == length,
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
                version: newVersion,
                status: Status.REVOKED
            });
            
            emit RevocationPublished(key, epochs[i], storagePointers[i]);
            emit StatusChanged(key, Status.REVOKED, newVersion);
        }
    }

    /**
     * @notice Get full revocation record including version and status
     * @param key keccak256(holderId)
     * @return epoch The revocation epoch
     * @return ptr The IPFS CID (direct pointer to ciphertext file)
     * @return version The record version (for supersede tracking)
     * @return status The current status (ACTIVE or REVOKED)
     */
    function getRevocationInfo(bytes32 key) external view returns (
        uint256 epoch, 
        string memory ptr, 
        uint256 version,
        Status status
    ) {
        Record memory record = revocations[key];
        return (record.epoch, record.ptr, record.version, record.status);
    }

    /**
     * @notice Get the latest record (alias for getRevocationInfo for clarity)
     * @param key keccak256(holderId)
     */
    function getLatestRecord(bytes32 key) external view returns (
        uint256 epoch,
        string memory ptr,
        uint256 version,
        Status status
    ) {
        Record memory record = revocations[key];
        return (record.epoch, record.ptr, record.version, record.status);
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
