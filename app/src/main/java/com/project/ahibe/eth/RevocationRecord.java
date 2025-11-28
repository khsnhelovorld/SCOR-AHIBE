package com.project.ahibe.eth;

/**
 * Represents a revocation record retrieved from the blockchain.
 * 
 * @param epoch The epoch when revocation takes effect (T_rev)
 * @param ptr The IPFS CID or storage pointer
 * @param leafHash The integrity hash of the ciphertext
 * @param aggregated Whether this points to an aggregated index
 * @param version The record version (for supersede tracking)
 * @param status The current status (ACTIVE=0 or REVOKED=1)
 */
public record RevocationRecord(
    long epoch, 
    String ptr, 
    String leafHash, 
    boolean aggregated,
    long version,
    int status
) {
    /** Status constant: Holder is ACTIVE (not revoked) */
    public static final int STATUS_ACTIVE = 0;
    
    /** Status constant: Holder is REVOKED */
    public static final int STATUS_REVOKED = 1;
    
    /**
     * Backward-compatible constructor without version and status.
     */
    public RevocationRecord(long epoch, String ptr, String leafHash, boolean aggregated) {
        this(epoch, ptr, leafHash, aggregated, 1, STATUS_REVOKED);
    }
    
    /**
     * Check if this record is empty (no revocation exists).
     */
    public boolean isEmpty() {
        return epoch == 0 && (ptr == null || ptr.isEmpty());
    }
    
    /**
     * Check if holder is currently revoked.
     * @return true if status is REVOKED
     */
    public boolean isRevoked() {
        return !isEmpty() && status == STATUS_REVOKED;
    }
    
    /**
     * Check if holder is currently active (un-revoked).
     * @return true if record exists but status is ACTIVE
     */
    public boolean isActive() {
        return !isEmpty() && status == STATUS_ACTIVE;
    }
}
