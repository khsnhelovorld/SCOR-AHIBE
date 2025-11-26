package com.project.ahibe.eth;

/**
 * Represents a revocation record retrieved from the blockchain.
 * 
 * @param epoch The epoch when revocation takes effect (T_rev)
 * @param ptr The IPFS CID or storage pointer
 */
public record RevocationRecord(long epoch, String ptr) {
    /**
     * Check if this record is empty (no revocation exists).
     */
    public boolean isEmpty() {
        return epoch == 0 && (ptr == null || ptr.isEmpty());
    }
}

