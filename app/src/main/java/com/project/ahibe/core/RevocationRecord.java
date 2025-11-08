package com.project.ahibe.core;

/**
 * Simple holder for AHIBE revocation artifacts.
 *
 * @param holderId   canonical identifier of the holder.
 * @param epoch      revocation epoch YYYY-MM-DD, block height,... depending on scenario.
 * @param sessionKey random key produced during encapsulation (kept off-chain).
 * @param ciphertext AHIBE ciphertext published on-chain.
 */
public record RevocationRecord(
        String holderId,
        String epoch,
        byte[] sessionKey,
        byte[] ciphertext
) {
}

