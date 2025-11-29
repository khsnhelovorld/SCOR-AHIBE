package com.project.ahibe.core;

/**
 * Simple holder for AHIBE revocation artifacts.
 * 
 * SCOR-AHIBE Principle: 1 on-chain key = 1 off-chain file.
 * Each holder has exactly one ciphertext file on IPFS with direct CID pointer.
 *
 * @param holderId   canonical identifier of the holder.
 * @param epoch      revocation epoch YYYY-MM-DD, block height,... depending on scenario.
 * @param sessionKey random key produced during encapsulation (kept off-chain).
 * @param ciphertext AHIBE ciphertext stored off-chain (e.g. IPFS object).
 * @param storagePointer Pointer or CID referencing the off-chain ciphertext.
 */
public record RevocationRecord(
        String holderId,
        String epoch,
        byte[] sessionKey,
        byte[] ciphertext,
        String storagePointer
) {

    public RevocationRecord withStoragePointer(String pointer) {
        return new RevocationRecord(holderId, epoch, sessionKey, ciphertext, pointer);
    }
}
