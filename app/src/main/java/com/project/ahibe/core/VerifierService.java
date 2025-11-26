package com.project.ahibe.core;

import com.project.ahibe.crypto.AhibeService;
import com.project.ahibe.eth.RevocationListClient;
import com.project.ahibe.eth.RevocationRecord;
import com.project.ahibe.io.StorageFetcher;
import com.project.ahibe.io.StoragePointer;
import it.unisa.dia.gas.crypto.jpbc.fe.ibe.dip10.params.AHIBEDIP10SecretKeyParameters;

import java.util.Objects;
import java.util.Optional;

/**
 * Verifier pulls storage pointers from the smart contract and validates them against local ciphertext.
 * Uses static key (ID only) and performs time-based comparison before downloading IPFS content.
 */
public class VerifierService {
    private final AhibeService ahibeService;

    public VerifierService(AhibeService ahibeService) {
        this.ahibeService = ahibeService;
    }

    public byte[] decapsulate(AHIBEDIP10SecretKeyParameters delegatedKey, byte[] ciphertext) {
        Objects.requireNonNull(delegatedKey, "delegatedKey must not be null");
        Objects.requireNonNull(ciphertext, "ciphertext must not be null");
        return ahibeService.decapsulate(delegatedKey, ciphertext);
    }

    /**
     * Fetch revocation record from blockchain using static key (ID only).
     * 
     * @param client The blockchain client
     * @param holderId The holder ID
     * @return Optional RevocationRecord containing epoch and pointer
     */
    public Optional<RevocationRecord> fetchRecord(RevocationListClient client, String holderId) {
        Objects.requireNonNull(client, "client must not be null");
        Objects.requireNonNull(holderId, "holderId must not be null");
        return client.fetchRecord(holderId);
    }

    /**
     * Verify revocation status by comparing check epoch with revocation epoch.
     * 
     * @param client The blockchain client
     * @param holderId The holder ID
     * @param checkEpoch The epoch to check (T_check)
     * @return VerificationResult indicating validity status
     */
    public VerificationResult verifyRevocation(RevocationListClient client,
                                              String holderId,
                                              String checkEpoch) {
        Objects.requireNonNull(client, "client must not be null");
        Objects.requireNonNull(holderId, "holderId must not be null");
        Objects.requireNonNull(checkEpoch, "checkEpoch must not be null");

        Optional<RevocationRecord> recordOpt = fetchRecord(client, holderId);
        
        if (recordOpt.isEmpty() || recordOpt.get().isEmpty()) {
            // No revocation record found - credential is valid
            return new VerificationResult(true, null, "No revocation record found - credential is valid");
        }

        RevocationRecord record = recordOpt.get();
        long revEpochDays = record.epoch();
        
        // Compare check epoch with revocation epoch
        if (EpochComparator.isBefore(checkEpoch, revEpochDays)) {
            // Check time is before revocation time - credential is valid
            return new VerificationResult(true, null, 
                String.format("Check epoch (%s) is before revocation epoch (days: %d) - credential is valid", 
                    checkEpoch, revEpochDays));
        }

        // Check time is at or after revocation time - potentially revoked
        // Return pointer for further verification via IPFS download and AHIBE decryption
        return new VerificationResult(false, record.ptr(),
            String.format("Check epoch (%s) is at or after revocation epoch (days: %d) - potentially revoked, " +
                "download from IPFS and decrypt for final confirmation", checkEpoch, revEpochDays));
    }

    /**
     * Fetch and decapsulate revocation certificate if revocation is detected.
     * 
     * @param client The blockchain client
     * @param fetcher The storage fetcher (IPFS/local)
     * @param delegatedKey The delegated key for decryption
     * @param holderId The holder ID
     * @param checkEpoch The epoch to check (T_check)
     * @return Optional session key if revocation is confirmed, empty if valid
     */
    public Optional<byte[]> fetchAndDecapsulate(RevocationListClient client,
                                                StorageFetcher fetcher,
                                                AHIBEDIP10SecretKeyParameters delegatedKey,
                                                String holderId,
                                                String checkEpoch) {
        Objects.requireNonNull(fetcher, "fetcher must not be null");
        Objects.requireNonNull(client, "client must not be null");
        Objects.requireNonNull(holderId, "holderId must not be null");
        Objects.requireNonNull(checkEpoch, "checkEpoch must not be null");

        VerificationResult result = verifyRevocation(client, holderId, checkEpoch);
        
        if (result.isValid()) {
            // Credential is valid, no need to download
            return Optional.empty();
        }

        // Potentially revoked - download from IPFS and decrypt
        if (result.pointer() == null || result.pointer().isEmpty()) {
            return Optional.empty();
        }

        return fetcher.fetch(result.pointer())
                .map(bytes -> ahibeService.decapsulate(delegatedKey, bytes));
    }

    /**
     * @deprecated Use fetchRecord() and verifyRevocation() instead.
     */
    @Deprecated
    public Optional<String> fetchPointer(RevocationListClient client,
                                         String holderId,
                                         String epoch) {
        Objects.requireNonNull(client, "client must not be null");
        Objects.requireNonNull(holderId, "holderId must not be null");
        Objects.requireNonNull(epoch, "epoch must not be null");

        return client.fetchPointer(holderId, epoch);
    }

    /**
     * Check if the pointer matches the record's pointer.
     * Note: This method works with core.RevocationRecord (off-chain record with ciphertext).
     * For blockchain records, use the pointer directly from eth.RevocationRecord.
     */
    public boolean matchesPointer(com.project.ahibe.core.RevocationRecord record, String pointer) {
        if (record == null) {
            throw new IllegalArgumentException("record must not be null");
        }
        if (pointer == null) {
            throw new IllegalArgumentException("pointer must not be null");
        }
        return StoragePointer.deriveCid(record.ciphertext()).equals(pointer);
    }

    /**
     * Result of revocation verification.
     */
    public record VerificationResult(
        boolean isValid,
        String pointer,
        String message
    ) {
    }
}
