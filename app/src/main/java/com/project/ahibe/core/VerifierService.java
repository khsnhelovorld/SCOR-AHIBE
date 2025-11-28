package com.project.ahibe.core;

import com.project.ahibe.crypto.AhibeService;
import com.project.ahibe.crypto.bls12.BLS12SecretKey;
import com.project.ahibe.eth.RevocationListClient;
import com.project.ahibe.eth.RevocationRecord;
import com.project.ahibe.io.StorageFetcher;
import com.project.ahibe.io.StoragePointer;

import java.util.Objects;
import java.util.Optional;

/**
 * Verifier pulls storage pointers from the smart contract and validates them against local ciphertext.
 * Uses static key (ID only) and performs time-based comparison before downloading IPFS content.
 * 
 * SCOR-AHIBE Principle: 1 on-chain key = 1 off-chain file.
 * - Direct CID pointer lookup with O(1) complexity
 * - No aggregation or Merkle proofs required
 * - IPFS CID integrity is sufficient
 * - Fully non-interactive verification
 * 
 * Updated to support:
 * - Version tracking for supersede model
 * - Status field (ACTIVE/REVOKED) for un-revoke mechanism
 */
public class VerifierService {
    
    private final AhibeService ahibeService;

    public VerifierService(AhibeService ahibeService) {
        this.ahibeService = ahibeService;
    }

    public byte[] decapsulate(BLS12SecretKey delegatedKey, byte[] ciphertext) {
        return decapsulate(delegatedKey, ciphertext, null);
    }
    
    public byte[] decapsulate(BLS12SecretKey delegatedKey, byte[] ciphertext, String issuerProfileId) {
        Objects.requireNonNull(delegatedKey, "delegatedKey must not be null");
        Objects.requireNonNull(ciphertext, "ciphertext must not be null");
        
        // Check for profile mismatch if issuer profile is known
        if (issuerProfileId != null && !issuerProfileId.isBlank()) {
            checkProfileMismatch(issuerProfileId);
        }
        
        return ahibeService.decapsulate(delegatedKey, ciphertext);
    }
    
    private void checkProfileMismatch(String issuerProfileId) {
        String verifierProfileId = ahibeService.profile().id();
        if (!issuerProfileId.equals(verifierProfileId)) {
            System.err.printf("WARNING: Profile mismatch detected! Issuer used profile '%s' but verifier is using '%s'. " +
                    "This may cause decryption failures or incorrect results. Ensure both Issuer and Verifier use the same AHIBE profile.%n",
                    issuerProfileId, verifierProfileId);
        }
    }

    /**
     * Fetch revocation record from blockchain using static key (ID only).
     * 
     * @param client The blockchain client
     * @param holderId The holder ID
     * @return Optional RevocationRecord containing epoch, pointer, version and status
     */
    public Optional<RevocationRecord> fetchRecord(RevocationListClient client, String holderId) {
        Objects.requireNonNull(client, "client must not be null");
        Objects.requireNonNull(holderId, "holderId must not be null");
        return client.fetchRecord(holderId);
    }

    /**
     * Check if a holder is currently revoked using the new status field.
     * 
     * @param client The blockchain client
     * @param holderId The holder ID
     * @return true if holder is currently revoked
     */
    public boolean isCurrentlyRevoked(RevocationListClient client, String holderId) {
        Objects.requireNonNull(client, "client must not be null");
        Objects.requireNonNull(holderId, "holderId must not be null");
        
        return fetchRecord(client, holderId)
                .map(RevocationRecord::isRevoked)
                .orElse(false);
    }

    /**
     * Verify revocation status by comparing check epoch with revocation epoch.
     * Also checks the current status (ACTIVE/REVOKED) for un-revoke support.
     * 
     * Direct O(1) lookup - no Merkle proofs or aggregation needed.
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
            return new VerificationResult(true, null, 0, RevocationRecord.STATUS_ACTIVE,
                    "No revocation record found - credential is valid");
        }

        RevocationRecord record = recordOpt.get();
        
        // Check if holder was un-revoked (status = ACTIVE)
        if (record.isActive()) {
            return new VerificationResult(true, record.ptr(),
                record.version(), record.status(),
                String.format("Holder was un-revoked (version: %d, status: ACTIVE) - credential is valid", 
                    record.version()));
        }
        
        long revEpochDays = record.epoch();
        
        // Compare check epoch with revocation epoch
        if (EpochComparator.isBefore(checkEpoch, revEpochDays)) {
            // Check time is before revocation time - credential is valid
            return new VerificationResult(true, null,
                record.version(), record.status(),
                String.format("Check epoch (%s) is before revocation epoch (days: %d) - credential is valid", 
                    checkEpoch, revEpochDays));
        }

        // Check time is at or after revocation time AND status is REVOKED
        // Return pointer for further verification via IPFS download and AHIBE decryption
        return new VerificationResult(false, record.ptr(),
            record.version(), record.status(),
            String.format("Check epoch (%s) is at or after revocation epoch (days: %d), status: REVOKED (v%d) - " +
                "download from IPFS and decrypt for final confirmation", checkEpoch, revEpochDays, record.version()));
    }

    /**
     * Fetch and decapsulate revocation certificate if revocation is detected.
     * 
     * Direct CID lookup - downloads exactly ONE file per verification.
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
                                                BLS12SecretKey delegatedKey,
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

        // Direct CID fetch - exactly one file download
        Optional<byte[]> payload = fetcher.fetch(result.pointer());

        return payload.map(bytes -> decapsulate(delegatedKey, bytes, null));
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
     * Now includes version and status for un-revoke mechanism support.
     * 
     * SCOR-AHIBE: Simplified without aggregation/Merkle fields.
     */
    public record VerificationResult(
        boolean isValid,
        String pointer,
        long version,
        int status,
        String message
    ) {
        /**
         * Backward-compatible constructor without version/status.
         */
        public VerificationResult(boolean isValid, String pointer, String message) {
            this(isValid, pointer, 0, 
                 isValid ? RevocationRecord.STATUS_ACTIVE : RevocationRecord.STATUS_REVOKED, 
                 message);
        }
    }
}
