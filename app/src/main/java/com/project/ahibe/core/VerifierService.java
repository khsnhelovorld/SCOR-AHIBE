package com.project.ahibe.core;

import com.project.ahibe.crypto.AhibeService;
import com.project.ahibe.crypto.HashingUtils;
import com.project.ahibe.crypto.bls12.BLS12SecretKey;
import com.project.ahibe.eth.RevocationListClient;
import com.project.ahibe.eth.RevocationRecord;
import com.project.ahibe.io.AggregatedRevocationIndex;
import com.project.ahibe.io.ByteEncoding;
import com.project.ahibe.io.StorageFetcher;
import com.project.ahibe.io.StoragePointer;

import java.time.Instant;
import java.util.Comparator;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Verifier pulls storage pointers from the smart contract and validates them against local ciphertext.
 * Uses static key (ID only) and performs time-based comparison before downloading IPFS content.
 * 
 * Updated to support:
 * - Version tracking for supersede model
 * - Status field (ACTIVE/REVOKED) for un-revoke mechanism
 */
public class VerifierService {
    private static final int MAX_CACHE_SIZE = 100;
    private static final long CACHE_TTL_SECONDS = 300; // 5 minutes
    private static final Map<String, CachedIndex> INDEX_CACHE = new ConcurrentHashMap<>();
    
    private record CachedIndex(AggregatedRevocationIndex index, Instant fetchedAt) {}
    
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
            return new VerificationResult(true, null, null, false, 0, RevocationRecord.STATUS_ACTIVE,
                    "No revocation record found - credential is valid");
        }

        RevocationRecord record = recordOpt.get();
        
        // Check if holder was un-revoked (status = ACTIVE)
        if (record.isActive()) {
            return new VerificationResult(true, record.ptr(), record.leafHash(), record.aggregated(),
                record.version(), record.status(),
                String.format("Holder was un-revoked (version: %d, status: ACTIVE) - credential is valid", 
                    record.version()));
        }
        
        long revEpochDays = record.epoch();
        
        // Compare check epoch with revocation epoch
        if (EpochComparator.isBefore(checkEpoch, revEpochDays)) {
            // Check time is before revocation time - credential is valid
            return new VerificationResult(true, null, null, record.aggregated(),
                record.version(), record.status(),
                String.format("Check epoch (%s) is before revocation epoch (days: %d) - credential is valid", 
                    checkEpoch, revEpochDays));
        }

        // Check time is at or after revocation time AND status is REVOKED
        // Return pointer for further verification via IPFS download and AHIBE decryption
        return new VerificationResult(false, record.ptr(), record.leafHash(), record.aggregated(),
            record.version(), record.status(),
            String.format("Check epoch (%s) is at or after revocation epoch (days: %d), status: REVOKED (v%d) - " +
                "download from IPFS and decrypt for final confirmation", checkEpoch, revEpochDays, record.version()));
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

        Optional<byte[]> payload;
        if (result.aggregated()) {
            // Use cached index if available
            AggregatedRevocationIndex index = getOrFetchIndex(fetcher, result.pointer());
            payload = index.findEntry(holderId, checkEpoch)
                    .filter(entry -> verifyMerkleProof(entry, index.merkleRoot(), result.leafHash()))
                    .map(AggregatedRevocationIndex.Entry::ciphertextBytes);
        } else {
            payload = fetcher.fetch(result.pointer());
        }

        return payload.map(bytes -> decapsulate(delegatedKey, bytes, null));
    }

    /**
     * @deprecated Use fetchRecord() / verifyRevocation() instead.
     * Provides backward compatibility by reading the static-key record
     * and returning only the pointer component.
     */
    @Deprecated
    public Optional<String> fetchPointer(RevocationListClient client,
                                         String holderId,
                                         String epoch) {
        Objects.requireNonNull(client, "client must not be null");
        Objects.requireNonNull(holderId, "holderId must not be null");
        Objects.requireNonNull(epoch, "epoch must not be null");

        return client.fetchRecord(holderId)
                .filter(record -> !record.isEmpty())
                .map(com.project.ahibe.eth.RevocationRecord::ptr)
                .filter(ptr -> ptr != null && !ptr.isBlank());
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
     */
    public record VerificationResult(
        boolean isValid,
        String pointer,
        String leafHash,
        boolean aggregated,
        long version,
        int status,
        String message
    ) {
        /**
         * Backward-compatible constructor without version/status.
         */
        public VerificationResult(boolean isValid, String pointer, String leafHash, 
                                  boolean aggregated, String message) {
            this(isValid, pointer, leafHash, aggregated, 0, 
                 isValid ? RevocationRecord.STATUS_ACTIVE : RevocationRecord.STATUS_REVOKED, 
                 message);
        }
    }

    private Optional<byte[]> extractAggregatedCiphertext(byte[] indexBytes,
                                                         String holderId,
                                                         String epoch,
                                                         String expectedLeafHash) {
        // Note: indexBytes is already fetched, but we still cache the parsed index
        // for potential future lookups of other entries in the same index
        AggregatedRevocationIndex index = AggregatedRevocationIndex.fromJson(indexBytes);
        return index.findEntry(holderId, epoch)
                .filter(entry -> verifyMerkleProof(entry, index.merkleRoot(), expectedLeafHash))
                .map(AggregatedRevocationIndex.Entry::ciphertextBytes);
    }
    
    /**
     * Get or fetch aggregated index from cache or storage.
     * Cache has 5-minute TTL and maximum 100 entries with LRU eviction.
     */
    private AggregatedRevocationIndex getOrFetchIndex(StorageFetcher fetcher, String pointer) {
        CachedIndex cached = INDEX_CACHE.get(pointer);
        if (cached != null && cached.fetchedAt().isAfter(Instant.now().minusSeconds(CACHE_TTL_SECONDS))) {
            return cached.index();
        }
        
        byte[] bytes = fetcher.fetch(pointer).orElseThrow(() -> 
            new IllegalStateException("Failed to fetch aggregated index: " + pointer));
        
        AggregatedRevocationIndex index = AggregatedRevocationIndex.fromJson(bytes);
        
        // Evict oldest entry if cache is full
        if (INDEX_CACHE.size() >= MAX_CACHE_SIZE) {
            INDEX_CACHE.entrySet().stream()
                .min(Comparator.comparing(e -> e.getValue().fetchedAt()))
                .ifPresent(e -> INDEX_CACHE.remove(e.getKey()));
        }
        
        INDEX_CACHE.put(pointer, new CachedIndex(index, Instant.now()));
        return index;
    }

    /**
     * Full Merkle proof verification including:
     * 1. Recompute leaf hash from holder/epoch/ciphertext
     * 2. Verify leaf hash matches stored value
     * 3. Verify inclusion proof from leaf to root
     * 
     * @param entry The index entry containing ciphertext and proof
     * @param merkleRoot The expected Merkle root
     * @param expectedLeafHash The leaf hash from blockchain (for integrity check)
     * @return true if all verifications pass
     */
    private boolean verifyMerkleProof(AggregatedRevocationIndex.Entry entry,
                                      String merkleRoot,
                                      String expectedLeafHash) {
        if (entry == null) {
            return false;
        }
        
        // Step 1: Recompute leaf hash from actual data (holder + epoch + ciphertext)
        byte[] ciphertext = entry.ciphertextBytes();
        byte[] recomputedLeafHash = HashingUtils.hashHolderEpochCiphertext(
            entry.holderId(), 
            entry.epoch(), 
            ciphertext
        );
        
        // Step 2: Verify recomputed hash matches stored leaf hash
        String recomputedHex = HashingUtils.toHex(recomputedLeafHash);
        if (!recomputedHex.equalsIgnoreCase(entry.leafHashHex())) {
            System.err.printf("[MerkleVerification] Leaf hash mismatch! Recomputed: %s, Stored: %s%n",
                recomputedHex, entry.leafHashHex());
            return false;
        }
        
        // Step 3: Verify against blockchain's expected leaf hash (if provided)
        if (expectedLeafHash != null && !expectedLeafHash.equalsIgnoreCase(entry.leafHashHex())) {
            System.err.printf("[MerkleVerification] Leaf hash does not match blockchain record! " +
                "Index: %s, Blockchain: %s%n", entry.leafHashHex(), expectedLeafHash);
            return false;
        }
        
        // Step 4: Verify Merkle inclusion proof (climb tree from leaf to root)
        byte[] currentHash = recomputedLeafHash;
        for (AggregatedRevocationIndex.ProofNode node : entry.proof()) {
            byte[] sibling = ByteEncoding.fromHex(node.hashHex());
            if ("LEFT".equalsIgnoreCase(node.position())) {
                // Sibling is on left: hash(sibling || current)
                currentHash = HashingUtils.sha256(sibling, currentHash);
            } else {
                // Sibling is on right: hash(current || sibling)
                currentHash = HashingUtils.sha256(currentHash, sibling);
            }
        }
        
        // Step 5: Final root comparison
        boolean rootMatches = HashingUtils.toHex(currentHash).equalsIgnoreCase(merkleRoot);
        if (!rootMatches) {
            System.err.printf("[MerkleVerification] Computed root does not match! " +
                "Computed: %s, Expected: %s%n", HashingUtils.toHex(currentHash), merkleRoot);
        }
        
        return rootMatches;
    }
    
    /**
     * Detailed Merkle verification result.
     */
    public record MerkleVerificationDetail(
        boolean leafHashValid,
        boolean proofValid,
        boolean blockchainMatchValid,
        String message
    ) {
        public boolean isFullyValid() {
            return leafHashValid && proofValid && blockchainMatchValid;
        }
    }
    
    /**
     * Perform detailed Merkle verification with full diagnostic output.
     * 
     * @param entry The index entry
     * @param merkleRoot The expected Merkle root
     * @param blockchainLeafHash The leaf hash from blockchain
     * @return Detailed verification result
     */
    public MerkleVerificationDetail verifyMerkleProofDetailed(
            AggregatedRevocationIndex.Entry entry,
            String merkleRoot,
            String blockchainLeafHash) {
        
        if (entry == null) {
            return new MerkleVerificationDetail(false, false, false, "Entry is null");
        }
        
        // Recompute and verify leaf hash
        byte[] ciphertext = entry.ciphertextBytes();
        byte[] recomputedLeafHash = HashingUtils.hashHolderEpochCiphertext(
            entry.holderId(), entry.epoch(), ciphertext
        );
        String recomputedHex = HashingUtils.toHex(recomputedLeafHash);
        boolean leafHashValid = recomputedHex.equalsIgnoreCase(entry.leafHashHex());
        
        // Verify blockchain match
        boolean blockchainMatchValid = blockchainLeafHash == null || 
            blockchainLeafHash.equalsIgnoreCase(entry.leafHashHex());
        
        // Verify Merkle proof
        byte[] currentHash = ByteEncoding.fromHex(entry.leafHashHex());
        for (AggregatedRevocationIndex.ProofNode node : entry.proof()) {
            byte[] sibling = ByteEncoding.fromHex(node.hashHex());
            if ("LEFT".equalsIgnoreCase(node.position())) {
                currentHash = HashingUtils.sha256(sibling, currentHash);
            } else {
                currentHash = HashingUtils.sha256(currentHash, sibling);
            }
        }
        boolean proofValid = HashingUtils.toHex(currentHash).equalsIgnoreCase(merkleRoot);
        
        String message = String.format(
            "Leaf: %s, Proof: %s, Blockchain: %s",
            leafHashValid ? "OK" : "FAIL",
            proofValid ? "OK" : "FAIL",
            blockchainMatchValid ? "OK" : "FAIL"
        );
        
        return new MerkleVerificationDetail(leafHashValid, proofValid, blockchainMatchValid, message);
    }
}
