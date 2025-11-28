package com.project.ahibe.core;

import com.project.ahibe.ipfs.IPFSService;
import com.project.ahibe.io.StoragePointer;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Higher-level utility that batches multiple revocation encapsulations.
 * 
 * SCOR-AHIBE Principle: 1 on-chain key = 1 off-chain file.
 * - Each holder gets their own individual CID
 * - No shared aggregated indices
 * - Batching is only at transaction level (multi-call), not data level
 * 
 * This service generates individual revocations for batch processing,
 * but each revocation still has its own unique IPFS file.
 */
public class BatchRevocationService {

    public record Request(String holderId, String epoch) {}

    public record BatchResult(
            List<RevocationRecord> records,
            int successCount,
            int failureCount
    ) {}

    private final IssuerService issuerService;
    private final Optional<IPFSService> ipfsService;

    public BatchRevocationService(IssuerService issuerService,
                                  Optional<IPFSService> ipfsService) {
        this.issuerService = issuerService;
        this.ipfsService = ipfsService;
    }

    /**
     * Process batch of revocation requests.
     * Each holder gets their own individual IPFS file (1:1 mapping).
     * 
     * @param requests List of holder/epoch pairs to revoke
     * @return BatchResult containing all processed records
     */
    public BatchResult publishBatch(List<Request> requests) {
        if (requests == null || requests.isEmpty()) {
            throw new IllegalArgumentException("requests must not be empty");
        }

        List<RevocationRecord> records = new ArrayList<>(requests.size());
        int successCount = 0;
        int failureCount = 0;

        for (Request request : requests) {
            try {
                // Build revocation record for this holder
                RevocationRecord raw = issuerService.buildRevocationRecord(request.holderId(), request.epoch());
                
                // Upload to IPFS (individual file per holder)
                String pointer = ipfsService
                        .map(service -> {
                            try {
                                return service.uploadRevocationCertificate(raw.ciphertext());
                            } catch (IOException e) {
                                throw new IllegalStateException("Failed to upload to IPFS", e);
                            }
                        })
                        .orElse(StoragePointer.deriveCid(raw.ciphertext()));

                // Create record with pointer
                RevocationRecord withPointer = raw.withStoragePointer(pointer);
                records.add(withPointer);
                successCount++;
                
            } catch (Exception e) {
                System.err.printf("Failed to process revocation for %s/%s: %s%n", 
                    request.holderId(), request.epoch(), e.getMessage());
                failureCount++;
            }
        }

        return new BatchResult(records, successCount, failureCount);
    }
}
