package com.project.ahibe.core;

import com.project.ahibe.crypto.AhibeService;
import com.project.ahibe.io.AggregatedRevocationIndex;
import com.project.ahibe.io.AggregatedRevocationIndexWriter;
import com.project.ahibe.ipfs.IPFSService;
import com.project.ahibe.io.StoragePointer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Higher-level utility that batches multiple revocation encapsulations into a single
 * aggregated index stored on IPFS (or disk fallback). The aggregated pointer drastically
 * reduces the number of CID writes when handling millions of holders.
 */
public class BatchRevocationService {

    public record Request(String holderId, String epoch) {}

    public record BatchResult(
            AggregatedRevocationIndex index,
            String indexPointer,
            List<RevocationRecord> records
    ) {}

    private final IssuerService issuerService;
    private final Optional<IPFSService> ipfsService;
    private final AggregatedRevocationIndexWriter writer;

    public BatchRevocationService(IssuerService issuerService,
                                  Optional<IPFSService> ipfsService,
                                  Path outbox) {
        this.issuerService = issuerService;
        this.ipfsService = ipfsService;
        this.writer = new AggregatedRevocationIndexWriter(outbox);
    }

    public BatchResult publishBatch(List<Request> requests) {
        if (requests == null || requests.isEmpty()) {
            throw new IllegalArgumentException("requests must not be empty");
        }

        List<RevocationRecord> minted = new ArrayList<>(requests.size());
        for (Request request : requests) {
            minted.add(issuerService.buildRevocationRecord(request.holderId(), request.epoch()));
        }

        AggregatedRevocationIndex index = AggregatedRevocationIndex.fromRecords(minted);
        Path localPath = writeIndex(index);

        String pointer = ipfsService
                .map(service -> {
                    try {
                        return service.uploadJson(index.toJsonBytes());
                    } catch (IOException e) {
                        throw new IllegalStateException("Failed to upload aggregated index to IPFS", e);
                    }
                })
                .orElseGet(() -> deriveLocalCid(localPath));

        AggregatedRevocationIndex indexed = index.withPointer(pointer);
        writeIndex(indexed);

        List<RevocationRecord> mapped = minted.stream()
                .map(r -> r.markAggregated(pointer))
                .toList();

        return new BatchResult(indexed, pointer, mapped);
    }

    private Path writeIndex(AggregatedRevocationIndex index) {
        try {
            return writer.write(index);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to write aggregated index", e);
        }
    }

    private String deriveLocalCid(Path path) {
        try {
            return StoragePointer.deriveCid(Files.readAllBytes(path));
        } catch (IOException e) {
            throw new IllegalStateException("Failed to derive fallback CID from " + path, e);
        }
    }
}

