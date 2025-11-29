package com.project.ahibe;

import com.project.ahibe.core.BatchRevocationService;
import com.project.ahibe.core.IssuerService;
import com.project.ahibe.core.PkgService;
import com.project.ahibe.core.RevocationRecord;
import com.project.ahibe.core.BatchRevocationService.Request;
import com.project.ahibe.crypto.AhibeService;
import com.project.ahibe.crypto.config.PairingProfile;
import com.project.ahibe.ipfs.IPFSService;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * CLI utility that reads a CSV file with {@code holderId,epoch} pairs, generates AHIBE
 * revocations for all entries, and uploads individual files to IPFS.
 * 
 * SCOR-AHIBE: 1 on-chain key = 1 off-chain file.
 * Each holder gets their own individual IPFS file.
 * No aggregation or shared indices.
 *
 * Usage:
 * {@code ./gradlew runBatchPublisher -PappArgs="batch.csv"}
 */
public class BatchPublisherApp {

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: BatchPublisherApp <csvFile>");
            System.err.println("CSV format: holder:alice@example.com,2025-10-30");
            System.exit(1);
        }

        Path csvPath = Paths.get(args[0]);
        if (!Files.exists(csvPath)) {
            System.err.println("CSV file not found: " + csvPath.toAbsolutePath());
            System.exit(1);
        }

        List<Request> requests = Files.lines(csvPath)
                .map(String::trim)
                .filter(line -> !line.isBlank() && !line.startsWith("#"))
                .map(line -> {
                    String[] parts = line.split(",");
                    if (parts.length < 2) {
                        throw new IllegalArgumentException("Invalid CSV row: " + line);
                    }
                    return new Request(parts[0].trim(), parts[1].trim());
                })
                .collect(Collectors.toList());

        // Always use BLS12-381 (AHIBE_PROFILE removed)
        PairingProfile profile = PairingProfile.BLS12_381;
        AhibeService ahibeService = new AhibeService(profile, 3);
        PkgService pkg = new PkgService(ahibeService);
        var setup = pkg.bootstrap();

        IPFSService ipfsService = initializeIPFS();
        IssuerService issuer = ipfsService != null
                ? new IssuerService(ahibeService, setup, ipfsService)
                : new IssuerService(ahibeService, setup);

        BatchRevocationService batchService = new BatchRevocationService(
                issuer,
                Optional.ofNullable(ipfsService)
        );

        BatchRevocationService.BatchResult result = batchService.publishBatch(requests);

        System.out.println("╔════════════════════════════════════════════════════════════════╗");
        System.out.println("║              BATCH REVOCATION RESULTS (SCOR-AHIBE)             ║");
        System.out.println("╚════════════════════════════════════════════════════════════════╝");
        System.out.println();
        System.out.println("Processed: " + requests.size() + " revocation requests");
        System.out.println("Success:   " + result.successCount());
        System.out.println("Failed:    " + result.failureCount());
        System.out.println();
        System.out.println("Individual CIDs (1:1 holder-to-file mapping):");
        for (RevocationRecord record : result.records()) {
            System.out.printf("  • %s [%s] -> %s%n", 
                record.holderId(), 
                record.epoch(), 
                record.storagePointer());
        }
        System.out.println();
        System.out.println("Use scripts/publishRevocation.js to register each entry on-chain.");
    }

    private static IPFSService initializeIPFS() {
        String ipfsHost = System.getenv("IPFS_HOST");
        String ipfsPort = System.getenv("IPFS_PORT");
        String ipfsUrl = System.getenv("IPFS_URL");

        IPFSService ipfsService;
        if (ipfsUrl != null && !ipfsUrl.isBlank()) {
            ipfsService = new IPFSService(ipfsUrl);
            System.out.println("Using IPFS URL: " + ipfsUrl);
        } else if (ipfsHost != null && !ipfsHost.isBlank()) {
            int port = ipfsPort != null ? Integer.parseInt(ipfsPort) : 5001;
            ipfsService = new IPFSService(ipfsHost, port);
            System.out.println("Using IPFS at " + ipfsHost + ":" + port);
        } else {
            System.out.println("IPFS env vars not set. Defaulting to http://127.0.0.1:5001");
            ipfsService = new IPFSService("127.0.0.1", 5001);
        }

        if (!ipfsService.isAvailable()) {
            System.err.println("Warning: IPFS node is not reachable. Files will remain local.");
            return null;
        }
        return ipfsService;
    }
}
