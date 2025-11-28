
package com.project.ahibe;

import com.project.ahibe.core.HolderService;
import com.project.ahibe.core.IssuerService;
import com.project.ahibe.core.PkgService;
import com.project.ahibe.core.VerifierService;
import com.project.ahibe.crypto.AhibeService;
import com.project.ahibe.crypto.CryptoMetrics;
import com.project.ahibe.crypto.config.PairingProfile;
import com.project.ahibe.eth.DeploymentRegistry;
import com.project.ahibe.eth.RevocationListClient;
import com.project.ahibe.ipfs.IPFSService;
import com.project.ahibe.ipfs.IPFSStorageFetcher;
import com.project.ahibe.crypto.bls12.BLS12PublicKey;
import com.project.ahibe.crypto.bls12.BLS12SecretKey;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Demo Application with BENCHMARKING (1000 iterations)
 * 
 * SCOR-AHIBE: 1 on-chain key = 1 off-chain file.
 * Direct CID lookup with O(1) complexity.
 * No aggregation or Merkle proofs.
 * 
 * Features:
 * - Detailed timing for each operation
 * - CSV export for benchmark results
 * - Statistics: avg, min, max, stddev
 */
public class DemoApp {
    // Statistics for each operation
    static class OperationStats {
        String operation;
        String note;
        List<Double> times = new ArrayList<>();
        
        OperationStats(String op, String n) {
            this.operation = op;
            this.note = n;
        }
        
        double getAverage() {
            return times.stream().mapToDouble(Double::doubleValue).average().orElse(0.0);
        }
        
        double getMin() {
            return times.stream().mapToDouble(Double::doubleValue).min().orElse(0.0);
        }
        
        double getMax() {
            return times.stream().mapToDouble(Double::doubleValue).max().orElse(0.0);
        }
        
        double getStdDev() {
            double avg = getAverage();
            double variance = times.stream()
                .mapToDouble(t -> Math.pow(t - avg, 2))
                .average()
                .orElse(0.0);
            return Math.sqrt(variance);
        }
    }

    static Map<String, OperationStats> statsMap = new HashMap<>();
    static int ITERATIONS = 1000;
    static String CSV_OUTPUT_DIR = "benchmark_results";

    public static void main(String[] args) {
        try {
            if (args.length < 2) {
                System.err.println("Usage: java DemoApp <holderId> <epoch> [iterations]");
                System.err.println("Example: java DemoApp holder:alice@example.com 2025-10-30");
                System.err.println("         java DemoApp holder:alice@example.com 2025-10-30 100");
                System.exit(1);
            }

            String holderId = args[0];
            String epoch = args[1];
            
            // Optional: custom iteration count
            if (args.length >= 3) {
                try {
                    ITERATIONS = Integer.parseInt(args[2]);
                } catch (NumberFormatException e) {
                    System.err.println("Warning: Invalid iteration count, using default: " + ITERATIONS);
                }
            }

            System.out.println("==========================================================================================");
            System.out.println("         SCOR-AHIBE BENCHMARK RUNNER (" + ITERATIONS + " iterations)         ");
            System.out.println("==========================================================================================");
            System.out.println();
            System.out.println("Holder ID: " + holderId);
            System.out.println("Epoch:     " + epoch);
            System.out.println("Iterations: " + ITERATIONS);
            System.out.println();

            // ==================== ONE-TIME SETUP ====================
            System.out.println("[Setup] Initializing system (one-time)...");
            long tStart = System.nanoTime();
            // Always use BLS12-381 (AHIBE_PROFILE removed)
            PairingProfile profile = PairingProfile.BLS12_381;
            AhibeService ahibeService = new AhibeService(profile, 3);
            double setupTime = (System.nanoTime() - tStart) / 1_000_000.0;
            System.out.printf("   -> System Setup: %.4f ms (one-time)%n", setupTime);

            tStart = System.nanoTime();
            PkgService pkg = new PkgService(ahibeService);
            AhibeService.SetupResult setup = pkg.bootstrap();
            BLS12PublicKey publicKey = setup.publicKey();
            double pkgTime = (System.nanoTime() - tStart) / 1_000_000.0;
            System.out.printf("   -> PKG Bootstrap: %.4f ms (one-time)%n", pkgTime);

            tStart = System.nanoTime();
            IssuerService issuer = new IssuerService(ahibeService, setup);
            BLS12SecretKey rootKey = issuer.issueRootKey(holderId);
            double issuerTime = (System.nanoTime() - tStart) / 1_000_000.0;
            System.out.printf("   -> Issuer Root Key Gen: %.4f ms (one-time)%n", issuerTime);

            // Setup services for benchmarking
            HolderService holder = new HolderService(ahibeService, publicKey);
            
            IPFSService ipfsService = initializeIPFS();
            if (ipfsService == null) throw new RuntimeException("IPFS not found");
            
            String network = System.getenv().getOrDefault("NETWORK", "hardhat");
            String rpcUrl = System.getenv().getOrDefault("ETH_RPC_URL", "http://127.0.0.1:8545");
            
            Path deploymentsPath = Paths.get("deployments");
            if (!deploymentsPath.toFile().exists()) {
                deploymentsPath = Paths.get("..").resolve("deployments");
            }
            DeploymentRegistry registry = new DeploymentRegistry(deploymentsPath);
            String contractAddress = registry.load(network).orElseThrow().address();

            // Pre-fetch CID and ciphertext once (for verifier operations)
            VerifierService verifierService = new VerifierService(ahibeService);
            String cid;
            byte[] ciphertext;
            try (RevocationListClient client = new RevocationListClient(rpcUrl, contractAddress)) {
                VerifierService.VerificationResult verification = verifierService.verifyRevocation(client, holderId, epoch);
                if (verification.isValid()) {
                    throw new RuntimeException("Credential not revoked for epoch " + epoch + ": " + verification.message());
                }

                cid = Optional.ofNullable(verification.pointer())
                        .filter(ptr -> !ptr.isBlank())
                        .orElseThrow(() -> new RuntimeException("Revocation record missing storage pointer"));

                // Direct CID fetch - exactly one file per verification (SCOR-AHIBE principle)
                IPFSStorageFetcher fetcher = new IPFSStorageFetcher(ipfsService);
                ciphertext = fetcher.fetch(cid).orElseThrow(() -> new RuntimeException("Failed to fetch ciphertext from IPFS"));
                System.out.printf("   -> Ciphertext size: %d bytes%n", CryptoMetrics.ciphertextSize(ciphertext));
            }

            // ==================== BENCHMARK LOOP ====================
            System.out.println();
            System.out.println("[Benchmark] Running " + ITERATIONS + " iterations...");
            System.out.println("Progress: ");

            for (int i = 0; i < ITERATIONS; i++) {
                // Holder: Delegate Key Generation
                tStart = System.nanoTime();
                BLS12SecretKey delegateKey = holder.deriveEpochKey(rootKey, epoch);
                recordTime("Holder: Delegate Key Gen", tStart, "Derive SK_{H||Epoch} (Off-chain)");

                // Verifier: Query Blockchain
                tStart = System.nanoTime();
                try (RevocationListClient client = new RevocationListClient(rpcUrl, contractAddress)) {
                    verifierService.verifyRevocation(client, holderId, epoch);
                }
                recordTime("Verifier: Query Blockchain", tStart, "Get CID (View call)");

                // Verifier: Fetch IPFS (direct CID fetch - O(1) lookup)
                tStart = System.nanoTime();
                IPFSStorageFetcher fetcher = new IPFSStorageFetcher(ipfsService);
                fetcher.fetch(cid).orElse(null);
                recordTime("Verifier: Fetch IPFS", tStart, "Download (" + ciphertext.length + " bytes)");

                // Verifier: Decrypt
                tStart = System.nanoTime();
                verifierService.decapsulate(delegateKey, ciphertext);
                recordTime("Verifier: Decrypt (Decaps)", tStart, "Pairing operation");

                // Progress indicator
                if ((i + 1) % 100 == 0) {
                    System.out.print(".");
                    if ((i + 1) % 500 == 0) {
                        System.out.println(" " + (i + 1) + "/" + ITERATIONS);
                    }
                }
            }
            System.out.println(" " + ITERATIONS + "/" + ITERATIONS + " completed!");
            System.out.println();

            // ==================== PRINT REPORT ====================
            printReport();
            
            // ==================== EXPORT CSV ====================
            String csvPath = exportToCsv(holderId, epoch);
            System.out.println("Benchmark results exported to: " + csvPath);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static void recordTime(String op, long startTimeNano, String note) {
        long duration = System.nanoTime() - startTimeNano;
        double ms = duration / 1_000_000.0;
        
        statsMap.computeIfAbsent(op, k -> new OperationStats(op, note)).times.add(ms);
    }

    private static void printReport() {
        System.out.println();
        System.out.println("==========================================================================================");
        System.out.println("|                    SCOR-AHIBE PERFORMANCE REPORT (" + ITERATIONS + " iterations)                    |");
        System.out.println("|========================================================================================|");
        System.out.println();
        System.out.println(String.format("| %-35s | %-10s | %-10s | %-10s | %-10s | %-20s |",
            "Operation", "Avg (ms)", "Min (ms)", "Max (ms)", "StdDev", "Note"));
        System.out.println("|-------------------------------------|------------|------------|------------|------------|----------------------|");
        
        for (OperationStats stats : statsMap.values()) {
            System.out.println(String.format("| %-35s | %10.4f | %10.4f | %10.4f | %10.4f | %-20s |",
                stats.operation,
                stats.getAverage(),
                stats.getMin(),
                stats.getMax(),
                stats.getStdDev(),
                stats.note));
        }
        
        System.out.println("|========================================================================================|");
        System.out.println();
        System.out.println("NOTE: Add Gas costs from Hardhat logs manually to this table.");
        System.out.println("==========================================================================================");
    }
    
    /**
     * Export benchmark results to CSV file.
     * 
     * @param holderId The holder ID used in benchmark
     * @param epoch The epoch used in benchmark
     * @return Path to the exported CSV file
     */
    private static String exportToCsv(String holderId, String epoch) throws IOException {
        // Create output directory
        Path outputDir = Paths.get(CSV_OUTPUT_DIR);
        Files.createDirectories(outputDir);
        
        // Generate filename with timestamp
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss"));
        String safeHolderId = holderId.replaceAll("[^a-zA-Z0-9._-]", "_");
        String filename = String.format("benchmark_%s_%s_%s.csv", safeHolderId, epoch, timestamp);
        Path csvPath = outputDir.resolve(filename);
        
        try (PrintWriter writer = new PrintWriter(new FileWriter(csvPath.toFile()))) {
            // Write header
            writer.println("operation,avg_ms,min_ms,max_ms,stddev_ms,iterations,note,holder_id,epoch,timestamp");
            
            // Write data rows
            for (OperationStats stats : statsMap.values()) {
                writer.printf("%s,%.6f,%.6f,%.6f,%.6f,%d,\"%s\",\"%s\",\"%s\",\"%s\"%n",
                    escapeCSV(stats.operation),
                    stats.getAverage(),
                    stats.getMin(),
                    stats.getMax(),
                    stats.getStdDev(),
                    stats.times.size(),
                    escapeCSV(stats.note),
                    escapeCSV(holderId),
                    escapeCSV(epoch),
                    timestamp
                );
            }
            
            // Write raw data section (optional, for detailed analysis)
            writer.println();
            writer.println("# Raw timing data (all iterations)");
            writer.println("operation,iteration,time_ms");
            for (OperationStats stats : statsMap.values()) {
                for (int i = 0; i < stats.times.size(); i++) {
                    writer.printf("%s,%d,%.6f%n", 
                        escapeCSV(stats.operation), 
                        i + 1, 
                        stats.times.get(i));
                }
            }
        }
        
        return csvPath.toString();
    }
    
    private static String escapeCSV(String value) {
        if (value == null) return "";
        // Escape quotes and handle special characters
        return value.replace("\"", "\"\"");
    }

    private static IPFSService initializeIPFS() {
        String ipfsUrl = System.getenv("IPFS_URL");
        if (ipfsUrl != null && !ipfsUrl.isBlank()) {
            return new IPFSService(ipfsUrl);
        }
        return new IPFSService("127.0.0.1", 5001);
    }
}
