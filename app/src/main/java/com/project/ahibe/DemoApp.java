/** 
package com.project.ahibe;

import com.project.ahibe.core.HolderService;
import com.project.ahibe.core.IssuerService;
import com.project.ahibe.core.PkgService;
import com.project.ahibe.core.VerifierService;
import com.project.ahibe.crypto.AhibeService;
import com.project.ahibe.eth.DeploymentRegistry;
import com.project.ahibe.eth.RevocationListClient;
import com.project.ahibe.ipfs.IPFSService;
import com.project.ahibe.ipfs.IPFSStorageFetcher;
import it.unisa.dia.gas.crypto.jpbc.fe.ibe.dip10.params.AHIBEDIP10PublicKeyParameters;
import it.unisa.dia.gas.crypto.jpbc.fe.ibe.dip10.params.AHIBEDIP10SecretKeyParameters;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;

public class DemoApp {
    public static void main(String[] args) {
        try {
            if (args.length < 2) {
                System.err.println("Usage: java DemoApp <holderId> <epoch>");
                System.err.println("Example: java DemoApp holder:alice@example.com 2025-10-30");
                System.exit(1);
            }

            String holderId = args[0];
            String epoch = args[1];

            System.out.println("╔════════════════════════════════════════════════════════════════╗");
            System.out.println("║              DEMO APPLICATION - Complete Flow                  ║");
            System.out.println("║         Holder → Delegate Key → Verifier (Same JVM)           ║");
            System.out.println("╚════════════════════════════════════════════════════════════════╝");
            System.out.println();
            
            // ==================== PART 1: HOLDER ====================
            System.out.println("═══════════════════════════════════════════════════════════════");
            System.out.println("PART 1: HOLDER - Generate Delegate Key");
            System.out.println("═══════════════════════════════════════════════════════════════");
            System.out.println();
            System.out.println("Holder ID: " + holderId);
            System.out.println("Epoch:     " + epoch);
            System.out.println();

            // Initialize AHIBE service
            System.out.println("[1/5] Initializing AHIBE cryptographic service...");
            AhibeService ahibeService = new AhibeService(160, 3);
            System.out.println("      ✓ AHIBE service initialized (160-bit security, depth 3)");

            // Bootstrap PKG
            System.out.println();
            System.out.println("[2/5] Bootstrapping PKG and obtaining public parameters...");
            PkgService pkg = new PkgService(ahibeService);
            AhibeService.SetupResult setup = pkg.bootstrap();
            AHIBEDIP10PublicKeyParameters publicKey = setup.publicKey();
            System.out.println("      ✓ PKG bootstrapped, public parameters obtained");

            // Get root key from Issuer
            System.out.println();
            System.out.println("[3/5] Requesting root key from Issuer...");
            IssuerService issuer = new IssuerService(ahibeService, setup);
            AHIBEDIP10SecretKeyParameters rootKey = issuer.issueRootKey(holderId);
            System.out.println("      ✓ Root key (SK_H) received from Issuer");

            // Holder derives delegate key
            System.out.println();
            System.out.println("[4/5] Deriving epoch-specific delegate key...");
            HolderService holder = new HolderService(ahibeService, publicKey);
            AHIBEDIP10SecretKeyParameters delegateKey = holder.deriveEpochKey(rootKey, epoch);
            System.out.println("      ✓ Delegate key (SK_{H||T}) derived for epoch: " + epoch);

            // Export delegate key
            System.out.println();
            System.out.println("[5/5] Exporting delegate key to file...");
            Path outputDir = Paths.get("outbox");
            String fileName = "delegate_key_" + sanitize(holderId) + "_" + sanitize(epoch) + ".key";
            Path outputPath = outputDir.resolve(fileName);
            KeySerializer.exportDelegateKey(delegateKey, outputPath);
            System.out.println("      ✓ Delegate key exported (in-memory storage)");

            System.out.println();
            System.out.println("✓ HOLDER COMPLETED - Delegate key ready in memory");
            
            // Small pause for visual separation
            System.out.println();
            System.out.println("Press Enter to continue to Verifier part...");
            System.in.read();
            
            // ==================== PART 2: VERIFIER ====================
            System.out.println();
            System.out.println("═══════════════════════════════════════════════════════════════");
            System.out.println("PART 2: VERIFIER - Verify Revocation Status");
            System.out.println("═══════════════════════════════════════════════════════════════");
            System.out.println();

            // Import delegate key (from in-memory storage in same JVM)
            System.out.println("[1/6] Importing delegate key from Holder...");
            AHIBEDIP10SecretKeyParameters importedKey = KeySerializer.importDelegateKey(outputPath, publicKey);
            System.out.println("      ✓ Delegate key imported from in-memory storage");
            System.out.println("      ℹ Same JVM process - key still in memory!");

            // Initialize IPFS
            System.out.println();
            System.out.println("[2/6] Connecting to IPFS node...");
            IPFSService ipfsService = initializeIPFS();
            if (ipfsService == null) {
                System.err.println("      ✗ IPFS service not available. Cannot verify.");
                System.exit(1);
            }
            System.out.println("      ✓ IPFS node is available and responding");

            // Initialize blockchain client
            System.out.println();
            System.out.println("[3/6] Connecting to blockchain network...");
            String network = System.getenv().getOrDefault("NETWORK", "hardhat");
            String rpcUrl = System.getenv().getOrDefault("ETH_RPC_URL", "http://127.0.0.1:8545");

            // Use absolute path or parent directory to find deployments folder
            Path deploymentsPath = Paths.get("deployments");
            if (!deploymentsPath.toFile().exists()) {
                // Try parent directory (when running from app/ folder)
                deploymentsPath = Paths.get("..").resolve("deployments");
            }
            DeploymentRegistry registry = new DeploymentRegistry(deploymentsPath);
            Optional<DeploymentMetadata> deployment = registry.load(network);

            if (deployment.isEmpty()) {
                System.err.println("      ✗ No deployment found for network: " + network);
                System.err.println("      Please run: npm run hardhat:deploy:local");
                System.exit(1);
            }

            String contractAddress = deployment.get().address();
            System.out.println("      ✓ Connected to network: " + network);
            System.out.println("      ✓ Using contract at: " + contractAddress);

            // Query blockchain
            System.out.println();
            System.out.println("[4/6] Querying blockchain for revocation record...");
            try (RevocationListClient client = new RevocationListClient(rpcUrl, contractAddress)) {
                VerifierService verifier = new VerifierService(ahibeService);
                Optional<String> cidOpt = verifier.fetchPointer(client, holderId, epoch);

                if (cidOpt.isEmpty()) {
                    System.out.println("      ℹ No revocation record found on blockchain");
                    System.out.println();
                    System.out.println("╔════════════════════════════════════════════════════════════════╗");
                    System.out.println("║                  VERIFICATION RESULT: NOT REVOKED              ║");
                    System.out.println("╚════════════════════════════════════════════════════════════════╝");
                    System.out.println();
                    System.out.println("⚠ Possible reasons:");
                    System.out.println("  1. Revocation was never published to this contract");
                    System.out.println("  2. Hardhat node was restarted (contract state lost)");
                    System.out.println("  3. Different contract address or network");
                    System.out.println();
                    System.out.println("To fix:");
                    System.out.println("  1. Ensure Hardhat node is still running from deployment/publish time");
                    System.out.println("  2. Or republish the revocation:");
                    System.out.println("     $env:RECORD_PATH=\"app/outbox/holder_alice_example_com__2025-10-30.json\"");
                    System.out.println("     npm run hardhat:publish");
                    System.out.println("  3. Or check contract state:");
                    System.out.println("     npm run hardhat:check");
                    return;
                }

                String cid = cidOpt.get();
                System.out.println("      ✓ Found revocation CID: " + cid);

                // Download from IPFS
                System.out.println();
                System.out.println("[5/6] Downloading ciphertext from IPFS...");
                IPFSStorageFetcher fetcher = new IPFSStorageFetcher(ipfsService);
                Optional<byte[]> ciphertextOpt = fetcher.fetch(cid);

                if (ciphertextOpt.isEmpty()) {
                    System.err.println("      ✗ Failed to download from IPFS");
                    System.exit(1);
                }

                byte[] ciphertext = ciphertextOpt.get();
                System.out.println("      ✓ Downloaded ciphertext (" + ciphertext.length + " bytes)");

                // Decrypt
                System.out.println();
                System.out.println("[6/6] Decrypting with delegate key...");
                byte[] sessionKey = verifier.decapsulate(importedKey, ciphertext);
                System.out.println("      ✓ Successfully decrypted!");
                System.out.println("      Session key: " + bytesToHex(sessionKey));

                System.out.println();
                System.out.println("╔════════════════════════════════════════════════════════════════╗");
                System.out.println("║                   VERIFICATION RESULT: REVOKED                 ║");
                System.out.println("╚════════════════════════════════════════════════════════════════╝");
                System.out.println();
                System.out.println("Status:        REVOKED");
                System.out.println("Holder:        " + holderId);
                System.out.println("Epoch:         " + epoch);
                System.out.println("CID:           " + cid);
                System.out.println("Verification:  SUCCESS - Delegate key decrypted the certificate");
                System.out.println();
            }

        } catch (Exception e) {
            System.err.println();
            System.err.println("╔════════════════════════════════════════════════════════════════╗");
            System.err.println("║                          ERROR                                 ║");
            System.err.println("╚════════════════════════════════════════════════════════════════╝");
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static IPFSService initializeIPFS() {
        String ipfsHost = System.getenv("IPFS_HOST");
        String ipfsPort = System.getenv("IPFS_PORT");
        String ipfsUrl = System.getenv("IPFS_URL");

        IPFSService ipfsService;
        if (ipfsUrl != null && !ipfsUrl.isBlank()) {
            ipfsService = new IPFSService(ipfsUrl);
        } else if (ipfsHost != null && !ipfsHost.isBlank()) {
            int port = ipfsPort != null ? Integer.parseInt(ipfsPort) : 5001;
            ipfsService = new IPFSService(ipfsHost, port);
        } else {
            ipfsService = new IPFSService("127.0.0.1", 5001);
        }

        return ipfsService.isAvailable() ? ipfsService : null;
    }

    private static String sanitize(String input) {
        return input.replaceAll("[^a-zA-Z0-9-_.]", "_");
    }

    private static String bytesToHex(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return "(empty)";
        StringBuilder result = new StringBuilder();
        int limit = Math.min(16, bytes.length);
        for (int i = 0; i < limit; i++) {
            result.append(String.format("%02x", bytes[i]));
        }
        if (bytes.length > 16) result.append("...");
        return result.toString();
    }
}
*/

package com.project.ahibe;

import com.project.ahibe.core.HolderService;
import com.project.ahibe.core.IssuerService;
import com.project.ahibe.core.PkgService;
import com.project.ahibe.core.VerifierService;
import com.project.ahibe.crypto.AhibeService;
import com.project.ahibe.eth.DeploymentRegistry;
import com.project.ahibe.eth.RevocationListClient;
import com.project.ahibe.ipfs.IPFSService;
import com.project.ahibe.ipfs.IPFSStorageFetcher;
import it.unisa.dia.gas.crypto.jpbc.fe.ibe.dip10.params.AHIBEDIP10PublicKeyParameters;
import it.unisa.dia.gas.crypto.jpbc.fe.ibe.dip10.params.AHIBEDIP10SecretKeyParameters;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Demo Application with BENCHMARKING (1000 iterations)
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
    static final int ITERATIONS = 1000;

    public static void main(String[] args) {
        try {
            if (args.length < 2) {
                System.err.println("Usage: java DemoApp <holderId> <epoch>");
                System.err.println("Example: java DemoApp holder:alice@example.com 2025-10-30");
                System.exit(1);
            }

            String holderId = args[0];
            String epoch = args[1];

            System.out.println("==========================================================================================");
            System.out.println("         SCOR-AHIBE BENCHMARK RUNNER (1000 iterations)         ");
            System.out.println("==========================================================================================");
            System.out.println();
            System.out.println("Holder ID: " + holderId);
            System.out.println("Epoch:     " + epoch);
            System.out.println("Iterations: " + ITERATIONS);
            System.out.println();

            // ==================== ONE-TIME SETUP ====================
            System.out.println("[Setup] Initializing system (one-time)...");
            long tStart = System.nanoTime();
            AhibeService ahibeService = new AhibeService(160, 3);
            double setupTime = (System.nanoTime() - tStart) / 1_000_000.0;
            System.out.printf("   -> System Setup: %.4f ms (one-time)%n", setupTime);

            tStart = System.nanoTime();
            PkgService pkg = new PkgService(ahibeService);
            AhibeService.SetupResult setup = pkg.bootstrap();
            AHIBEDIP10PublicKeyParameters publicKey = setup.publicKey();
            double pkgTime = (System.nanoTime() - tStart) / 1_000_000.0;
            System.out.printf("   -> PKG Bootstrap: %.4f ms (one-time)%n", pkgTime);

            tStart = System.nanoTime();
            IssuerService issuer = new IssuerService(ahibeService, setup);
            AHIBEDIP10SecretKeyParameters rootKey = issuer.issueRootKey(holderId);
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
            String cid;
            byte[] ciphertext;
            try (RevocationListClient client = new RevocationListClient(rpcUrl, contractAddress)) {
                VerifierService verifierService = new VerifierService(ahibeService);
                Optional<String> cidOpt = verifierService.fetchPointer(client, holderId, epoch);
                if (cidOpt.isEmpty()) throw new RuntimeException("CID not found on chain");
                cid = cidOpt.get();
                
                IPFSStorageFetcher fetcher = new IPFSStorageFetcher(ipfsService);
                ciphertext = fetcher.fetch(cid).orElseThrow();
            }

            // ==================== BENCHMARK LOOP ====================
            System.out.println();
            System.out.println("[Benchmark] Running " + ITERATIONS + " iterations...");
            System.out.println("Progress: ");

            for (int i = 0; i < ITERATIONS; i++) {
                // Holder: Delegate Key Generation
                tStart = System.nanoTime();
                AHIBEDIP10SecretKeyParameters delegateKey = holder.deriveEpochKey(rootKey, epoch);
                recordTime("Holder: Delegate Key Gen", tStart, "Derive SK_{H||Epoch} (Off-chain)");

                // Verifier: Query Blockchain
                tStart = System.nanoTime();
                try (RevocationListClient client = new RevocationListClient(rpcUrl, contractAddress)) {
                    VerifierService verifierService = new VerifierService(ahibeService);
                    verifierService.fetchPointer(client, holderId, epoch);
                }
                recordTime("Verifier: Query Blockchain", tStart, "Get CID (View call)");

                // Verifier: Fetch IPFS
                tStart = System.nanoTime();
                IPFSStorageFetcher fetcher = new IPFSStorageFetcher(ipfsService);
                fetcher.fetch(cid);
                recordTime("Verifier: Fetch IPFS", tStart, "Download Ciphertext (" + ciphertext.length + " bytes)");

                // Verifier: Decrypt
                tStart = System.nanoTime();
                VerifierService verifierService = new VerifierService(ahibeService);
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
        System.out.println("|                    SCOR-AHIBE PERFORMANCE REPORT (1000 iterations)                    |");
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

    private static IPFSService initializeIPFS() {
        String ipfsUrl = System.getenv("IPFS_URL");
        if (ipfsUrl != null && !ipfsUrl.isBlank()) {
            return new IPFSService(ipfsUrl);
        }
        return new IPFSService("127.0.0.1", 5001);
    }
}