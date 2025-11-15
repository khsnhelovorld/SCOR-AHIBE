package com.project.ahibe;

import com.project.ahibe.core.HolderService;
import com.project.ahibe.core.IssuerService;
import com.project.ahibe.core.PkgService;
import com.project.ahibe.core.VerifierService;
import com.project.ahibe.crypto.AhibeService;
import com.project.ahibe.eth.DeploymentMetadata;
import com.project.ahibe.eth.DeploymentRegistry;
import com.project.ahibe.eth.RevocationListClient;
import com.project.ahibe.io.KeySerializer;
import com.project.ahibe.ipfs.IPFSService;
import com.project.ahibe.ipfs.IPFSStorageFetcher;
import it.unisa.dia.gas.crypto.jpbc.fe.ibe.dip10.params.AHIBEDIP10PublicKeyParameters;
import it.unisa.dia.gas.crypto.jpbc.fe.ibe.dip10.params.AHIBEDIP10SecretKeyParameters;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;

/**
 * Combined Demo Application: Runs Holder and Verifier in the same JVM process.
 * This demonstrates the complete flow with in-memory key storage.
 * 
 * Usage: java DemoApp <holderId> <epoch>
 * Example: java DemoApp holder:alice@example.com 2025-10-30
 */
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
