package com.project.ahibe;

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
 * Verifier application: receives delegate key from Holder, queries blockchain, 
 * downloads ciphertext from IPFS, and verifies revocation status.
 * 
 * This application demonstrates the complete verification flow:
 * 1. Import delegate key from Holder
 * 2. Query smart contract for revocation CID
 * 3. Download encrypted revocation certificate from IPFS
 * 4. Decrypt using delegate key
 * 5. Determine revocation status
 * 
 * Usage: java VerifierApp <delegateKeyPath> <holderId> <epoch>
 * Example: java VerifierApp outbox/delegate_key_holder_alice_example_com_2025-10-30.key holder:alice@example.com 2025-10-30
 */
public class VerifierApp {
    public static void main(String[] args) {
        try {
            if (args.length < 3) {
                System.err.println("Usage: java VerifierApp <delegateKeyPath> <holderId> <epoch>");
                System.err.println("Example: java VerifierApp outbox/delegate_key_holder_alice_example_com_2025-10-30.key holder:alice@example.com 2025-10-30");
                System.exit(1);
            }

            Path delegateKeyPath = Paths.get(args[0]);
            String holderId = args[1];
            String epoch = args[2];

            System.out.println("╔════════════════════════════════════════════════════════════════╗");
            System.out.println("║         VERIFIER APPLICATION - Revocation Status Check        ║");
            System.out.println("╚════════════════════════════════════════════════════════════════╝");
            System.out.println();
            System.out.println("Delegate Key: " + delegateKeyPath);
            System.out.println("Holder ID:    " + holderId);
            System.out.println("Epoch:        " + epoch);
            System.out.println();

            // Initialize AHIBE service
            System.out.println("[1/7] Initializing AHIBE cryptographic service...");
            AhibeService ahibeService = new AhibeService(160, 3);
            System.out.println("      ✓ AHIBE service initialized");

            // In production, Verifier would receive publicKey from PKG
            // For demo, we bootstrap here to get public parameters
            System.out.println();
            System.out.println("[2/7] Obtaining public parameters from PKG...");
            PkgService pkg = new PkgService(ahibeService);
            AhibeService.SetupResult setup = pkg.bootstrap();
            AHIBEDIP10PublicKeyParameters publicKey = setup.publicKey();
            System.out.println("      ✓ Public parameters obtained");

            // Import delegate key from Holder
            System.out.println();
            System.out.println("[3/7] Importing delegate key from Holder...");
            AHIBEDIP10SecretKeyParameters delegateKey = KeySerializer.importDelegateKey(delegateKeyPath, publicKey);
            System.out.println("      ✓ Delegate key imported successfully");
            System.out.println("      ℹ This key can only decrypt revocations for: " + holderId + " || " + epoch);

            // Initialize IPFS service
            System.out.println();
            System.out.println("[4/7] Connecting to IPFS node...");
            IPFSService ipfsService = initializeIPFS();
            if (ipfsService == null) {
                System.err.println("      ✗ IPFS service not available. Cannot verify.");
                System.err.println();
                System.err.println("Please ensure IPFS Desktop is running or IPFS daemon is active.");
                System.err.println("You can start IPFS with: ipfs daemon");
                System.exit(1);
            }
            System.out.println("      ✓ IPFS node is available and responding");

            // Initialize blockchain client
            System.out.println();
            System.out.println("[5/7] Connecting to blockchain network...");
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
                System.err.println();
                System.err.println("Please deploy the smart contract first:");
                System.err.println("  npm run hardhat:deploy:local");
                System.exit(1);
            }

            String contractAddress = deployment.get().address();
            System.out.println("      ✓ Connected to network: " + network);
            System.out.println("      ✓ Using contract at: " + contractAddress);

            // Query blockchain for CID
            System.out.println();
            System.out.println("[6/7] Querying blockchain for revocation record...");
            try (RevocationListClient client = new RevocationListClient(rpcUrl, contractAddress)) {
                VerifierService verifier = new VerifierService(ahibeService);

                VerifierService.VerificationResult verification = verifier.verifyRevocation(client, holderId, epoch);

                if (verification.isValid()) {
                    System.out.println("      ℹ " + verification.message());
                    System.out.println();
                    System.out.println("╔════════════════════════════════════════════════════════════════╗");
                    System.out.println("║                  VERIFICATION RESULT: NOT REVOKED              ║");
                    System.out.println("╚════════════════════════════════════════════════════════════════╝");
                    System.out.println();
                    System.out.println("Status:    NOT REVOKED");
                    System.out.println("Holder:    " + holderId);
                    System.out.println("Epoch:     " + epoch);
                    System.out.println("Reason:    " + verification.message());
                    System.out.println();
                    return;
                }

                String cid = Optional.ofNullable(verification.pointer())
                        .filter(ptr -> !ptr.isBlank())
                        .orElseThrow(() -> new IllegalStateException("Revocation record missing storage pointer"));
                System.out.println("      ✓ Found revocation CID on blockchain: " + cid);

                // Download ciphertext from IPFS
                System.out.println();
                System.out.println("[7/7] Downloading and decrypting revocation certificate...");
                IPFSStorageFetcher fetcher = new IPFSStorageFetcher(ipfsService);
                Optional<byte[]> ciphertextOpt = fetcher.fetch(cid);

                if (ciphertextOpt.isEmpty()) {
                    System.err.println("      ✗ Failed to download ciphertext from IPFS");
                    System.err.println("      CID: " + cid);
                    System.err.println();
                    System.err.println("The revocation record exists on blockchain but is not available on IPFS.");
                    System.err.println("This could mean:");
                    System.err.println("  • IPFS node doesn't have the content");
                    System.err.println("  • Content has not propagated through the network");
                    System.err.println("  • CID is invalid or corrupted");
                    System.exit(1);
                }

                byte[] ciphertext = ciphertextOpt.get();
                System.out.println("      ✓ Downloaded ciphertext from IPFS (" + ciphertext.length + " bytes)");

                // Decrypt using delegate key
                System.out.println("      ⏳ Decrypting with delegate key...");
                byte[] sessionKey = verifier.decapsulate(delegateKey, ciphertext);
                System.out.println("      ✓ Successfully decrypted revocation certificate");
                System.out.println("      ℹ Session key (first 16 bytes): " + bytesToHex(sessionKey));

                System.out.println();
                System.out.println("╔════════════════════════════════════════════════════════════════╗");
                System.out.println("║                   VERIFICATION RESULT: REVOKED                 ║");
                System.out.println("╚════════════════════════════════════════════════════════════════╝");
                System.out.println();
                System.out.println("Status:        REVOKED");
                System.out.println("Holder:        " + holderId);
                System.out.println("Epoch:         " + epoch);
                System.out.println("CID:           " + cid);
                System.out.println("Verification:  SUCCESS - Delegate key successfully decrypted the certificate");
                System.out.println();
                System.out.println("Interpretation:");
                System.out.println("  • A revocation certificate exists on blockchain for this holder+epoch");
                System.out.println("  • The certificate was successfully downloaded from IPFS");
                System.out.println("  • The delegate key correctly decrypted the certificate");
                System.out.println("  • This proves the holder's credential for this epoch is REVOKED");
                System.out.println();

            } catch (Exception e) {
                System.err.println("      ✗ Error during verification: " + e.getMessage());
                throw e;
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

    /**
     * Initialize IPFS service with environment variables or defaults
     */
    private static IPFSService initializeIPFS() {
        String ipfsHost = System.getenv("IPFS_HOST");
        String ipfsPort = System.getenv("IPFS_PORT");
        String ipfsUrl = System.getenv("IPFS_URL");

        IPFSService ipfsService;
        if (ipfsUrl != null && !ipfsUrl.isBlank()) {
            ipfsService = new IPFSService(ipfsUrl);
            System.out.println("      Using IPFS URL: " + ipfsUrl);
        } else if (ipfsHost != null && !ipfsHost.isBlank()) {
            int port = ipfsPort != null ? Integer.parseInt(ipfsPort) : 5001;
            ipfsService = new IPFSService(ipfsHost, port);
            System.out.println("      Using IPFS at " + ipfsHost + ":" + port);
        } else {
            System.out.println("      IPFS env vars not set, trying default: http://127.0.0.1:5001");
            ipfsService = new IPFSService("127.0.0.1", 5001);
        }

        if (!ipfsService.isAvailable()) {
            System.err.println("      Warning: IPFS node is not responding");
            return null;
        }

        return ipfsService;
    }

    /**
     * Convert byte array to hex string for display (truncated)
     */
    private static String bytesToHex(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "(empty)";
        }
        StringBuilder result = new StringBuilder();
        int limit = Math.min(16, bytes.length);
        for (int i = 0; i < limit; i++) {
            result.append(String.format("%02x", bytes[i]));
        }
        if (bytes.length > 16) {
            result.append("...");
        }
        return result.toString();
    }
}
