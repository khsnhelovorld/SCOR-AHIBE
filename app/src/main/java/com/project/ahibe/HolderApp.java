package com.project.ahibe;

import com.project.ahibe.core.HolderService;
import com.project.ahibe.core.IssuerService;
import com.project.ahibe.core.PkgService;
import com.project.ahibe.crypto.AhibeService;
import com.project.ahibe.io.KeySerializer;
import it.unisa.dia.gas.crypto.jpbc.fe.ibe.dip10.params.AHIBEDIP10SecretKeyParameters;

import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Holder application: receives root key from Issuer, derives epoch key, and exports delegate key.
 * 
 * This application simulates the Holder's role in the AHIBE hierarchy:
 * 1. Receive root key from Issuer (SK_H for holder identity)
 * 2. Derive epoch-specific delegate key (SK_{H||epoch})
 * 3. Export delegate key to file for secure transfer to Verifier
 * 
 * Usage: java HolderApp <holderId> <epoch>
 * Example: java HolderApp holder:alice@example.com 2025-10-30
 */
public class HolderApp {
    public static void main(String[] args) {
        try {
            if (args.length < 2) {
                System.err.println("Usage: java HolderApp <holderId> <epoch>");
                System.err.println("Example: java HolderApp holder:alice@example.com 2025-10-30");
                System.exit(1);
            }

            String holderId = args[0];
            String epoch = args[1];

            System.out.println("╔════════════════════════════════════════════════════════════════╗");
            System.out.println("║            HOLDER APPLICATION - AHIBE Key Derivation          ║");
            System.out.println("╚════════════════════════════════════════════════════════════════╝");
            System.out.println();
            System.out.println("Holder ID: " + holderId);
            System.out.println("Epoch:     " + epoch);
            System.out.println();

            // Initialize AHIBE service (same parameters as PKG/Issuer)
            System.out.println("[1/5] Initializing AHIBE cryptographic service...");
            AhibeService ahibeService = new AhibeService(160, 3);
            System.out.println("      ✓ AHIBE service initialized (160-bit security, depth 3)");

            // In production, Holder would receive setup.publicKey from PKG via secure channel
            // For demo, we bootstrap here
            System.out.println();
            System.out.println("[2/5] Bootstrapping PKG and obtaining public parameters...");
            PkgService pkg = new PkgService(ahibeService);
            var setup = pkg.bootstrap();
            System.out.println("      ✓ PKG bootstrapped, public parameters obtained");

            // In production, Holder would receive rootKey from Issuer via secure channel
            // For demo, we generate it here
            System.out.println();
            System.out.println("[3/5] Requesting root key from Issuer...");
            IssuerService issuer = new IssuerService(ahibeService, setup);
            AHIBEDIP10SecretKeyParameters rootKey = issuer.issueRootKey(holderId);
            System.out.println("      ✓ Root key (SK_H) received from Issuer");
            System.out.println("      ℹ In production, this key would be transmitted via secure channel");

            // Holder derives epoch-specific delegate key
            System.out.println();
            System.out.println("[4/5] Deriving epoch-specific delegate key...");
            HolderService holder = new HolderService(ahibeService, setup.publicKey());
            AHIBEDIP10SecretKeyParameters delegateKey = holder.deriveEpochKey(rootKey, epoch);
            System.out.println("      ✓ Delegate key (SK_{H||T}) derived for epoch: " + epoch);
            System.out.println("      ℹ This demonstrates AHIBE hierarchical key derivation");

            // Export delegate key to file for Verifier
            System.out.println();
            System.out.println("[5/5] Exporting delegate key to file...");
            Path outputDir = Paths.get("outbox");
            String fileName = "delegate_key_" + sanitize(holderId) + "_" + sanitize(epoch) + ".key";
            Path outputPath = outputDir.resolve(fileName);

            KeySerializer.exportDelegateKey(delegateKey, outputPath);
            System.out.println("      ✓ Delegate key exported to: " + outputPath.toAbsolutePath());

            System.out.println();
            System.out.println("╔════════════════════════════════════════════════════════════════╗");
            System.out.println("║                    SUCCESS - Key Generated                     ║");
            System.out.println("╚════════════════════════════════════════════════════════════════╝");
            System.out.println();
            System.out.println("Next Steps:");
            System.out.println("  1. Securely transmit the delegate key file to Verifier");
            System.out.println("  2. Verifier can use this key to check revocation status");
            System.out.println("  3. The key is valid only for the specific epoch: " + epoch);
            System.out.println();
            System.out.println("Security Notes:");
            System.out.println("  • The delegate key can only decrypt revocations for this holder+epoch");
            System.out.println("  • If compromised, only affects this specific epoch");
            System.out.println("  • Root key remains secure with the Holder");
            System.out.println();

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
     * Sanitize input string to create safe filenames
     */
    private static String sanitize(String input) {
        return input.replaceAll("[^a-zA-Z0-9-_.]", "_");
    }
}
