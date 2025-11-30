package com.project.ahibe;

import com.project.ahibe.core.HolderService;
import com.project.ahibe.core.IssuerService;
import com.project.ahibe.core.PkgService;
import com.project.ahibe.core.RevocationRecord;
import com.project.ahibe.core.VerifierService;
import com.project.ahibe.crypto.AhibeService;
import com.project.ahibe.crypto.CryptoMetrics;
import com.project.ahibe.crypto.config.PairingProfile;
import com.project.ahibe.eth.DeploymentRegistry;
import com.project.ahibe.eth.RevocationListClient;
import com.project.ahibe.ipfs.IPFSService;
import com.project.ahibe.ipfs.IPFSStorageFetcher;
import com.project.ahibe.io.StorageFetcher;
import com.project.ahibe.io.RevocationRecordWriter;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

public class App {
    public static void main(String[] args) {
        try {
            PairingProfile profile = resolveProfile();
        AhibeService ahibeService = new AhibeService(profile, 3);
        System.out.println("Using AHIBE profile: " + profile.metadata().id() +
                " (~" + profile.estimatedSecurityBits() + "-bit security)");

        PkgService pkg = new PkgService(ahibeService);
        var setup = pkg.bootstrap();
        int publicKeySize = CryptoMetrics.estimatePublicKeySize(setup.publicKey());
        System.out.printf("Public parameter footprint: %d bytes%n", publicKeySize);

        // Initialize IPFS service if configured
        IPFSService ipfsService = null;
        String ipfsHost = System.getenv("IPFS_HOST");
        String ipfsPort = System.getenv("IPFS_PORT");
        String ipfsUrl = System.getenv("IPFS_URL");

        if (ipfsUrl != null && !ipfsUrl.isBlank()) {
            ipfsService = new IPFSService(ipfsUrl);
            System.out.println("Using IPFS URL: " + ipfsUrl);
        } else if (ipfsHost != null && !ipfsHost.isBlank()) {
            int port = ipfsPort != null ? Integer.parseInt(ipfsPort) : 5001;
            ipfsService = new IPFSService(ipfsHost, port);
            System.out.println("Using IPFS at " + ipfsHost + ":" + port);
        } else {
            System.out.println("IPFS env vars not set. Trying default http://127.0.0.1:5001 ...");
            ipfsService = new IPFSService("127.0.0.1", 5001);
        }

        // Check IPFS availability if configured
        if (ipfsService != null) {
            if (ipfsService.isAvailable()) {
                System.out.println("IPFS node is available.");
            } else {
                System.err.println("Warning: IPFS node is not available at configured/default address. Falling back to simulated CID.");
                ipfsService = null;
            }
        }

        IssuerService issuer = ipfsService != null 
            ? new IssuerService(ahibeService, setup, ipfsService)
            : new IssuerService(ahibeService, setup);
        HolderService holder = new HolderService(ahibeService, setup.publicKey());
        VerifierService verifier = new VerifierService(ahibeService);

        String holderId = "holder:alice@example.com";
        String epoch = "2025-10-30";

        var rootKey = issuer.issueRootKey(holderId);
        var epochKey = holder.deriveEpochKey(rootKey, epoch);
        
        System.out.println("Publishing revocation certificate...");
        RevocationRecord record = issuer.publishRevocation(holderId, epoch);
        System.out.printf("Revocation certificate uploaded. IPFS CID: %s%n", record.storagePointer());

        byte[] recovered = verifier.decapsulate(epochKey, record.ciphertext());

        System.out.printf("Recovered session key matches: %s%n",
                Arrays.equals(record.sessionKey(), recovered) ? "YES" : "NO");
        System.out.printf("Ciphertext length (bytes): %d | Session key length: %d%n",
                CryptoMetrics.ciphertextSize(record.ciphertext()),
                CryptoMetrics.sessionKeySize(record.sessionKey()));

        // Use IPFS fetcher if available, otherwise fallback to local file fetcher
        StorageFetcher storageFetcher;
        if (ipfsService != null) {
            storageFetcher = new IPFSStorageFetcher(ipfsService);
            System.out.println("Using IPFS storage fetcher for verification.");
        } else {
            System.err.println("Warning: IPFS not available. Cannot verify from IPFS. Please configure IPFS for full functionality.");
            storageFetcher = null;
        }

        RevocationRecordWriter writer = new RevocationRecordWriter(Paths.get("outbox"));
        try {
            Path output = writer.write(record, profile.id());
            System.out.printf("Revocation material exported to: %s%n", output.toAbsolutePath());
        } catch (Exception e) {
            throw new RuntimeException("Failed to export revocation record", e);
        }

            // Verify from blockchain and IPFS
            DeploymentRegistry registry = new DeploymentRegistry(Paths.get("deployments"));
            // Try to load deployment from supported networks (localhost or sepolia)
            String[] networks = {"hardhat", "localhost", "sepolia"};
            for (String network : networks) {
                registry.load(network).ifPresent(deployment -> {
                    String rpcUrl = System.getenv().getOrDefault("ETH_RPC_URL", 
                        network.equals("hardhat") ? "http://127.0.0.1:8545" : "");
                    if (rpcUrl.isEmpty() && !network.equals("hardhat")) {
                        System.out.println("Skipping network " + network + " - ETH_RPC_URL not set");
                        return;
                    }
                    System.out.println("Verifying from blockchain network: " + network);
                    System.out.println("Contract address: " + deployment.address());
                    try (RevocationListClient client = new RevocationListClient(rpcUrl, deployment.address())) {
                        // Use new verification logic with time comparison
                        VerifierService.VerificationResult result = verifier.verifyRevocation(client, holderId, epoch);
                        System.out.println("Verification result: " + result.message());
                        
                        if (!result.isValid() && result.pointer() != null && !result.pointer().isEmpty()) {
                            System.out.printf("On-chain pointer: %s%n", result.pointer());
                            System.out.printf(
                                    "On-chain pointer matches local CID: %s%n",
                                    record.storagePointer().equals(result.pointer()) ? "YES" : "NO"
                            );
                            
                            // Download from IPFS and verify using delegate key
                            if (storageFetcher != null) {
                                verifier.fetchAndDecapsulate(client, storageFetcher, epochKey, holderId, epoch)
                                        .ifPresent(onChainRecovered -> System.out.printf(
                                                "On-chain decapsulation (from IPFS) matches session key: %s%n",
                                                Arrays.equals(onChainRecovered, record.sessionKey()) ? "YES" : "NO"
                                        ));
                            }
                        }
                    } catch (Exception e) {
                        System.err.println("Failed to verify on-chain pointer or ciphertext: " + e.getMessage());
                    }
                });
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static PairingProfile resolveProfile() {
        // Always use BLS12-381 (AHIBE_PROFILE removed)
        return PairingProfile.BLS12_381;
    }
}
