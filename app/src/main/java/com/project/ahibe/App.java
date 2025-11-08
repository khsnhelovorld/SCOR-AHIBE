package com.project.ahibe;

import com.project.ahibe.core.HolderService;
import com.project.ahibe.core.IssuerService;
import com.project.ahibe.core.PkgService;
import com.project.ahibe.core.RevocationRecord;
import com.project.ahibe.core.VerifierService;
import com.project.ahibe.crypto.AhibeService;
import com.project.ahibe.eth.DeploymentRegistry;
import com.project.ahibe.eth.RevocationListClient;
import com.project.ahibe.io.RevocationRecordWriter;

import java.util.Arrays;
import java.nio.file.Path;
import java.nio.file.Paths;

public class App {
    public static void main(String[] args) {
        AhibeService ahibeService = new AhibeService(160, 3);

        PkgService pkg = new PkgService(ahibeService);
        var setup = pkg.bootstrap();

        IssuerService issuer = new IssuerService(ahibeService, setup);
        HolderService holder = new HolderService(ahibeService, setup.publicKey());
        VerifierService verifier = new VerifierService(ahibeService);

        String holderId = "holder:alice@example.com";
        String epoch = "2025-10-30";

        var rootKey = issuer.issueRootKey(holderId);
        var epochKey = holder.deriveEpochKey(rootKey, epoch);
        RevocationRecord record = issuer.publishRevocation(holderId, epoch);

        byte[] recovered = verifier.decapsulate(epochKey, record.ciphertext());

        System.out.printf("Recovered session key matches: %s%n",
                Arrays.equals(record.sessionKey(), recovered) ? "YES" : "NO");
        System.out.printf("Ciphertext length (bytes): %d%n", record.ciphertext().length);

        RevocationRecordWriter writer = new RevocationRecordWriter(Paths.get("outbox"));
        try {
            Path output = writer.write(record);
            System.out.printf("Revocation material exported to: %s%n", output.toAbsolutePath());
        } catch (Exception e) {
            throw new RuntimeException("Failed to export revocation record", e);
        }

        DeploymentRegistry registry = new DeploymentRegistry(Paths.get("deployments"));
        registry.load("hardhat").ifPresent(deployment -> {
            String rpcUrl = System.getenv().getOrDefault("ETH_RPC_URL", "http://127.0.0.1:8545");
            try (RevocationListClient client = new RevocationListClient(rpcUrl, deployment.address())) {
                verifier.fetchAndDecapsulate(client, epochKey, holderId, epoch)
                        .ifPresent(chainRecovered -> System.out.printf(
                                "On-chain decapsulation matches: %s%n",
                                Arrays.equals(chainRecovered, record.sessionKey()) ? "YES" : "NO"
                        ));
            } catch (Exception e) {
                System.err.println("Failed to verify on-chain revocation: " + e.getMessage());
            }
        });
    }
}
