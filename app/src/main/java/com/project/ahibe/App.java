package com.project.ahibe;

import com.project.ahibe.core.HolderService;
import com.project.ahibe.core.IssuerService;
import com.project.ahibe.core.PkgService;
import com.project.ahibe.core.RevocationRecord;
import com.project.ahibe.core.VerifierService;
import com.project.ahibe.crypto.AhibeService;
import com.project.ahibe.eth.DeploymentRegistry;
import com.project.ahibe.eth.RevocationListClient;
import com.project.ahibe.io.LocalFileStorageFetcher;
import com.project.ahibe.io.RevocationRecordWriter;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;

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
        System.out.printf("Derived storage pointer (simulated CID): %s%n", record.storagePointer());

        Path storageDir = Paths.get("storage");
        try {
            Files.createDirectories(storageDir);
            Path blob = storageDir.resolve(record.storagePointer() + ".bin");
            Files.write(
                    blob,
                    record.ciphertext(),
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING,
                    StandardOpenOption.WRITE
            );
            System.out.printf("Ciphertext blob exported to: %s%n", blob.toAbsolutePath());
        } catch (IOException e) {
            throw new RuntimeException("Failed to persist ciphertext blob", e);
        }
        LocalFileStorageFetcher storageFetcher = new LocalFileStorageFetcher(storageDir);

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
                verifier.fetchPointer(client, holderId, epoch).ifPresent(pointer -> {
                    System.out.printf(
                            "On-chain pointer matches local ciphertext: %s%n",
                            verifier.matchesPointer(record, pointer) ? "YES" : "NO"
                    );
                });

                verifier.fetchAndDecapsulate(client, storageFetcher, epochKey, holderId, epoch)
                        .ifPresent(onChainRecovered -> System.out.printf(
                                "On-chain decapsulation matches session key: %s%n",
                                Arrays.equals(onChainRecovered, record.sessionKey()) ? "YES" : "NO"
                        ));
            } catch (Exception e) {
                System.err.println("Failed to verify on-chain pointer or ciphertext: " + e.getMessage());
            }
        });
    }
}
