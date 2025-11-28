package com.project.ahibe.core;

import com.project.ahibe.crypto.AhibeService;
import com.project.ahibe.crypto.bls12.BLS12SecretKey;
import com.project.ahibe.ipfs.IPFSService;
import com.project.ahibe.io.StoragePointer;

import java.io.IOException;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Issuer interacts with PKG outputs to mint credentials and publish revocations.
 * 
 * SCOR-AHIBE Principle: 1 on-chain key = 1 off-chain file.
 * Each holder has exactly one ciphertext file on IPFS with direct CID pointer.
 */
public class IssuerService {
    private final AhibeService ahibeService;
    private final AhibeService.SetupResult setup;
    private final Optional<IPFSService> ipfsService;

    public IssuerService(AhibeService ahibeService, AhibeService.SetupResult setup) {
        this.ahibeService = ahibeService;
        this.setup = setup;
        this.ipfsService = Optional.empty();
    }

    public IssuerService(AhibeService ahibeService, AhibeService.SetupResult setup, IPFSService ipfsService) {
        this.ahibeService = ahibeService;
        this.setup = setup;
        this.ipfsService = Optional.of(ipfsService);
    }

    public BLS12SecretKey issueRootKey(String holderId) {
        Objects.requireNonNull(holderId, "holderId must not be null");
        return ahibeService.keyGen(setup, List.of(holderId));
    }

    public RevocationRecord publishRevocation(String holderId, String epoch) {
        RevocationRecord raw = buildRevocationRecord(holderId, epoch);
        String pointer = ipfsService.map(service -> {
            try {
                return service.uploadRevocationCertificate(raw.ciphertext());
            } catch (IOException e) {
                throw new IllegalStateException("Failed to upload revocation certificate to IPFS", e);
            }
        }).orElse(StoragePointer.deriveCid(raw.ciphertext()));

        return raw.withStoragePointer(pointer);
    }

    public RevocationRecord buildRevocationRecord(String holderId, String epoch) {
        Objects.requireNonNull(holderId, "holderId must not be null");
        Objects.requireNonNull(epoch, "epoch must not be null");

        var encapsulation = ahibeService.encapsulate(setup.publicKey(), List.of(holderId, epoch));

        return new RevocationRecord(
                holderId,
                epoch,
                encapsulation.sessionKey(),
                encapsulation.ciphertext(),
                StoragePointer.deriveCid(encapsulation.ciphertext())
        );
    }

    public AhibeService.SetupResult setup() {
        return setup;
    }
}
