package com.project.ahibe.core;

import com.project.ahibe.crypto.AhibeService;
import com.project.ahibe.ipfs.IPFSService;
import com.project.ahibe.io.StoragePointer;
import it.unisa.dia.gas.crypto.jpbc.fe.ibe.dip10.params.AHIBEDIP10SecretKeyParameters;

import java.io.IOException;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Issuer interacts with PKG outputs to mint credentials and publish revocations.
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

    public AHIBEDIP10SecretKeyParameters issueRootKey(String holderId) {
        Objects.requireNonNull(holderId, "holderId must not be null");
        return ahibeService.keyGen(setup, List.of(holderId));
    }

    public RevocationRecord publishRevocation(String holderId, String epoch) {
        Objects.requireNonNull(holderId, "holderId must not be null");
        Objects.requireNonNull(epoch, "epoch must not be null");

        var encapsulation = ahibeService.encapsulate(setup.publicKey(), List.of(holderId, epoch));
        String storagePointer;

        // If IPFS service is available, upload revocation certificate and get real CID
        if (ipfsService.isPresent()) {
            try {
                String cid = ipfsService.get().uploadRevocationCertificate(encapsulation.ciphertext());
                storagePointer = cid;
            } catch (IOException e) {
                throw new IllegalStateException("Failed to upload revocation certificate to IPFS", e);
            }
        } else {
            // Fallback to simulated CID if IPFS is not configured
            storagePointer = StoragePointer.deriveCid(encapsulation.ciphertext());
        }

        return new RevocationRecord(holderId, epoch, encapsulation.sessionKey(), encapsulation.ciphertext(), storagePointer);
    }

    public AhibeService.SetupResult setup() {
        return setup;
    }
}

