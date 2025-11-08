package com.project.ahibe.core;

import com.project.ahibe.crypto.AhibeService;
import it.unisa.dia.gas.crypto.jpbc.fe.ibe.dip10.params.AHIBEDIP10SecretKeyParameters;

import java.util.List;
import java.util.Objects;

/**
 * Issuer interacts with PKG outputs to mint credentials and publish revocations.
 */
public class IssuerService {
    private final AhibeService ahibeService;
    private final AhibeService.SetupResult setup;

    public IssuerService(AhibeService ahibeService, AhibeService.SetupResult setup) {
        this.ahibeService = ahibeService;
        this.setup = setup;
    }

    public AHIBEDIP10SecretKeyParameters issueRootKey(String holderId) {
        Objects.requireNonNull(holderId, "holderId must not be null");
        return ahibeService.keyGen(setup, List.of(holderId));
    }

    public RevocationRecord publishRevocation(String holderId, String epoch) {
        Objects.requireNonNull(holderId, "holderId must not be null");
        Objects.requireNonNull(epoch, "epoch must not be null");

        var encapsulation = ahibeService.encapsulate(setup.publicKey(), List.of(holderId, epoch));
        return new RevocationRecord(holderId, epoch, encapsulation.sessionKey(), encapsulation.ciphertext());
    }

    public AhibeService.SetupResult setup() {
        return setup;
    }
}

