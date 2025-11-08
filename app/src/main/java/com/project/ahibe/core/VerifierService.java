package com.project.ahibe.core;

import com.project.ahibe.crypto.AhibeService;
import com.project.ahibe.eth.RevocationListClient;
import it.unisa.dia.gas.crypto.jpbc.fe.ibe.dip10.params.AHIBEDIP10SecretKeyParameters;

import java.util.Objects;
import java.util.Optional;

/**
 * Verifier pulls ciphertext from the smart contract and checks revocation locally.
 */
public class VerifierService {
    private final AhibeService ahibeService;

    public VerifierService(AhibeService ahibeService) {
        this.ahibeService = ahibeService;
    }

    public byte[] decapsulate(AHIBEDIP10SecretKeyParameters delegatedKey, byte[] ciphertext) {
        Objects.requireNonNull(delegatedKey, "delegatedKey must not be null");
        Objects.requireNonNull(ciphertext, "ciphertext must not be null");
        return ahibeService.decapsulate(delegatedKey, ciphertext);
    }

    public Optional<byte[]> fetchAndDecapsulate(RevocationListClient client,
                                                AHIBEDIP10SecretKeyParameters delegatedKey,
                                                String holderId,
                                                String epoch) {
        Objects.requireNonNull(client, "client must not be null");
        Objects.requireNonNull(delegatedKey, "delegatedKey must not be null");
        Objects.requireNonNull(holderId, "holderId must not be null");
        Objects.requireNonNull(epoch, "epoch must not be null");

        return client.fetchCiphertext(holderId, epoch)
                .map(ciphertext -> ahibeService.decapsulate(delegatedKey, ciphertext));
    }
}

