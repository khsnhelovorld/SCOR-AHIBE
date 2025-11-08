package com.project.ahibe.core;

import com.project.ahibe.crypto.AhibeService;
import com.project.ahibe.eth.RevocationListClient;
import com.project.ahibe.io.StorageFetcher;
import com.project.ahibe.io.StoragePointer;
import it.unisa.dia.gas.crypto.jpbc.fe.ibe.dip10.params.AHIBEDIP10SecretKeyParameters;

import java.util.Objects;
import java.util.Optional;

/**
 * Verifier pulls storage pointers from the smart contract and validates them against local ciphertext.
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

    public Optional<String> fetchPointer(RevocationListClient client,
                                         String holderId,
                                         String epoch) {
        Objects.requireNonNull(client, "client must not be null");
        Objects.requireNonNull(holderId, "holderId must not be null");
        Objects.requireNonNull(epoch, "epoch must not be null");

        return client.fetchPointer(holderId, epoch);
    }

    public Optional<byte[]> fetchAndDecapsulate(RevocationListClient client,
                                                StorageFetcher fetcher,
                                                AHIBEDIP10SecretKeyParameters delegatedKey,
                                                String holderId,
                                                String epoch) {
        Objects.requireNonNull(fetcher, "fetcher must not be null");
        return fetchPointer(client, holderId, epoch)
                .flatMap(pointer -> fetcher.fetch(pointer)
                        .map(bytes -> ahibeService.decapsulate(delegatedKey, bytes)));
    }

    public boolean matchesPointer(RevocationRecord record, String pointer) {
        if (record == null) {
            throw new IllegalArgumentException("record must not be null");
        }
        if (pointer == null) {
            throw new IllegalArgumentException("pointer must not be null");
        }
        return StoragePointer.deriveCid(record.ciphertext()).equals(pointer);
    }
}
