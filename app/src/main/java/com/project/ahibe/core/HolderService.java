package com.project.ahibe.core;

import com.project.ahibe.crypto.AhibeService;
import com.project.ahibe.crypto.bls12.BLS12PublicKey;
import com.project.ahibe.crypto.bls12.BLS12SecretKey;

import java.util.Objects;

/**
 * Holder stores root key material and derives time-scoped child keys.
 */
public class HolderService {
    private final AhibeService ahibeService;
    private final BLS12PublicKey publicParameters;

    public HolderService(AhibeService ahibeService, BLS12PublicKey publicParameters) {
        this.ahibeService = ahibeService;
        this.publicParameters = publicParameters;
    }

    public BLS12SecretKey deriveEpochKey(BLS12SecretKey rootKey, String epoch) {
        Objects.requireNonNull(rootKey, "rootKey must not be null");
        Objects.requireNonNull(epoch, "epoch must not be null");
        return ahibeService.delegate(publicParameters, rootKey, epoch);
    }
}

