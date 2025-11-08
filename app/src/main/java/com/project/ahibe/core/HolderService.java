package com.project.ahibe.core;

import com.project.ahibe.crypto.AhibeService;
import it.unisa.dia.gas.crypto.jpbc.fe.ibe.dip10.params.AHIBEDIP10PublicKeyParameters;
import it.unisa.dia.gas.crypto.jpbc.fe.ibe.dip10.params.AHIBEDIP10SecretKeyParameters;

import java.util.Objects;

/**
 * Holder stores root key material and derives time-scoped child keys.
 */
public class HolderService {
    private final AhibeService ahibeService;
    private final AHIBEDIP10PublicKeyParameters publicParameters;

    public HolderService(AhibeService ahibeService, AHIBEDIP10PublicKeyParameters publicParameters) {
        this.ahibeService = ahibeService;
        this.publicParameters = publicParameters;
    }

    public AHIBEDIP10SecretKeyParameters deriveEpochKey(AHIBEDIP10SecretKeyParameters rootKey, String epoch) {
        Objects.requireNonNull(rootKey, "rootKey must not be null");
        Objects.requireNonNull(epoch, "epoch must not be null");
        return ahibeService.delegate(publicParameters, rootKey, epoch);
    }
}

