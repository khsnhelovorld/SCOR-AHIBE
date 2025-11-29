package com.project.ahibe.crypto.config;

import java.util.Locale;
import java.util.Objects;

/**
 * Catalog of supported pairing parameter profiles for AHIBE.
 *
 * <p>This implementation now uses real BLS12-381 operations. The BLS12_381 profile
 * is the primary and recommended profile for production use.</p>
 */
public enum PairingProfile {
    BLS12_381(
            "bls12-381",
            381,
            12,
            192,
            "Production-grade profile using real BLS12-381 curve. This is the standard BLS12-381 curve specification, interoperable with Ethereum/Zcash implementations."
    );

    private final String id;
    private final int estimatedBits;
    private final int embeddingDegree;
    private final int estimatedSecurityBits;
    private final String description;

    PairingProfile(String id, int estimatedBits, int embeddingDegree, int estimatedSecurityBits, String description) {
        this.id = id;
        this.estimatedBits = estimatedBits;
        this.embeddingDegree = embeddingDegree;
        this.estimatedSecurityBits = estimatedSecurityBits;
        this.description = description;
    }

    public int estimatedSecurityBits() {
        return estimatedSecurityBits;
    }

    public String description() {
        return description;
    }

    public String id() {
        return id;
    }

    public static PairingProfile fromEnv(String value, PairingProfile fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        for (PairingProfile profile : values()) {
            if (profile.id.equalsIgnoreCase(normalized)) {
                return profile;
            }
        }
        throw new IllegalArgumentException("Unknown AHIBE pairing profile: " + value);
    }

    public record Metadata(
            String id,
            int pairingBits,
            int embeddingDegree,
            int estimatedSecurityBits,
            String description
    ) {
    }

    public Metadata metadata() {
        return new Metadata(id, estimatedBits, embeddingDegree, estimatedSecurityBits, description);
    }
}
