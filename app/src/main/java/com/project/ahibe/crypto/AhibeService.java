package com.project.ahibe.crypto;

import com.project.ahibe.crypto.bls12.BLS12MasterSecret;
import com.project.ahibe.crypto.bls12.BLS12PublicKey;
import com.project.ahibe.crypto.bls12.BLS12SecretKey;
import com.project.ahibe.crypto.config.PairingProfile;

import java.util.List;
import java.util.Objects;

/**
 * High-level façade for AHIBE DIP10 primitives using real BLS12-381.
 *
 * <p>The service exposes the minimal operations required by the SCOR-AHIBE flow:</p>
 * <ul>
 *     <li><strong>setup</strong>: executed by PKG to generate public parameters and the master secret key.</li>
 *     <li><strong>keyGen</strong>: executed by Issuer to derive {@code SK_H} for a concrete Holder identity path.</li>
 *     <li><strong>delegate</strong>: executed by Holder to derive time-scoped keys {@code SK_{H||T}}.</li>
 *     <li><strong>encaps/decaps</strong>: executed by Issuer/Verifier to publish and verify revocation ciphertexts.</li>
 * </ul>
 *
 * <p>This implementation uses real BLS12-381 operations, replacing the jPBC-based implementation.</p>
 */
public class AhibeService {

    private final PairingProfile profile;
    private final int maxHierarchyDepth;
    private final BLS12AhibeService bls12Service;

    /**
     * @param profile pairing profile (BLS12-381 is now the only supported profile)
     * @param maxHierarchyDepth maximum number of identity components supported (Holder_ID || Epoch || ...).
     */
    public AhibeService(PairingProfile profile, int maxHierarchyDepth) {
        this.profile = Objects.requireNonNull(profile, "profile must not be null");
        if (maxHierarchyDepth < 1) {
            throw new IllegalArgumentException("maxHierarchyDepth must be positive.");
        }
        this.maxHierarchyDepth = maxHierarchyDepth;
        
        // Initialize BLS12-381 service
        try {
            this.bls12Service = new BLS12AhibeService(maxHierarchyDepth);
        } catch (Exception e) {
            ErrorLogger.logError("AhibeService.constructor", "Failed to initialize BLS12-381 service", e);
            throw new RuntimeException("Failed to initialize AHIBE service", e);
        }
    }

    /**
     * Legacy constructor kept for backwards compatibility with older tooling that only passed
     * a bit-length. It now always uses BLS12-381.
     */
    @Deprecated
    public AhibeService(int securityParameterBits, int maxHierarchyDepth) {
        this(PairingProfile.BLS12_381, maxHierarchyDepth);
    }

    /**
     * Run AHIBE setup and obtain the master secret / public parameters bundle.
     */
    public SetupResult setup() {
        try {
            BLS12AhibeService.SetupResult result = bls12Service.setup();
            return new SetupResult(result.publicKey(), result.masterSecretKey());
        } catch (Exception e) {
            ErrorLogger.logError("AhibeService.setup", "Setup failed", e);
            throw new RuntimeException("AHIBE setup failed", e);
        }
    }

    /**
     * Derive a Holder secret key {@code SK_H} for the given identity path.
     */
    public BLS12SecretKey keyGen(SetupResult setup, List<String> identityPath) {
        try {
            BLS12AhibeService.SetupResult bls12Setup = new BLS12AhibeService.SetupResult(
                setup.publicKey(), setup.masterSecretKey()
            );
            return bls12Service.keyGen(bls12Setup, identityPath);
        } catch (Exception e) {
            ErrorLogger.logError("AhibeService.keyGen", "KeyGen failed for identityPath=" + identityPath, e);
            throw new RuntimeException("AHIBE key generation failed", e);
        }
    }

    /**
     * Delegate a previously issued Holder key down one more level (e.g. add a time epoch).
     */
    public BLS12SecretKey delegate(BLS12PublicKey publicKey, BLS12SecretKey parentSecretKey, String childIdentity) {
        try {
            return bls12Service.delegate(publicKey, parentSecretKey, childIdentity);
        } catch (Exception e) {
            ErrorLogger.logError("AhibeService.delegate", "Delegate failed for childIdentity=" + childIdentity, e);
            throw new RuntimeException("AHIBE delegation failed", e);
        }
    }

    /**
     * Encapsulate a random session key bound to the supplied identity path.
     * <p>The result contains both the shared secret (for off-chain symmetric crypto) and the ciphertext that
     * must be published on-chain.</p>
     */
    public EncapsulationResult encapsulate(BLS12PublicKey publicKey, List<String> identityPath) {
        try {
            BLS12AhibeService.EncapsulationResult result = bls12Service.encapsulate(publicKey, identityPath);
            return new EncapsulationResult(result.sessionKey(), result.ciphertext());
        } catch (IllegalArgumentException e) {
            // Re-throw IllegalArgumentException directly without wrapping
            ErrorLogger.logError("AhibeService.encapsulate", "Encapsulate failed for identityPath=" + identityPath, e);
            throw e;
        } catch (Exception e) {
            ErrorLogger.logError("AhibeService.encapsulate", "Encapsulate failed for identityPath=" + identityPath, e);
            throw new RuntimeException("AHIBE encapsulation failed", e);
        }
    }

    /**
     * Recover the encapsulated session key from the ciphertext using the delegated secret key.
     */
    public byte[] decapsulate(BLS12SecretKey secretKey, byte[] ciphertext) {
        try {
            return bls12Service.decapsulate(secretKey, ciphertext);
        } catch (Exception e) {
            ErrorLogger.logError("AhibeService.decapsulate", "Decapsulate failed", e);
            throw new RuntimeException("AHIBE decapsulation failed", e);
        }
    }

    /**
     * Bundle returned by {@link #setup()}.
     */
    public record SetupResult(BLS12PublicKey publicKey, BLS12MasterSecret masterSecretKey) {
    }

    /**
     * Encapsulation output: {@code sessionKey} is kept off-chain, {@code ciphertext} is published on-chain.
     */
    public record EncapsulationResult(byte[] sessionKey, byte[] ciphertext) {
    }

    public PairingProfile profile() {
        return profile;
    }
}

