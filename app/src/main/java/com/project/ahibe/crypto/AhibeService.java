package com.project.ahibe.crypto;

import it.unisa.dia.gas.crypto.jpbc.fe.ibe.dip10.engines.AHIBEDIP10KEMEngine;
import it.unisa.dia.gas.crypto.jpbc.fe.ibe.dip10.generators.AHIBEDIP10KeyPairGenerator;
import it.unisa.dia.gas.crypto.jpbc.fe.ibe.dip10.generators.AHIBEDIP10SecretKeyGenerator;
import it.unisa.dia.gas.crypto.jpbc.fe.ibe.dip10.params.AHIBEDIP10DelegateGenerationParameters;
import it.unisa.dia.gas.crypto.jpbc.fe.ibe.dip10.params.AHIBEDIP10EncryptionParameters;
import it.unisa.dia.gas.crypto.jpbc.fe.ibe.dip10.params.AHIBEDIP10KeyPairGenerationParameters;
import it.unisa.dia.gas.crypto.jpbc.fe.ibe.dip10.params.AHIBEDIP10MasterSecretKeyParameters;
import it.unisa.dia.gas.crypto.jpbc.fe.ibe.dip10.params.AHIBEDIP10PublicKeyParameters;
import it.unisa.dia.gas.crypto.jpbc.fe.ibe.dip10.params.AHIBEDIP10SecretKeyGenerationParameters;
import it.unisa.dia.gas.crypto.jpbc.fe.ibe.dip10.params.AHIBEDIP10SecretKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * High-level façade around the AHIBE DIP10 primitives shipped with jPBC.
 *
 * <p>The service exposes the minimal operations required by the SCOR-AHIBE flow:</p>
 * <ul>
 *     <li><strong>setup</strong>: executed by PKG to generate public parameters and the master secret key.</li>
 *     <li><strong>keyGen</strong>: executed by Issuer to derive {@code SK_H} for a concrete Holder identity path.</li>
 *     <li><strong>delegate</strong>: executed by Holder to derive time-scoped keys {@code SK_{H||T}}.</li>
 *     <li><strong>encaps/decaps</strong>: executed by Issuer/Verifier to publish and verify revocation ciphertexts.</li>
 * </ul>
 *
 * <p>All low-level Element conversions are hidden – callers only provide identity strings and receive raw byte
 * arrays ready for on-chain storage or off-chain session key usage.</p>
 */
public class AhibeService {

    private final int securityParameterBits;
    private final int maxHierarchyDepth;

    /**
     * @param securityParameterBits size of the Type A1 curve generated under the hood (e.g. 160 or 256 bits).
     * @param maxHierarchyDepth maximum number of identity components supported (Holder_ID || Epoch || ...).
     */
    public AhibeService(int securityParameterBits, int maxHierarchyDepth) {
        if (securityParameterBits < 80) {
            throw new IllegalArgumentException("securityParameterBits should be >= 80 bits for meaningful security.");
        }
        if (maxHierarchyDepth < 1) {
            throw new IllegalArgumentException("maxHierarchyDepth must be positive.");
        }
        this.securityParameterBits = securityParameterBits;
        this.maxHierarchyDepth = maxHierarchyDepth;

        // Ensure the pairing factory stays purely Java (no native PBC dependency expected in this project).
        PairingFactory.getInstance().setUsePBCWhenPossible(false);
        PairingFactory.getInstance().setReuseInstance(true);
    }

    /**
     * Run AHIBE setup and obtain the master secret / public parameters bundle.
     */
    public SetupResult setup() {
        AHIBEDIP10KeyPairGenerator generator = new AHIBEDIP10KeyPairGenerator();
        generator.init(new AHIBEDIP10KeyPairGenerationParameters(securityParameterBits, maxHierarchyDepth));

        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
        AHIBEDIP10PublicKeyParameters publicKey = (AHIBEDIP10PublicKeyParameters) keyPair.getPublic();
        AHIBEDIP10MasterSecretKeyParameters masterSecret =
                (AHIBEDIP10MasterSecretKeyParameters) keyPair.getPrivate();

        return new SetupResult(publicKey, masterSecret);
    }

    /**
     * Derive a Holder secret key {@code SK_H} for the given identity path.
     */
    public AHIBEDIP10SecretKeyParameters keyGen(SetupResult setup, List<String> identityPath) {
        Objects.requireNonNull(setup, "setup must not be null");
        validateIdentityDepth(identityPath);

        Pairing pairing = PairingFactory.getPairing(setup.publicKey().getParameters());
        Element[] ids = toIdentityVector(pairing, identityPath);

        AHIBEDIP10SecretKeyGenerator generator = new AHIBEDIP10SecretKeyGenerator();
        generator.init(new AHIBEDIP10SecretKeyGenerationParameters(
                setup.masterSecretKey(),
                setup.publicKey(),
                ids
        ));

        return (AHIBEDIP10SecretKeyParameters) generator.generateKey();
    }

    /**
     * Delegate a previously issued Holder key down one more level (e.g. add a time epoch).
     */
    public AHIBEDIP10SecretKeyParameters delegate(AHIBEDIP10PublicKeyParameters publicKey,
                                                  AHIBEDIP10SecretKeyParameters parentSecretKey,
                                                  String childIdentity) {
        Objects.requireNonNull(publicKey, "publicKey must not be null");
        Objects.requireNonNull(parentSecretKey, "parentSecretKey must not be null");
        Objects.requireNonNull(childIdentity, "childIdentity must not be null");

        Pairing pairing = PairingFactory.getPairing(publicKey.getParameters());
        Element id = hashToZr(pairing, childIdentity);

        AHIBEDIP10SecretKeyGenerator generator = new AHIBEDIP10SecretKeyGenerator();
        generator.init(new AHIBEDIP10DelegateGenerationParameters(publicKey, parentSecretKey, id));

        return (AHIBEDIP10SecretKeyParameters) generator.generateKey();
    }

    /**
     * Encapsulate a random session key bound to the supplied identity path.
     * <p>The result contains both the shared secret (for off-chain symmetric crypto) and the ciphertext that
     * must be published on-chain.</p>
     */
    public EncapsulationResult encapsulate(AHIBEDIP10PublicKeyParameters publicKey, List<String> identityPath) {
        Objects.requireNonNull(publicKey, "publicKey must not be null");
        validateIdentityDepth(identityPath);

        Pairing pairing = PairingFactory.getPairing(publicKey.getParameters());
        Element[] ids = toIdentityVector(pairing, identityPath);

        AHIBEDIP10KEMEngine kem = new AHIBEDIP10KEMEngine();
        kem.init(true, new AHIBEDIP10EncryptionParameters(publicKey, ids));

        try {
            byte[] kemOutput = kem.process();
            int keySize = kem.getKeyBlockSize();

            byte[] sessionKey = Arrays.copyOfRange(kemOutput, 0, keySize);
            byte[] ciphertext = Arrays.copyOfRange(kemOutput, keySize, kemOutput.length);

            return new EncapsulationResult(sessionKey, ciphertext);
        } catch (InvalidCipherTextException e) {
            throw new IllegalStateException("AHIBE encapsulation failed", e);
        }
    }

    /**
     * Recover the encapsulated session key from the ciphertext using the delegated secret key.
     */
    public byte[] decapsulate(AHIBEDIP10SecretKeyParameters secretKey, byte[] ciphertext) {
        Objects.requireNonNull(secretKey, "secretKey must not be null");
        Objects.requireNonNull(ciphertext, "ciphertext must not be null");

        AHIBEDIP10KEMEngine kem = new AHIBEDIP10KEMEngine();
        kem.init(false, secretKey);
        return kem.process(ciphertext, 0, ciphertext.length);
    }

    private Element[] toIdentityVector(Pairing pairing, List<String> identityPath) {
        Element[] ids = new Element[identityPath.size()];
        for (int i = 0; i < identityPath.size(); i++) {
            ids[i] = hashToZr(pairing, identityPath.get(i));
        }
        return ids;
    }

    private Element hashToZr(Pairing pairing, String identityComponent) {
        byte[] utf8 = identityComponent.getBytes(StandardCharsets.UTF_8);

        return pairing.getZr().newElement().setFromHash(utf8, 0, utf8.length).getImmutable();
    }

    private void validateIdentityDepth(List<String> identityPath) {
        Objects.requireNonNull(identityPath, "identityPath must not be null");
        if (identityPath.isEmpty()) {
            throw new IllegalArgumentException("identityPath must contain at least one component.");
        }
        if (identityPath.size() > maxHierarchyDepth) {
            throw new IllegalArgumentException("identityPath exceeds configured hierarchy depth (" + maxHierarchyDepth + ").");
        }
    }

    /**
     * Bundle returned by {@link #setup()}.
     */
    public record SetupResult(AHIBEDIP10PublicKeyParameters publicKey,
                              AHIBEDIP10MasterSecretKeyParameters masterSecretKey) {
    }

    /**
     * Encapsulation output: {@code sessionKey} is kept off-chain, {@code ciphertext} is published on-chain.
     */
    public record EncapsulationResult(byte[] sessionKey, byte[] ciphertext) {
    }
}

