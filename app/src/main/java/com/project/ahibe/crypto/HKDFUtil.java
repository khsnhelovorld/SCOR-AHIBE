package com.project.ahibe.crypto;

import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.HKDFParameters;

import java.nio.charset.StandardCharsets;

/**
 * HKDF utility for secure key derivation (replaces insecure XOR).
 */
public final class HKDFUtil {
    private HKDFUtil() {
    }
    
    /**
     * Derive a key using HKDF-SHA256.
     * 
     * @param inputKeyMaterial The input key material
     * @param salt Optional salt (can be null)
     * @param info Optional context/application specific information (can be null)
     * @param outputLength Desired output length in bytes
     * @return Derived key
     */
    public static byte[] deriveKey(byte[] inputKeyMaterial, byte[] salt, byte[] info, int outputLength) {
        try {
            HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
            HKDFParameters params = new HKDFParameters(inputKeyMaterial, salt, info);
            hkdf.init(params);
            
            byte[] output = new byte[outputLength];
            hkdf.generateBytes(output, 0, outputLength);
            return output;
        } catch (Exception e) {
            throw new RuntimeException("HKDF key derivation failed", e);
        }
    }
    
    /**
     * Derive a session key from pairing result and identity.
     */
    public static byte[] deriveSessionKey(byte[] pairingResult, byte[] identityHash, int keyLength) {
        // Use pairing result as IKM, identity hash as info
        return deriveKey(pairingResult, null, identityHash, keyLength);
    }
    
    /**
     * Derive encryption key from identity.
     */
    public static byte[] deriveEncryptionKey(byte[] identityHash, int keyLength) {
        // Use identity hash as IKM
        byte[] info = "AHIBE_ENCRYPTION_KEY".getBytes(StandardCharsets.UTF_8);
        return deriveKey(identityHash, null, info, keyLength);
    }
}

