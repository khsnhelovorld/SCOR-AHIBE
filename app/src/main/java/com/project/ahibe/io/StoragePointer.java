package com.project.ahibe.io;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public final class StoragePointer {

    private StoragePointer() {
    }

    /**
     * Simulate deriving an IPFS CID by hashing the ciphertext.
     * In production, replace this method with actual upload logic returning the CID string.
     */
    public static String deriveCid(byte[] ciphertext) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(ciphertext);
            return "cid-sha256-" + ByteEncoding.toHex(hash).substring(2);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}

