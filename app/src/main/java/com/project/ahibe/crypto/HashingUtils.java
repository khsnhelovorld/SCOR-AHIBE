package com.project.ahibe.crypto;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;

/**
 * Cryptographic hashing utilities for SCOR-AHIBE.
 * 
 * Provides SHA-256 based hashing for:
 * - CID derivation
 * - Data integrity verification
 * 
 * SCOR-AHIBE: Simplified without Merkle tree operations.
 * IPFS CID integrity is sufficient for verification.
 */
public final class HashingUtils {
    private static final ThreadLocal<MessageDigest> SHA256 = ThreadLocal.withInitial(() -> {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    });

    private HashingUtils() {
    }

    public static byte[] sha256(byte[] input) {
        MessageDigest digest = SHA256.get();
        digest.reset();
        return digest.digest(input);
    }

    public static byte[] sha256(byte[] left, byte[] right) {
        MessageDigest digest = SHA256.get();
        digest.reset();
        digest.update(left);
        digest.update(right);
        return digest.digest();
    }

    public static byte[] sha256Concat(List<byte[]> inputs) {
        MessageDigest digest = SHA256.get();
        digest.reset();
        inputs.forEach(digest::update);
        return digest.digest();
    }

    /**
     * Hash holder ID, epoch, and ciphertext for integrity verification.
     * This is used for deriving consistent content identifiers.
     */
    public static byte[] hashHolderEpochCiphertext(String holderId, String epoch, byte[] ciphertext) {
        byte[] holderBytes = holderId.getBytes(StandardCharsets.UTF_8);
        byte[] epochBytes = epoch.getBytes(StandardCharsets.UTF_8);
        MessageDigest digest = SHA256.get();
        digest.reset();
        digest.update(intToBytes(holderBytes.length));
        digest.update(holderBytes);
        digest.update(intToBytes(epochBytes.length));
        digest.update(epochBytes);
        digest.update(ciphertext);
        return digest.digest();
    }

    public static String toHex(byte[] input) {
        return "0x" + HexFormat.of().withUpperCase().formatHex(input);
    }

    /**
     * Parse hex string to bytes.
     */
    public static byte[] fromHex(String hex) {
        String normalized = hex.startsWith("0x") ? hex.substring(2) : hex;
        return HexFormat.of().parseHex(normalized);
    }

    private static byte[] intToBytes(int value) {
        return ByteBuffer.allocate(4).putInt(value).array();
    }
}
