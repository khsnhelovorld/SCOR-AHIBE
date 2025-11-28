package com.project.ahibe.crypto.bls12;

import java.math.BigInteger;

/**
 * BLS12-381 curve constants following standard specifications.
 * 
 * BLS12-381 is a pairing-friendly elliptic curve with embedding degree 12.
 * 
 * Security level: ~128 bits (conservative) to ~192 bits (optimistic)
 * 
 * References:
 * - https://electriccoin.co/blog/new-snark-curve/
 * - https://hackmd.io/@benjaminion/bls12-381
 * - https://datatracker.ietf.org/doc/html/rfc9380
 */
public final class BLS12Constants {
    private BLS12Constants() {}
    
    // BLS12-381 field modulus (p)
    // p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    public static final BigInteger FIELD_MODULUS = new BigInteger(
        "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16
    );
    
    // BLS12-381 scalar field order (r) - the order of G1, G2, and GT
    // r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    public static final BigInteger CURVE_ORDER = new BigInteger(
        "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16
    );
    
    // Cofactor for G1
    // h1 = (p - 1) / r = 0x396c8c005555e1568c00aaab0000aaab
    public static final BigInteger G1_COFACTOR = new BigInteger(
        "396c8c005555e1568c00aaab0000aaab", 16
    );
    
    // Cofactor for G2 (much larger)
    public static final BigInteger G2_COFACTOR = new BigInteger(
        "5d543a95414e7f1091d50792876a202cd91de4547085abaa68a205b2e5a7ddfa628f1cb4d9e82ef21537e293a6691ae1616ec6e786f0c70cf1c38e31c7238e5", 16
    );
    
    // Curve equation: y^2 = x^3 + 4 (for G1)
    public static final BigInteger G1_B = BigInteger.valueOf(4);
    
    // G1 generator point (compressed x-coordinate, 48 bytes)
    public static final byte[] G1_GENERATOR_X = hexToBytes(
        "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
    );
    
    // G2 generator x-coordinate (96 bytes, two Fp elements)
    public static final byte[] G2_GENERATOR_X = hexToBytes(
        "024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8" +
        "13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"
    );
    
    // Size constants
    public static final int G1_COMPRESSED_SIZE = 48;
    public static final int G1_UNCOMPRESSED_SIZE = 96;
    public static final int G2_COMPRESSED_SIZE = 96;
    public static final int G2_UNCOMPRESSED_SIZE = 192;
    public static final int GT_SIZE = 576; // 12 * 48
    public static final int SCALAR_SIZE = 32;
    
    // Hash-to-curve Domain Separation Tags (RFC 9380)
    public static final String DST_G1 = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_";
    public static final String DST_G2 = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_";
    
    // AHIBE-specific DSTs
    public static final String DST_AHIBE_G1 = "AHIBE_BLS12381G1_XMD:SHA-256_SSWU_RO_";
    public static final String DST_AHIBE_G2 = "AHIBE_BLS12381G2_XMD:SHA-256_SSWU_RO_";
    
    // Helper method to convert hex string to bytes
    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                 + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }
    
    /**
     * Validate that a scalar is in the valid range [1, r-1].
     */
    public static boolean isValidScalar(BigInteger scalar) {
        return scalar != null && 
               scalar.compareTo(BigInteger.ZERO) > 0 && 
               scalar.compareTo(CURVE_ORDER) < 0;
    }
    
    /**
     * Reduce a BigInteger modulo the curve order r.
     * Ensures the result is in [0, r-1].
     */
    public static BigInteger reduceModOrder(BigInteger value) {
        BigInteger result = value.mod(CURVE_ORDER);
        if (result.signum() < 0) {
            result = result.add(CURVE_ORDER);
        }
        return result;
    }
    
    /**
     * Reduce a BigInteger modulo the field modulus p.
     * Ensures the result is in [0, p-1].
     */
    public static BigInteger reduceModField(BigInteger value) {
        BigInteger result = value.mod(FIELD_MODULUS);
        if (result.signum() < 0) {
            result = result.add(FIELD_MODULUS);
        }
        return result;
    }
}

