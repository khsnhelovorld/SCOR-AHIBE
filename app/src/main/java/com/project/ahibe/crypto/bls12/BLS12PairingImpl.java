package com.project.ahibe.crypto.bls12;

import com.project.ahibe.crypto.ErrorLogger;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * BLS12-381 Pairing implementation using native blst library.
 * 
 * This implementation REQUIRES the supranational/blst native library for:
 * - Real optimal Ate pairing (Miller loop + final exponentiation)
 * - RFC 9380 compliant hash-to-curve (SSWU isogeny map)
 * - Constant-time operations to prevent timing attacks
 * - Production-ready cryptographic security
 * 
 * IMPORTANT: Native library is REQUIRED. No fallback to simulated operations.
 * Add jblst dependency: implementation 'tech.pegasys:jblst:0.3.11'
 * 
 * BLS12-381 parameters:
 * - G1: 48 bytes (compressed), 96 bytes (uncompressed)
 * - G2: 96 bytes (compressed), 192 bytes (uncompressed)  
 * - GT: 576 bytes (12 × 48 bytes for Fp12 element)
 * - Scalar field (Fr): 32 bytes
 * - Security: ~128-bit (conservative), ~192-bit (optimistic)
 * 
 * @see NativeBLS12Pairing for the native implementation
 */
public class BLS12PairingImpl {
    private static final SecureRandom RANDOM = new SecureRandom();
    
    // Size constants from BLS12Constants
    private static final int G1_COMPRESSED_SIZE = BLS12Constants.G1_COMPRESSED_SIZE;
    private static final int G2_COMPRESSED_SIZE = BLS12Constants.G2_COMPRESSED_SIZE;
    private static final int GT_SIZE = BLS12Constants.GT_SIZE;
    private static final int SCALAR_SIZE = BLS12Constants.SCALAR_SIZE;
    
    // Curve order for scalar field operations
    private final BigInteger curveOrder;
    
    // Native implementation (null if not available)
    private final NativeBLS12Pairing nativePairing;
    private final boolean useNative;
    
    public BLS12PairingImpl() {
        this.curveOrder = BLS12Constants.CURVE_ORDER;
        
        // Initialize native BLS12-381 implementation (REQUIRED)
        NativeBLS12Pairing native_ = null;
        boolean nativeAvailable = false;
        try {
            native_ = new NativeBLS12Pairing();
            nativeAvailable = native_.isAvailable();
        } catch (Exception e) {
            throw new RuntimeException(
                "[BLS12-381] CRITICAL: Failed to initialize native library: " + e.getMessage() + "\n" +
                "Native BLS12-381 library is REQUIRED for cryptographic security.\n" +
                "Add jblst dependency to build.gradle: implementation 'tech.pegasys:jblst:0.3.11'",
                e
            );
        }
        
        if (!nativeAvailable) {
            throw new RuntimeException(
                "[BLS12-381] CRITICAL: Native library not available.\n" +
                "Native BLS12-381 library is REQUIRED for cryptographic security.\n" +
                "Add jblst dependency to build.gradle: implementation 'tech.pegasys:jblst:0.3.11'"
            );
        }
        
        System.out.println("[BLS12-381] Using NATIVE implementation (blst) - cryptographically secure");
        this.nativePairing = native_;
        this.useNative = true;
    }
    
    /**
     * Check if native BLS12-381 implementation is being used.
     */
    public boolean isUsingNative() {
        return useNative;
    }
    
    /**
     * Hash a string to a scalar field element (Fr) using RFC 9380 hash_to_field.
     * 
     * Uses proper reduction modulo BLS12-381 scalar field order r.
     * Result is guaranteed to be in range [1, r-1].
     */
    public BigInteger hashToZr(String input) {
        try {
            if (input == null || input.isEmpty()) {
                throw new IllegalArgumentException("Input must not be null or empty");
            }
            
            byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
            
            // Use RFC 9380 compliant hash_to_field for scalar field
            BigInteger[] scalars = HashToCurve.hashToFieldFr(
                inputBytes, 
                BLS12Constants.DST_AHIBE_G1 + "Fr", 
                1
            );
            
            BigInteger result = scalars[0];
            
            // Ensure non-zero result
            if (result.equals(BigInteger.ZERO)) {
                result = BigInteger.ONE;
            }
            
            return result;
        } catch (Exception e) {
            ErrorLogger.logError("BLS12PairingImpl.hashToZr", "Failed to hash to Fr: " + input, e);
            throw new RuntimeException("Failed to hash to Fr", e);
        }
    }
    
    /**
     * Generate a random scalar field element (Fr).
     * 
     * Uses secure random generation with proper reduction modulo r.
     * Result is guaranteed to be in range [1, r-1].
     */
    public BigInteger randomZr() {
        try {
            // Generate 64 bytes of randomness for uniform distribution after reduction
            byte[] randomBytes = new byte[64];
            RANDOM.nextBytes(randomBytes);
            
            // Reduce modulo curve order
            BigInteger result = new BigInteger(1, randomBytes).mod(curveOrder);
            
            // Ensure non-zero
            if (result.equals(BigInteger.ZERO)) {
                result = BigInteger.ONE;
            }
            
            return result;
        } catch (Exception e) {
            ErrorLogger.logError("BLS12PairingImpl.randomZr", "Failed to generate random Fr", e);
            throw new RuntimeException("Failed to generate random Fr", e);
        }
    }
    
    /**
     * Get the curve order (r) - the order of the scalar field Fr.
     */
    public BigInteger getOrder() {
        return curveOrder;
    }
    
    /**
     * Get G1 compressed size in bytes (48).
     */
    public int getG1CompressedSize() {
        return G1_COMPRESSED_SIZE;
    }
    
    /**
     * Get G2 compressed size in bytes (96).
     */
    public int getG2CompressedSize() {
        return G2_COMPRESSED_SIZE;
    }
    
    /**
     * Get GT size in bytes (576).
     */
    public int getGTSize() {
        return GT_SIZE;
    }
    
    /**
     * Get scalar field size in bytes (32).
     */
    public int getScalarSize() {
        return SCALAR_SIZE;
    }
    
    /**
     * Compute bilinear pairing: e(g1, g2) -> gt
     * 
     * Uses optimal Ate pairing with Miller loop + final exponentiation.
     * 
     * The bilinearity property is maintained:
     * e(a*G1, b*G2) = e(G1, G2)^(a*b)
     */
    public byte[] pairing(byte[] g1Bytes, byte[] g2Bytes) {
        try {
            if (g1Bytes == null || g1Bytes.length < G1_COMPRESSED_SIZE) {
                throw new IllegalArgumentException("Invalid G1 element: must be " + G1_COMPRESSED_SIZE + " bytes");
            }
            if (g2Bytes == null || g2Bytes.length < G2_COMPRESSED_SIZE) {
                throw new IllegalArgumentException("Invalid G2 element: must be " + G2_COMPRESSED_SIZE + " bytes");
            }
            
            return nativePairing.pairing(g1Bytes, g2Bytes);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            ErrorLogger.logError("BLS12PairingImpl.pairing", "Failed to compute pairing", e);
            throw new RuntimeException("Failed to compute pairing", e);
        }
    }
    
    
    /**
     * Hash to G1: maps a string to a point in G1 using RFC 9380 hash-to-curve.
     * 
     * Uses SSWU isogeny map (full RFC 9380 compliance).
     */
    public byte[] hashToG1(String input) {
        try {
            if (input == null || input.isEmpty()) {
                throw new IllegalArgumentException("Input must not be null or empty");
            }
            
            return nativePairing.hashToG1(input);
        } catch (Exception e) {
            ErrorLogger.logError("BLS12PairingImpl.hashToG1", "Failed to hash to G1: " + input, e);
            throw new RuntimeException("Failed to hash to G1", e);
        }
    }
    
    /**
     * Hash to G2: maps a string to a point in G2 using RFC 9380 hash-to-curve.
     * 
     * Uses SSWU isogeny map (full RFC 9380 compliance).
     */
    public byte[] hashToG2(String input) {
        try {
            if (input == null || input.isEmpty()) {
                throw new IllegalArgumentException("Input must not be null or empty");
            }
            
            return nativePairing.hashToG2(input);
        } catch (Exception e) {
            ErrorLogger.logError("BLS12PairingImpl.hashToG2", "Failed to hash to G2: " + input, e);
            throw new RuntimeException("Failed to hash to G2", e);
        }
    }
    
    /**
     * G1 scalar multiplication: result = scalar * g1
     * 
     * Uses native EC scalar multiplication.
     * The scalar is first reduced modulo the curve order r.
     */
    public byte[] g1Mul(byte[] g1Bytes, BigInteger scalar) {
        try {
            if (g1Bytes == null || g1Bytes.length < G1_COMPRESSED_SIZE) {
                throw new IllegalArgumentException("Invalid G1 element");
            }
            if (scalar == null) {
                throw new IllegalArgumentException("Scalar must not be null");
            }
            
            return nativePairing.g1Mul(g1Bytes, scalar);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            ErrorLogger.logError("BLS12PairingImpl.g1Mul", "Failed G1 scalar multiplication", e);
            throw new RuntimeException("Failed G1 scalar multiplication", e);
        }
    }
    
    /**
     * G2 scalar multiplication: result = scalar * g2
     * 
     * Uses native EC scalar multiplication.
     */
    public byte[] g2Mul(byte[] g2Bytes, BigInteger scalar) {
        try {
            if (g2Bytes == null || g2Bytes.length < G2_COMPRESSED_SIZE) {
                throw new IllegalArgumentException("Invalid G2 element");
            }
            if (scalar == null) {
                throw new IllegalArgumentException("Scalar must not be null");
            }
            
            return nativePairing.g2Mul(g2Bytes, scalar);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            ErrorLogger.logError("BLS12PairingImpl.g2Mul", "Failed G2 scalar multiplication", e);
            throw new RuntimeException("Failed G2 scalar multiplication", e);
        }
    }
    
    /**
     * G1 addition: result = g1a + g1b
     * 
     * Uses native EC point addition.
     */
    public byte[] g1Add(byte[] g1a, byte[] g1b) {
        try {
            if (g1a == null || g1a.length < G1_COMPRESSED_SIZE) {
                throw new IllegalArgumentException("Invalid first G1 element");
            }
            if (g1b == null || g1b.length < G1_COMPRESSED_SIZE) {
                throw new IllegalArgumentException("Invalid second G1 element");
            }
            
            return nativePairing.g1Add(g1a, g1b);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            ErrorLogger.logError("BLS12PairingImpl.g1Add", "Failed G1 addition", e);
            throw new RuntimeException("Failed G1 addition", e);
        }
    }
    
    /**
     * G2 addition: result = g2a + g2b
     * 
     * Uses native EC point addition.
     */
    public byte[] g2Add(byte[] g2a, byte[] g2b) {
        try {
            if (g2a == null || g2a.length < G2_COMPRESSED_SIZE) {
                throw new IllegalArgumentException("Invalid first G2 element");
            }
            if (g2b == null || g2b.length < G2_COMPRESSED_SIZE) {
                throw new IllegalArgumentException("Invalid second G2 element");
            }
            
            return nativePairing.g2Add(g2a, g2b);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            ErrorLogger.logError("BLS12PairingImpl.g2Add", "Failed G2 addition", e);
            throw new RuntimeException("Failed G2 addition", e);
        }
    }
    
    /**
     * Compute scalar field inverse: result = scalar^(-1) mod r
     */
    public BigInteger scalarInverse(BigInteger scalar) {
        if (scalar == null || scalar.equals(BigInteger.ZERO)) {
            throw new IllegalArgumentException("Cannot invert zero");
        }
        return scalar.modInverse(curveOrder);
    }
    
    /**
     * Compute scalar field multiplication: result = a * b mod r
     */
    public BigInteger scalarMul(BigInteger a, BigInteger b) {
        if (a == null || b == null) {
            throw new IllegalArgumentException("Scalars must not be null");
        }
        return BLS12Constants.reduceModOrder(a.multiply(b));
    }
    
    /**
     * Compute scalar field addition: result = a + b mod r
     */
    public BigInteger scalarAdd(BigInteger a, BigInteger b) {
        if (a == null || b == null) {
            throw new IllegalArgumentException("Scalars must not be null");
        }
        return BLS12Constants.reduceModOrder(a.add(b));
    }
}
