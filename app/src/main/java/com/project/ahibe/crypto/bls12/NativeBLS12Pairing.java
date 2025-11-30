package com.project.ahibe.crypto.bls12;

import com.project.ahibe.crypto.ErrorLogger;

import java.lang.reflect.Method;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * Native BLS12-381 pairing wrapper using reflection for optional native library.
 * 
 * This class attempts to load and use native BLS12-381 operations (e.g., jblst)
 * via reflection. If the native library is not available, all methods will
 * throw UnsupportedOperationException, and the caller (BLS12PairingImpl) will
 * fall back to simulated operations.
 * 
 * To enable native pairing:
 * 1. Add jblst dependency to build.gradle:
 *    implementation 'tech.pegasys:jblst:0.3.11'
 * 2. Ensure native library is available for your platform
 * 
 * Native pairing provides:
 * - Real optimal Ate pairing (Miller loop + final exponentiation)
 * - RFC 9380 compliant hash-to-curve (SSWU isogeny map)
 * - Constant-time operations (timing attack resistant)
 * - ~10x faster than pure Java implementations
 */
public class NativeBLS12Pairing {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String AHIBE_DST_G1 = "AHIBE_BLS12381G1_XMD:SHA-256_SSWU_RO_";
    private static final String AHIBE_DST_G2 = "AHIBE_BLS12381G2_XMD:SHA-256_SSWU_RO_";
    
    // Native library loaded flag
    private final boolean nativeAvailable;
    
    public NativeBLS12Pairing() {
        boolean available = false;
        
        try {
            // Try to load the native library classes via reflection
            Class<?> p1Class = Class.forName("supranational.blst.P1");
            
            // Test that native operations work
            p1Class.getMethod("generator").invoke(null);
            
            available = true;
            System.out.println("[NativeBLS12Pairing] Native blst library loaded successfully");
        } catch (ClassNotFoundException e) {
            System.out.println("[NativeBLS12Pairing] Native library not found: " + e.getMessage());
        } catch (UnsatisfiedLinkError e) {
            System.out.println("[NativeBLS12Pairing] Native library link error: " + e.getMessage());
        } catch (Exception e) {
            System.out.println("[NativeBLS12Pairing] Failed to initialize: " + e.getMessage());
        }
        
        this.nativeAvailable = available;
    }
    
    /**
     * Check if native library is available.
     */
    public boolean isAvailable() {
        return nativeAvailable;
    }
    
    /**
     * Hash to G1 using native RFC 9380 SSWU map.
     */
    public byte[] hashToG1(String input) {
        if (!nativeAvailable) {
            throw new UnsupportedOperationException("Native BLS12-381 library not available");
        }
        
        try {
            byte[] msg = input.getBytes(StandardCharsets.UTF_8);
            
            // jblst 0.3.11 API: hash_to(byte[] msg, String dst) returns P1
            Class<?> p1Class = Class.forName("supranational.blst.P1");
            Object point = p1Class.getDeclaredConstructor().newInstance();
            Method hashTo = p1Class.getMethod("hash_to", byte[].class, String.class);
            hashTo.invoke(point, msg, AHIBE_DST_G1);
            
            Method compress = p1Class.getMethod("compress");
            return (byte[]) compress.invoke(point);
        } catch (Exception e) {
            ErrorLogger.logError("NativeBLS12Pairing.hashToG1", "Native hash_to_G1 failed", e);
            throw new RuntimeException("Native hash to G1 failed", e);
        }
    }
    
    /**
     * Hash to G2 using native RFC 9380 SSWU map.
     */
    public byte[] hashToG2(String input) {
        if (!nativeAvailable) {
            throw new UnsupportedOperationException("Native BLS12-381 library not available");
        }
        
        try {
            byte[] msg = input.getBytes(StandardCharsets.UTF_8);
            
            // jblst 0.3.11 API: hash_to(byte[] msg, String dst) returns P2
            Class<?> p2Class = Class.forName("supranational.blst.P2");
            Object point = p2Class.getDeclaredConstructor().newInstance();
            Method hashTo = p2Class.getMethod("hash_to", byte[].class, String.class);
            hashTo.invoke(point, msg, AHIBE_DST_G2);
            
            Method compress = p2Class.getMethod("compress");
            return (byte[]) compress.invoke(point);
        } catch (Exception e) {
            ErrorLogger.logError("NativeBLS12Pairing.hashToG2", "Native hash_to_G2 failed", e);
            throw new RuntimeException("Native hash to G2 failed", e);
        }
    }
    
    /**
     * Compute bilinear pairing using native Miller loop + final exponentiation.
     */
    public byte[] pairing(byte[] g1Bytes, byte[] g2Bytes) {
        if (!nativeAvailable) {
            throw new UnsupportedOperationException("Native BLS12-381 library not available");
        }
        
        try {
            Class<?> p1AffineClass = Class.forName("supranational.blst.P1_Affine");
            Class<?> p2AffineClass = Class.forName("supranational.blst.P2_Affine");
            Class<?> ptClass = Class.forName("supranational.blst.PT");
            
            Object p1 = p1AffineClass.getDeclaredConstructor(byte[].class).newInstance((Object) g1Bytes);
            Object p2 = p2AffineClass.getDeclaredConstructor(byte[].class).newInstance((Object) g2Bytes);
            
            // Check points are in subgroup
            Method inGroup1 = p1AffineClass.getMethod("in_group");
            Method inGroup2 = p2AffineClass.getMethod("in_group");
            
            if (!(boolean) inGroup1.invoke(p1)) {
                throw new IllegalArgumentException("G1 point not in subgroup");
            }
            if (!(boolean) inGroup2.invoke(p2)) {
                throw new IllegalArgumentException("G2 point not in subgroup");
            }
            
            // Compute pairing
            Object pt = ptClass.getDeclaredConstructor(p1AffineClass, p2AffineClass).newInstance(p1, p2);
            Method finalExp = ptClass.getMethod("final_exp");
            finalExp.invoke(pt);
            
            Method toBendian = ptClass.getMethod("to_bendian");
            return (byte[]) toBendian.invoke(pt);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            ErrorLogger.logError("NativeBLS12Pairing.pairing", "Native pairing failed", e);
            throw new RuntimeException("Native pairing failed", e);
        }
    }
    
    /**
     * G1 scalar multiplication using native library.
     */
    public byte[] g1Mul(byte[] g1Bytes, BigInteger scalar) {
        if (!nativeAvailable) {
            throw new UnsupportedOperationException("Native BLS12-381 library not available");
        }
        
        try {
            Class<?> p1AffineClass = Class.forName("supranational.blst.P1_Affine");
            Class<?> p1Class = Class.forName("supranational.blst.P1");
            
            Object p1Affine = p1AffineClass.getDeclaredConstructor(byte[].class).newInstance((Object) g1Bytes);
            Object p1 = p1Class.getDeclaredConstructor(p1AffineClass).newInstance(p1Affine);
            
            // jblst 0.3.11 API: mult(BigInteger) - direct BigInteger support
            BigInteger reduced = BLS12Constants.reduceModOrder(scalar);
            Method mult = p1Class.getMethod("mult", BigInteger.class);
            mult.invoke(p1, reduced);
            
            Method compress = p1Class.getMethod("compress");
            return (byte[]) compress.invoke(p1);
        } catch (Exception e) {
            ErrorLogger.logError("NativeBLS12Pairing.g1Mul", "Native G1 multiplication failed", e);
            throw new RuntimeException("Native G1 multiplication failed", e);
        }
    }
    
    /**
     * G2 scalar multiplication using native library.
     */
    public byte[] g2Mul(byte[] g2Bytes, BigInteger scalar) {
        if (!nativeAvailable) {
            throw new UnsupportedOperationException("Native BLS12-381 library not available");
        }
        
        try {
            Class<?> p2AffineClass = Class.forName("supranational.blst.P2_Affine");
            Class<?> p2Class = Class.forName("supranational.blst.P2");
            
            Object p2Affine = p2AffineClass.getDeclaredConstructor(byte[].class).newInstance((Object) g2Bytes);
            Object p2 = p2Class.getDeclaredConstructor(p2AffineClass).newInstance(p2Affine);
            
            // jblst 0.3.11 API: mult(BigInteger) - direct BigInteger support
            BigInteger reduced = BLS12Constants.reduceModOrder(scalar);
            Method mult = p2Class.getMethod("mult", BigInteger.class);
            mult.invoke(p2, reduced);
            
            Method compress = p2Class.getMethod("compress");
            return (byte[]) compress.invoke(p2);
        } catch (Exception e) {
            ErrorLogger.logError("NativeBLS12Pairing.g2Mul", "Native G2 multiplication failed", e);
            throw new RuntimeException("Native G2 multiplication failed", e);
        }
    }
    
    /**
     * G1 point addition using native library.
     */
    public byte[] g1Add(byte[] p1Bytes, byte[] q1Bytes) {
        if (!nativeAvailable) {
            throw new UnsupportedOperationException("Native BLS12-381 library not available");
        }
        
        try {
            Class<?> p1AffineClass = Class.forName("supranational.blst.P1_Affine");
            Class<?> p1Class = Class.forName("supranational.blst.P1");
            
            Object p1Affine = p1AffineClass.getDeclaredConstructor(byte[].class).newInstance((Object) p1Bytes);
            Object q1Affine = p1AffineClass.getDeclaredConstructor(byte[].class).newInstance((Object) q1Bytes);
            
            Object p1 = p1Class.getDeclaredConstructor(p1AffineClass).newInstance(p1Affine);
            Method add = p1Class.getMethod("add", p1AffineClass);
            add.invoke(p1, q1Affine);
            
            Method compress = p1Class.getMethod("compress");
            return (byte[]) compress.invoke(p1);
        } catch (Exception e) {
            ErrorLogger.logError("NativeBLS12Pairing.g1Add", "Native G1 addition failed", e);
            throw new RuntimeException("Native G1 addition failed", e);
        }
    }
    
    /**
     * G2 point addition using native library.
     */
    public byte[] g2Add(byte[] p2Bytes, byte[] q2Bytes) {
        if (!nativeAvailable) {
            throw new UnsupportedOperationException("Native BLS12-381 library not available");
        }
        
        try {
            Class<?> p2AffineClass = Class.forName("supranational.blst.P2_Affine");
            Class<?> p2Class = Class.forName("supranational.blst.P2");
            
            Object p2Affine = p2AffineClass.getDeclaredConstructor(byte[].class).newInstance((Object) p2Bytes);
            Object q2Affine = p2AffineClass.getDeclaredConstructor(byte[].class).newInstance((Object) q2Bytes);
            
            Object p2 = p2Class.getDeclaredConstructor(p2AffineClass).newInstance(p2Affine);
            Method add = p2Class.getMethod("add", p2AffineClass);
            add.invoke(p2, q2Affine);
            
            Method compress = p2Class.getMethod("compress");
            return (byte[]) compress.invoke(p2);
        } catch (Exception e) {
            ErrorLogger.logError("NativeBLS12Pairing.g2Add", "Native G2 addition failed", e);
            throw new RuntimeException("Native G2 addition failed", e);
        }
    }
    
    /**
     * Get G1 generator point.
     */
    public byte[] getG1Generator() {
        if (!nativeAvailable) {
            throw new UnsupportedOperationException("Native BLS12-381 library not available");
        }
        
        try {
            Class<?> p1Class = Class.forName("supranational.blst.P1");
            Method generator = p1Class.getMethod("generator");
            Object g = generator.invoke(null);
            
            Object p1 = p1Class.getDeclaredConstructor(p1Class).newInstance(g);
            Method compress = p1Class.getMethod("compress");
            return (byte[]) compress.invoke(p1);
        } catch (Exception e) {
            throw new RuntimeException("Failed to get G1 generator", e);
        }
    }
    
    /**
     * Generate random scalar.
     */
    public BigInteger randomScalar() {
        byte[] randomBytes = new byte[64];
        RANDOM.nextBytes(randomBytes);
        BigInteger scalar = new BigInteger(1, randomBytes);
        return BLS12Constants.reduceModOrder(scalar);
    }
    
    /**
     * Convert BigInteger to scalar bytes for blst (32 bytes, little-endian).
     */
    private byte[] toScalarBytes(BigInteger scalar) {
        BigInteger reduced = BLS12Constants.reduceModOrder(scalar);
        byte[] bytes = reduced.toByteArray();
        
        byte[] result = new byte[32];
        int srcOffset = bytes.length > 32 ? bytes.length - 32 : 0;
        int dstOffset = 32 - Math.min(bytes.length, 32);
        System.arraycopy(bytes, srcOffset, result, dstOffset, Math.min(bytes.length, 32));
        
        // Reverse for little-endian
        for (int i = 0; i < 16; i++) {
            byte tmp = result[i];
            result[i] = result[31 - i];
            result[31 - i] = tmp;
        }
        
        return result;
    }
}
