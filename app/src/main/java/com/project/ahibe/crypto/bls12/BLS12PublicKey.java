package com.project.ahibe.crypto.bls12;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Objects;

/**
 * BLS12-381 Public Key for AHIBE scheme.
 * Replaces AHIBEDIP10PublicKeyParameters.
 */
public class BLS12PublicKey implements Serializable {
    private static final long serialVersionUID = 1L;
    
    // Public parameters: y1, y3, y4, t, us[], omega
    private final byte[] y1;
    private final byte[] y3;
    private final byte[] y4;
    private final byte[] t;
    private final byte[][] us;  // Array of u elements for hierarchy
    private final byte[] omega;
    
    // Curve parameters (serialized)
    private final byte[] curveParams;
    
    public BLS12PublicKey(byte[] y1, byte[] y3, byte[] y4, byte[] t, 
                         byte[][] us, byte[] omega, byte[] curveParams) {
        this.y1 = Objects.requireNonNull(y1, "y1 cannot be null");
        this.y3 = Objects.requireNonNull(y3, "y3 cannot be null");
        this.y4 = Objects.requireNonNull(y4, "y4 cannot be null");
        this.t = Objects.requireNonNull(t, "t cannot be null");
        this.us = Objects.requireNonNull(us, "us cannot be null");
        this.omega = Objects.requireNonNull(omega, "omega cannot be null");
        this.curveParams = Objects.requireNonNull(curveParams, "curveParams cannot be null");
    }
    
    public byte[] getY1() { return y1.clone(); }
    public byte[] getY3() { return y3.clone(); }
    public byte[] getY4() { return y4.clone(); }
    public byte[] getT() { return t.clone(); }
    public byte[][] getUs() { 
        byte[][] copy = new byte[us.length][];
        for (int i = 0; i < us.length; i++) {
            copy[i] = us[i].clone();
        }
        return copy;
    }
    public byte[] getOmega() { return omega.clone(); }
    public byte[] getCurveParams() { return curveParams.clone(); }
    
    public int getHierarchyDepth() {
        return us.length;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        BLS12PublicKey that = (BLS12PublicKey) o;
        return Arrays.equals(y1, that.y1) &&
               Arrays.equals(y3, that.y3) &&
               Arrays.equals(y4, that.y4) &&
               Arrays.equals(t, that.t) &&
               Arrays.deepEquals(us, that.us) &&
               Arrays.equals(omega, that.omega) &&
               Arrays.equals(curveParams, that.curveParams);
    }
    
    @Override
    public int hashCode() {
        int result = Arrays.hashCode(y1);
        result = 31 * result + Arrays.hashCode(y3);
        result = 31 * result + Arrays.hashCode(y4);
        result = 31 * result + Arrays.hashCode(t);
        result = 31 * result + Arrays.deepHashCode(us);
        result = 31 * result + Arrays.hashCode(omega);
        result = 31 * result + Arrays.hashCode(curveParams);
        return result;
    }
}

