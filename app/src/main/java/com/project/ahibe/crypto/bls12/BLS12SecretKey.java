package com.project.ahibe.crypto.bls12;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Objects;

/**
 * BLS12-381 Secret Key for AHIBE scheme.
 * Replaces AHIBEDIP10SecretKeyParameters.
 */
public class BLS12SecretKey implements Serializable {
    private static final long serialVersionUID = 1L;
    
    // Secret key components: k11, k12, k21, k22, e1s[], e2s[], ids[]
    private final byte[] k11;
    private final byte[] k12;
    private final byte[] k21;
    private final byte[] k22;
    private final byte[][] e1s;
    private final byte[][] e2s;
    private final byte[][] ids;
    
    // Curve parameters (serialized)
    private final byte[] curveParams;
    
    public BLS12SecretKey(byte[] k11, byte[] k12, byte[] k21, byte[] k22,
                         byte[][] e1s, byte[][] e2s, byte[][] ids, byte[] curveParams) {
        this.k11 = Objects.requireNonNull(k11, "k11 cannot be null");
        this.k12 = Objects.requireNonNull(k12, "k12 cannot be null");
        this.k21 = Objects.requireNonNull(k21, "k21 cannot be null");
        this.k22 = Objects.requireNonNull(k22, "k22 cannot be null");
        this.e1s = Objects.requireNonNull(e1s, "e1s cannot be null");
        this.e2s = Objects.requireNonNull(e2s, "e2s cannot be null");
        this.ids = Objects.requireNonNull(ids, "ids cannot be null");
        this.curveParams = Objects.requireNonNull(curveParams, "curveParams cannot be null");
    }
    
    public byte[] getK11() { return k11.clone(); }
    public byte[] getK12() { return k12.clone(); }
    public byte[] getK21() { return k21.clone(); }
    public byte[] getK22() { return k22.clone(); }
    public byte[][] getE1s() {
        byte[][] copy = new byte[e1s.length][];
        for (int i = 0; i < e1s.length; i++) {
            copy[i] = e1s[i].clone();
        }
        return copy;
    }
    public byte[][] getE2s() {
        byte[][] copy = new byte[e2s.length][];
        for (int i = 0; i < e2s.length; i++) {
            copy[i] = e2s[i].clone();
        }
        return copy;
    }
    public byte[][] getIds() {
        byte[][] copy = new byte[ids.length][];
        for (int i = 0; i < ids.length; i++) {
            copy[i] = ids[i].clone();
        }
        return copy;
    }
    public byte[] getCurveParams() { return curveParams.clone(); }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        BLS12SecretKey that = (BLS12SecretKey) o;
        return Arrays.equals(k11, that.k11) &&
               Arrays.equals(k12, that.k12) &&
               Arrays.equals(k21, that.k21) &&
               Arrays.equals(k22, that.k22) &&
               Arrays.deepEquals(e1s, that.e1s) &&
               Arrays.deepEquals(e2s, that.e2s) &&
               Arrays.deepEquals(ids, that.ids) &&
               Arrays.equals(curveParams, that.curveParams);
    }
    
    @Override
    public int hashCode() {
        int result = Arrays.hashCode(k11);
        result = 31 * result + Arrays.hashCode(k12);
        result = 31 * result + Arrays.hashCode(k21);
        result = 31 * result + Arrays.hashCode(k22);
        result = 31 * result + Arrays.deepHashCode(e1s);
        result = 31 * result + Arrays.deepHashCode(e2s);
        result = 31 * result + Arrays.deepHashCode(ids);
        result = 31 * result + Arrays.hashCode(curveParams);
        return result;
    }
}

