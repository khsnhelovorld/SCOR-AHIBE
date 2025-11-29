package com.project.ahibe.crypto.bls12;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Objects;

/**
 * BLS12-381 Master Secret Key for AHIBE scheme.
 * Replaces AHIBEDIP10MasterSecretKeyParameters.
 */
public class BLS12MasterSecret implements Serializable {
    private static final long serialVersionUID = 1L;
    
    // Master secret: x1, alpha
    private final byte[] x1;
    private final byte[] alpha;
    
    // Curve parameters (serialized)
    private final byte[] curveParams;
    
    public BLS12MasterSecret(byte[] x1, byte[] alpha, byte[] curveParams) {
        this.x1 = Objects.requireNonNull(x1, "x1 cannot be null");
        this.alpha = Objects.requireNonNull(alpha, "alpha cannot be null");
        this.curveParams = Objects.requireNonNull(curveParams, "curveParams cannot be null");
    }
    
    public byte[] getX1() { return x1.clone(); }
    public byte[] getAlpha() { return alpha.clone(); }
    public byte[] getCurveParams() { return curveParams.clone(); }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        BLS12MasterSecret that = (BLS12MasterSecret) o;
        return Arrays.equals(x1, that.x1) &&
               Arrays.equals(alpha, that.alpha) &&
               Arrays.equals(curveParams, that.curveParams);
    }
    
    @Override
    public int hashCode() {
        int result = Arrays.hashCode(x1);
        result = 31 * result + Arrays.hashCode(alpha);
        result = 31 * result + Arrays.hashCode(curveParams);
        return result;
    }
}

