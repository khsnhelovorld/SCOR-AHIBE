package com.project.ahibe.crypto;

import com.project.ahibe.crypto.bls12.BLS12PublicKey;

import java.util.Arrays;

public final class CryptoMetrics {

    private CryptoMetrics() {
    }

    public static int estimatePublicKeySize(BLS12PublicKey pk) {
        int total = 0;
        total += pk.getY1().length;
        total += pk.getY3().length;
        total += pk.getY4().length;
        total += pk.getT().length;
        total += pk.getOmega().length;
        return total + Arrays.stream(pk.getUs()).mapToInt(e -> e.length).sum();
    }

    public static int ciphertextSize(byte[] ciphertext) {
        return ciphertext == null ? 0 : ciphertext.length;
    }

    public static int sessionKeySize(byte[] sessionKey) {
        return sessionKey == null ? 0 : sessionKey.length;
    }
}

