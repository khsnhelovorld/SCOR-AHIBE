package com.project.ahibe.io;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public final class ByteEncoding {

    private ByteEncoding() {
    }

    public static String toHex(byte[] data) {
        StringBuilder builder = new StringBuilder(2 + data.length * 2);
        builder.append("0x");
        for (byte b : data) {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    }

    public static byte[] fromHex(String hex) {
        String normalized = hex.startsWith("0x") ? hex.substring(2) : hex;
        if (normalized.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string must have even length");
        }
        byte[] bytes = new byte[normalized.length() / 2];
        for (int i = 0; i < normalized.length(); i += 2) {
            bytes[i / 2] = (byte) Integer.parseInt(normalized.substring(i, i + 2), 16);
        }
        return bytes;
    }

    public static String toBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public static byte[] fromBase64(String value) {
        return Base64.getDecoder().decode(value.getBytes(StandardCharsets.UTF_8));
    }
}

