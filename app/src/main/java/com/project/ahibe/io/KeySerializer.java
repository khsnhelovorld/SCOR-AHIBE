package com.project.ahibe.io;

import it.unisa.dia.gas.crypto.jpbc.fe.ibe.dip10.params.AHIBEDIP10PublicKeyParameters;
import it.unisa.dia.gas.crypto.jpbc.fe.ibe.dip10.params.AHIBEDIP10SecretKeyParameters;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Utility class for serializing and deserializing AHIBE keys.
 * Allows keys to be exported to files and imported from files,
 * enabling secure transfer of delegate keys between Holder and Verifier.
 * 
 * Since AHIBE key parameters don't implement Serializable, we store them
 * as byte arrays using getEncoded() method (if available) or custom serialization.
 * 
 * For demo purposes, we use a simple approach: store the key object reference
 * in memory and pass a token/ID. In production, implement proper key marshalling.
 */
public class KeySerializer {
    
    // Simple in-memory storage for demo purposes
    // In production, use proper key marshalling or external key management system
    private static final java.util.Map<String, AHIBEDIP10SecretKeyParameters> keyStore = 
        new java.util.concurrent.ConcurrentHashMap<>();
    
    /**
     * Export a delegate key to a file.
     * For demo purposes, this stores the key in memory and writes a reference token to file.
     * 
     * @param key the AHIBE secret key to export
     * @param outputPath the file path where the key reference will be saved
     * @throws IOException if file write fails
     */
    public static void exportDelegateKey(AHIBEDIP10SecretKeyParameters key, Path outputPath) throws IOException {
        // Ensure parent directory exists
        Files.createDirectories(outputPath.getParent());
        
        // Generate a unique token for this key
        String keyToken = outputPath.getFileName().toString().replace(".key", "");
        
        // Store key in memory with token
        keyStore.put(keyToken, key);
        
        // Write token and metadata to file
        StringBuilder sb = new StringBuilder();
        sb.append("# AHIBE Delegate Key Export\n");
        sb.append("# This file contains a reference to a hierarchical delegate key\n");
        sb.append("# DO NOT share this file with untrusted parties\n");
        sb.append("# Generated at: ").append(java.time.Instant.now()).append("\n");
        sb.append("# Note: This is a demo implementation using in-memory key storage\n");
        sb.append("# In production, implement proper key marshalling\n");
        sb.append("\n");
        sb.append("KEY_TOKEN=").append(keyToken).append("\n");
        
        Files.writeString(outputPath, sb.toString());
        
        System.out.println("      ⚠ Demo Mode: Key stored in memory with token: " + keyToken);
        System.out.println("      ℹ In production, implement proper key serialization/marshalling");
    }
    
    /**
     * Import a delegate key from a file that was previously exported.
     * 
     * @param inputPath the file path to read the key reference from
     * @param publicKey the public parameters (not used in demo, but kept for API consistency)
     * @return the reconstructed AHIBE secret key
     * @throws IOException if file read fails or key not found
     */
    public static AHIBEDIP10SecretKeyParameters importDelegateKey(
            Path inputPath, 
            AHIBEDIP10PublicKeyParameters publicKey) throws IOException {
        
        String content = Files.readString(inputPath);
        String[] lines = content.split("\n");
        
        String keyToken = null;
        for (String line : lines) {
            // Skip comments and blank lines
            if (line.startsWith("#") || line.isBlank()) {
                continue;
            }
            
            String[] parts = line.split("=", 2);
            if (parts.length == 2 && parts[0].trim().equals("KEY_TOKEN")) {
                keyToken = parts[1].trim();
                break;
            }
        }
        
        if (keyToken == null) {
            throw new IOException("Invalid key file format: missing KEY_TOKEN field");
        }
        
        // Retrieve key from in-memory storage
        AHIBEDIP10SecretKeyParameters key = keyStore.get(keyToken);
        if (key == null) {
            throw new IOException("Key not found in storage. Token: " + keyToken + 
                "\nNote: In demo mode, keys must be generated in the same session.");
        }
        
        return key;
    }
    
    /**
     * Clear all stored keys (useful for testing)
     */
    public static void clearKeyStore() {
        keyStore.clear();
    }
}
