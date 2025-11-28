package com.project.ahibe.io;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.project.ahibe.crypto.ErrorLogger;
import com.project.ahibe.crypto.bls12.BLS12PublicKey;
import com.project.ahibe.crypto.bls12.BLS12SecretKey;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Utility class for serializing and deserializing BLS12-381 AHIBE keys.
 * Supports AES-GCM encrypted exports (with PBKDF2 key derivation) when
 * {@code DELEGATE_KEY_SECRET} is set, while keeping a legacy in-memory fallback
 * for demos without a passphrase.
 */
public class KeySerializer {

    private static final String FORMAT_MAGIC = "SCOR-AHIBE-DELEGATE-KEY-BLS12";
    private static final int FORMAT_VERSION = 2;
    private static final int SALT_BYTES = 16;
    private static final int IV_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final int PBKDF2_ITERATIONS = 200_000;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final ObjectMapper MAPPER = new ObjectMapper();

    // Legacy in-memory storage for demo mode (no passphrase)
    private static final Map<String, BLS12SecretKey> keyStore = new ConcurrentHashMap<>();

    /**
     * Export a delegate key to a file.
     * <p>If {@code DELEGATE_KEY_SECRET} is configured, the file will contain
     * an AES-GCM encrypted payload that can be imported across sessions. When
     * the secret is absent, we fall back to the legacy in-memory token format
     * (demo mode only).
     */
    public static void exportDelegateKey(BLS12SecretKey key, Path outputPath) throws IOException {
        try {
            Files.createDirectories(outputPath.getParent());
            Optional<String> secret = resolveSecret();
            if (secret.isEmpty()) {
                legacyExport(key, outputPath);
                return;
            }

            byte[] plaintext = MAPPER.writeValueAsBytes(SerializedKey.from(key));
            EncryptedKeyFile encrypted = encryptPayload(plaintext, secret.get().toCharArray());
            MAPPER.writerWithDefaultPrettyPrinter().writeValue(outputPath.toFile(), encrypted);
            System.out.println("      ✓ Delegate key encrypted with AES-GCM into " + outputPath.toAbsolutePath());
            System.out.println("      ℹ Set DELEGATE_KEY_SECRET consistently to import this key on another machine.");
        } catch (GeneralSecurityException e) {
            ErrorLogger.logError("KeySerializer.exportDelegateKey", "Failed to encrypt delegate key", e);
            throw new IOException("Failed to encrypt delegate key", e);
        } catch (Exception e) {
            ErrorLogger.logError("KeySerializer.exportDelegateKey", "Failed to export delegate key", e);
            throw new IOException("Failed to export delegate key", e);
        }
    }

    /**
     * Import a delegate key from disk. Automatically detects encrypted JSON
     * format vs. legacy token notes.
     */
    public static BLS12SecretKey importDelegateKey(Path inputPath, BLS12PublicKey publicKey) throws IOException {
        try {
            String content = Files.readString(inputPath).trim();
            if (content.startsWith("{")) {
                return importEncrypted(content);
            }
            return importLegacy(content);
        } catch (Exception e) {
            ErrorLogger.logError("KeySerializer.importDelegateKey", "Failed to import delegate key from " + inputPath, e);
            throw new IOException("Failed to import delegate key", e);
        }
    }

    /**
     * Clear legacy in-memory keys (testing helper).
     */
    public static void clearKeyStore() {
        keyStore.clear();
    }

    // ----- Legacy fallback (demo mode) -----

    /**
     * Legacy export for demo mode when DELEGATE_KEY_SECRET is not set.
     * 
     * SECURITY WARNING: This method stores keys in-memory only and exposes them
     * through a simple token mechanism. This is INSECURE and should only be used
     * for single-session demos. For any production or multi-session use:
     * 1. Set DELEGATE_KEY_SECRET environment variable to enable AES-GCM encryption
     * 2. Use a strong passphrase (at least 16 characters with mixed case, numbers, symbols)
     * 
     * @param key The secret key to export
     * @param outputPath The output file path
     * @throws IOException if file writing fails
     */
    private static void legacyExport(BLS12SecretKey key, Path outputPath) throws IOException {
        String keyToken = outputPath.getFileName().toString().replace(".key", "");
        keyStore.put(keyToken, key);

        StringBuilder sb = new StringBuilder();
        sb.append("# ============================================================================\n");
        sb.append("# AHIBE Delegate Key Export (Legacy Mode - INSECURE)\n");
        sb.append("# ============================================================================\n");
        sb.append("# Generated at: ").append(Instant.now()).append("\n");
        sb.append("#\n");
        sb.append("# ⚠️  SECURITY WARNING: DEMO MODE ONLY ⚠️\n");
        sb.append("#\n");
        sb.append("# This key file uses in-memory token storage which is INSECURE:\n");
        sb.append("# - Key is stored only in JVM memory (lost when application stops)\n");
        sb.append("# - Cannot be transferred to another machine or session\n");
        sb.append("# - No encryption or access control\n");
        sb.append("#\n");
        sb.append("# For secure key export, set DELEGATE_KEY_SECRET environment variable:\n");
        sb.append("#   Windows PowerShell: $env:DELEGATE_KEY_SECRET=\"your-strong-passphrase\"\n");
        sb.append("#   Linux/macOS: export DELEGATE_KEY_SECRET='your-strong-passphrase'\n");
        sb.append("#\n");
        sb.append("# With DELEGATE_KEY_SECRET set:\n");
        sb.append("# - Keys are encrypted with AES-256-GCM\n");
        sb.append("# - Key derivation uses PBKDF2 with 200,000 iterations\n");
        sb.append("# - Files can be safely transferred between machines\n");
        sb.append("#\n");
        sb.append("# ============================================================================\n\n");
        sb.append("KEY_TOKEN=").append(keyToken).append("\n");
        Files.writeString(outputPath, sb.toString(), StandardCharsets.UTF_8);

        // Print prominent warning to console
        System.err.println();
        System.err.println("╔════════════════════════════════════════════════════════════════════════╗");
        System.err.println("║  ⚠️  SECURITY WARNING: DEMO MODE - KEYS NOT ENCRYPTED  ⚠️               ║");
        System.err.println("╠════════════════════════════════════════════════════════════════════════╣");
        System.err.println("║  Key stored in memory only with token: " + padRight(keyToken, 32) + " ║");
        System.err.println("║                                                                        ║");
        System.err.println("║  This is INSECURE and only suitable for single-session demos.         ║");
        System.err.println("║  For production use, set DELEGATE_KEY_SECRET environment variable.    ║");
        System.err.println("╚════════════════════════════════════════════════════════════════════════╝");
        System.err.println();
        
        ErrorLogger.logInfo("KeySerializer.legacyExport", 
            "WARNING: Demo mode export used. Key stored in-memory only. " +
            "Set DELEGATE_KEY_SECRET for secure encrypted exports.");
    }
    
    private static String padRight(String s, int n) {
        if (s.length() >= n) {
            return s.substring(0, n);
        }
        return String.format("%-" + n + "s", s);
    }

    private static BLS12SecretKey importLegacy(String content) throws IOException {
        String keyToken = null;
        for (String line : content.split("\n")) {
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
            throw new IOException("Invalid legacy key file: missing KEY_TOKEN");
        }
        BLS12SecretKey key = keyStore.get(keyToken);
        if (key == null) {
            throw new IOException("Legacy key token not available in memory: " + keyToken +
                    "\nRegenerate the delegate key in the same JVM or migrate to encrypted exports.");
        }
        return key;
    }

    // ----- Encrypted format helpers -----

    private static BLS12SecretKey importEncrypted(String json) throws IOException {
        Optional<String> secret = resolveSecret();
        if (secret.isEmpty()) {
            throw new IOException("Encrypted key file detected but DELEGATE_KEY_SECRET is not set.");
        }
        try {
            EncryptedKeyFile file = MAPPER.readValue(json, EncryptedKeyFile.class);
            validateEncryptedFile(file);
            byte[] plaintext = decryptPayload(file, secret.get().toCharArray());
            SerializedKey payload = MAPPER.readValue(plaintext, SerializedKey.class);
            return payload.toSecretKey();
        } catch (GeneralSecurityException e) {
            ErrorLogger.logError("KeySerializer.importEncrypted", "Failed to decrypt delegate key", e);
            throw new IOException("Failed to decrypt delegate key", e);
        } catch (Exception e) {
            ErrorLogger.logError("KeySerializer.importEncrypted", "Failed to import encrypted key", e);
            throw new IOException("Failed to import encrypted key", e);
        }
    }

    private static Optional<String> resolveSecret() {
        String value = System.getenv("DELEGATE_KEY_SECRET");
        if (value == null || value.isBlank()) {
            return Optional.empty();
        }
        return Optional.of(value);
    }

    private static EncryptedKeyFile encryptPayload(byte[] plaintext, char[] secret)
            throws GeneralSecurityException {
        byte[] salt = RANDOM.generateSeed(SALT_BYTES);
        byte[] iv = RANDOM.generateSeed(IV_BYTES);
        SecretKeySpec keySpec = deriveKey(secret, salt);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] ciphertext = cipher.doFinal(plaintext);

        EncryptedKeyFile file = new EncryptedKeyFile();
        file.format = FORMAT_MAGIC;
        file.version = FORMAT_VERSION;
        file.createdAt = Instant.now().toString();
        file.kdf = "PBKDF2WithHmacSHA256";
        file.iterations = PBKDF2_ITERATIONS;
        file.salt = Base64.getEncoder().encodeToString(salt);
        file.iv = Base64.getEncoder().encodeToString(iv);
        file.ciphertext = Base64.getEncoder().encodeToString(ciphertext);
        return file;
    }

    private static byte[] decryptPayload(EncryptedKeyFile file, char[] secret)
            throws GeneralSecurityException {
        SecretKeySpec keySpec = deriveKey(secret, Base64.getDecoder().decode(file.salt));
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec,
                new GCMParameterSpec(GCM_TAG_BITS, Base64.getDecoder().decode(file.iv)));
        return cipher.doFinal(Base64.getDecoder().decode(file.ciphertext));
    }

    private static SecretKeySpec deriveKey(char[] secret, byte[] salt) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(secret, salt, PBKDF2_ITERATIONS, 256);
        return new SecretKeySpec(
                SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded(),
                "AES"
        );
    }

    private static void validateEncryptedFile(EncryptedKeyFile file) throws IOException {
        if (!FORMAT_MAGIC.equals(file.format)) {
            throw new IOException("Unknown key file format: " + file.format);
        }
        if (file.version != FORMAT_VERSION) {
            throw new IOException("Unsupported key file version: " + file.version + " (expected " + FORMAT_VERSION + ")");
        }
    }

    // ----- Serialization payloads -----

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private static final class EncryptedKeyFile {
        public String format;
        public int version;
        public String createdAt;
        public String kdf;
        public int iterations;
        public String salt;
        public String iv;
        public String ciphertext;
    }

    private record SerializedKey(
            String curveParams,
            String k11,
            String k12,
            String k21,
            String k22,
            List<String> e1s,
            List<String> e2s,
            List<String> ids
    ) {
        static SerializedKey from(BLS12SecretKey key) {
            return new SerializedKey(
                    new String(key.getCurveParams(), StandardCharsets.UTF_8),
                    Base64.getEncoder().encodeToString(key.getK11()),
                    Base64.getEncoder().encodeToString(key.getK12()),
                    Base64.getEncoder().encodeToString(key.getK21()),
                    Base64.getEncoder().encodeToString(key.getK22()),
                    encodeList(key.getE1s()),
                    encodeList(key.getE2s()),
                    encodeList(key.getIds())
            );
        }

        BLS12SecretKey toSecretKey() {
            byte[] curveParamsBytes = curveParams.getBytes(StandardCharsets.UTF_8);
            byte[] k11 = Base64.getDecoder().decode(this.k11);
            byte[] k12 = Base64.getDecoder().decode(this.k12);
            byte[] k21 = Base64.getDecoder().decode(this.k21);
            byte[] k22 = Base64.getDecoder().decode(this.k22);
            byte[][] e1s = decodeList(this.e1s);
            byte[][] e2s = decodeList(this.e2s);
            byte[][] ids = decodeList(this.ids);
            
            return new BLS12SecretKey(k11, k12, k21, k22, e1s, e2s, ids, curveParamsBytes);
        }

        private static List<String> encodeList(byte[][] arrays) {
            return java.util.Arrays.stream(arrays)
                    .map(arr -> Base64.getEncoder().encodeToString(arr))
                    .toList();
        }

        private static byte[][] decodeList(List<String> encoded) {
            byte[][] decoded = new byte[encoded.size()][];
            for (int i = 0; i < encoded.size(); i++) {
                decoded[i] = Base64.getDecoder().decode(encoded.get(i));
            }
            return decoded;
        }
    }
}
