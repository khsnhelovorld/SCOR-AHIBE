package com.project.ahibe.core;

import java.util.regex.Pattern;

/**
 * Input validation utilities for SCOR-AHIBE system.
 * 
 * Provides comprehensive validation for:
 * - Holder IDs (format, length, character restrictions)
 * - Epoch strings (format, date range)
 * - Boundary checks for various inputs
 */
public final class InputValidator {
    
    // Holder ID constraints
    private static final int HOLDER_ID_MIN_LENGTH = 3;
    private static final int HOLDER_ID_MAX_LENGTH = 256;
    
    // Pattern for valid holder ID: alphanumeric, @, ., _, -, :
    // Must start with alphanumeric or "holder:"
    private static final Pattern HOLDER_ID_PATTERN = Pattern.compile(
        "^(holder:)?[a-zA-Z0-9][a-zA-Z0-9@._\\-:]{" + (HOLDER_ID_MIN_LENGTH - 1) + "," + (HOLDER_ID_MAX_LENGTH - 1) + "}$"
    );
    
    // Dangerous characters that could cause injection issues
    private static final Pattern DANGEROUS_CHARS = Pattern.compile("[<>\"'`;\\\\|&$]");
    
    // IPFS CID pattern (simplified - covers CIDv0 and CIDv1)
    private static final Pattern CID_PATTERN = Pattern.compile(
        "^(Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{58,})$"
    );
    
    // Storage pointer pattern (IPFS CID or ipfs:// URI)
    private static final Pattern STORAGE_POINTER_PATTERN = Pattern.compile(
        "^(ipfs://)?[a-zA-Z0-9]+$"
    );
    
    private InputValidator() {}
    
    /**
     * Validate holder ID format and content.
     * 
     * @param holderId The holder ID to validate
     * @throws InvalidInputException if validation fails
     */
    public static void validateHolderId(String holderId) {
        if (holderId == null) {
            throw new InvalidInputException("Holder ID must not be null");
        }
        
        String trimmed = holderId.trim();
        
        if (trimmed.isEmpty()) {
            throw new InvalidInputException("Holder ID must not be empty");
        }
        
        if (trimmed.length() < HOLDER_ID_MIN_LENGTH) {
            throw new InvalidInputException(
                String.format("Holder ID must be at least %d characters: '%s' (length: %d)",
                    HOLDER_ID_MIN_LENGTH, trimmed, trimmed.length())
            );
        }
        
        if (trimmed.length() > HOLDER_ID_MAX_LENGTH) {
            throw new InvalidInputException(
                String.format("Holder ID must be at most %d characters: length %d exceeds maximum",
                    HOLDER_ID_MAX_LENGTH, trimmed.length())
            );
        }
        
        if (DANGEROUS_CHARS.matcher(trimmed).find()) {
            throw new InvalidInputException(
                String.format("Holder ID contains dangerous characters: '%s'. " +
                    "Allowed characters: alphanumeric, @, ., _, -, :", trimmed)
            );
        }
        
        if (!HOLDER_ID_PATTERN.matcher(trimmed).matches()) {
            throw new InvalidInputException(
                String.format("Holder ID has invalid format: '%s'. " +
                    "Must start with alphanumeric or 'holder:' prefix, " +
                    "followed by alphanumeric or @._-: characters", trimmed)
            );
        }
    }
    
    /**
     * Check if holder ID is valid without throwing.
     */
    public static boolean isValidHolderId(String holderId) {
        try {
            validateHolderId(holderId);
            return true;
        } catch (InvalidInputException e) {
            return false;
        }
    }
    
    /**
     * Validate epoch string.
     * Delegates to EpochComparator for actual validation.
     * 
     * @param epoch The epoch string to validate
     * @throws InvalidInputException if validation fails
     */
    public static void validateEpoch(String epoch) {
        if (epoch == null) {
            throw new InvalidInputException("Epoch must not be null");
        }
        
        String trimmed = epoch.trim();
        if (trimmed.isEmpty()) {
            throw new InvalidInputException("Epoch must not be empty");
        }
        
        String error = EpochComparator.validateEpoch(trimmed);
        if (!error.isEmpty()) {
            throw new InvalidInputException("Invalid epoch: " + error);
        }
    }
    
    /**
     * Check if epoch is valid without throwing.
     */
    public static boolean isValidEpoch(String epoch) {
        return EpochComparator.isValidEpoch(epoch);
    }
    
    /**
     * Validate storage pointer (IPFS CID or URI).
     * 
     * @param pointer The storage pointer to validate
     * @throws InvalidInputException if validation fails
     */
    public static void validateStoragePointer(String pointer) {
        if (pointer == null) {
            throw new InvalidInputException("Storage pointer must not be null");
        }
        
        String trimmed = pointer.trim();
        if (trimmed.isEmpty()) {
            throw new InvalidInputException("Storage pointer must not be empty");
        }
        
        // Remove ipfs:// prefix if present
        String cid = trimmed;
        if (cid.startsWith("ipfs://")) {
            cid = cid.substring(7);
        }
        
        // Basic format check
        if (cid.length() < 10 || cid.length() > 100) {
            throw new InvalidInputException(
                String.format("Storage pointer has invalid length: %d. Expected 10-100 characters.", cid.length())
            );
        }
        
        // Check for dangerous characters
        if (DANGEROUS_CHARS.matcher(cid).find()) {
            throw new InvalidInputException(
                String.format("Storage pointer contains dangerous characters: '%s'", pointer)
            );
        }
    }
    
    /**
     * Validate byte array is not null or empty.
     * 
     * @param data The byte array to validate
     * @param fieldName Name of the field for error messages
     * @throws InvalidInputException if validation fails
     */
    public static void validateByteArray(byte[] data, String fieldName) {
        if (data == null) {
            throw new InvalidInputException(fieldName + " must not be null");
        }
        if (data.length == 0) {
            throw new InvalidInputException(fieldName + " must not be empty");
        }
    }
    
    /**
     * Validate byte array has expected length.
     * 
     * @param data The byte array to validate
     * @param expectedLength Expected length
     * @param fieldName Name of the field for error messages
     * @throws InvalidInputException if validation fails
     */
    public static void validateByteArrayLength(byte[] data, int expectedLength, String fieldName) {
        validateByteArray(data, fieldName);
        if (data.length != expectedLength) {
            throw new InvalidInputException(
                String.format("%s has invalid length: expected %d bytes, got %d",
                    fieldName, expectedLength, data.length)
            );
        }
    }
    
    /**
     * Validate byte array has minimum length.
     * 
     * @param data The byte array to validate
     * @param minLength Minimum length
     * @param fieldName Name of the field for error messages
     * @throws InvalidInputException if validation fails
     */
    public static void validateByteArrayMinLength(byte[] data, int minLength, String fieldName) {
        validateByteArray(data, fieldName);
        if (data.length < minLength) {
            throw new InvalidInputException(
                String.format("%s too short: expected at least %d bytes, got %d",
                    fieldName, minLength, data.length)
            );
        }
    }
    
    /**
     * Validate positive integer.
     * 
     * @param value The value to validate
     * @param fieldName Name of the field for error messages
     * @throws InvalidInputException if validation fails
     */
    public static void validatePositive(int value, String fieldName) {
        if (value <= 0) {
            throw new InvalidInputException(
                String.format("%s must be positive: got %d", fieldName, value)
            );
        }
    }
    
    /**
     * Validate non-negative integer.
     * 
     * @param value The value to validate
     * @param fieldName Name of the field for error messages
     * @throws InvalidInputException if validation fails
     */
    public static void validateNonNegative(long value, String fieldName) {
        if (value < 0) {
            throw new InvalidInputException(
                String.format("%s must not be negative: got %d", fieldName, value)
            );
        }
    }
    
    /**
     * Validate value is within range.
     * 
     * @param value The value to validate
     * @param min Minimum value (inclusive)
     * @param max Maximum value (inclusive)
     * @param fieldName Name of the field for error messages
     * @throws InvalidInputException if validation fails
     */
    public static void validateRange(long value, long min, long max, String fieldName) {
        if (value < min || value > max) {
            throw new InvalidInputException(
                String.format("%s must be in range [%d, %d]: got %d", 
                    fieldName, min, max, value)
            );
        }
    }
    
    /**
     * Sanitize holder ID by normalizing format.
     * Does NOT validate - call validateHolderId first.
     * 
     * @param holderId The holder ID to sanitize
     * @return Sanitized holder ID
     */
    public static String sanitizeHolderId(String holderId) {
        if (holderId == null) {
            return null;
        }
        
        String trimmed = holderId.trim();
        
        // Ensure holder: prefix if not present
        if (!trimmed.startsWith("holder:")) {
            return "holder:" + trimmed;
        }
        
        return trimmed;
    }
    
    /**
     * Normalize holder ID by trimming, lowercasing, and ensuring holder: prefix.
     * This prevents case-sensitivity issues when comparing holder IDs.
     * 
     * @param holderId The holder ID to normalize
     * @return Normalized holder ID (lowercase with holder: prefix)
     */
    public static String normalizeHolderId(String holderId) {
        if (holderId == null) {
            return null;
        }
        
        String trimmed = holderId.trim().toLowerCase(java.util.Locale.ROOT);
        
        // Ensure holder: prefix if not present
        if (!trimmed.startsWith("holder:")) {
            return "holder:" + trimmed;
        }
        
        return trimmed;
    }
    
    /**
     * Exception thrown when input validation fails.
     */
    public static class InvalidInputException extends IllegalArgumentException {
        public InvalidInputException(String message) {
            super(message);
        }
        
        public InvalidInputException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}

