package com.project.ahibe.core;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;

/**
 * Utility class for comparing epoch strings (YYYY-MM-DD format).
 * 
 * Epochs represent dates and are used for time-based revocation in SCOR-AHIBE.
 * All epoch strings must be in ISO-8601 date format (YYYY-MM-DD).
 */
public final class EpochComparator {

    private static final DateTimeFormatter EPOCH_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE;
    
    // Validation constants
    private static final int EPOCH_MIN_YEAR = 1970;
    private static final int EPOCH_MAX_YEAR = 2100;

    private EpochComparator() {
    }

    /**
     * Convert epoch string (YYYY-MM-DD) to days since epoch (1970-01-01).
     * 
     * @param epoch The epoch string in YYYY-MM-DD format
     * @return Days since 1970-01-01
     * @throws InvalidEpochException if the epoch string cannot be parsed or is out of valid range
     */
    public static long epochToDays(String epoch) {
        if (epoch == null || epoch.isBlank()) {
            throw new InvalidEpochException("Epoch must not be null or empty");
        }
        
        String trimmedEpoch = epoch.trim();
        
        // Try parsing as ISO date first
        try {
            LocalDate date = LocalDate.parse(trimmedEpoch, EPOCH_FORMATTER);
            validateDateRange(date, trimmedEpoch);
            return date.toEpochDay();
        } catch (DateTimeParseException e) {
            // If not a date, try parsing as numeric (days since epoch or timestamp)
            return parseNumericEpoch(trimmedEpoch, e);
        }
    }
    
    /**
     * Validate that the epoch string has correct format without throwing.
     * 
     * @param epoch The epoch string to validate
     * @return true if valid, false otherwise
     */
    public static boolean isValidEpoch(String epoch) {
        if (epoch == null || epoch.isBlank()) {
            return false;
        }
        
        try {
            epochToDays(epoch);
            return true;
        } catch (InvalidEpochException e) {
            return false;
        }
    }
    
    /**
     * Validate epoch string and return detailed error message if invalid.
     * 
     * @param epoch The epoch string to validate
     * @return Empty string if valid, error message if invalid
     */
    public static String validateEpoch(String epoch) {
        if (epoch == null) {
            return "Epoch must not be null";
        }
        if (epoch.isBlank()) {
            return "Epoch must not be empty or blank";
        }
        
        try {
            epochToDays(epoch);
            return "";
        } catch (InvalidEpochException e) {
            return e.getMessage();
        }
    }

    private static void validateDateRange(LocalDate date, String original) {
        int year = date.getYear();
        if (year < EPOCH_MIN_YEAR) {
            throw new InvalidEpochException(
                String.format("Epoch year %d is before minimum allowed year %d: '%s'", 
                    year, EPOCH_MIN_YEAR, original)
            );
        }
        if (year > EPOCH_MAX_YEAR) {
            throw new InvalidEpochException(
                String.format("Epoch year %d is after maximum allowed year %d: '%s'", 
                    year, EPOCH_MAX_YEAR, original)
            );
        }
    }
    
    private static long parseNumericEpoch(String epoch, DateTimeParseException originalException) {
        try {
            long numericValue = Long.parseLong(epoch);
            
            // Validate numeric epoch is reasonable
            // Days since 1970: reasonable range is 0 to ~50000 (year 2100)
            if (numericValue < 0) {
                throw new InvalidEpochException(
                    String.format("Numeric epoch must not be negative: %d", numericValue)
                );
            }
            
            // If value seems like a timestamp (> year 2100 in days), reject it
            long maxDays = (EPOCH_MAX_YEAR - 1970) * 366L; // ~47816 days
            if (numericValue > maxDays) {
                throw new InvalidEpochException(
                    String.format("Numeric epoch %d exceeds maximum allowed value %d (approximately year %d)", 
                        numericValue, maxDays, EPOCH_MAX_YEAR)
                );
            }
            
            return numericValue;
        } catch (NumberFormatException ex) {
            throw new InvalidEpochException(
                String.format("Invalid epoch format '%s': expected YYYY-MM-DD date or numeric days since epoch. " +
                    "Parse error: %s", epoch, originalException.getMessage()),
                originalException
            );
        }
    }

    /**
     * Compare two epoch strings.
     * 
     * @param epoch1 First epoch string
     * @param epoch2 Second epoch string
     * @return Negative if epoch1 < epoch2, zero if equal, positive if epoch1 > epoch2
     * @throws InvalidEpochException if either epoch string is invalid
     */
    public static int compare(String epoch1, String epoch2) {
        long days1 = epochToDays(epoch1);
        long days2 = epochToDays(epoch2);
        return Long.compare(days1, days2);
    }

    /**
     * Check if checkEpoch is before revEpoch.
     * 
     * @param checkEpoch The epoch to check (T_check)
     * @param revEpoch The revocation epoch (T_rev)
     * @return true if checkEpoch < revEpoch
     * @throws InvalidEpochException if either epoch string is invalid
     */
    public static boolean isBefore(String checkEpoch, String revEpoch) {
        return compare(checkEpoch, revEpoch) < 0;
    }

    /**
     * Check if checkEpoch is at or after revEpoch.
     * 
     * @param checkEpoch The epoch to check (T_check)
     * @param revEpoch The revocation epoch (T_rev)
     * @return true if checkEpoch >= revEpoch
     * @throws InvalidEpochException if either epoch string is invalid
     */
    public static boolean isAtOrAfter(String checkEpoch, String revEpoch) {
        return compare(checkEpoch, revEpoch) >= 0;
    }

    /**
     * Check if checkEpoch is at or after revEpoch (numeric).
     * 
     * @param checkEpoch The epoch to check (T_check) as string
     * @param revEpochDays The revocation epoch (T_rev) as days since epoch
     * @return true if checkEpoch >= revEpoch
     * @throws InvalidEpochException if checkEpoch is invalid
     */
    public static boolean isAtOrAfter(String checkEpoch, long revEpochDays) {
        if (revEpochDays < 0) {
            throw new InvalidEpochException("Revocation epoch days must not be negative: " + revEpochDays);
        }
        long checkDays = epochToDays(checkEpoch);
        return checkDays >= revEpochDays;
    }

    /**
     * Check if checkEpoch is before revEpoch (numeric).
     * 
     * @param checkEpoch The epoch to check (T_check) as string
     * @param revEpochDays The revocation epoch (T_rev) as days since epoch
     * @return true if checkEpoch < revEpoch
     * @throws InvalidEpochException if checkEpoch is invalid
     */
    public static boolean isBefore(String checkEpoch, long revEpochDays) {
        if (revEpochDays < 0) {
            throw new InvalidEpochException("Revocation epoch days must not be negative: " + revEpochDays);
        }
        long checkDays = epochToDays(checkEpoch);
        return checkDays < revEpochDays;
    }
    
    /**
     * Convert days since epoch to ISO date string (YYYY-MM-DD).
     * 
     * @param days Days since 1970-01-01
     * @return ISO date string
     * @throws InvalidEpochException if days is out of valid range
     */
    public static String daysToEpoch(long days) {
        if (days < 0) {
            throw new InvalidEpochException("Days since epoch must not be negative: " + days);
        }
        
        LocalDate date = LocalDate.ofEpochDay(days);
        validateDateRange(date, String.valueOf(days));
        
        return date.format(EPOCH_FORMATTER);
    }
    
    /**
     * Exception thrown when an epoch string is invalid.
     */
    public static class InvalidEpochException extends IllegalArgumentException {
        public InvalidEpochException(String message) {
            super(message);
        }
        
        public InvalidEpochException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
