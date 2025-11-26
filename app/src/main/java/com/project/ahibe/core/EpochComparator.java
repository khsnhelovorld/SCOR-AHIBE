package com.project.ahibe.core;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;

/**
 * Utility class for comparing epoch strings (YYYY-MM-DD format).
 */
public final class EpochComparator {

    private static final DateTimeFormatter EPOCH_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE;

    private EpochComparator() {
    }

    /**
     * Convert epoch string (YYYY-MM-DD) to days since epoch (1970-01-01).
     * 
     * @param epoch The epoch string in YYYY-MM-DD format
     * @return Days since 1970-01-01, or 0 if parsing fails
     */
    public static long epochToDays(String epoch) {
        try {
            LocalDate date = LocalDate.parse(epoch, EPOCH_FORMATTER);
            return date.toEpochDay();
        } catch (DateTimeParseException e) {
            // If parsing fails, try to parse as number (for block height or timestamp)
            try {
                return Long.parseLong(epoch);
            } catch (NumberFormatException ex) {
                return 0;
            }
        }
    }

    /**
     * Compare two epoch strings.
     * 
     * @param epoch1 First epoch string
     * @param epoch2 Second epoch string
     * @return Negative if epoch1 < epoch2, zero if equal, positive if epoch1 > epoch2
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
     */
    public static boolean isAtOrAfter(String checkEpoch, long revEpochDays) {
        long checkDays = epochToDays(checkEpoch);
        return checkDays >= revEpochDays;
    }

    /**
     * Check if checkEpoch is before revEpoch (numeric).
     * 
     * @param checkEpoch The epoch to check (T_check) as string
     * @param revEpochDays The revocation epoch (T_rev) as days since epoch
     * @return true if checkEpoch < revEpoch
     */
    public static boolean isBefore(String checkEpoch, long revEpochDays) {
        long checkDays = epochToDays(checkEpoch);
        return checkDays < revEpochDays;
    }
}

