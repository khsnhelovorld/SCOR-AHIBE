package com.project.ahibe.crypto;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.time.Instant;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Centralized error logging utility for debugging cryptographic operations.
 * Logs errors to both console and file for analysis.
 */
public class ErrorLogger {
    private static final String LOG_FILE = "ahibe-errors.log";
    private static final ReentrantLock lock = new ReentrantLock();
    private static PrintWriter logWriter;
    
    static {
        try {
            logWriter = new PrintWriter(new FileWriter(LOG_FILE, true));
        } catch (IOException e) {
            System.err.println("Failed to initialize error logger: " + e.getMessage());
        }
    }
    
    public static void logError(String operation, String message, Throwable error) {
        lock.lock();
        try {
            String timestamp = Instant.now().toString();
            String logEntry = String.format("[%s] ERROR in %s: %s", timestamp, operation, message);
            
            // Log to console
            System.err.println(logEntry);
            if (error != null) {
                System.err.println("  Exception: " + error.getClass().getName());
                System.err.println("  Message: " + error.getMessage());
                error.printStackTrace(System.err);
            }
            
            // Log to file
            if (logWriter != null) {
                logWriter.println(logEntry);
                if (error != null) {
                    logWriter.println("  Exception: " + error.getClass().getName());
                    logWriter.println("  Message: " + error.getMessage());
                    error.printStackTrace(logWriter);
                }
                logWriter.flush();
            }
        } finally {
            lock.unlock();
        }
    }
    
    public static void logInfo(String operation, String message) {
        lock.lock();
        try {
            String timestamp = Instant.now().toString();
            String logEntry = String.format("[%s] INFO in %s: %s", timestamp, operation, message);
            
            System.out.println(logEntry);
            
            if (logWriter != null) {
                logWriter.println(logEntry);
                logWriter.flush();
            }
        } finally {
            lock.unlock();
        }
    }
    
    public static void close() {
        lock.lock();
        try {
            if (logWriter != null) {
                logWriter.close();
                logWriter = null;
            }
        } finally {
            lock.unlock();
        }
    }
}

