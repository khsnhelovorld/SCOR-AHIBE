package com.project.ahibe.ipfs;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

/**
 * Circuit breaker pattern implementation for IPFS operations.
 * 
 * Prevents cascading failures by temporarily blocking requests to
 * a failing service. States:
 * 
 * - CLOSED: Normal operation, requests pass through
 * - OPEN: Service is failing, requests are blocked
 * - HALF_OPEN: Testing if service recovered, limited requests allowed
 * 
 * Transitions:
 * - CLOSED -> OPEN: After failureThreshold consecutive failures
 * - OPEN -> HALF_OPEN: After openDuration has passed
 * - HALF_OPEN -> CLOSED: After successThreshold consecutive successes
 * - HALF_OPEN -> OPEN: After any failure
 */
public class CircuitBreaker {
    
    public enum State {
        CLOSED,
        OPEN,
        HALF_OPEN
    }
    
    private final String name;
    private final int failureThreshold;
    private final int successThreshold;
    private final Duration openDuration;
    private final Duration halfOpenDuration;
    
    private final AtomicReference<State> state;
    private final AtomicInteger failureCount;
    private final AtomicInteger successCount;
    private final AtomicReference<Instant> lastFailureTime;
    private final AtomicReference<Instant> stateChangedTime;
    
    /**
     * Create a circuit breaker with default settings.
     * 
     * @param name Identifier for logging
     */
    public CircuitBreaker(String name) {
        this(name, 5, 3, Duration.ofSeconds(30), Duration.ofSeconds(10));
    }
    
    /**
     * Create a circuit breaker with custom settings.
     * 
     * @param name Identifier for logging
     * @param failureThreshold Number of failures before opening circuit
     * @param successThreshold Number of successes in half-open to close circuit
     * @param openDuration How long to stay open before trying half-open
     * @param halfOpenDuration Maximum time in half-open before re-opening
     */
    public CircuitBreaker(String name, int failureThreshold, int successThreshold,
                         Duration openDuration, Duration halfOpenDuration) {
        if (failureThreshold <= 0 || successThreshold <= 0) {
            throw new IllegalArgumentException("Thresholds must be positive");
        }
        
        this.name = name;
        this.failureThreshold = failureThreshold;
        this.successThreshold = successThreshold;
        this.openDuration = openDuration;
        this.halfOpenDuration = halfOpenDuration;
        
        this.state = new AtomicReference<>(State.CLOSED);
        this.failureCount = new AtomicInteger(0);
        this.successCount = new AtomicInteger(0);
        this.lastFailureTime = new AtomicReference<>(Instant.MIN);
        this.stateChangedTime = new AtomicReference<>(Instant.now());
    }
    
    /**
     * Execute an operation through the circuit breaker.
     * 
     * @param operation The operation to execute
     * @return Result of the operation
     * @throws CircuitBreakerOpenException if circuit is open
     * @throws Exception if operation fails
     */
    public <T> T execute(Supplier<T> operation) throws Exception {
        if (!canExecute()) {
            throw new CircuitBreakerOpenException(
                String.format("Circuit breaker '%s' is OPEN. Last failure: %s", 
                    name, lastFailureTime.get())
            );
        }
        
        try {
            T result = operation.get();
            recordSuccess();
            return result;
        } catch (Exception e) {
            recordFailure();
            throw e;
        }
    }
    
    /**
     * Execute an operation that may throw checked exceptions.
     */
    public <T> T executeChecked(CheckedSupplier<T> operation) throws Exception {
        if (!canExecute()) {
            throw new CircuitBreakerOpenException(
                String.format("Circuit breaker '%s' is OPEN. Last failure: %s", 
                    name, lastFailureTime.get())
            );
        }
        
        try {
            T result = operation.get();
            recordSuccess();
            return result;
        } catch (Exception e) {
            recordFailure();
            throw e;
        }
    }
    
    /**
     * Check if an operation can be executed.
     */
    public boolean canExecute() {
        State currentState = state.get();
        
        switch (currentState) {
            case CLOSED:
                return true;
                
            case OPEN:
                // Check if we should transition to half-open
                if (shouldTransitionToHalfOpen()) {
                    transitionTo(State.HALF_OPEN);
                    return true;
                }
                return false;
                
            case HALF_OPEN:
                // In half-open, allow limited requests
                return true;
                
            default:
                return false;
        }
    }
    
    /**
     * Record a successful operation.
     */
    public void recordSuccess() {
        State currentState = state.get();
        
        if (currentState == State.HALF_OPEN) {
            int successes = successCount.incrementAndGet();
            if (successes >= successThreshold) {
                transitionTo(State.CLOSED);
            }
        } else if (currentState == State.CLOSED) {
            // Reset failure count on success
            failureCount.set(0);
        }
    }
    
    /**
     * Record a failed operation.
     */
    public void recordFailure() {
        lastFailureTime.set(Instant.now());
        State currentState = state.get();
        
        if (currentState == State.HALF_OPEN) {
            // Any failure in half-open goes back to open
            transitionTo(State.OPEN);
        } else if (currentState == State.CLOSED) {
            int failures = failureCount.incrementAndGet();
            if (failures >= failureThreshold) {
                transitionTo(State.OPEN);
            }
        }
    }
    
    private boolean shouldTransitionToHalfOpen() {
        Instant changedAt = stateChangedTime.get();
        return Instant.now().isAfter(changedAt.plus(openDuration));
    }
    
    private synchronized void transitionTo(State newState) {
        State oldState = state.get();
        if (oldState != newState) {
            state.set(newState);
            stateChangedTime.set(Instant.now());
            
            // Reset counters based on new state
            if (newState == State.CLOSED) {
                failureCount.set(0);
                successCount.set(0);
            } else if (newState == State.HALF_OPEN) {
                successCount.set(0);
            } else if (newState == State.OPEN) {
                successCount.set(0);
            }
            
            System.out.println(String.format(
                "[CircuitBreaker:%s] State changed: %s -> %s", name, oldState, newState));
        }
    }
    
    /**
     * Get current state.
     */
    public State getState() {
        // Check for automatic state transitions
        if (state.get() == State.OPEN && shouldTransitionToHalfOpen()) {
            transitionTo(State.HALF_OPEN);
        }
        return state.get();
    }
    
    /**
     * Get circuit breaker name.
     */
    public String getName() {
        return name;
    }
    
    /**
     * Get current failure count.
     */
    public int getFailureCount() {
        return failureCount.get();
    }
    
    /**
     * Get current success count (in half-open state).
     */
    public int getSuccessCount() {
        return successCount.get();
    }
    
    /**
     * Manually reset the circuit breaker to closed state.
     */
    public void reset() {
        transitionTo(State.CLOSED);
    }
    
    /**
     * Manually trip the circuit breaker to open state.
     */
    public void trip() {
        transitionTo(State.OPEN);
    }
    
    /**
     * Functional interface for operations that throw checked exceptions.
     */
    @FunctionalInterface
    public interface CheckedSupplier<T> {
        T get() throws Exception;
    }
    
    /**
     * Exception thrown when circuit breaker is open.
     */
    public static class CircuitBreakerOpenException extends RuntimeException {
        public CircuitBreakerOpenException(String message) {
            super(message);
        }
    }
}

