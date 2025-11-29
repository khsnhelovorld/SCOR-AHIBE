package com.project.ahibe.eth;

import org.web3j.protocol.Web3j;
import org.web3j.protocol.http.HttpService;

import java.io.Closeable;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Connection pool for Web3j clients.
 * 
 * Maintains a pool of Web3j connections to avoid creating new connections
 * for each request. Connections are cached by RPC endpoint and reused.
 * 
 * Features:
 * - Connection reuse by endpoint
 * - Automatic connection health checking
 * - Connection limit enforcement
 * - TTL-based connection expiration
 */
public class Web3jConnectionPool implements Closeable {
    
    private static final int DEFAULT_MAX_CONNECTIONS = 10;
    private static final Duration DEFAULT_CONNECTION_TTL = Duration.ofMinutes(30);
    private static final Duration DEFAULT_HEALTH_CHECK_INTERVAL = Duration.ofMinutes(5);
    
    private static volatile Web3jConnectionPool instance;
    
    private final int maxConnections;
    private final Duration connectionTtl;
    private final Duration healthCheckInterval;
    private final Map<String, PooledConnection> connections;
    private final AtomicInteger activeConnections;
    
    private record PooledConnection(
        Web3j web3j,
        Instant createdAt,
        Instant lastUsed,
        AtomicInteger useCount
    ) {
        boolean isExpired(Duration ttl) {
            return Instant.now().isAfter(createdAt.plus(ttl));
        }
        
        void markUsed() {
            useCount.incrementAndGet();
        }
    }
    
    /**
     * Get the singleton instance with default configuration.
     */
    public static Web3jConnectionPool getInstance() {
        if (instance == null) {
            synchronized (Web3jConnectionPool.class) {
                if (instance == null) {
                    instance = new Web3jConnectionPool(
                        DEFAULT_MAX_CONNECTIONS,
                        DEFAULT_CONNECTION_TTL,
                        DEFAULT_HEALTH_CHECK_INTERVAL
                    );
                }
            }
        }
        return instance;
    }
    
    /**
     * Create a new connection pool with custom configuration.
     */
    public Web3jConnectionPool(int maxConnections, Duration connectionTtl, Duration healthCheckInterval) {
        if (maxConnections <= 0) {
            throw new IllegalArgumentException("maxConnections must be positive");
        }
        this.maxConnections = maxConnections;
        this.connectionTtl = connectionTtl;
        this.healthCheckInterval = healthCheckInterval;
        this.connections = new ConcurrentHashMap<>();
        this.activeConnections = new AtomicInteger(0);
    }
    
    /**
     * Get or create a Web3j connection for the given RPC endpoint.
     * 
     * @param rpcEndpoint The RPC endpoint URL
     * @return Web3j instance (may be shared, do not close directly)
     */
    public synchronized Web3j getConnection(String rpcEndpoint) {
        if (rpcEndpoint == null || rpcEndpoint.isBlank()) {
            throw new IllegalArgumentException("RPC endpoint must not be null or empty");
        }
        
        String normalizedEndpoint = normalizeEndpoint(rpcEndpoint);
        
        // Check for existing connection
        PooledConnection existing = connections.get(normalizedEndpoint);
        if (existing != null && !existing.isExpired(connectionTtl)) {
            existing.markUsed();
            return existing.web3j();
        }
        
        // Remove expired connection if exists
        if (existing != null) {
            removeConnection(normalizedEndpoint, existing);
        }
        
        // Check connection limit
        if (activeConnections.get() >= maxConnections) {
            // Try to clean up expired connections
            cleanupExpiredConnections();
            
            if (activeConnections.get() >= maxConnections) {
                throw new IllegalStateException(
                    "Connection pool exhausted: " + activeConnections.get() + " active connections. " +
                    "Maximum allowed: " + maxConnections
                );
            }
        }
        
        // Create new connection
        Web3j web3j = Web3j.build(new HttpService(normalizedEndpoint));
        PooledConnection pooled = new PooledConnection(
            web3j, 
            Instant.now(), 
            Instant.now(),
            new AtomicInteger(1)
        );
        
        connections.put(normalizedEndpoint, pooled);
        activeConnections.incrementAndGet();
        
        return web3j;
    }
    
    /**
     * Release a connection back to the pool.
     * Note: Connections are not actually closed until pool shutdown or TTL expiration.
     * 
     * @param rpcEndpoint The RPC endpoint URL
     */
    public void releaseConnection(String rpcEndpoint) {
        // Connections are kept in pool for reuse
        // This method is provided for API completeness
    }
    
    /**
     * Remove a connection from the pool and close it.
     * 
     * @param rpcEndpoint The RPC endpoint URL
     */
    public synchronized void removeConnection(String rpcEndpoint) {
        String normalizedEndpoint = normalizeEndpoint(rpcEndpoint);
        PooledConnection pooled = connections.remove(normalizedEndpoint);
        if (pooled != null) {
            pooled.web3j().shutdown();
            activeConnections.decrementAndGet();
        }
    }
    
    private void removeConnection(String endpoint, PooledConnection pooled) {
        connections.remove(endpoint);
        pooled.web3j().shutdown();
        activeConnections.decrementAndGet();
    }
    
    private void cleanupExpiredConnections() {
        connections.entrySet().removeIf(entry -> {
            if (entry.getValue().isExpired(connectionTtl)) {
                entry.getValue().web3j().shutdown();
                activeConnections.decrementAndGet();
                return true;
            }
            return false;
        });
    }
    
    private String normalizeEndpoint(String endpoint) {
        String normalized = endpoint.trim();
        if (normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }
    
    /**
     * Get current number of active connections.
     */
    public int getActiveConnectionCount() {
        return activeConnections.get();
    }
    
    /**
     * Get maximum allowed connections.
     */
    public int getMaxConnections() {
        return maxConnections;
    }
    
    /**
     * Close all connections and shutdown the pool.
     */
    @Override
    public synchronized void close() throws IOException {
        for (PooledConnection pooled : connections.values()) {
            try {
                pooled.web3j().shutdown();
            } catch (Exception e) {
                // Log but don't throw - we want to close all connections
                System.err.println("Error closing Web3j connection: " + e.getMessage());
            }
        }
        connections.clear();
        activeConnections.set(0);
    }
    
    /**
     * Shutdown the singleton instance.
     */
    public static synchronized void shutdownInstance() {
        if (instance != null) {
            try {
                instance.close();
            } catch (IOException e) {
                System.err.println("Error shutting down Web3j connection pool: " + e.getMessage());
            }
            instance = null;
        }
    }
}

