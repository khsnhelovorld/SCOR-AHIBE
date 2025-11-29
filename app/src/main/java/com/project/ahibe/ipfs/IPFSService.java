package com.project.ahibe.ipfs;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.Call;
import okhttp3.HttpUrl;
import okhttp3.MediaType;
import okhttp3.MultipartBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;

/**
 * Service for interacting with IPFS to upload and download revocation certificates.
 * 
 * Features:
 * - Retries with exponential backoff
 * - Optional authentication (Bearer token, Basic auth)
 * - TLS/mTLS support with custom certificates
 * - Automatic pinning after upload
 * - Gateway fallback for read operations
 * - Circuit breaker for failure protection
 * 
 * Configuration via environment variables:
 * - IPFS_HOST, IPFS_PORT: Direct IPFS API endpoint
 * - IPFS_URL: Alternative URL-based configuration
 * - IPFS_GATEWAY_URL: Fallback gateway for reads
 * - IPFS_PIN_AFTER_ADD: Enable/disable automatic pinning
 * - IPFS_MAX_RETRIES: Number of retry attempts
 * - IPFS_RETRY_BACKOFF_MS: Initial backoff duration
 * - IPFS_API_BEARER_TOKEN, IPFS_API_BASIC_AUTH: Authentication
 * - IPFS_TLS_INSECURE, IPFS_CLIENT_CERT_*, IPFS_CA_CERT_PATH: TLS options
 */
public class IPFSService {
    private static final MediaType OCTET_STREAM = MediaType.parse("application/octet-stream");
    private static final RequestBody EMPTY_BODY = RequestBody.create(new byte[0], OCTET_STREAM);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final String ipfsBaseUrl;
    private final OkHttpClient httpClient;
    private final IpfsOptions options;
    private final CircuitBreaker circuitBreaker;

    public IPFSService(String ipfsHost, int ipfsPort) {
        this(buildBaseUrl("http://" + ipfsHost + ":" + ipfsPort), IpfsOptions.fromEnv());
    }

    public IPFSService(String ipfsUrl) {
        this(buildBaseUrl(resolveUrl(ipfsUrl)), IpfsOptions.fromEnv());
    }

    private IPFSService(String baseUrl, IpfsOptions options) {
        this.ipfsBaseUrl = baseUrl;
        this.options = options;
        this.httpClient = buildHttpClient(options);
        this.circuitBreaker = new CircuitBreaker(
            "IPFS-" + baseUrl.hashCode(),
            5,  // Open after 5 failures
            3,  // Close after 3 successes in half-open
            java.time.Duration.ofSeconds(30),  // Stay open for 30 seconds
            java.time.Duration.ofSeconds(10)   // Half-open test window
        );
    }
    
    /**
     * Check if the circuit breaker is allowing requests.
     */
    public boolean isCircuitClosed() {
        return circuitBreaker.getState() == CircuitBreaker.State.CLOSED;
    }
    
    /**
     * Get the current circuit breaker state.
     */
    public CircuitBreaker.State getCircuitState() {
        return circuitBreaker.getState();
    }
    
    /**
     * Reset the circuit breaker to closed state.
     * Use after manual verification that IPFS is available.
     */
    public void resetCircuitBreaker() {
        circuitBreaker.reset();
    }

    /**
     * Upload revocation certificate (ciphertext) to IPFS and return the CID.
     */
    public String uploadRevocationCertificate(byte[] revocationCertificate) throws IOException {
        return uploadBytes(revocationCertificate, "revocation.bin");
    }

    public String uploadJson(byte[] jsonBytes) throws IOException {
        return uploadBytes(jsonBytes, "revocation-index.json");
    }

    private String uploadBytes(byte[] bytes, String fileName) throws IOException {
        RequestBody requestBody = new MultipartBody.Builder()
                .setType(MultipartBody.FORM)
                .addFormDataPart("file", fileName, RequestBody.create(bytes, OCTET_STREAM))
                .build();

        Request request = withAuth(new Request.Builder()
                .url(apiUrl("/api/v0/add"))
                .post(requestBody))
                .build();

        String cid = executeWithRetry(request, response -> {
            JsonNode json = MAPPER.readTree(response.body().string());
            return json.get("Hash").asText();
        });

        pinCid(cid);
        return cid;
    }

    /**
     * Download revocation certificate from IPFS using CID with API first, then gateway fallback.
     */
    public Optional<byte[]> downloadRevocationCertificate(String cid) {
        try {
            byte[] data = catViaApi(cid);
            if (data != null) {
                return Optional.of(data);
            }
        } catch (IOException ignored) {
            // fall back below
        }
        return fetchViaGateway(cid);
    }

    /**
     * Check if IPFS node is accessible.
     */
    public boolean isAvailable() {
        Request request = withAuth(new Request.Builder()
                .url(apiUrl("/api/v0/version"))
                .post(EMPTY_BODY))
                .build();
        try {
            return executeWithRetry(request, response -> true);
        } catch (IOException e) {
            return false;
        }
    }

    // ----- Internal helpers -----

    private byte[] catViaApi(String cid) throws IOException {
        HttpUrl url = HttpUrl.parse(apiUrl("/api/v0/cat"))
                .newBuilder()
                .addQueryParameter("arg", cid)
                .build();
        Request request = withAuth(new Request.Builder()
                .url(url)
                .post(EMPTY_BODY))
                .build();
        return executeWithRetry(request, response -> response.body().bytes());
    }

    private Optional<byte[]> fetchViaGateway(String cid) {
        if (options.gatewayUrl().isEmpty()) {
            return Optional.empty();
        }
        String gatewayBase = options.gatewayUrl().get();
        HttpUrl url = HttpUrl.parse(gatewayBase.endsWith("/") ? gatewayBase + cid : gatewayBase + "/" + cid);
        if (url == null) {
            return Optional.empty();
        }
        Request request = new Request.Builder().url(url).get().build();
        try {
            return Optional.of(executeWithRetry(request, response -> response.body().bytes()));
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    private void pinCid(String cid) {
        if (!options.pinAfterAdd()) {
            return;
        }
        try {
            HttpUrl url = HttpUrl.parse(apiUrl("/api/v0/pin/add"))
                    .newBuilder()
                    .addQueryParameter("arg", cid)
                    .build();
            Request request = withAuth(new Request.Builder().url(url).post(EMPTY_BODY)).build();
            executeWithRetry(request, response -> null);
        } catch (IOException e) {
            System.err.println("Warning: failed to pin CID " + cid + ": " + e.getMessage());
        }
    }

    private Request.Builder withAuth(Request.Builder builder) {
        options.authHeader().ifPresent(value -> builder.header("Authorization", value));
        return builder;
    }

    private String apiUrl(String path) {
        if (ipfsBaseUrl.endsWith("/")) {
            return ipfsBaseUrl + path.substring(1);
        }
        return ipfsBaseUrl + path;
    }

    private <T> T executeWithRetry(Request request, ResponseHandler<T> handler) throws IOException {
        // Check circuit breaker first
        if (!circuitBreaker.canExecute()) {
            throw new IOException("IPFS circuit breaker is OPEN - service temporarily unavailable. " +
                "Circuit will attempt recovery in " + circuitBreaker.getName());
        }
        
        IOException last = null;
        long backoffMs = options.initialBackoffMillis();
        for (int attempt = 1; attempt <= options.maxRetries(); attempt++) {
            try (Response response = httpClient.newCall(request).execute()) {
                if (!response.isSuccessful()) {
                    throw new IOException("IPFS API error " + response.code() + ": " + response.message());
                }
                T result = handler.handle(response);
                circuitBreaker.recordSuccess();
                return result;
            } catch (IOException ex) {
                last = ex;
                if (attempt == options.maxRetries()) {
                    circuitBreaker.recordFailure();
                    throw last;
                }
                try {
                    Thread.sleep(backoffMs);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    circuitBreaker.recordFailure();
                    throw new IOException("Interrupted during IPFS retry", ie);
                }
                backoffMs = Math.min(backoffMs * 2, 2000);
            }
        }
        circuitBreaker.recordFailure();
        throw new IOException("IPFS request failed after retries", last);
    }

    private static String resolveUrl(String ipfsUrl) {
        if (ipfsUrl.startsWith("http://") || ipfsUrl.startsWith("https://")) {
            return ipfsUrl;
        }
        return "http://" + ipfsUrl.replace("/ip4/", "").replace("/tcp/", ":").replace("/", "");
    }

    private static String buildBaseUrl(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    private static OkHttpClient buildHttpClient(IpfsOptions options) {
        OkHttpClient.Builder builder = new OkHttpClient.Builder()
                .connectTimeout(Duration.ofSeconds(10))
                .writeTimeout(Duration.ofSeconds(30))
                .readTimeout(Duration.ofSeconds(60))
                .callTimeout(Duration.ofSeconds(60));
        try {
            SslBundle sslBundle = buildSslBundle(options);
            if (sslBundle != null && sslBundle.sslSocketFactory() != null && sslBundle.trustManager() != null) {
                builder.sslSocketFactory(sslBundle.sslSocketFactory(), sslBundle.trustManager());
            }
            if (options.tlsInsecure()) {
                builder.hostnameVerifier((hostname, session) -> true);
            }
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalStateException("Failed to configure IPFS HTTP client", e);
        }
        return builder.build();
    }

    private static SslBundle buildSslBundle(IpfsOptions options) throws IOException, GeneralSecurityException {
        if (options.tlsInsecure()) {
            X509TrustManager trustAll = new TrustAllManager();
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[]{trustAll}, new java.security.SecureRandom());
            return new SslBundle(context.getSocketFactory(), trustAll);
        }

        TrustManagerFactory tmf = null;
        if (options.caCertPath().isPresent()) {
            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null, null);
            try (InputStream in = Files.newInputStream(Path.of(options.caCertPath().get()))) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                Certificate ca = cf.generateCertificate(in);
                trustStore.setCertificateEntry("custom-ca", ca);
            }
            tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
        }

        KeyManagerFactory kmf = null;
        if (options.clientCertPath().isPresent()) {
            KeyStore clientStore = KeyStore.getInstance("PKCS12");
            char[] password = options.clientCertPassword().orElse("").toCharArray();
            try (InputStream in = Files.newInputStream(Path.of(options.clientCertPath().get()))) {
                clientStore.load(in, password);
            }
            kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(clientStore, password);
        }

        if (tmf == null && kmf == null) {
            return null;
        }

        TrustManager[] trustManagers = tmf != null ? tmf.getTrustManagers() : null;
        X509TrustManager trustManager = trustManagers != null
                ? (X509TrustManager) trustManagers[0]
                : new TrustAllManager();

        SSLContext context = SSLContext.getInstance("TLS");
        context.init(kmf != null ? kmf.getKeyManagers() : null,
                trustManagers != null ? trustManagers : new TrustManager[]{trustManager},
                new java.security.SecureRandom());
        return new SslBundle(context.getSocketFactory(), trustManager);
    }

    private interface ResponseHandler<T> {
        T handle(Response response) throws IOException;
    }

    private record SslBundle(SSLSocketFactory sslSocketFactory, X509TrustManager trustManager) {
    }

    private static final class TrustAllManager implements X509TrustManager {
        @Override
        public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) {
        }

        @Override
        public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {
        }

        @Override
        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            return new java.security.cert.X509Certificate[0];
        }
    }

    private record IpfsOptions(
            Optional<String> gatewayUrl,
            Optional<String> authHeader,
            boolean pinAfterAdd,
            int maxRetries,
            boolean tlsInsecure,
            Optional<String> clientCertPath,
            Optional<String> clientCertPassword,
            Optional<String> caCertPath,
            long initialBackoffMillis
    ) {
        static IpfsOptions fromEnv() {
            String gateway = getenv("IPFS_GATEWAY_URL");
            boolean pin = !"false".equalsIgnoreCase(getenv("IPFS_PIN_AFTER_ADD"));
            int retries = parseInt(getenv("IPFS_MAX_RETRIES"), 3);
            boolean tlsInsecure = "true".equalsIgnoreCase(getenv("IPFS_TLS_INSECURE"));
            String clientCert = getenv("IPFS_CLIENT_CERT_P12");
            String clientPass = getenv("IPFS_CLIENT_CERT_PASSWORD");
            String caPath = getenv("IPFS_CA_CERT_PATH");
            long backoff = parseLong(getenv("IPFS_RETRY_BACKOFF_MS"), 200L);
            return new IpfsOptions(
                    Optional.ofNullable(normalizeGateway(gateway)),
                    Optional.ofNullable(buildAuthHeader()),
                    pin,
                    Math.max(retries, 1),
                    tlsInsecure,
                    Optional.ofNullable(clientCert),
                    Optional.ofNullable(clientPass),
                    Optional.ofNullable(caPath),
                    Math.max(backoff, 100L)
            );
        }

        private static String normalizeGateway(String gateway) {
            if (gateway == null || gateway.isBlank()) {
                return null;
            }
            return gateway.endsWith("/") ? gateway : gateway + "/";
        }

        private static String buildAuthHeader() {
            String bearer = getenv("IPFS_API_BEARER_TOKEN");
            if (bearer != null && !bearer.isBlank()) {
                return "Bearer " + bearer.trim();
            }
            String basic = getenv("IPFS_API_BASIC_AUTH");
            if (basic != null && !basic.isBlank()) {
                return "Basic " + Base64.getEncoder().encodeToString(basic.getBytes(StandardCharsets.UTF_8));
            }
            String user = getenv("IPFS_API_BASIC_USER");
            String pass = getenv("IPFS_API_BASIC_PASS");
            if (user != null && pass != null) {
                String credential = user + ":" + pass;
                return "Basic " + Base64.getEncoder().encodeToString(credential.getBytes(StandardCharsets.UTF_8));
            }
            return null;
        }

        private static String getenv(String name) {
            return System.getenv(name);
        }

        private static int parseInt(String value, int defaultValue) {
            if (value == null || value.isBlank()) {
                return defaultValue;
            }
            try {
                return Integer.parseInt(value);
            } catch (NumberFormatException e) {
                return defaultValue;
            }
        }

        private static long parseLong(String value, long defaultValue) {
            if (value == null || value.isBlank()) {
                return defaultValue;
            }
            try {
                return Long.parseLong(value);
            } catch (NumberFormatException e) {
                return defaultValue;
            }
        }
    }
}
