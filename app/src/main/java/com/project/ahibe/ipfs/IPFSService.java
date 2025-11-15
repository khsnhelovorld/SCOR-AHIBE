package com.project.ahibe.ipfs;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;

import java.io.IOException;
import java.util.Optional;

/**
 * Service for interacting with IPFS to upload and download revocation certificates.
 * Uses IPFS HTTP API directly.
 */
public class IPFSService {
    private static final MediaType OCTET_STREAM = MediaType.parse("application/octet-stream");
    private static final RequestBody EMPTY_BODY = RequestBody.create(new byte[0], OCTET_STREAM);

    private final String ipfsBaseUrl;
    private final OkHttpClient httpClient;

    public IPFSService(String ipfsHost, int ipfsPort) {
        this.ipfsBaseUrl = "http://" + ipfsHost + ":" + ipfsPort;
        this.httpClient = new OkHttpClient();
    }

    public IPFSService(String ipfsUrl) {
        // Parse URL like "http://127.0.0.1:5001"
        if (ipfsUrl.startsWith("http://") || ipfsUrl.startsWith("https://")) {
            this.ipfsBaseUrl = ipfsUrl;
        } else {
            // Assume it's a multiaddr format, extract host and port
            this.ipfsBaseUrl = "http://" + ipfsUrl.replace("/ip4/", "").replace("/tcp/", ":").replace("/", "");
        }
        this.httpClient = new OkHttpClient();
    }

    /**
     * Upload revocation certificate (ciphertext) to IPFS and return the CID.
     *
     * @param revocationCertificate The revocation certificate bytes to upload
     * @return The CID (Content Identifier) of the uploaded file
     * @throws IOException if upload fails
     */
    public String uploadRevocationCertificate(byte[] revocationCertificate) throws IOException {
        RequestBody requestBody = new MultipartBody.Builder()
                .setType(MultipartBody.FORM)
                .addFormDataPart("file", "revocation.bin",
                        RequestBody.create(revocationCertificate, OCTET_STREAM))
                .build();

        Request request = new Request.Builder()
                .url(ipfsBaseUrl + "/api/v0/add")
                .post(requestBody)
                .build();

        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("IPFS upload failed: " + response.code() + " " + response.message());
            }

            String responseBody = response.body().string();
            ObjectMapper mapper = new ObjectMapper();
            JsonNode json = mapper.readTree(responseBody);
            String hash = json.get("Hash").asText();
            return hash;
        }
    }

    /**
     * Download revocation certificate from IPFS using CID.
     *
     * @param cid The Content Identifier (CID) of the file to download
     * @return Optional containing the revocation certificate bytes, or empty if not found
     */
    public Optional<byte[]> downloadRevocationCertificate(String cid) {
        try {
            HttpUrl url = HttpUrl.parse(ipfsBaseUrl + "/api/v0/cat")
                    .newBuilder()
                    .addQueryParameter("arg", cid)
                    .build();

            Request request = new Request.Builder()
                    .url(url)
                    .post(EMPTY_BODY)
                    .build();

            try (Response response = httpClient.newCall(request).execute()) {
                if (!response.isSuccessful()) {
                    return Optional.empty();
                }

                byte[] fileContents = response.body().bytes();
                return Optional.of(fileContents);
            }
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    /**
     * Check if IPFS node is accessible.
     *
     * @return true if IPFS node is reachable, false otherwise
     */
    public boolean isAvailable() {
        try {
            Request request = new Request.Builder()
                    .url(ipfsBaseUrl + "/api/v0/version")
                    .post(EMPTY_BODY)
                    .build();

            try (Response response = httpClient.newCall(request).execute()) {
                return response.isSuccessful();
            }
        } catch (Exception e) {
            return false;
        }
    }
}

