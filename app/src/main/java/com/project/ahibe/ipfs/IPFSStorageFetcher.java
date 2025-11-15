package com.project.ahibe.ipfs;

import com.project.ahibe.io.StorageFetcher;

import java.util.Optional;

/**
 * StorageFetcher implementation that downloads revocation certificates from IPFS.
 */
public class IPFSStorageFetcher implements StorageFetcher {
    private final IPFSService ipfsService;

    public IPFSStorageFetcher(IPFSService ipfsService) {
        this.ipfsService = ipfsService;
    }

    @Override
    public Optional<byte[]> fetch(String pointer) {
        if (pointer == null || pointer.isBlank()) {
            return Optional.empty();
        }

        // Remove ipfs:// prefix if present
        String cid = pointer.replace("ipfs://", "").trim();
        
        return ipfsService.downloadRevocationCertificate(cid);
    }
}

