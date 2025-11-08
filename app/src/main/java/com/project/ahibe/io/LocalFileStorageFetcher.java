package com.project.ahibe.io;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

public class LocalFileStorageFetcher implements StorageFetcher {

    private final Path baseDirectory;

    public LocalFileStorageFetcher(Path baseDirectory) {
        this.baseDirectory = baseDirectory;
    }

    @Override
    public Optional<byte[]> fetch(String pointer) {
        if (pointer == null || pointer.isBlank()) {
            return Optional.empty();
        }

        String sanitized = pointer.replace("ipfs://", "");
        sanitized = sanitized.replaceAll("[^a-zA-Z0-9-_\\.]", "_");

        Path candidate = baseDirectory.resolve(sanitized);
        if (Files.notExists(candidate)) {
            candidate = baseDirectory.resolve(sanitized + ".bin");
        }

        if (!Files.exists(candidate)) {
            return Optional.empty();
        }

        try {
            return Optional.of(Files.readAllBytes(candidate));
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read stored ciphertext for pointer " + pointer, e);
        }
    }
}

