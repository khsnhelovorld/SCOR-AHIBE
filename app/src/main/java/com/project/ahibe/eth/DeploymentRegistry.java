package com.project.ahibe.eth;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

public class DeploymentRegistry {

    private final Path deploymentsDirectory;
    private final ObjectMapper mapper = new ObjectMapper();

    public DeploymentRegistry(Path deploymentsDirectory) {
        this.deploymentsDirectory = deploymentsDirectory;
    }

    public Optional<DeploymentMetadata> load(String networkName) {
        Path file = deploymentsDirectory.resolve(networkName + ".json");
        if (!Files.exists(file)) {
            return Optional.empty();
        }
        try {
            return Optional.of(mapper.readValue(file.toFile(), DeploymentMetadata.class));
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read deployment metadata: " + file, e);
        }
    }
}

