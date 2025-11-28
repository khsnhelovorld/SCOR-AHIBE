package com.project.ahibe.io;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.format.DateTimeFormatter;

public class AggregatedRevocationIndexWriter {

    private final Path baseDir;

    public AggregatedRevocationIndexWriter(Path baseDir) {
        this.baseDir = baseDir;
    }

    public Path write(AggregatedRevocationIndex index) throws IOException {
        Files.createDirectories(baseDir);
        String fileName = index.indexId() + "-" + DateTimeFormatter.ISO_INSTANT.format(index.createdAt()) + ".json";
        Path target = baseDir.resolve(fileName.replace(":", "_"));
        Files.write(target, index.toJsonBytes());
        return target;
    }
}

