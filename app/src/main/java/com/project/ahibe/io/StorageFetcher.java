package com.project.ahibe.io;

import java.util.Optional;

@FunctionalInterface
public interface StorageFetcher {
    Optional<byte[]> fetch(String pointer);
}

