package com.project.ahibe.core;

import com.project.ahibe.crypto.AhibeService;

/**
 * Trusted PKG (Private Key Generator) responsible for system bootstrap.
 */
public class PkgService {
    private final AhibeService ahibeService;

    public PkgService(AhibeService ahibeService) {
        this.ahibeService = ahibeService;
    }

    public AhibeService.SetupResult bootstrap() {
        return ahibeService.setup();
    }
}

