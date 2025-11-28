package com.project.ahibe.io;

import com.project.ahibe.core.RevocationRecord;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;

/**
 * Writer for revocation records to JSON files.
 * 
 * SCOR-AHIBE: 1 on-chain key = 1 off-chain file.
 * Each holder has exactly one ciphertext file on IPFS.
 */
public class RevocationRecordWriter {

    private final Path outputDirectory;

    public RevocationRecordWriter(Path outputDirectory) {
        this.outputDirectory = outputDirectory;
    }

    public Path write(RevocationRecord record) throws IOException {
        return write(record, null);
    }
    
    public Path write(RevocationRecord record, String profileId) throws IOException {
        Files.createDirectories(outputDirectory);

        String fileName = buildFileName(record);
        Path target = outputDirectory.resolve(fileName);

        String json = toJson(record, profileId);
        Files.writeString(
                target,
                json,
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE
        );

        return target;
    }

    private String buildFileName(RevocationRecord record) {
        String holderSafe = sanitize(record.holderId());
        String epochSafe = sanitize(record.epoch());
        return holderSafe + "__" + epochSafe + ".json";
    }

    private String sanitize(String input) {
        return input.replaceAll("[^a-zA-Z0-9-_]", "_");
    }

    private String toJson(RevocationRecord record) {
        return toJson(record, null);
    }
    
    private String toJson(RevocationRecord record, String profileId) {
        String sessionKeyB64 = ByteEncoding.toBase64(record.sessionKey());
        String ciphertextHex = ByteEncoding.toHex(record.ciphertext());
        String pointer = record.storagePointer() == null ? "" : record.storagePointer();
        String profileField = profileId != null ? 
            String.format("\n                  \"profileId\": \"%s\",", profileId) : "";
        return String.format("""
                {
                  "holderId": "%s",
                  "epoch": "%s",%s
                  "sessionKey": "%s",
                  "ciphertext": "%s",
                  "storagePointer": "%s",
                  "exportedAt": "%s"
                }
                """,
                record.holderId(),
                record.epoch(),
                profileField,
                sessionKeyB64,
                ciphertextHex,
                pointer,
                Instant.now().toString()
        );
    }
}
