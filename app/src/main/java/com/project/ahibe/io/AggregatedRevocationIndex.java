package com.project.ahibe.io;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.project.ahibe.core.RevocationRecord;
import com.project.ahibe.crypto.HashingUtils;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Represents an aggregated revocation index that packs multiple AHIBE ciphertexts
 * into a single IPFS object. Each entry records the ciphertext (hex-encoded), the
 * associated holder metadata, and the per-leaf hash used for contract integrity.
 * 
 * Supports two output formats:
 * - Standard: Full field names for readability
 * - Compact: Shortened keys for reduced IPFS storage overhead
 *   Mapping: h=holderId, e=epoch, c=ciphertextHex, l=leafHashHex, p=proof, pos=position, hash=hashHex
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@com.fasterxml.jackson.annotation.JsonAutoDetect(
    fieldVisibility = com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility.ANY,
    getterVisibility = com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility.NONE,
    isGetterVisibility = com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility.NONE
)
public final class AggregatedRevocationIndex {

    private static final ObjectMapper MAPPER = new ObjectMapper()
        .registerModule(new JavaTimeModule())
        .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    /** Environment variable to enable compact JSON format */
    private static final String COMPACT_FORMAT_ENV = "OUTPUT_FORMAT";
    
    private final String indexId;
    private final Instant createdAt;
    private final List<Entry> entries;
    private final String merkleRoot;
    private final String storagePointer;

    @JsonCreator
    private AggregatedRevocationIndex(
            @JsonProperty("indexId") String indexId,
            @JsonProperty("createdAt") Instant createdAt,
            @JsonProperty("entries") List<Entry> entries,
            @JsonProperty("merkleRoot") String merkleRoot,
            @JsonProperty("storagePointer") String storagePointer) {
        this.indexId = indexId;
        this.createdAt = createdAt;
        this.entries = entries != null ? new ArrayList<>(entries) : new ArrayList<>();
        this.merkleRoot = merkleRoot;
        this.storagePointer = storagePointer;
    }

    public String indexId() {
        return indexId;
    }

    public Instant createdAt() {
        return createdAt;
    }

    public List<Entry> entries() {
        return Collections.unmodifiableList(entries);
    }

    public String merkleRoot() {
        return merkleRoot;
    }

    public String storagePointer() {
        return storagePointer;
    }

    public AggregatedRevocationIndex withPointer(String pointer) {
        return new AggregatedRevocationIndex(indexId, createdAt, entries, merkleRoot, pointer);
    }

    /**
     * Serialize to JSON bytes using the format specified by OUTPUT_FORMAT env var.
     * If OUTPUT_FORMAT=compact, uses shortened keys. Otherwise uses full keys.
     */
    public byte[] toJsonBytes() {
        String format = System.getenv(COMPACT_FORMAT_ENV);
        if ("compact".equalsIgnoreCase(format)) {
            return toCompactJsonBytes();
        }
        return toStandardJsonBytes();
    }
    
    /**
     * Serialize to standard JSON with full field names.
     */
    public byte[] toStandardJsonBytes() {
        try {
            return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsBytes(this);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize aggregated index", e);
        }
    }
    
    /**
     * Serialize to compact JSON with shortened keys.
     * Keys: id=indexId, t=createdAt, r=merkleRoot, s=storagePointer, ent=entries
     * Entry keys: h=holderId, e=epoch, c=ciphertextHex, l=leafHashHex, p=proof
     * Proof keys: pos=position, hash=hashHex
     */
    public byte[] toCompactJsonBytes() {
        try {
            ObjectNode root = MAPPER.createObjectNode();
            root.put("id", indexId);
            root.put("t", createdAt.toString());
            root.put("r", merkleRoot);
            if (storagePointer != null) {
                root.put("s", storagePointer);
            }
            
            ArrayNode entriesArray = root.putArray("ent");
            for (Entry entry : entries) {
                ObjectNode entryNode = entriesArray.addObject();
                entryNode.put("h", entry.holderId());
                entryNode.put("e", entry.epoch());
                entryNode.put("c", entry.ciphertextHex());
                entryNode.put("l", entry.leafHashHex());
                
                ArrayNode proofArray = entryNode.putArray("p");
                for (ProofNode node : entry.proof()) {
                    ObjectNode proofNode = proofArray.addObject();
                    proofNode.put("pos", node.position());
                    proofNode.put("hash", node.hashHex());
                }
            }
            
            return MAPPER.writeValueAsBytes(root);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize compact aggregated index", e);
        }
    }

    public static AggregatedRevocationIndex fromRecords(List<RevocationRecord> records) {
        if (records == null || records.isEmpty()) {
            throw new IllegalArgumentException("records must not be empty");
        }

        List<Entry> entries = new ArrayList<>(records.size());
        List<byte[]> leaves = new ArrayList<>(records.size());

        for (RevocationRecord record : records) {
            byte[] leaf = HashingUtils.hashHolderEpochCiphertext(
                    record.holderId(),
                    record.epoch(),
                    record.ciphertext()
            );
            entries.add(new Entry(
                    record.holderId(),
                    record.epoch(),
                    ByteEncoding.toHex(record.ciphertext()),
                    HashingUtils.toHex(leaf),
                    List.of()
            ));
            leaves.add(leaf);
        }

        List<List<byte[]>> levels = buildLevels(leaves);
        byte[] root = levels.get(levels.size() - 1).get(0);
        List<List<ProofNode>> proofs = buildProofs(levels);

        for (int i = 0; i < entries.size(); i++) {
            Entry existing = entries.get(i);
            entries.set(i, new Entry(
                    existing.holderId(),
                    existing.epoch(),
                    existing.ciphertextHex(),
                    existing.leafHashHex(),
                    proofs.get(i)
            ));
        }

        return new AggregatedRevocationIndex(
                "index-" + UUID.randomUUID(),
                Instant.now(),
                entries,
                HashingUtils.toHex(root),
                null
        );
    }

    /**
     * Parse from JSON bytes. Supports both standard and compact formats.
     */
    public static AggregatedRevocationIndex fromJson(byte[] json) {
        try {
            JsonNode root = MAPPER.readTree(json);
            
            // Detect compact format by checking for shortened keys
            if (root.has("ent") || root.has("id")) {
                return fromCompactJson(root);
            }
            
            return MAPPER.readValue(json, AggregatedRevocationIndex.class);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse aggregated index", e);
        }
    }
    
    /**
     * Parse compact JSON format with shortened keys.
     */
    private static AggregatedRevocationIndex fromCompactJson(JsonNode root) {
        String indexId = root.has("id") ? root.get("id").asText() : root.path("indexId").asText();
        Instant createdAt = Instant.parse(
            root.has("t") ? root.get("t").asText() : root.path("createdAt").asText()
        );
        String merkleRoot = root.has("r") ? root.get("r").asText() : root.path("merkleRoot").asText();
        String storagePointer = root.has("s") ? root.get("s").asText(null) : root.path("storagePointer").asText(null);
        
        JsonNode entriesNode = root.has("ent") ? root.get("ent") : root.get("entries");
        List<Entry> entries = new ArrayList<>();
        
        if (entriesNode != null && entriesNode.isArray()) {
            for (JsonNode entryNode : entriesNode) {
                String holderId = entryNode.has("h") ? entryNode.get("h").asText() : entryNode.get("holderId").asText();
                String epoch = entryNode.has("e") ? entryNode.get("e").asText() : entryNode.get("epoch").asText();
                String ciphertextHex = entryNode.has("c") ? entryNode.get("c").asText() : entryNode.get("ciphertextHex").asText();
                String leafHashHex = entryNode.has("l") ? entryNode.get("l").asText() : entryNode.get("leafHashHex").asText();
                
                JsonNode proofNode = entryNode.has("p") ? entryNode.get("p") : entryNode.get("proof");
                List<ProofNode> proof = new ArrayList<>();
                
                if (proofNode != null && proofNode.isArray()) {
                    for (JsonNode pn : proofNode) {
                        String position = pn.has("pos") ? pn.get("pos").asText() : pn.get("position").asText();
                        String hashHex = pn.has("hash") ? pn.get("hash").asText() : pn.get("hashHex").asText();
                        proof.add(new ProofNode(position, hashHex));
                    }
                }
                
                entries.add(new Entry(holderId, epoch, ciphertextHex, leafHashHex, proof));
            }
        }
        
        return new AggregatedRevocationIndex(indexId, createdAt, entries, merkleRoot, storagePointer);
    }

    public Optional<Entry> findEntry(String holderId, String epoch) {
        return entries.stream()
                .filter(e -> e.holderId.equals(holderId) && e.epoch.equals(epoch))
                .findFirst();
    }

    public record Entry(
            String holderId,
            String epoch,
            String ciphertextHex,
            String leafHashHex,
            List<ProofNode> proof
    ) {
        public byte[] ciphertextBytes() {
            String normalized = ciphertextHex.startsWith("0x") ? ciphertextHex.substring(2) : ciphertextHex;
            return HexFormat.of().parseHex(normalized);
        }
    }

    public record ProofNode(String position, String hashHex) { }

    private enum ProofPosition { LEFT, RIGHT }

    private static List<List<byte[]>> buildLevels(List<byte[]> leaves) {
        List<List<byte[]>> levels = new ArrayList<>();
        levels.add(new ArrayList<>(leaves));
        while (levels.get(levels.size() - 1).size() > 1) {
            List<byte[]> current = levels.get(levels.size() - 1);
            List<byte[]> next = new ArrayList<>((current.size() + 1) / 2);
            for (int i = 0; i < current.size(); i += 2) {
                byte[] left = current.get(i);
                byte[] right = (i + 1 < current.size()) ? current.get(i + 1) : left;
                next.add(HashingUtils.sha256(left, right));
            }
            levels.add(next);
        }
        return levels;
    }

    private static List<List<ProofNode>> buildProofs(List<List<byte[]>> levels) {
        int leafCount = levels.get(0).size();
        List<List<ProofNode>> proofs = new ArrayList<>(leafCount);

        for (int leafIndex = 0; leafIndex < leafCount; leafIndex++) {
            List<ProofNode> proof = new ArrayList<>();
            int pointer = leafIndex;
            for (int level = 0; level < levels.size() - 1; level++) {
                List<byte[]> current = levels.get(level);
                int siblingIndex = pointer ^ 1;
                if (siblingIndex >= current.size()) {
                    siblingIndex = pointer;
                }
                byte[] sibling = current.get(siblingIndex);
                ProofPosition position;
                if (siblingIndex == pointer) {
                    position = ProofPosition.RIGHT;
                } else {
                    position = siblingIndex < pointer ? ProofPosition.LEFT : ProofPosition.RIGHT;
                }
                proof.add(new ProofNode(position.name(), HashingUtils.toHex(sibling)));
                pointer /= 2;
            }
            proofs.add(proof);
        }

        return proofs;
    }
}
