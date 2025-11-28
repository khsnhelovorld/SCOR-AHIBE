package com.project.ahibe.crypto;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

/**
 * Cryptographic hashing utilities for SCOR-AHIBE.
 * 
 * Provides SHA-256 based hashing for:
 * - Leaf hash computation (holder + epoch + ciphertext)
 * - Merkle tree construction
 * - Merkle proof verification
 */
public final class HashingUtils {
    private static final ThreadLocal<MessageDigest> SHA256 = ThreadLocal.withInitial(() -> {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    });

    private HashingUtils() {
    }

    public static byte[] sha256(byte[] input) {
        MessageDigest digest = SHA256.get();
        digest.reset();
        return digest.digest(input);
    }

    public static byte[] sha256(byte[] left, byte[] right) {
        MessageDigest digest = SHA256.get();
        digest.reset();
        digest.update(left);
        digest.update(right);
        return digest.digest();
    }

    public static byte[] sha256Concat(List<byte[]> inputs) {
        MessageDigest digest = SHA256.get();
        digest.reset();
        inputs.forEach(digest::update);
        return digest.digest();
    }

    public static byte[] hashHolderEpochCiphertext(String holderId, String epoch, byte[] ciphertext) {
        byte[] holderBytes = holderId.getBytes(StandardCharsets.UTF_8);
        byte[] epochBytes = epoch.getBytes(StandardCharsets.UTF_8);
        MessageDigest digest = SHA256.get();
        digest.reset();
        digest.update(intToBytes(holderBytes.length));
        digest.update(holderBytes);
        digest.update(intToBytes(epochBytes.length));
        digest.update(epochBytes);
        digest.update(ciphertext);
        return digest.digest();
    }

    public static String toHex(byte[] input) {
        return "0x" + HexFormat.of().withUpperCase().formatHex(input);
    }

    /**
     * Parse hex string to bytes.
     */
    public static byte[] fromHex(String hex) {
        String normalized = hex.startsWith("0x") ? hex.substring(2) : hex;
        return HexFormat.of().parseHex(normalized);
    }

    private static byte[] intToBytes(int value) {
        return ByteBuffer.allocate(4).putInt(value).array();
    }
    
    // ==================== Merkle Proof Verification ====================
    
    /**
     * Verify a Merkle inclusion proof.
     * 
     * @param leafHash The leaf hash to verify
     * @param proof List of sibling hashes with positions (LEFT or RIGHT)
     * @param expectedRoot The expected Merkle root
     * @return true if the proof is valid
     */
    public static boolean verifyMerkleProof(byte[] leafHash, List<MerkleProofNode> proof, byte[] expectedRoot) {
        Objects.requireNonNull(leafHash, "leafHash must not be null");
        Objects.requireNonNull(proof, "proof must not be null");
        Objects.requireNonNull(expectedRoot, "expectedRoot must not be null");
        
        if (leafHash.length != 32 || expectedRoot.length != 32) {
            return false;
        }
        
        byte[] currentHash = leafHash.clone();
        
        for (MerkleProofNode node : proof) {
            byte[] siblingHash = node.hash();
            if (siblingHash == null || siblingHash.length != 32) {
                return false;
            }
            
            // Combine based on position
            if (node.position() == MerklePosition.LEFT) {
                // Sibling is on the left, so: hash(sibling || current)
                currentHash = sha256(siblingHash, currentHash);
            } else {
                // Sibling is on the right, so: hash(current || sibling)
                currentHash = sha256(currentHash, siblingHash);
            }
        }
        
        return Arrays.equals(currentHash, expectedRoot);
    }
    
    /**
     * Verify a Merkle proof with hex-encoded values.
     * 
     * @param leafHashHex Leaf hash as hex string (0x prefixed or not)
     * @param proofNodes List of proof nodes with position and hash
     * @param merkleRootHex Expected Merkle root as hex string
     * @return true if the proof is valid
     */
    public static boolean verifyMerkleProofHex(String leafHashHex, 
                                               List<ProofNodeData> proofNodes, 
                                               String merkleRootHex) {
        try {
            byte[] leafHash = fromHex(leafHashHex);
            byte[] merkleRoot = fromHex(merkleRootHex);
            
            List<MerkleProofNode> proof = proofNodes.stream()
                .map(node -> new MerkleProofNode(
                    MerklePosition.valueOf(node.position().toUpperCase()),
                    fromHex(node.hashHex())
                ))
                .toList();
            
            return verifyMerkleProof(leafHash, proof, merkleRoot);
        } catch (Exception e) {
            // Any parsing error means invalid proof
            return false;
        }
    }
    
    /**
     * Verify that a leaf hash correctly represents the holder/epoch/ciphertext.
     * 
     * @param holderId The holder identifier
     * @param epoch The epoch string
     * @param ciphertext The ciphertext bytes
     * @param expectedLeafHash The expected leaf hash
     * @return true if the computed hash matches the expected hash
     */
    public static boolean verifyLeafHash(String holderId, String epoch, byte[] ciphertext, byte[] expectedLeafHash) {
        if (holderId == null || epoch == null || ciphertext == null || expectedLeafHash == null) {
            return false;
        }
        
        byte[] computedHash = hashHolderEpochCiphertext(holderId, epoch, ciphertext);
        return Arrays.equals(computedHash, expectedLeafHash);
    }
    
    /**
     * Verify leaf hash with hex-encoded expected value.
     */
    public static boolean verifyLeafHashHex(String holderId, String epoch, byte[] ciphertext, String expectedLeafHashHex) {
        try {
            byte[] expectedLeafHash = fromHex(expectedLeafHashHex);
            return verifyLeafHash(holderId, epoch, ciphertext, expectedLeafHash);
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Full Merkle proof verification: verify both leaf hash and inclusion proof.
     * 
     * @param holderId The holder identifier
     * @param epoch The epoch string
     * @param ciphertext The ciphertext bytes
     * @param proof The Merkle proof nodes
     * @param merkleRoot The expected Merkle root
     * @return MerkleVerificationResult with detailed status
     */
    public static MerkleVerificationResult verifyFull(
            String holderId, 
            String epoch, 
            byte[] ciphertext,
            List<MerkleProofNode> proof,
            byte[] merkleRoot) {
        
        // Step 1: Compute and verify leaf hash
        byte[] computedLeafHash = hashHolderEpochCiphertext(holderId, epoch, ciphertext);
        
        // Step 2: Verify Merkle inclusion proof
        if (proof == null || proof.isEmpty()) {
            // No proof provided - single entry or missing proof
            return new MerkleVerificationResult(false, false, 
                "No Merkle proof provided", computedLeafHash);
        }
        
        boolean proofValid = verifyMerkleProof(computedLeafHash, proof, merkleRoot);
        
        if (proofValid) {
            return new MerkleVerificationResult(true, true, 
                "Merkle proof verified successfully", computedLeafHash);
        } else {
            return new MerkleVerificationResult(true, false, 
                "Merkle proof verification failed", computedLeafHash);
        }
    }
    
    /**
     * Merkle proof node with position and hash.
     */
    public record MerkleProofNode(MerklePosition position, byte[] hash) {
        public MerkleProofNode {
            Objects.requireNonNull(position, "position must not be null");
            Objects.requireNonNull(hash, "hash must not be null");
        }
    }
    
    /**
     * Position of sibling in Merkle tree.
     */
    public enum MerklePosition {
        LEFT, RIGHT
    }
    
    /**
     * Proof node data for JSON parsing.
     */
    public record ProofNodeData(String position, String hashHex) {}
    
    /**
     * Result of Merkle verification.
     */
    public record MerkleVerificationResult(
            boolean leafHashValid,
            boolean proofValid,
            String message,
            byte[] computedLeafHash
    ) {
        public boolean isFullyValid() {
            return leafHashValid && proofValid;
        }
    }
}

