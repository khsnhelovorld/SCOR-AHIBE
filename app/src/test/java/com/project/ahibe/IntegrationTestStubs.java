package com.project.ahibe;

import com.project.ahibe.core.*;
import com.project.ahibe.crypto.*;
import com.project.ahibe.crypto.bls12.*;
import com.project.ahibe.crypto.config.PairingProfile;
import org.junit.jupiter.api.*;

import java.nio.charset.StandardCharsets;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for SCOR-AHIBE components.
 * 
 * SCOR-AHIBE: 1 on-chain key = 1 off-chain file.
 * Direct CID lookup with O(1) complexity.
 * No aggregation or Merkle proofs.
 * 
 * These tests verify:
 * - BLS12-381 cryptographic operations
 * - AHIBE key generation and delegation
 * - Full end-to-end revocation flow
 * 
 * Note: Tests that require external services (IPFS, Ethereum) are marked
 * with @Tag("integration") and can be skipped in CI without external dependencies.
 */
@DisplayName("SCOR-AHIBE Integration Tests")
public class IntegrationTestStubs {

    // ==================== BLS12-381 Pairing Tests ====================

    @Nested
    @DisplayName("BLS12-381 Pairing Operations")
    class BLS12PairingTests {

        private BLS12PairingImpl pairing;

        @BeforeEach
        void setUp() {
            pairing = new BLS12PairingImpl();
        }

        @Test
        @DisplayName("Hash to G1 produces valid 48-byte compressed point")
        void testHashToG1() {
            byte[] g1Point = pairing.hashToG1("test_identity");
            
            assertNotNull(g1Point);
            assertEquals(48, g1Point.length, "G1 compressed point should be 48 bytes");
            
            // Verify compression flag is set (high bit of first byte)
            assertTrue((g1Point[0] & 0x80) != 0, "Compression flag should be set");
        }

        @Test
        @DisplayName("Hash to G2 produces valid 96-byte compressed point")
        void testHashToG2() {
            byte[] g2Point = pairing.hashToG2("test_identity");
            
            assertNotNull(g2Point);
            assertEquals(96, g2Point.length, "G2 compressed point should be 96 bytes");
            
            // Verify compression flag is set
            assertTrue((g2Point[0] & 0x80) != 0, "Compression flag should be set");
        }

        @Test
        @DisplayName("Pairing produces valid GT element")
        void testPairing() {
            byte[] g1 = pairing.hashToG1("element_a");
            byte[] g2 = pairing.hashToG2("element_b");
            
            byte[] gt = pairing.pairing(g1, g2);
            
            assertNotNull(gt);
            assertEquals(576, gt.length, "GT element should be 576 bytes");
        }

        @Test
        @DisplayName("Same inputs produce same pairing result (deterministic)")
        void testPairingDeterministic() {
            byte[] g1 = pairing.hashToG1("same_input");
            byte[] g2 = pairing.hashToG2("same_input");
            
            byte[] gt1 = pairing.pairing(g1, g2);
            byte[] gt2 = pairing.pairing(g1, g2);
            
            assertArrayEquals(gt1, gt2, "Same inputs should produce same pairing result");
        }

        @Test
        @DisplayName("Different inputs produce different pairing results")
        void testPairingDifferentInputs() {
            byte[] g1a = pairing.hashToG1("input_a");
            byte[] g2a = pairing.hashToG2("input_a");
            byte[] g1b = pairing.hashToG1("input_b");
            byte[] g2b = pairing.hashToG2("input_b");
            
            byte[] gtA = pairing.pairing(g1a, g2a);
            byte[] gtB = pairing.pairing(g1b, g2b);
            
            assertFalse(Arrays.equals(gtA, gtB), "Different inputs should produce different results");
        }

        @Test
        @DisplayName("Random scalar generation produces valid scalars")
        void testRandomZr() {
            java.math.BigInteger scalar1 = pairing.randomZr();
            java.math.BigInteger scalar2 = pairing.randomZr();
            
            assertNotNull(scalar1);
            assertNotNull(scalar2);
            assertNotEquals(scalar1, scalar2, "Random scalars should be different");
            assertTrue(scalar1.compareTo(java.math.BigInteger.ZERO) > 0);
            assertTrue(scalar1.compareTo(BLS12Constants.CURVE_ORDER) < 0);
        }

        @Test
        @DisplayName("Report native vs simulated implementation")
        void testImplementationMode() {
            System.out.println("BLS12-381 Implementation: " + 
                (pairing.isUsingNative() ? "NATIVE (blst)" : "SIMULATED"));
        }
    }

    // ==================== AHIBE Service Tests ====================

    @Nested
    @DisplayName("AHIBE Service Operations")
    class AhibeServiceTests {

        private AhibeService ahibeService;
        private AhibeService.SetupResult setup;

        @BeforeEach
        void setUp() {
            ahibeService = new AhibeService(PairingProfile.BLS12_381, 3);
            setup = ahibeService.setup();
        }

        @Test
        @DisplayName("Setup produces valid public key and master secret")
        void testSetup() {
            assertNotNull(setup.publicKey());
            assertNotNull(setup.masterSecretKey());
            assertNotNull(setup.publicKey().getY1());
            assertNotNull(setup.publicKey().getY3());
        }

        @Test
        @DisplayName("KeyGen produces valid secret key for identity")
        void testKeyGen() {
            List<String> identityPath = List.of("holder:alice@example.com");
            BLS12SecretKey secretKey = ahibeService.keyGen(setup, identityPath);
            
            assertNotNull(secretKey);
            assertNotNull(secretKey.getK11());
            assertEquals(identityPath.size(), secretKey.getIds().length);
        }

        @Test
        @DisplayName("Delegate produces child key from parent key")
        void testDelegate() {
            List<String> identityPath = List.of("holder:alice@example.com");
            BLS12SecretKey parentKey = ahibeService.keyGen(setup, identityPath);
            
            BLS12SecretKey childKey = ahibeService.delegate(
                setup.publicKey(), parentKey, "2025-01-01"
            );
            
            assertNotNull(childKey);
            assertEquals(2, childKey.getIds().length, "Child key should have parent + child identity");
        }

        @Test
        @DisplayName("Encapsulate and decapsulate round-trip")
        void testEncapsulateDecapsulate() {
            List<String> identityPath = List.of("holder:test@example.com", "2025-01-01");
            BLS12SecretKey secretKey = ahibeService.keyGen(setup, identityPath);
            
            AhibeService.EncapsulationResult encapsulation = 
                ahibeService.encapsulate(setup.publicKey(), identityPath);
            
            assertNotNull(encapsulation.sessionKey());
            assertNotNull(encapsulation.ciphertext());
            assertEquals(32, encapsulation.sessionKey().length, "Session key should be 32 bytes");
            
            byte[] recovered = ahibeService.decapsulate(secretKey, encapsulation.ciphertext());
            
            assertArrayEquals(encapsulation.sessionKey(), recovered, 
                "Decapsulated session key should match original");
        }

        @Test
        @DisplayName("Wrong key cannot decapsulate correctly")
        void testWrongKeyDecapsulation() {
            List<String> identityPath1 = List.of("holder:alice@example.com", "2025-01-01");
            List<String> identityPath2 = List.of("holder:bob@example.com", "2025-01-01");
            
            BLS12SecretKey key2 = ahibeService.keyGen(setup, identityPath2);
            
            AhibeService.EncapsulationResult encapsulation = 
                ahibeService.encapsulate(setup.publicKey(), identityPath1);
            
            byte[] recovered = ahibeService.decapsulate(key2, encapsulation.ciphertext());
            
            // With wrong key, recovered session key should not match
            assertFalse(Arrays.equals(encapsulation.sessionKey(), recovered),
                "Wrong key should not recover correct session key");
        }
    }

    // ==================== Hashing Utility Tests ====================

    @Nested
    @DisplayName("Hashing Utilities")
    class HashingTests {

        @Test
        @DisplayName("SHA-256 hash computation is deterministic")
        void testSha256Deterministic() {
            byte[] input = "test_input".getBytes(StandardCharsets.UTF_8);
            
            byte[] hash1 = HashingUtils.sha256(input);
            byte[] hash2 = HashingUtils.sha256(input);
            
            assertArrayEquals(hash1, hash2);
            assertEquals(32, hash1.length, "SHA-256 hash should be 32 bytes");
        }

        @Test
        @DisplayName("Different inputs produce different hashes")
        void testSha256DifferentInputs() {
            byte[] hash1 = HashingUtils.sha256("input_a".getBytes());
            byte[] hash2 = HashingUtils.sha256("input_b".getBytes());
            
            assertFalse(Arrays.equals(hash1, hash2), "Different inputs should produce different hashes");
        }

        @Test
        @DisplayName("Holder/epoch/ciphertext hash is deterministic")
        void testHashHolderEpochCiphertext() {
            String holderId = "holder:test@example.com";
            String epoch = "2025-01-01";
            byte[] ciphertext = "test_ciphertext".getBytes(StandardCharsets.UTF_8);
            
            byte[] hash1 = HashingUtils.hashHolderEpochCiphertext(holderId, epoch, ciphertext);
            byte[] hash2 = HashingUtils.hashHolderEpochCiphertext(holderId, epoch, ciphertext);
            
            assertArrayEquals(hash1, hash2);
            assertEquals(32, hash1.length, "SHA-256 hash should be 32 bytes");
        }

        @Test
        @DisplayName("Hex conversion round-trip")
        void testHexConversion() {
            byte[] original = "test".getBytes(StandardCharsets.UTF_8);
            String hex = HashingUtils.toHex(original);
            byte[] recovered = HashingUtils.fromHex(hex);
            
            assertArrayEquals(original, recovered);
            assertTrue(hex.startsWith("0x"), "Hex string should start with 0x");
        }
    }

    // ==================== Input Validation Tests ====================

    @Nested
    @DisplayName("Input Validation")
    class InputValidationTests {

        @Test
        @DisplayName("Valid holder IDs pass validation")
        void testValidHolderIds() {
            String[] validIds = {
                "holder:alice@example.com",
                "holder:bob_123",
                "user@domain.com",
                "abc",
                "test-user-123"
            };
            
            for (String id : validIds) {
                assertDoesNotThrow(() -> InputValidator.validateHolderId(id),
                    "Should accept valid holder ID: " + id);
            }
        }

        @Test
        @DisplayName("Invalid holder IDs fail validation")
        void testInvalidHolderIds() {
            String[] invalidIds = {
                "",
                "ab",  // Too short
                "<script>alert(1)</script>",  // Injection attempt
                "user|pipe",  // Invalid character
                null
            };
            
            for (String id : invalidIds) {
                assertThrows(InputValidator.InvalidInputException.class,
                    () -> InputValidator.validateHolderId(id),
                    "Should reject invalid holder ID: " + id);
            }
        }

        @Test
        @DisplayName("Valid epochs pass validation")
        void testValidEpochs() {
            String[] validEpochs = {
                "2025-01-01",
                "2024-12-31",
                "1970-01-01",
                "2099-12-31"
            };
            
            for (String epoch : validEpochs) {
                assertDoesNotThrow(() -> InputValidator.validateEpoch(epoch),
                    "Should accept valid epoch: " + epoch);
            }
        }

        @Test
        @DisplayName("Invalid epochs fail validation")
        void testInvalidEpochs() {
            String[] invalidEpochs = {
                "",
                "not-a-date",
                "2025/01/01",  // Wrong format
                "1969-12-31",  // Before minimum
                null
            };
            
            for (String epoch : invalidEpochs) {
                assertThrows(Exception.class,
                    () -> InputValidator.validateEpoch(epoch),
                    "Should reject invalid epoch: " + epoch);
            }
        }

        @Test
        @DisplayName("Epoch comparison works correctly")
        void testEpochComparison() {
            assertTrue(EpochComparator.isBefore("2025-01-01", "2025-01-02"));
            assertFalse(EpochComparator.isBefore("2025-01-02", "2025-01-01"));
            assertTrue(EpochComparator.isAtOrAfter("2025-01-01", "2025-01-01"));
            assertTrue(EpochComparator.isAtOrAfter("2025-01-02", "2025-01-01"));
        }
    }

    // ==================== End-to-End Flow Tests ====================

    @Nested
    @DisplayName("End-to-End Revocation Flow")
    class EndToEndTests {

        @Test
        @DisplayName("Full revocation workflow: Issue, Revoke, Verify")
        void testFullRevocationWorkflow() {
            // Setup
            AhibeService ahibeService = new AhibeService(PairingProfile.BLS12_381, 3);
            AhibeService.SetupResult setup = ahibeService.setup();
            
            String holderId = "holder:alice@example.com";
            String epoch = "2025-01-15";
            
            // Issuer creates root key for holder
            IssuerService issuer = new IssuerService(ahibeService, setup);
            BLS12SecretKey rootKey = issuer.issueRootKey(holderId);
            assertNotNull(rootKey);
            
            // Holder derives epoch key
            HolderService holder = new HolderService(ahibeService, setup.publicKey());
            BLS12SecretKey epochKey = holder.deriveEpochKey(rootKey, epoch);
            assertNotNull(epochKey);
            
            // Issuer creates revocation record (1:1 holder-to-file mapping)
            RevocationRecord record = issuer.buildRevocationRecord(holderId, epoch);
            assertNotNull(record.ciphertext());
            assertNotNull(record.sessionKey());
            assertNotNull(record.storagePointer()); // Direct CID pointer
            
            // Verifier decrypts with correct key
            VerifierService verifier = new VerifierService(ahibeService);
            byte[] recovered = verifier.decapsulate(epochKey, record.ciphertext());
            
            assertArrayEquals(record.sessionKey(), recovered,
                "Verifier should recover correct session key with matching epoch key");
        }

        @Test
        @DisplayName("Delegated key works for correct epoch only")
        void testDelegatedKeyEpochBinding() {
            AhibeService ahibeService = new AhibeService(PairingProfile.BLS12_381, 3);
            AhibeService.SetupResult setup = ahibeService.setup();
            
            String holderId = "holder:bob@example.com";
            String correctEpoch = "2025-02-01";
            String wrongEpoch = "2025-02-02";
            
            IssuerService issuer = new IssuerService(ahibeService, setup);
            BLS12SecretKey rootKey = issuer.issueRootKey(holderId);
            
            HolderService holder = new HolderService(ahibeService, setup.publicKey());
            BLS12SecretKey correctEpochKey = holder.deriveEpochKey(rootKey, correctEpoch);
            BLS12SecretKey wrongEpochKey = holder.deriveEpochKey(rootKey, wrongEpoch);
            
            // Create revocation for correctEpoch
            RevocationRecord record = issuer.buildRevocationRecord(holderId, correctEpoch);
            
            VerifierService verifier = new VerifierService(ahibeService);
            
            // Correct epoch key works
            byte[] recoveredCorrect = verifier.decapsulate(correctEpochKey, record.ciphertext());
            assertArrayEquals(record.sessionKey(), recoveredCorrect);
            
            // Wrong epoch key does NOT work
            byte[] recoveredWrong = verifier.decapsulate(wrongEpochKey, record.ciphertext());
            assertFalse(Arrays.equals(record.sessionKey(), recoveredWrong),
                "Wrong epoch key should not recover correct session key");
        }

        @Test
        @DisplayName("SCOR-AHIBE principle: each holder has unique storage pointer")
        void testOneKeyOneFileMapping() {
            AhibeService ahibeService = new AhibeService(PairingProfile.BLS12_381, 3);
            AhibeService.SetupResult setup = ahibeService.setup();
            IssuerService issuer = new IssuerService(ahibeService, setup);
            
            // Create revocations for different holders
            RevocationRecord record1 = issuer.buildRevocationRecord("holder:user1@example.com", "2025-01-01");
            RevocationRecord record2 = issuer.buildRevocationRecord("holder:user2@example.com", "2025-01-01");
            RevocationRecord record3 = issuer.buildRevocationRecord("holder:user1@example.com", "2025-01-02");
            
            // Each record should have a unique storage pointer (CID)
            assertNotEquals(record1.storagePointer(), record2.storagePointer(),
                "Different holders should have different CIDs");
            assertNotEquals(record1.storagePointer(), record3.storagePointer(),
                "Different epochs should have different CIDs");
            assertNotEquals(record2.storagePointer(), record3.storagePointer(),
                "Different holder/epoch combinations should have different CIDs");
        }
    }
}
