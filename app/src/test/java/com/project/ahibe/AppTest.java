package com.project.ahibe;

import com.project.ahibe.core.HolderService;
import com.project.ahibe.core.IssuerService;
import com.project.ahibe.core.PkgService;
import com.project.ahibe.core.RevocationRecord;
import com.project.ahibe.core.VerifierService;
import com.project.ahibe.crypto.AhibeService;
import com.project.ahibe.crypto.config.PairingProfile;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AppTest {

    @Test
    void roundTripEncapsulationMatches() {
        AhibeService service = new AhibeService(PairingProfile.BLS12_381, 3);
        PkgService pkg = new PkgService(service);
        var setup = pkg.bootstrap();

        IssuerService issuer = new IssuerService(service, setup);
        HolderService holder = new HolderService(service, setup.publicKey());
        VerifierService verifier = new VerifierService(service);

        var rootKey = issuer.issueRootKey("holder123");
        var epochKey = holder.deriveEpochKey(rootKey, "epoch-2025-10-30");
        RevocationRecord record = issuer.publishRevocation("holder123", "epoch-2025-10-30");

        byte[] recovered = verifier.decapsulate(epochKey, record.ciphertext());
        assertArrayEquals(record.sessionKey(), recovered, "session key mismatch after decapsulation");

        assertThrows(IllegalArgumentException.class, () -> verifier.matchesPointer(null, record.storagePointer()));
        assertThrows(IllegalArgumentException.class, () -> verifier.matchesPointer(record, null));
        assertTrue(verifier.matchesPointer(record, record.storagePointer()));
    }

    @Test
    void exceedingHierarchyDepthThrows() {
        AhibeService service = new AhibeService(PairingProfile.BLS12_381, 1);
        PkgService pkg = new PkgService(service);
        var setup = pkg.bootstrap();
        IssuerService issuer = new IssuerService(service, setup);

        assertThrows(IllegalArgumentException.class,
                () -> issuer.publishRevocation("holder", "epoch"));
    }
}
