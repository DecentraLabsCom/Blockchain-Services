package decentralabs.blockchain.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PucNormalizerTest {

    @Test
    @DisplayName("Should trim and lowercase generic stable identifiers")
    void shouldTrimAndLowercaseGenericStableIdentifiers() {
        assertEquals(
            "user@university.edu|targeted-user",
            PucNormalizer.normalize("  User@University.EDU|Targeted-User  ")
        );
    }

    @Test
    @DisplayName("Should extract and lowercase SCHAC personalUniqueCode tail")
    void shouldExtractAndLowercaseSchacTail() {
        assertEquals(
            "12345678a",
            PucNormalizer.normalize("urn:schac:personalUniqueCode:ES:DNI:12345678A")
        );
    }

    @Test
    @DisplayName("Should return null for null values")
    void shouldReturnNullForNullValues() {
        assertNull(PucNormalizer.normalize(null));
    }
}
