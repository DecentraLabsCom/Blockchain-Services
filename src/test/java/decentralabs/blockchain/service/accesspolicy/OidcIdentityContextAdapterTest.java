package decentralabs.blockchain.service.accesspolicy;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class OidcIdentityContextAdapterTest {
    private final OidcIdentityContextAdapter adapter = new OidcIdentityContextAdapter();
    private final OidcIdentityContextAdapter.OidcProviderConfiguration provider =
        new OidcIdentityContextAdapter.OidcProviderConfiguration(List.of("https://idp.example"), "marketplace");

    @Test
    void rejectsUnverifiedOrUntrustedClaims() {
        assertThrows(IllegalArgumentException.class, () -> adapter.normalize(Map.of("iss", "https://idp.example", "sub", "1"), provider, null, "uni.example", null));
        assertThrows(IllegalArgumentException.class, () -> adapter.normalize(Map.of("signatureVerified", true, "iss", "https://evil.example", "sub", "1", "aud", "marketplace"), provider, null, "uni.example", null));
    }

    @Test
    void normalizesValidatedClaimsWithoutPersistingToken() {
        var context = adapter.normalize(Map.of("signatureVerified", true, "iss", "https://idp.example", "sub", "user-1",
            "aud", "marketplace", "nonce", "n", "eduPersonEntitlement", List.of("engineering")), provider, "n", "uni.example", "0xhash");

        assertEquals("oidc", context.authMethod());
        assertEquals(List.of("engineering"), context.attributes().get("eduPersonEntitlement"));
    }
}
