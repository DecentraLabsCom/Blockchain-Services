package decentralabs.blockchain.service.accesspolicy;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.assertj.core.api.Assertions.assertThat;

import decentralabs.blockchain.service.auth.SamlAssertionAttributes;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class InstitutionalIdentityContextPersistenceServiceTest {
    @Test
    void storesOnlyNormalizedAttributesAndAHashedIdentityReference() {
        var service = new InstitutionalIdentityContextPersistenceService(null, new ObjectMapper());
        var assertion = new SamlAssertionAttributes("https://idp.example", "puc-value", "uni.example", "user@example.com", "User",
            List.of("uni.example"), Map.of("puc", List.of("puc-value"), "eduPersonEntitlement", List.of("engineering")),
            "0x" + "a".repeat(64), "saml-attestation-v1");

        service.upsertSaml("uni.example", "puc-value", assertion, Instant.now().plusSeconds(60));
        var context = service.find("uni.example", decentralabs.blockchain.util.PucHashUtil.hashPuc("puc-value"));

        assertNotNull(context);
        assertFalse(context.attributes().containsKey("puc"));
        assertFalse(context.identityReference().contains("puc-value"));
    }

    @Test
    void storesNormalizedOidcClaimsWithoutTheRawToken() {
        var service = new InstitutionalIdentityContextPersistenceService(null, new ObjectMapper());
        service.upsertOidc("uni.example", "oidc:entra-id:tenant:oid-123", "entra-id",
            "https://login.microsoftonline.com/tenant/v2.0", Map.of(
                "roles", List.of("provider"),
                "email", "user@example.com",
                "access_token", "must-not-be-persisted"
            ), Instant.now().plusSeconds(60));

        var context = service.find("uni.example",
            decentralabs.blockchain.util.PucHashUtil.hashPuc("oidc:entra-id:tenant:oid-123"));

        assertNotNull(context);
        assertThat(context.authMethod()).isEqualTo("oidc");
        assertThat(context.attributes()).containsKey("roles");
        assertFalse(context.attributes().containsKey("access_token"));
    }
}
