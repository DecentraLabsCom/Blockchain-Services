package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class IdentityEvidenceHashServiceTest {

    private final IdentityEvidenceHashService service = new IdentityEvidenceHashService(new ObjectMapper());

    @Test
    void computeCanonicalHash_returnsSameHashForEquivalentMaps() {
        Map<String, Object> first = new LinkedHashMap<>();
        first.put("type", "saml");
        first.put("format", "saml2-base64");
        first.put("claims", Map.of(
            "stableUserId", "user@university.edu",
            "institutionId", "university.edu",
            "puc", "user@university.edu"
        ));
        first.put("audience", List.of("backend", "marketplace"));

        Map<String, Object> second = new LinkedHashMap<>();
        second.put("audience", List.of("backend", "marketplace"));
        second.put("claims", Map.of(
            "puc", "user@university.edu",
            "institutionId", "university.edu",
            "stableUserId", "user@university.edu"
        ));
        second.put("format", "saml2-base64");
        second.put("type", "saml");

        String firstHash = service.computeCanonicalHash(first);
        String secondHash = service.computeCanonicalHash(second);

        assertThat(firstHash).isEqualTo(secondHash);
        assertThat(firstHash).startsWith("0x");
        assertThat(firstHash).hasSize(66);
    }

    @Test
    void computeCanonicalHash_normalizesNestedCollections() {
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("type", "openid4vp");
        evidence.put("claims", Map.of(
            "roles", List.of("student", "researcher"),
            "puc", "user@university.edu"
        ));

        String hash = service.computeCanonicalHash(evidence);

        assertThat(hash).startsWith("0x");
        assertThat(hash).hasSize(66);
    }
}
