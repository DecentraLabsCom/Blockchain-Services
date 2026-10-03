package decentralabs.blockchain.service.accesspolicy;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/** Normalized, backend-owned identity facts. Raw SAML/OIDC tokens are never stored here. */
public record InstitutionalIdentityContext(
    String institutionId,
    String identityReference,
    String authMethod,
    String issuer,
    Map<String, List<String>> attributes,
    Instant observedAt,
    Instant expiresAt
) {
    public boolean hasAttributes() {
        return attributes != null && !attributes.isEmpty();
    }
}
