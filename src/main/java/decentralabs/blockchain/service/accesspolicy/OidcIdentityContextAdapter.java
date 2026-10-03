package decentralabs.blockchain.service.accesspolicy;

import decentralabs.blockchain.util.PucHashUtil;
import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Normalizes claims only after the OIDC JWT library has verified its signature.
 * The adapter deliberately accepts no raw token and never persists it.
 */
public final class OidcIdentityContextAdapter {
    public InstitutionalIdentityContext normalize(
        Map<String, Object> claims,
        OidcProviderConfiguration provider,
        String expectedNonce,
        String institutionId,
        String evidenceHash
    ) {
        if (claims == null || provider == null || !Boolean.TRUE.equals(claims.get("signatureVerified"))) {
            throw new IllegalArgumentException("OIDC signature must be verified before normalization");
        }
        String issuer = text(claims.get("iss"));
        if (issuer == null || !provider.issuers().contains(issuer)) throw new IllegalArgumentException("Untrusted OIDC issuer");
        if (!audienceContains(claims.get("aud"), provider.audience())) throw new IllegalArgumentException("OIDC audience mismatch");
        if (expectedNonce != null && !expectedNonce.equals(text(claims.get("nonce")))) throw new IllegalArgumentException("OIDC nonce mismatch");
        String subject = text(claims.get("sub"));
        if (subject == null) throw new IllegalArgumentException("OIDC subject is required");
        Map<String, List<String>> attributes = new LinkedHashMap<>();
        copy(attributes, "eduPersonEntitlement", claims.get("eduPersonEntitlement"));
        copy(attributes, "eduPersonAffiliation", claims.get("eduPersonAffiliation"));
        copy(attributes, "orgUnit", claims.get("orgUnit"));
        copy(attributes, "email", claims.get("email"));
        String stableId = issuer + "|" + subject;
        return new InstitutionalIdentityContext(institutionId, PucHashUtil.hashPuc(stableId), "oidc", issuer,
            attributes, Instant.now(), expiry(claims.get("exp")));
    }

    private boolean audienceContains(Object value, String expected) {
        if (expected == null) return false;
        if (value instanceof Collection<?> collection) return collection.stream().anyMatch(item -> expected.equals(String.valueOf(item)));
        return expected.equals(text(value));
    }

    private void copy(Map<String, List<String>> target, String key, Object value) {
        if (value instanceof Collection<?> collection) target.put(key, collection.stream().map(String::valueOf).toList());
        else if (value != null && !String.valueOf(value).isBlank()) target.put(key, List.of(String.valueOf(value)));
    }

    private String text(Object value) { return value == null || String.valueOf(value).isBlank() ? null : String.valueOf(value); }
    private Instant expiry(Object value) {
        if (value instanceof Number number) return Instant.ofEpochSecond(number.longValue());
        return null;
    }

    public record OidcProviderConfiguration(List<String> issuers, String audience) {
        public OidcProviderConfiguration {
            issuers = issuers == null ? List.of() : List.copyOf(issuers);
        }
    }
}
