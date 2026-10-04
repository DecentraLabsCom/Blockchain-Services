package decentralabs.blockchain.service.accesspolicy;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.service.auth.SamlAssertionAttributes;
import decentralabs.blockchain.util.PucHashUtil;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class InstitutionalIdentityContextPersistenceService {
    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;
    private final Map<String, InstitutionalIdentityContext> memory = new ConcurrentHashMap<>();

    public InstitutionalIdentityContextPersistenceService(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
    }

    public void upsertSaml(String institutionId, String puc, SamlAssertionAttributes assertion, Instant expiresAt) {
        Map<String, List<String>> safeAttributes = new LinkedHashMap<>();
        if (assertion != null && assertion.attributes() != null) {
            assertion.attributes().forEach((key, values) -> {
                if (key == null || "puc".equalsIgnoreCase(key) || values == null) return;
                safeAttributes.put(key, values.stream().filter(value -> value != null && !value.isBlank()).limit(32).toList());
            });
        }
        InstitutionalIdentityContext context = new InstitutionalIdentityContext(
            institutionId.toLowerCase(), PucHashUtil.hashPuc(puc), "saml",
            assertion == null ? null : assertion.issuer(), safeAttributes, Instant.now(), expiresAt
        );
        upsert(context);
    }

    /**
     * Persists only the normalized OIDC context. Raw tokens and unbounded
     * provider claims deliberately never cross this boundary.
     */
    public void upsertOidc(
        String institutionId,
        String stableUserId,
        String provider,
        String issuer,
        Map<String, ?> claims,
        Instant expiresAt
    ) {
        Map<String, List<String>> safeAttributes = new LinkedHashMap<>();
        if (claims != null) {
            List.of(
                "roles", "scp", "preferred_username", "email", "name", "tid", "oid",
                "idp", "idp_name", "affiliation", "schacHomeOrganization",
                "eduPersonAffiliation", "eduPersonEntitlement"
            ).forEach(key -> {
                Object value = claims.get(key);
                List<String> values = value instanceof Collection<?> collection
                    ? collection.stream().map(String::valueOf).toList()
                    : value == null ? List.of() : List.of(String.valueOf(value));
                List<String> bounded = values.stream()
                    .filter(item -> item != null && !item.isBlank())
                    .map(item -> item.length() > 512 ? item.substring(0, 512) : item)
                    .limit(32)
                    .toList();
                if (!bounded.isEmpty()) safeAttributes.put(key, bounded);
            });
        }
        upsert(new InstitutionalIdentityContext(
            institutionId == null ? null : institutionId.toLowerCase(),
            PucHashUtil.hashPuc(stableUserId),
            "oidc",
            issuer,
            safeAttributes,
            Instant.now(),
            expiresAt
        ));
    }

    public void upsert(InstitutionalIdentityContext context) {
        if (context == null || context.institutionId() == null || context.identityReference() == null) return;
        memory.put(key(context.institutionId(), context.identityReference()), context);
        if (jdbcTemplate == null) return;
        try {
            String attributesJson = objectMapper.writeValueAsString(context.attributes() == null ? Map.of() : context.attributes());
            jdbcTemplate.update(
                """
                INSERT INTO institutional_identity_contexts
                    (institution_id, identity_reference_hash, auth_method, issuer, attributes_json, observed_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE auth_method=VALUES(auth_method), issuer=VALUES(issuer),
                    attributes_json=VALUES(attributes_json), observed_at=VALUES(observed_at), expires_at=VALUES(expires_at)
                """,
                context.institutionId(), context.identityReference(), context.authMethod(), context.issuer(), attributesJson,
                Timestamp.from(context.observedAt() == null ? Instant.now() : context.observedAt()),
                context.expiresAt() == null ? null : Timestamp.from(context.expiresAt())
            );
        } catch (Exception ex) {
            log.warn("Institutional identity context persistence unavailable; keeping current request context: {}", ex.getMessage());
        }
    }

    public InstitutionalIdentityContext find(String institutionId, String identityReference) {
        InstitutionalIdentityContext cached = memory.get(key(institutionId, identityReference));
        if (cached != null && (cached.expiresAt() == null || cached.expiresAt().isAfter(Instant.now()))) return cached;
        try {
            return jdbcTemplate.query("SELECT * FROM institutional_identity_contexts WHERE institution_id=? AND identity_reference_hash=? LIMIT 1",
                (rs, rowNum) -> {
                    Map<String, List<String>> attrs = readJson(rs.getString("attributes_json"), new TypeReference<>() {});
                    Timestamp observed = rs.getTimestamp("observed_at");
                    Timestamp expires = rs.getTimestamp("expires_at");
                    return new InstitutionalIdentityContext(rs.getString("institution_id"), rs.getString("identity_reference_hash"),
                        rs.getString("auth_method"), rs.getString("issuer"), attrs,
                        observed == null ? null : observed.toInstant(), expires == null ? null : expires.toInstant());
                }, institutionId, identityReference).stream().findFirst().orElse(null);
        } catch (Exception ex) {
            return cached;
        }
    }

    private String key(String institutionId, String reference) {
        return String.valueOf(institutionId).toLowerCase() + ":" + reference;
    }

    private <T> T readJson(String value, TypeReference<T> type) {
        try {
            return objectMapper.readValue(value, type);
        } catch (Exception ex) {
            throw new IllegalArgumentException("Invalid identity context JSON", ex);
        }
    }
}
