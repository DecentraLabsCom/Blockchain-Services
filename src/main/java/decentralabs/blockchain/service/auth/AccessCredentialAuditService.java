package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.dto.auth.AccessCredentialSessionObservedRequest;
import decentralabs.blockchain.dto.auth.SamlAuthRequest;
import decentralabs.blockchain.util.LogSanitizer;
import decentralabs.blockchain.util.PucHashUtil;
import decentralabs.blockchain.util.PucNormalizer;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.BadSqlGrammarException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class AccessCredentialAuditService {

    private final JdbcTemplate jdbcTemplate;

    @Value("${access.audit.issuer-backend-id:blockchain-services}")
    private String issuerBackendId;

    public AccessCredentialAuditService(ObjectProvider<JdbcTemplate> jdbcTemplateProvider) {
        this.jdbcTemplate = jdbcTemplateProvider.getIfAvailable();
    }

    public void recordJwtIssued(
        SamlAuthRequest request,
        Map<String, Object> marketplaceClaims,
        Map<String, Object> bookingInfo,
        JwtService.IssuedToken issuedToken
    ) {
        if (issuedToken == null || !hasText(issuedToken.token())) {
            return;
        }
        String reservationKey = stringValue(bookingInfo, "reservationKey");
        if (!hasText(reservationKey)) {
            log.debug("Access credential audit skipped: missing reservationKey");
            return;
        }

        String accessType = resolveAccessType(bookingInfo);
        String subject = stringValue(bookingInfo, "sub");
        String guacUsername = "guacamole".equals(accessType) ? subject : null;
        persist(new AuditRecord(
            reservationKey,
            firstNonBlank(stringValue(bookingInfo, "lab"), stringValue(bookingInfo, "labId")),
            resolvePucHash(marketplaceClaims, bookingInfo),
            accessType,
            issuedToken.jti(),
            guacUsername,
            null,
            issuedToken.issuedAt(),
            firstNonNull(issuedToken.expiresAt(), epochSecond(bookingInfo.get("exp"))),
            issuerBackendId,
            sha256Hex(issuedToken.token())
        ));
    }

    public void recordFmuTicketIssued(String sessionTicket, Map<String, Object> claims, long expiresAt) {
        if (!hasText(sessionTicket)) {
            return;
        }
        String reservationKey = stringValue(claims, "reservationKey");
        if (!hasText(reservationKey)) {
            log.debug("FMU ticket audit skipped: missing reservationKey");
            return;
        }

        String ticketHash = sha256Hex(sessionTicket);
        persist(new AuditRecord(
            reservationKey,
            firstNonBlank(stringValue(claims, "labId"), stringValue(claims, "lab")),
            resolvePucHash(claims, claims),
            "fmu",
            stringValue(claims, "jti"),
            null,
            ticketHash,
            Instant.now().getEpochSecond(),
            expiresAt,
            issuerBackendId,
            ticketHash
        ));
    }

    public boolean recordFmuTicketRedeemed(String sessionTicket, Map<String, Object> claims, String sessionId, String gatewayId, Long observedAt) {
        if (!hasText(sessionTicket)) {
            return false;
        }
        String reservationKey = stringValue(claims, "reservationKey");
        if (!hasText(reservationKey)) {
            log.debug("FMU session observation skipped: missing reservationKey");
            return false;
        }

        String ticketHash = sha256Hex(sessionTicket);
        AccessCredentialSessionObservedRequest request = new AccessCredentialSessionObservedRequest();
        request.setReservationKey(reservationKey);
        request.setFmuTicketId(ticketHash);
        request.setSessionId(firstNonBlank(sessionId, "fmu:" + ticketHash));
        request.setGatewayId(gatewayId);
        request.setAccessType("fmu");
        request.setObservedAt(observedAt);
        return recordSessionObserved(request);
    }

    public boolean recordSessionObserved(AccessCredentialSessionObservedRequest request) {
        if (jdbcTemplate == null) {
            log.debug("Access credential session observation skipped: no datasource configured");
            return false;
        }
        if (request == null || !hasText(request.getReservationKey())) {
            return false;
        }
        if (!hasText(request.getCredentialHash()) && !hasText(request.getJwtJti()) && !hasText(request.getFmuTicketId())) {
            return false;
        }

        Long observedAt = firstNonNull(request.getObservedAt(), Instant.now().getEpochSecond());
        String observationType = normalizeAccessType(firstNonBlank(request.getAccessType(), "session"));
        try {
            int updated = jdbcTemplate.update(
                """
                UPDATE access_credential_audit
                SET session_id = COALESCE(session_id, ?),
                    gateway_id = COALESCE(gateway_id, ?),
                    session_observed_at = COALESCE(session_observed_at, ?),
                    session_observation_type = COALESCE(session_observation_type, ?),
                    updated_at = CURRENT_TIMESTAMP
                WHERE reservation_key = ?
                  AND (
                    (? IS NOT NULL AND credential_hash = ?)
                    OR (? IS NOT NULL AND jwt_jti = ?)
                    OR (? IS NOT NULL AND fmu_ticket_id = ?)
                  )
                """,
                blankToNull(request.getSessionId()),
                blankToNull(request.getGatewayId()),
                toTimestamp(observedAt),
                observationType,
                request.getReservationKey(),
                blankToNull(request.getCredentialHash()),
                blankToNull(request.getCredentialHash()),
                blankToNull(request.getJwtJti()),
                blankToNull(request.getJwtJti()),
                blankToNull(request.getFmuTicketId()),
                blankToNull(request.getFmuTicketId())
            );
            return updated > 0;
        } catch (BadSqlGrammarException ex) {
            log.warn("Access credential audit table unavailable for session observation: {}", LogSanitizer.sanitize(ex.getMessage()));
        } catch (DataAccessException ex) {
            log.warn("Access credential session observation failed: {}", LogSanitizer.sanitize(ex.getMessage()));
        }
        return false;
    }

    public List<AuditEntry> findByReservationKey(String reservationKey) {
        if (jdbcTemplate == null || !hasText(reservationKey)) {
            return List.of();
        }
        try {
            return jdbcTemplate.query(
                """
                SELECT reservation_key, lab_id, puc_hash, access_type, jwt_jti,
                       guac_username, fmu_ticket_id, session_id, gateway_id,
                       issued_at, expires_at, session_observed_at,
                       session_observation_type, issuer_backend_id, credential_hash
                FROM access_credential_audit
                WHERE reservation_key = ?
                ORDER BY created_at ASC, id ASC
                """,
                auditEntryRowMapper(),
                reservationKey
            );
        } catch (BadSqlGrammarException ex) {
            log.warn("Access credential audit table unavailable for lookup: {}", LogSanitizer.sanitize(ex.getMessage()));
        } catch (DataAccessException ex) {
            log.warn("Access credential audit lookup failed: {}", LogSanitizer.sanitize(ex.getMessage()));
        }
        return List.of();
    }

    private void persist(AuditRecord record) {
        if (jdbcTemplate == null) {
            log.debug("Access credential audit skipped: no datasource configured");
            return;
        }
        try {
            jdbcTemplate.update(
                """
                INSERT INTO access_credential_audit (
                    reservation_key, lab_id, puc_hash, access_type, jwt_jti,
                    guac_username, fmu_ticket_id, issued_at, expires_at,
                    issuer_backend_id, credential_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE
                    expires_at = VALUES(expires_at),
                    issuer_backend_id = VALUES(issuer_backend_id),
                    updated_at = CURRENT_TIMESTAMP
                """,
                record.reservationKey(),
                record.labId(),
                record.pucHash(),
                record.accessType(),
                record.jwtJti(),
                record.guacUsername(),
                record.fmuTicketId(),
                toTimestamp(record.issuedAt()),
                toTimestamp(record.expiresAt()),
                record.issuerBackendId(),
                record.credentialHash()
            );
        } catch (BadSqlGrammarException ex) {
            log.warn("Access credential audit table unavailable: {}", LogSanitizer.sanitize(ex.getMessage()));
        } catch (DataAccessException ex) {
            log.warn("Access credential audit write failed: {}", LogSanitizer.sanitize(ex.getMessage()));
        }
    }

    private RowMapper<AuditEntry> auditEntryRowMapper() {
        return (rs, rowNum) -> new AuditEntry(
            rs.getString("reservation_key"),
            rs.getString("lab_id"),
            rs.getString("puc_hash"),
            rs.getString("access_type"),
            rs.getString("jwt_jti"),
            rs.getString("guac_username"),
            rs.getString("fmu_ticket_id"),
            rs.getString("session_id"),
            rs.getString("gateway_id"),
            epochSecond(rs.getTimestamp("issued_at")),
            epochSecond(rs.getTimestamp("expires_at")),
            epochSecond(rs.getTimestamp("session_observed_at")),
            rs.getString("session_observation_type"),
            rs.getString("issuer_backend_id"),
            rs.getString("credential_hash")
        );
    }

    private String resolveAccessType(Map<String, Object> bookingInfo) {
        String resourceType = stringValue(bookingInfo, "resourceType");
        if ("fmu".equalsIgnoreCase(resourceType)) {
            return "fmu";
        }
        String accessKey = stringValue(bookingInfo, "accessKey");
        String labUrl = stringValue(bookingInfo, "labURL");
        if ((accessKey != null && accessKey.toLowerCase(Locale.ROOT).startsWith("guac:"))
            || (labUrl != null && labUrl.toLowerCase(Locale.ROOT).contains("guacamole"))) {
            return "guacamole";
        }
        return hasText(resourceType) ? resourceType.toLowerCase(Locale.ROOT) : "lab";
    }

    private String normalizeAccessType(String value) {
        return hasText(value) ? value.trim().toLowerCase(Locale.ROOT) : null;
    }

    private String resolvePucHash(Map<String, Object> claims, Map<String, Object> fallback) {
        String existing = firstNonBlank(stringValue(claims, "pucHash"), stringValue(fallback, "pucHash"));
        if (hasText(existing)) {
            return existing;
        }
        String puc = PucNormalizer.normalize(firstNonBlank(stringValue(claims, "puc"), stringValue(claims, "userid")));
        return hasText(puc) ? PucHashUtil.hashPuc(puc) : null;
    }

    private Timestamp toTimestamp(Long epochSecond) {
        return epochSecond == null ? null : Timestamp.from(Instant.ofEpochSecond(epochSecond));
    }

    private Long epochSecond(Object value) {
        if (value instanceof Timestamp timestamp) {
            return timestamp.toInstant().getEpochSecond();
        }
        if (value instanceof BigInteger bigInteger) {
            return bigInteger.longValue();
        }
        if (value instanceof Number number) {
            return number.longValue();
        }
        if (value != null) {
            try {
                return Long.parseLong(value.toString());
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    private String sha256Hex(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                builder.append(String.format("%02x", b));
            }
            return builder.toString();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 algorithm not available", ex);
        }
    }

    private Long firstNonNull(Long first, Long second) {
        return first != null ? first : second;
    }

    private String firstNonBlank(String first, String second) {
        return hasText(first) ? first : second;
    }

    private String blankToNull(String value) {
        return hasText(value) ? value.trim() : null;
    }

    private String stringValue(Map<String, Object> values, String key) {
        if (values == null || key == null) {
            return null;
        }
        Object value = values.get(key);
        return value == null ? null : String.valueOf(value);
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private record AuditRecord(
        String reservationKey,
        String labId,
        String pucHash,
        String accessType,
        String jwtJti,
        String guacUsername,
        String fmuTicketId,
        Long issuedAt,
        Long expiresAt,
        String issuerBackendId,
        String credentialHash
    ) { }

    public record AuditEntry(
        String reservationKey,
        String labId,
        String pucHash,
        String accessType,
        String jwtJti,
        String guacUsername,
        String fmuTicketId,
        String sessionId,
        String gatewayId,
        Long issuedAt,
        Long expiresAt,
        Long sessionObservedAt,
        String sessionObservationType,
        String issuerBackendId,
        String credentialHash
    ) {
        public boolean sessionObserved() {
            return sessionObservedAt != null;
        }
    }
}
