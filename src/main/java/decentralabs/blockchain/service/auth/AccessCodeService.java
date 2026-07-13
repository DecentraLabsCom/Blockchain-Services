package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.dto.auth.AccessCodeResponse;
import decentralabs.blockchain.dto.auth.AuthResponse;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

/** Issues short-lived, opaque, single-use handles for browser-to-gateway access. */
@Service
@Slf4j
public class AccessCodeService {
    private static final String TABLE = "lab_access_codes";
    private final JdbcTemplate jdbcTemplate;
    private final JwtService jwtService;
    private final AccessCodeTokenCipher tokenCipher;
    private final SecureRandom random = new SecureRandom();
    private final ConcurrentMap<String, CodeRecord> memory = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, String> memoryDeliveries = new ConcurrentHashMap<>();

    @Value("${auth.access-code.ttl-seconds:60}")
    private long ttlSeconds = 60;

    public AccessCodeService(
        ObjectProvider<JdbcTemplate> jdbcTemplateProvider,
        JwtService jwtService,
        AccessCodeTokenCipher tokenCipher
    ) {
        this.jdbcTemplate = jdbcTemplateProvider.getIfAvailable();
        this.jwtService = jwtService;
        this.tokenCipher = tokenCipher;
    }

    /** Backward-compatible constructor for in-memory unit tests. */
    AccessCodeService(ObjectProvider<JdbcTemplate> jdbcTemplateProvider, JwtService jwtService) {
        this(jdbcTemplateProvider, jwtService, new AccessCodeTokenCipher(""));
    }

    @Transactional
    public AccessCodeResponse issue(String token) {
        return issueInternal(token, null, null);
    }

    @Transactional
    public AccessCodeResponse issue(String token, String reservationKey, long provisioningGeneration) {
        if (reservationKey == null || reservationKey.isBlank() || provisioningGeneration < 1) {
            throw new IllegalArgumentException("reservationKey and provisioningGeneration are required");
        }
        return issueInternal(token, reservationKey, provisioningGeneration);
    }

    private AccessCodeResponse issueInternal(String token, String reservationKey, Long provisioningGeneration) {
        ValidatedCredential credential = validatedAccessCredential(token);
        long now = Instant.now().getEpochSecond();
        long expiresAt = boundedCodeExpiry(now, credential.expiresAt());
        String code = generateCode();
        CodeRecord record = new CodeRecord(
            code,
            token,
            credential.labURL(),
            credential.resourceType(),
            credential.targetGatewayId(),
            expiresAt,
            credential.expiresAt(),
            reservationKey,
            provisioningGeneration
        );
        if (inMemoryMode()) {
            String codeHash = hash(code);
            memory.put(codeHash, record);
            if (reservationKey != null) {
                memoryDeliveries.put(deliveryKey(reservationKey, provisioningGeneration), codeHash);
            }
        } else {
            persist(code, record);
        }
        return new AccessCodeResponse(code, credential.labURL(), credential.resourceType());
    }

    /** Returns the exact unconsumed delivery, refreshing only its opaque code after code expiry. */
    @Transactional
    public AccessCodeResponse recoverDelivery(String reservationKey, long provisioningGeneration) {
        if (reservationKey == null || reservationKey.isBlank() || provisioningGeneration < 1) {
            return null;
        }
        long now = Instant.now().getEpochSecond();
        if (inMemoryMode()) {
            String key = deliveryKey(reservationKey, provisioningGeneration);
            String codeHash = memoryDeliveries.get(key);
            CodeRecord record = codeHash != null ? memory.get(codeHash) : null;
            if (record == null || now >= record.credentialExpiresAt()) {
                memoryDeliveries.remove(key);
                if (codeHash != null) memory.remove(codeHash);
                return null;
            }
            if (now < record.expiresAt()) {
                return new AccessCodeResponse(record.code(), record.labURL(), record.resourceType());
            }
            String refreshed = generateCode();
            CodeRecord refreshedRecord = new CodeRecord(
                refreshed, record.token(), record.labURL(), record.resourceType(), record.targetGatewayId(),
                boundedCodeExpiry(now, record.credentialExpiresAt()),
                record.credentialExpiresAt(), reservationKey, provisioningGeneration
            );
            memory.remove(codeHash);
            String refreshedHash = hash(refreshed);
            memory.put(refreshedHash, refreshedRecord);
            memoryDeliveries.put(key, refreshedHash);
            return new AccessCodeResponse(refreshed, record.labURL(), record.resourceType());
        }
        return recoverPersistedDelivery(reservationKey, provisioningGeneration, now);
    }

    @Transactional
    public void revoke(String code) {
        if (code == null || code.isBlank()) return;
        String codeHash = hash(code.trim());
        if (inMemoryMode()) {
            CodeRecord removed = memory.remove(codeHash);
            if (removed != null && removed.reservationKey() != null) {
                memoryDeliveries.remove(deliveryKey(removed.reservationKey(), removed.provisioningGeneration()));
            }
        } else {
            jdbcTemplate.query(
                "SELECT reservation_key, provisioning_generation FROM " + TABLE + " WHERE code_hash = ? FOR UPDATE",
                ps -> ps.setString(1, codeHash),
                rs -> {
                    if (!rs.next()) return null;
                    String reservationKey = rs.getString(1);
                    Long generation = rs.getObject(2) == null ? null : rs.getLong(2);
                    if (reservationKey == null || generation == null) {
                        jdbcTemplate.update("DELETE FROM " + TABLE + " WHERE code_hash = ?", codeHash);
                    } else {
                        jdbcTemplate.update(
                            "UPDATE " + TABLE + " SET consumed_at = CURRENT_TIMESTAMP, recoverable_code = NULL, "
                                + "recoverable_code_ciphertext = NULL, "
                                + "access_token = NULL, access_token_ciphertext = NULL WHERE code_hash = ?",
                            codeHash
                        );
                        markProvisioningState(reservationKey, generation, "REVOKED", "CODE_PERSISTED", "DELIVERED");
                    }
                    return null;
                }
            );
        }
    }

    @Transactional
    public AuthResponse redeem(String code) {
        return redeem(code, null);
    }

    @Transactional
    public AuthResponse redeem(String code, String gatewayId) {
        if (code == null || code.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "accessCode is required");
        }
        String normalized = code.trim();
        long now = Instant.now().getEpochSecond();
        String codeHash = hash(normalized);
        CodeRecord record;
        if (inMemoryMode()) {
            record = memory.get(codeHash);
            enforceTargetGateway(record, gatewayId);
            if (record != null) {
                memory.remove(codeHash, record);
            }
        } else {
            record = consumePersisted(normalized, now, gatewayId);
            enforceTargetGateway(record, gatewayId);
        }
        if (record == null || now >= record.expiresAt()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid or expired access code");
        }
        if (inMemoryMode() && record.reservationKey() != null) {
            memoryDeliveries.remove(deliveryKey(record.reservationKey(), record.provisioningGeneration()));
        }
        return new AuthResponse(record.token(), record.labURL(), null, record.resourceType());
    }

    @Scheduled(fixedDelayString = "${auth.access-code.cleanup-interval-ms:30000}")
    @Transactional
    public void cleanupExpired() {
        long now = Instant.now().getEpochSecond();
        if (inMemoryMode()) {
            memory.entrySet().removeIf(entry -> {
                CodeRecord record = entry.getValue();
                boolean remove = now >= record.credentialExpiresAt()
                    || (record.reservationKey() == null && now >= record.expiresAt());
                if (remove && record.reservationKey() != null) {
                    memoryDeliveries.remove(deliveryKey(record.reservationKey(), record.provisioningGeneration()));
                }
                return remove;
            });
        } else {
            try {
                jdbcTemplate.update(
                    "UPDATE access_authorization_provisioning p JOIN " + TABLE + " c "
                        + "ON c.reservation_key = p.reservation_key "
                        + "AND c.provisioning_generation = p.generation "
                        + "SET p.status = 'REVOKED', p.updated_at = CURRENT_TIMESTAMP "
                        + "WHERE c.credential_expires_at <= FROM_UNIXTIME(?) "
                        + "AND p.status IN ('CODE_PERSISTED', 'DELIVERED')",
                    now
                );
                jdbcTemplate.update(
                    "DELETE FROM " + TABLE + " WHERE "
                        + "(reservation_key IS NULL AND expires_at <= FROM_UNIXTIME(?)) "
                        + "OR (reservation_key IS NOT NULL AND credential_expires_at <= FROM_UNIXTIME(?))",
                    now,
                    now
                );
            } catch (DataAccessException ex) {
                log.warn("Access-code cleanup failed", ex);
            }
        }
    }

    private void persist(String code, CodeRecord record) {
        try {
            String encryptedToken = tokenCipher.encrypt(record.token());
            if (record.reservationKey() != null) {
                jdbcTemplate.update(
                    "UPDATE " + TABLE + " SET consumed_at = CURRENT_TIMESTAMP, recoverable_code = NULL, "
                        + "recoverable_code_ciphertext = NULL, "
                        + "access_token = NULL, access_token_ciphertext = NULL "
                        + "WHERE reservation_key = ? AND provisioning_generation <> ? AND consumed_at IS NULL",
                    record.reservationKey(), record.provisioningGeneration()
                );
            }
            jdbcTemplate.update(
                "INSERT INTO " + TABLE + " (code_hash, access_token, access_token_ciphertext, lab_url, resource_type, "
                    + "target_gateway_id, expires_at, reservation_key, provisioning_generation, recoverable_code, "
                    + "recoverable_code_ciphertext, credential_expires_at) "
                    + "VALUES (?, NULL, ?, ?, ?, ?, FROM_UNIXTIME(?), ?, ?, NULL, ?, FROM_UNIXTIME(?))",
                hash(code), encryptedToken, record.labURL(), record.resourceType(), record.targetGatewayId(), record.expiresAt(),
                record.reservationKey(), record.provisioningGeneration(),
                record.reservationKey() != null ? tokenCipher.encrypt(code) : null,
                record.credentialExpiresAt()
            );
            if (record.reservationKey() != null && !markProvisioningState(
                record.reservationKey(), record.provisioningGeneration(), "CODE_PERSISTED", "ACTIVATED"
            )) {
                throw new IllegalStateException("Provisioning generation is not active for access-code persistence");
            }
        } catch (DataAccessException | IllegalStateException ex) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Access-code persistence unavailable", ex);
        }
    }

    private CodeRecord consumePersisted(String code, long now, String gatewayId) {
        String hash = hash(code);
        String normalizedGatewayId = gatewayId == null ? null : gatewayId.trim().toLowerCase();
        try {
            return jdbcTemplate.query(
                "SELECT access_token_ciphertext, lab_url, resource_type, target_gateway_id, UNIX_TIMESTAMP(expires_at), "
                    + "reservation_key, provisioning_generation, UNIX_TIMESTAMP(credential_expires_at) FROM " + TABLE
                    + " WHERE code_hash = ? AND target_gateway_id = ? AND consumed_at IS NULL "
                    + "AND expires_at > FROM_UNIXTIME(?) FOR UPDATE",
                ps -> { ps.setString(1, hash); ps.setString(2, normalizedGatewayId); ps.setLong(3, now); },
                rs -> {
                    if (!rs.next()) return null;
                    String reservationKey = rs.getString(6);
                    Long generation = rs.getObject(7) != null ? rs.getLong(7) : null;
                    long credentialExpiresAt = rs.getObject(8) != null ? rs.getLong(8) : rs.getLong(5);
                    CodeRecord record = new CodeRecord(
                        code, tokenCipher.decrypt(rs.getString(1)), rs.getString(2), rs.getString(3),
                        rs.getString(4), rs.getLong(5),
                        credentialExpiresAt, reservationKey, generation
                    );
                    if (reservationKey == null) {
                        jdbcTemplate.update("DELETE FROM " + TABLE + " WHERE code_hash = ?", hash);
                    } else {
                        jdbcTemplate.update(
                            "UPDATE " + TABLE + " SET consumed_at = CURRENT_TIMESTAMP, recoverable_code = NULL, "
                                + "recoverable_code_ciphertext = NULL, "
                                + "access_token = NULL, access_token_ciphertext = NULL "
                                + "WHERE code_hash = ? AND consumed_at IS NULL",
                            hash
                        );
                        if (!markProvisioningState(
                            reservationKey, generation, "CONSUMED", "DELIVERED", "CODE_PERSISTED"
                        )) {
                            throw new IllegalStateException("Access delivery generation is not consumable");
                        }
                    }
                    return record;
                }
            );
        } catch (EmptyResultDataAccessException ex) {
            return null;
        } catch (DataAccessException | IllegalStateException ex) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Access-code persistence unavailable", ex);
        }
    }

    private AccessCodeResponse recoverPersistedDelivery(String reservationKey, long generation, long now) {
        try {
            return jdbcTemplate.query(
                "SELECT code_hash, recoverable_code_ciphertext, lab_url, resource_type, target_gateway_id, UNIX_TIMESTAMP(expires_at), "
                    + "UNIX_TIMESTAMP(credential_expires_at) FROM " + TABLE
                    + " WHERE reservation_key = ? AND provisioning_generation = ? AND consumed_at IS NULL "
                    + "AND credential_expires_at > FROM_UNIXTIME(?) FOR UPDATE",
                ps -> {
                    ps.setString(1, reservationKey);
                    ps.setLong(2, generation);
                    ps.setLong(3, now);
                },
                rs -> {
                    if (!rs.next()) return null;
                    String code = rs.getString(2) == null ? null : tokenCipher.decrypt(rs.getString(2));
                    String labURL = rs.getString(3);
                    String resourceType = rs.getString(4);
                    if (code != null && now < rs.getLong(6)) {
                        return new AccessCodeResponse(code, labURL, resourceType);
                    }
                    String refreshed = generateCode();
                    long refreshedExpiry = boundedCodeExpiry(now, rs.getLong(7));
                    int updated = jdbcTemplate.update(
                        "UPDATE " + TABLE + " SET code_hash = ?, recoverable_code = NULL, "
                            + "recoverable_code_ciphertext = ?, expires_at = FROM_UNIXTIME(?) "
                            + "WHERE code_hash = ? AND consumed_at IS NULL",
                        hash(refreshed), tokenCipher.encrypt(refreshed), refreshedExpiry, rs.getString(1)
                    );
                    return updated == 1 ? new AccessCodeResponse(refreshed, labURL, resourceType) : null;
                }
            );
        } catch (DataAccessException | IllegalStateException ex) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Access delivery recovery unavailable", ex);
        }
    }

    private ValidatedCredential validatedAccessCredential(String token) {
        if (token == null || token.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "token is required");
        }
        Map<String, Object> claims;
        try {
            claims = jwtService.extractAllClaims(token);
        } catch (RuntimeException ex) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid access credential", ex);
        }
        String resourceType = stringClaim(claims, "resourceType");
        String labURL = stringClaim(claims, "labURL");
        String audience = stringClaim(claims, "aud");
        String targetGatewayId = stringClaim(claims, "targetGatewayId");
        if (!isAllowedAccessUrl(labURL, resourceType) || !sameUrl(labURL, audience)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid access credential destination");
        }
        if (targetGatewayId == null || targetGatewayId.isBlank()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Access credential has no target gateway");
        }
        long now = Instant.now().getEpochSecond();
        Object expClaim = claims.get("exp");
        long credentialExpiresAt;
        if (expClaim instanceof Number number) {
            credentialExpiresAt = number.longValue();
        } else if (expClaim instanceof java.util.Date date) {
            credentialExpiresAt = date.toInstant().getEpochSecond();
        } else {
            credentialExpiresAt = now + Math.max(60L, ttlSeconds);
        }
        if (credentialExpiresAt <= now) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Expired access credential");
        }
        return new ValidatedCredential(
            labURL, resourceType, targetGatewayId.trim().toLowerCase(), credentialExpiresAt
        );
    }

    long boundedCodeExpiry(long now, long credentialExpiresAt) {
        return Math.min(now + Math.max(1, ttlSeconds), credentialExpiresAt);
    }

    private boolean markProvisioningState(
        String reservationKey, Long generation, String targetStatus, String... allowedStatuses
    ) {
        if (reservationKey == null || generation == null) return false;
        String placeholders = String.join(", ", java.util.Collections.nCopies(allowedStatuses.length, "?"));
        Object[] parameters = new Object[3 + allowedStatuses.length];
        parameters[0] = targetStatus;
        parameters[1] = reservationKey;
        parameters[2] = generation;
        System.arraycopy(allowedStatuses, 0, parameters, 3, allowedStatuses.length);
        return jdbcTemplate.update(
            "UPDATE access_authorization_provisioning SET status = ?, updated_at = CURRENT_TIMESTAMP "
                + "WHERE reservation_key = ? AND generation = ? AND status IN (" + placeholders + ")",
            parameters
        ) == 1;
    }

    private void enforceTargetGateway(CodeRecord record, String gatewayId) {
        if (record == null) {
            return;
        }
        String expected = record.targetGatewayId();
        String actual = gatewayId == null ? null : gatewayId.trim().toLowerCase();
        if (expected == null || expected.isBlank() || !expected.equals(actual)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Access code is not valid for this gateway");
        }
    }

    private boolean inMemoryMode() {
        return jdbcTemplate == null;
    }

    private boolean isAllowedAccessUrl(String value, String resourceType) {
        try {
            URI uri = new URI(value);
            if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null || uri.getPath() == null) {
                return false;
            }
            return switch (String.valueOf(resourceType)) {
                case "lab" -> uri.getPath().startsWith("/guacamole");
                case "fmu" -> uri.getPath().startsWith("/fmu");
                default -> false;
            };
        } catch (URISyntaxException | NullPointerException ex) {
            return false;
        }
    }

    private boolean sameUrl(String first, String second) {
        return first != null && second != null && stripTrailingSlash(first).equals(stripTrailingSlash(second));
    }

    private String stripTrailingSlash(String value) {
        int end = value.length();
        while (end > 0 && value.charAt(end - 1) == '/') {
            end--;
        }
        return value.substring(0, end);
    }

    private String stringClaim(Map<String, Object> claims, String name) {
        Object value = claims.get(name);
        return value == null ? null : String.valueOf(value);
    }

    private String generateCode() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String deliveryKey(String reservationKey, Long generation) {
        return reservationKey + ":" + generation;
    }

    private String hash(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder(64);
            for (byte b : digest) result.append(String.format("%02x", b));
            return result.toString();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 unavailable", ex);
        }
    }

    private record ValidatedCredential(String labURL, String resourceType, String targetGatewayId, long expiresAt) { }

    private record CodeRecord(
        String code,
        String token,
        String labURL,
        String resourceType,
        String targetGatewayId,
        long expiresAt,
        long credentialExpiresAt,
        String reservationKey,
        Long provisioningGeneration
    ) { }
}
