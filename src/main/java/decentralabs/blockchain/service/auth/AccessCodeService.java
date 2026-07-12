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
    private final SecureRandom random = new SecureRandom();
    private final ConcurrentMap<String, CodeRecord> memory = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, String> memoryDeliveries = new ConcurrentHashMap<>();

    @Value("${auth.access-code.ttl-seconds:60}")
    private long ttlSeconds = 60;

    public AccessCodeService(ObjectProvider<JdbcTemplate> jdbcTemplateProvider, JwtService jwtService) {
        this.jdbcTemplate = jdbcTemplateProvider.getIfAvailable();
        this.jwtService = jwtService;
    }

    public AccessCodeResponse issue(String token) {
        return issueInternal(token, null, null);
    }

    public AccessCodeResponse issue(String token, String reservationKey, long provisioningGeneration) {
        if (reservationKey == null || reservationKey.isBlank() || provisioningGeneration < 1) {
            throw new IllegalArgumentException("reservationKey and provisioningGeneration are required");
        }
        return issueInternal(token, reservationKey, provisioningGeneration);
    }

    private AccessCodeResponse issueInternal(String token, String reservationKey, Long provisioningGeneration) {
        ValidatedCredential credential = validatedAccessCredential(token);
        long expiresAt = Instant.now().plusSeconds(Math.max(1, ttlSeconds)).getEpochSecond();
        String code = generateCode();
        CodeRecord record = new CodeRecord(
            code,
            token,
            credential.labURL(),
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
        return new AccessCodeResponse(code, credential.labURL());
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
                return new AccessCodeResponse(record.code(), record.labURL());
            }
            String refreshed = generateCode();
            CodeRecord refreshedRecord = new CodeRecord(
                refreshed, record.token(), record.labURL(),
                Instant.now().plusSeconds(Math.max(1, ttlSeconds)).getEpochSecond(),
                record.credentialExpiresAt(), reservationKey, provisioningGeneration
            );
            memory.remove(codeHash);
            String refreshedHash = hash(refreshed);
            memory.put(refreshedHash, refreshedRecord);
            memoryDeliveries.put(key, refreshedHash);
            return new AccessCodeResponse(refreshed, record.labURL());
        }
        return recoverPersistedDelivery(reservationKey, provisioningGeneration, now);
    }

    public void revoke(String code) {
        if (code == null || code.isBlank()) return;
        String codeHash = hash(code.trim());
        if (inMemoryMode()) {
            CodeRecord removed = memory.remove(codeHash);
            if (removed != null && removed.reservationKey() != null) {
                memoryDeliveries.remove(deliveryKey(removed.reservationKey(), removed.provisioningGeneration()));
            }
        } else {
            jdbcTemplate.update("DELETE FROM " + TABLE + " WHERE code_hash = ?", codeHash);
        }
    }

    @Transactional
    public AuthResponse redeem(String code) {
        if (code == null || code.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "accessCode is required");
        }
        String normalized = code.trim();
        long now = Instant.now().getEpochSecond();
        String codeHash = hash(normalized);
        CodeRecord record = inMemoryMode()
            ? memory.remove(codeHash)
            : consumePersisted(normalized, now);
        if (record == null || now >= record.expiresAt()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid or expired access code");
        }
        if (inMemoryMode() && record.reservationKey() != null) {
            memoryDeliveries.remove(deliveryKey(record.reservationKey(), record.provisioningGeneration()));
        }
        return new AuthResponse(record.token(), record.labURL());
    }

    @Scheduled(fixedDelayString = "${auth.access-code.cleanup-interval-ms:30000}")
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
            jdbcTemplate.update(
                "INSERT INTO " + TABLE + " (code_hash, access_token, lab_url, expires_at, "
                    + "reservation_key, provisioning_generation, recoverable_code, credential_expires_at) "
                    + "VALUES (?, ?, ?, FROM_UNIXTIME(?), ?, ?, ?, FROM_UNIXTIME(?))",
                hash(code), record.token(), record.labURL(), record.expiresAt(),
                record.reservationKey(), record.provisioningGeneration(),
                record.reservationKey() != null ? code : null,
                record.credentialExpiresAt()
            );
        } catch (DataAccessException ex) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Access-code persistence unavailable", ex);
        }
    }

    private CodeRecord consumePersisted(String code, long now) {
        String hash = hash(code);
        try {
            return jdbcTemplate.query(
                "SELECT access_token, lab_url, UNIX_TIMESTAMP(expires_at), reservation_key, "
                    + "provisioning_generation, UNIX_TIMESTAMP(credential_expires_at), recoverable_code FROM " + TABLE
                    + " WHERE code_hash = ? AND consumed_at IS NULL AND expires_at > FROM_UNIXTIME(?) FOR UPDATE",
                ps -> { ps.setString(1, hash); ps.setLong(2, now); },
                rs -> {
                    if (!rs.next()) return null;
                    String reservationKey = rs.getString(4);
                    Long generation = rs.getObject(5) != null ? rs.getLong(5) : null;
                    long credentialExpiresAt = rs.getObject(6) != null ? rs.getLong(6) : rs.getLong(3);
                    CodeRecord record = new CodeRecord(
                        rs.getString(7), rs.getString(1), rs.getString(2), rs.getLong(3),
                        credentialExpiresAt, reservationKey, generation
                    );
                    if (reservationKey == null) {
                        jdbcTemplate.update("DELETE FROM " + TABLE + " WHERE code_hash = ?", hash);
                    } else {
                        jdbcTemplate.update(
                            "UPDATE " + TABLE + " SET consumed_at = CURRENT_TIMESTAMP, recoverable_code = NULL "
                                + "WHERE code_hash = ? AND consumed_at IS NULL",
                            hash
                        );
                    }
                    return record;
                }
            );
        } catch (EmptyResultDataAccessException ex) {
            return null;
        } catch (DataAccessException ex) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Access-code persistence unavailable", ex);
        }
    }

    private AccessCodeResponse recoverPersistedDelivery(String reservationKey, long generation, long now) {
        try {
            return jdbcTemplate.query(
                "SELECT code_hash, recoverable_code, access_token, lab_url, UNIX_TIMESTAMP(expires_at), "
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
                    String code = rs.getString(2);
                    String labURL = rs.getString(4);
                    if (code != null && now < rs.getLong(5)) {
                        return new AccessCodeResponse(code, labURL);
                    }
                    String refreshed = generateCode();
                    long refreshedExpiry = Instant.now().plusSeconds(Math.max(1, ttlSeconds)).getEpochSecond();
                    int updated = jdbcTemplate.update(
                        "UPDATE " + TABLE + " SET code_hash = ?, recoverable_code = ?, expires_at = FROM_UNIXTIME(?) "
                            + "WHERE code_hash = ? AND consumed_at IS NULL",
                        hash(refreshed), refreshed, refreshedExpiry, rs.getString(1)
                    );
                    return updated == 1 ? new AccessCodeResponse(refreshed, labURL) : null;
                }
            );
        } catch (DataAccessException ex) {
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
        if (!isAllowedAccessUrl(labURL, resourceType) || !sameUrl(labURL, audience)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid access credential destination");
        }
        long now = Instant.now().getEpochSecond();
        Object expClaim = claims.get("exp");
        long credentialExpiresAt = expClaim instanceof Number number
            ? number.longValue()
            : now + Math.max(60L, ttlSeconds);
        if (credentialExpiresAt <= now) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Expired access credential");
        }
        return new ValidatedCredential(labURL, credentialExpiresAt);
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

    private record ValidatedCredential(String labURL, long expiresAt) { }

    private record CodeRecord(
        String code,
        String token,
        String labURL,
        long expiresAt,
        long credentialExpiresAt,
        String reservationKey,
        Long provisioningGeneration
    ) { }
}
