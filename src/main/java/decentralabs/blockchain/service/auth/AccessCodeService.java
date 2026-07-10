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

    @Value("${auth.access-code.ttl-seconds:60}")
    private long ttlSeconds = 60;

    public AccessCodeService(ObjectProvider<JdbcTemplate> jdbcTemplateProvider, JwtService jwtService) {
        this.jdbcTemplate = jdbcTemplateProvider.getIfAvailable();
        this.jwtService = jwtService;
    }

    public AccessCodeResponse issue(String token) {
        String labURL = validatedGuacamoleLabUrl(token);
        long expiresAt = Instant.now().plusSeconds(Math.max(1, ttlSeconds)).getEpochSecond();
        String code = generateCode();
        CodeRecord record = new CodeRecord(token, labURL, expiresAt);
        if (inMemoryMode()) {
            memory.put(hash(code), record);
        } else {
            persist(code, record);
        }
        return new AccessCodeResponse(code, labURL);
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
        return new AuthResponse(record.token(), record.labURL());
    }

    @Scheduled(fixedDelayString = "${auth.access-code.cleanup-interval-ms:30000}")
    public void cleanupExpired() {
        long now = Instant.now().getEpochSecond();
        if (inMemoryMode()) {
            memory.entrySet().removeIf(entry -> now >= entry.getValue().expiresAt());
        } else {
            try {
                jdbcTemplate.update("DELETE FROM " + TABLE + " WHERE expires_at <= FROM_UNIXTIME(?)", now);
            } catch (DataAccessException ex) {
                log.warn("Access-code cleanup failed", ex);
            }
        }
    }

    private void persist(String code, CodeRecord record) {
        try {
            jdbcTemplate.update(
                "INSERT INTO " + TABLE + " (code_hash, access_token, lab_url, expires_at) VALUES (?, ?, ?, FROM_UNIXTIME(?))",
                hash(code), record.token(), record.labURL(), record.expiresAt()
            );
        } catch (DataAccessException ex) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Access-code persistence unavailable", ex);
        }
    }

    private CodeRecord consumePersisted(String code, long now) {
        String hash = hash(code);
        try {
            return jdbcTemplate.query(
                "SELECT access_token, lab_url, UNIX_TIMESTAMP(expires_at) FROM " + TABLE +
                    " WHERE code_hash = ? AND expires_at > FROM_UNIXTIME(?) FOR UPDATE",
                ps -> { ps.setString(1, hash); ps.setLong(2, now); },
                rs -> {
                    if (!rs.next()) return null;
                    CodeRecord record = new CodeRecord(rs.getString(1), rs.getString(2), rs.getLong(3));
                    jdbcTemplate.update("DELETE FROM " + TABLE + " WHERE code_hash = ?", hash);
                    return record;
                }
            );
        } catch (EmptyResultDataAccessException ex) {
            return null;
        } catch (DataAccessException ex) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Access-code persistence unavailable", ex);
        }
    }

    private String validatedGuacamoleLabUrl(String token) {
        if (token == null || token.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "token is required");
        }
        Map<String, Object> claims;
        try {
            claims = jwtService.extractAllClaims(token);
        } catch (RuntimeException ex) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid access credential", ex);
        }
        if (!"lab".equals(String.valueOf(claims.get("resourceType")))) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Access codes are only supported for Guacamole labs");
        }
        String labURL = stringClaim(claims, "labURL");
        String audience = stringClaim(claims, "aud");
        if (!isHttpsUrl(labURL) || !sameUrl(labURL, audience)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid Guacamole access credential");
        }
        return labURL;
    }

    private boolean inMemoryMode() {
        return jdbcTemplate == null;
    }

    private boolean isHttpsUrl(String value) {
        try {
            URI uri = new URI(value);
            return "https".equalsIgnoreCase(uri.getScheme())
                && uri.getHost() != null
                && uri.getPath() != null
                && uri.getPath().startsWith("/guacamole");
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

    private record CodeRecord(String token, String labURL, long expiresAt) { }
}
