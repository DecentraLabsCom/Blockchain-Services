package decentralabs.blockchain.service.auth;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import io.micrometer.observation.annotation.Observed;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * Service for storing and retrieving WebAuthn credentials.
 * 
 * Credentials are persisted to the database by default. Memory-only storage is available only
 * when explicitly enabled for an isolated development or standalone deployment; it must not be
 * used by a deployment that accepts reservations.
 */
@Service
@Slf4j
public class WebauthnCredentialService {

    private static final Pattern SAFE_TABLE_NAME = Pattern.compile("^[a-zA-Z_][a-zA-Z0-9_]*$");

    @Value("${webauthn.credentials.table:webauthn_credentials}")
    private String credentialsTable;

    @Value("${webauthn.credentials.max-age-days:365}")
    private long credentialsMaxAgeDays;

    @Value("${webauthn.credentials.require-database:true}")
    private boolean databaseRequired = true;

    private final JdbcTemplate jdbcTemplate;

    /**
     * In-memory fallback storage when database is not available.
     * Key: puc + ":" + credentialId
     */
    private final ConcurrentHashMap<String, WebauthnCredential> inMemoryCredentials = new ConcurrentHashMap<>();

    public WebauthnCredentialService(ObjectProvider<JdbcTemplate> jdbcTemplateProvider) {
        this.jdbcTemplate = jdbcTemplateProvider.getIfAvailable();
        if (this.jdbcTemplate == null) {
            log.warn("WebauthnCredentialService: No database configured. Durable credential operations require a datasource; "
                + "memory-only mode must be explicitly enabled for isolated deployments.");
        }
    }

    @jakarta.annotation.PostConstruct
    void validateTableName() {
        if (!SAFE_TABLE_NAME.matcher(credentialsTable).matches()) {
            throw new IllegalStateException(
                "Invalid webauthn.credentials.table value: must match [a-zA-Z_][a-zA-Z0-9_]*");
        }
        requireDatabaseIfConfigured();
    }

    /**
     * Check if database persistence is available.
     */
    public boolean isDatabaseAvailable() {
        return jdbcTemplate != null;
    }

    public synchronized void register(String puc, String credentialId, String publicKey, String aaguid, Long signCount,
                                      String authenticatorAttachment, Boolean residentKey, String transports) {
        String normalizedPuc = normalize(puc);
        String normalizedCred = normalize(credentialId);
        long now = Instant.now().getEpochSecond();
        String normalizedAttachment = normalize(authenticatorAttachment);
        String normalizedTransports = normalize(transports);

        String key = normalizedPuc + ":" + normalizedCred;
        WebauthnCredential credential = new WebauthnCredential(
            normalizedCred, publicKey, aaguid, 
            signCount != null ? signCount : 0L, 
            true, now, now, null,
            normalizedAttachment.isEmpty() ? null : normalizedAttachment,
            residentKey,
            normalizedTransports.isEmpty() ? null : normalizedTransports
        );
        if (jdbcTemplate == null) {
            requireDatabaseIfConfigured();
            inMemoryCredentials.put(key, credential);
            log.warn("WebAuthn credential stored in explicitly enabled memory-only mode");
            return;
        }

        try {
            String sql = "INSERT INTO " + credentialsTable + " (puc, credential_id, public_key, aaguid, sign_count, active, " +
                "created_at, updated_at, authenticator_attachment, resident_key, transports) " +
                "VALUES (?, ?, ?, ?, ?, TRUE, FROM_UNIXTIME(?), FROM_UNIXTIME(?), ?, ?, ?) " +
                "ON DUPLICATE KEY UPDATE " +
                "public_key=VALUES(public_key), " +
                "aaguid=VALUES(aaguid), " +
                "sign_count=VALUES(sign_count), " +
                "active=TRUE, " +
                "revoked_at=NULL, " +
                "authenticator_attachment=VALUES(authenticator_attachment), " +
                "resident_key=VALUES(resident_key), " +
                "transports=VALUES(transports), " +
                "updated_at=VALUES(updated_at)";
            jdbcTemplate.update(sql,
                normalizedPuc,
                normalizedCred,
                publicKey,
                aaguid,
                signCount != null ? signCount : 0L,
                now,
                now,
                normalizedAttachment.isEmpty() ? null : normalizedAttachment,
                residentKey,
                normalizedTransports.isEmpty() ? null : normalizedTransports
            );
        } catch (DataAccessException ex) {
            throw new IllegalStateException("WebAuthn credential durable persistence failed", ex);
        }
    }

    public synchronized void revoke(String puc, String credentialId) {
        String normalizedPuc = normalize(puc);
        String normalizedCred = normalize(credentialId);
        long now = Instant.now().getEpochSecond();

        String key = normalizedPuc + ":" + normalizedCred;
        if (jdbcTemplate == null) {
            requireDatabaseIfConfigured();
            revokeInMemory(key, now);
            log.warn("WebAuthn credential revoked in explicitly enabled memory-only mode");
            return;
        }

        try {
            String sql = "UPDATE " + credentialsTable + " " +
                "SET active=FALSE, revoked_at=FROM_UNIXTIME(?), updated_at=FROM_UNIXTIME(?) " +
                "WHERE puc = ? AND credential_id = ?";
            jdbcTemplate.update(sql,
                now,
                now,
                normalizedPuc,
                normalizedCred
            );
        } catch (DataAccessException ex) {
            throw new IllegalStateException("WebAuthn credential durable revocation failed", ex);
        }
    }

    @Observed(name = "webauthn.credentials.revoke", contextualName = "revoke-expired-webauthn-credentials")
    @Scheduled(fixedDelayString = "${webauthn.credentials.revoke.interval.ms:86400000}")
    public synchronized void revokeExpiredCredentials() {
        if (credentialsMaxAgeDays <= 0) {
            return;
        }

        Instant now = Instant.now();
        long cutoffEpoch = now.minus(credentialsMaxAgeDays, ChronoUnit.DAYS).getEpochSecond();
        long nowEpoch = now.getEpochSecond();

        if (jdbcTemplate == null) {
            requireDatabaseIfConfigured();
            int memoryRevoked = 0;
            for (WebauthnCredential credential : inMemoryCredentials.values()) {
                if (!credential.isActive()) {
                    continue;
                }
                Long createdAt = credential.getCreatedAt();
                if (createdAt != null && createdAt > 0 && createdAt <= cutoffEpoch) {
                    credential.setActive(false);
                    credential.setRevokedAt(nowEpoch);
                    credential.setUpdatedAt(nowEpoch);
                    memoryRevoked++;
                }
            }
            if (memoryRevoked > 0) {
                log.info("Revoked {} expired WebAuthn credential(s) from memory", memoryRevoked);
            }
            return;
        }

        try {
            String sql = "UPDATE " + credentialsTable + " " +
                "SET active=FALSE, revoked_at=FROM_UNIXTIME(?), updated_at=FROM_UNIXTIME(?) " +
                "WHERE active=TRUE AND created_at < FROM_UNIXTIME(?)";
            int dbRevoked = jdbcTemplate.update(sql, nowEpoch, nowEpoch, cutoffEpoch);
            if (dbRevoked > 0) {
                log.info("Revoked {} expired WebAuthn credential(s) from database", dbRevoked);
            }
        } catch (DataAccessException ex) {
            throw new IllegalStateException("WebAuthn expired-credential revocation failed", ex);
        }
    }

    public boolean isCredentialActive(String puc, String credentialId) {
        return findCredential(puc, credentialId).map(credential -> credential.isActive()).orElse(false);
    }

    public Optional<WebauthnCredential> findCredential(String puc, String credentialId) {
        String normalizedPuc = normalize(puc);
        String normalizedCred = normalize(credentialId);

        String key = normalizedPuc + ":" + normalizedCred;
        if (jdbcTemplate == null) {
            requireDatabaseIfConfigured();
            WebauthnCredential inMemory = inMemoryCredentials.get(key);
            return inMemory == null ? Optional.empty() : Optional.of(inMemory);
        }

        try {
            String sql = "SELECT credential_id, public_key, aaguid, sign_count, active, " +
                "UNIX_TIMESTAMP(created_at), UNIX_TIMESTAMP(updated_at), UNIX_TIMESTAMP(revoked_at), " +
                "authenticator_attachment, resident_key, transports " +
                "FROM " + credentialsTable + " " +
                "WHERE puc = ? AND credential_id = ? " +
                "LIMIT 1";
            return jdbcTemplate.query(sql,
                ps -> {
                    ps.setString(1, normalizedPuc);
                    ps.setString(2, normalizedCred);
                },
                rs -> rs.next()
                    ? Optional.of(new WebauthnCredential(
                        rs.getString(1),
                        rs.getString(2),
                        rs.getString(3),
                        rs.getLong(4),
                        rs.getBoolean(5),
                        rs.getLong(6),
                        rs.getLong(7),
                        rs.getObject(8) != null ? rs.getLong(8) : null,
                        rs.getString(9),
                        rs.getObject(10) != null ? rs.getBoolean(10) : null,
                        rs.getString(11)
                    ))
                    : Optional.empty()
            );
        } catch (DataAccessException ex) {
            log.warn("webAuthn DB fetch failed: {}", ex.getMessage());
            throw ex;
        }
    }

    private void revokeInMemory(String key, long now) {
        WebauthnCredential existing = inMemoryCredentials.get(key);
        if (existing != null) {
            existing.setActive(false);
            existing.setRevokedAt(now);
            existing.setUpdatedAt(now);
        }
    }

    private void requireDatabaseIfConfigured() {
        if (databaseRequired && jdbcTemplate == null) {
            throw new IllegalStateException(
                "WebAuthn credential database is required; configure a datasource or explicitly disable "
                    + "webauthn.credentials.require-database only for isolated memory-only deployments"
            );
        }
    }

    /**
     * Applies the WebAuthn signature counter after a signature has been
     * verified. A non-zero counter must move forward; when a database is
     * configured the compare-and-set update also serializes assertions across
     * backend instances.
     */
    public synchronized boolean advanceSignCount(String puc, String credentialId, long newSignCount) {
        if (newSignCount < 0 || newSignCount > 0xFFFF_FFFFL) {
            return false;
        }

        Optional<WebauthnCredential> found = findCredential(puc, credentialId);
        if (found.isEmpty() || !found.get().isActive()) {
            return false;
        }

        WebauthnCredential credential = found.get();
        long currentSignCount = credential.getSignCount() == null ? 0L : credential.getSignCount();
        if (currentSignCount > 0 && newSignCount > 0 && newSignCount <= currentSignCount) {
            return false;
        }
        // Authenticators with a zero counter do not provide clone detection.
        if (newSignCount <= currentSignCount) {
            return true;
        }

        String normalizedPuc = normalize(puc);
        String normalizedCred = normalize(credentialId);
        long now = Instant.now().getEpochSecond();

        if (jdbcTemplate != null) {
            String sql = "UPDATE " + credentialsTable + " "
                + "SET sign_count=?, updated_at=FROM_UNIXTIME(?) "
                + "WHERE puc=? AND credential_id=? AND active=TRUE AND sign_count=?";
            int updated = jdbcTemplate.update(sql,
                newSignCount,
                now,
                normalizedPuc,
                normalizedCred,
                currentSignCount
            );
            if (updated != 1) {
                return false;
            }
        }

        credential.setSignCount(newSignCount);
        credential.setUpdatedAt(now);
        return true;
    }

    public List<WebauthnCredential> getCredentials(String puc) {
        String normalizedPuc = normalize(puc);
        if (jdbcTemplate == null) {
            requireDatabaseIfConfigured();
            String keyPrefix = normalizedPuc + ":";
            List<WebauthnCredential> result = new ArrayList<>();
            for (var entry : inMemoryCredentials.entrySet()) {
                if (entry.getKey().startsWith(keyPrefix)) {
                    result.add(entry.getValue());
                }
            }
            return result;
        }

        try {
            String sql = "SELECT credential_id, public_key, aaguid, sign_count, active, " +
                "UNIX_TIMESTAMP(created_at), UNIX_TIMESTAMP(updated_at), UNIX_TIMESTAMP(revoked_at), " +
                "authenticator_attachment, resident_key, transports " +
                "FROM " + credentialsTable + " " +
                "WHERE puc = ?";
            List<WebauthnCredential> dbCredentials = jdbcTemplate.query(sql,
                ps -> ps.setString(1, normalizedPuc),
                (rs, rowNum) -> new WebauthnCredential(
                    rs.getString(1),
                    rs.getString(2),
                    rs.getString(3),
                    rs.getLong(4),
                    rs.getBoolean(5),
                    rs.getLong(6),
                    rs.getLong(7),
                    rs.getObject(8) != null ? rs.getLong(8) : null,
                    rs.getString(9),
                    rs.getObject(10) != null ? rs.getBoolean(10) : null,
                    rs.getString(11)
                )
            );
            return dbCredentials;
        } catch (DataAccessException ex) {
            log.warn("webAuthn DB fetch all failed: {}", ex.getMessage());
            throw ex;
        }
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim();
    }

    /**
     * Get the key status for a user - whether they have registered credentials.
     * This is used by the SP to determine if onboarding is needed.
     * 
     * @param puc The stable user identifier (Principal User Claim)
     * @return KeyStatus containing credential information
     */
    public KeyStatus getKeyStatus(String puc) {
        String normalizedPuc = normalize(puc);
        List<WebauthnCredential> credentials = getCredentials(normalizedPuc);
        
        int activeCount = 0;
        int revokedCount = 0;
        Long mostRecentRegistration = null;
        boolean hasPlatformCredential = false;
        boolean hasCrossPlatformCredential = false;
        boolean hasResidentCredential = false;
        
        for (WebauthnCredential cred : credentials) {
            if (cred.isActive()) {
                activeCount++;
                if (mostRecentRegistration == null || 
                    (cred.getCreatedAt() != null && cred.getCreatedAt() > mostRecentRegistration)) {
                    mostRecentRegistration = cred.getCreatedAt();
                }
                if (isPlatformCredential(cred)) {
                    hasPlatformCredential = true;
                }
                if (isCrossPlatformCredential(cred)) {
                    hasCrossPlatformCredential = true;
                }
                if (Boolean.TRUE.equals(cred.getResidentKey())) {
                    hasResidentCredential = true;
                }
            } else {
                revokedCount++;
            }
        }
        
        return new KeyStatus(
            activeCount > 0,
            activeCount,
            revokedCount > 0,
            mostRecentRegistration,
            hasPlatformCredential,
            hasCrossPlatformCredential,
            hasResidentCredential
        );
    }

    private boolean isPlatformCredential(WebauthnCredential credential) {
        if (credential == null) return false;
        String transports = normalize(credential.getTransports());
        if (!transports.isEmpty()) {
            List<String> transportList = Arrays.stream(transports.split(","))
                .map(transport -> transport.trim())
                .map(transport -> transport.toLowerCase())
                .filter(s -> !s.isEmpty())
                .toList();
            return transportList.contains("internal");
        }
        String attachment = normalize(credential.getAuthenticatorAttachment());
        if (attachment.equalsIgnoreCase("platform")) return true;
        if (attachment.equalsIgnoreCase("mixed")) return true;
        return false;
    }

    private boolean isCrossPlatformCredential(WebauthnCredential credential) {
        if (credential == null) return false;
        String transports = normalize(credential.getTransports());
        if (!transports.isEmpty()) {
            List<String> transportList = Arrays.stream(transports.split(","))
                .map(transport -> transport.trim())
                .map(transport -> transport.toLowerCase())
                .filter(s -> !s.isEmpty())
                .toList();
            return transportList.stream().anyMatch(t -> !"internal".equals(t));
        }
        String attachment = normalize(credential.getAuthenticatorAttachment());
        if (attachment.equalsIgnoreCase("cross-platform")) return true;
        if (attachment.equalsIgnoreCase("mixed")) return true;
        return false;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class KeyStatus {
        private boolean hasCredential;
        private int credentialCount;
        private boolean hasRevokedCredentials;
        private Long lastRegisteredEpoch;
        private boolean hasPlatformCredential;
        private boolean hasCrossPlatformCredential;
        private boolean hasResidentCredential;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class WebauthnCredential {
        private String credentialId;
        private String publicKey;
        private String aaguid;
        private Long signCount;
        private boolean active;
        private Long createdAt;
        private Long updatedAt;
        private Long revokedAt;
        private String authenticatorAttachment;
        private Boolean residentKey;
        private String transports;
    }
}
