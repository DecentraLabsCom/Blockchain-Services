package decentralabs.blockchain.service.auth;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
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
 * When running with Lab Gateway (MySQL available), credentials are persisted to the database.
 * When running standalone (no database), credentials are stored in memory only and will be
 * lost on service restart. This is acceptable for standalone mode since credential storage
 * is primarily needed for the Lab Gateway deployment.
 */
@Service
@Slf4j
public class WebauthnCredentialService {

    @Value("${webauthn.credentials.table:webauthn_credentials}")
    private String credentialsTable;

    @Value("${webauthn.credentials.max-age-days:365}")
    private long credentialsMaxAgeDays;

    private final JdbcTemplate jdbcTemplate; // May be null if no datasource

    /**
     * In-memory fallback storage when database is not available.
     * Key: puc + ":" + credentialId
     */
    private final ConcurrentHashMap<String, WebauthnCredential> inMemoryCredentials = new ConcurrentHashMap<>();

    public WebauthnCredentialService(ObjectProvider<JdbcTemplate> jdbcTemplateProvider) {
        this.jdbcTemplate = jdbcTemplateProvider.getIfAvailable();
        if (this.jdbcTemplate == null) {
            log.warn("WebauthnCredentialService: No database configured. Credentials will be stored in memory only and lost on restart.");
        }
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

        // Always store in memory (for immediate lookup)
        String key = normalizedPuc + ":" + normalizedCred;
        WebauthnCredential credential = new WebauthnCredential(
            normalizedCred, publicKey, aaguid, 
            signCount != null ? signCount : 0L, 
            true, now, now, null,
            normalizedAttachment.isEmpty() ? null : normalizedAttachment,
            residentKey,
            normalizedTransports.isEmpty() ? null : normalizedTransports
        );
        inMemoryCredentials.put(key, credential);

        // Also persist to database if available
        if (jdbcTemplate == null) {
            log.debug("WebAuthn credential stored in memory only (no database): puc={}", normalizedPuc);
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
            log.warn("webAuthn DB persistence failed (credential still in memory): {}", ex.getMessage());
            // Don't throw - credential is still usable from memory
        }
    }

    public synchronized void revoke(String puc, String credentialId) {
        String normalizedPuc = normalize(puc);
        String normalizedCred = normalize(credentialId);
        long now = Instant.now().getEpochSecond();

        // Update in-memory
        String key = normalizedPuc + ":" + normalizedCred;
        WebauthnCredential existing = inMemoryCredentials.get(key);
        if (existing != null) {
            existing.setActive(false);
            existing.setRevokedAt(now);
            existing.setUpdatedAt(now);
        }

        // Also update database if available
        if (jdbcTemplate == null) {
            log.debug("WebAuthn credential revoked in memory only (no database): puc={}", normalizedPuc);
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
            log.warn("webAuthn DB revoke failed: {}", ex.getMessage());
            // Don't throw - credential is still revoked in memory
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

        if (jdbcTemplate == null) {
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
            if (dbRevoked > 0 || memoryRevoked > 0) {
                log.info("Revoked {} expired WebAuthn credential(s) (db={}, memory={})",
                    dbRevoked + memoryRevoked, dbRevoked, memoryRevoked);
            }
        } catch (DataAccessException ex) {
            log.warn("webAuthn DB revoke-expired failed: {}", ex.getMessage());
        }
    }

    public boolean isCredentialActive(String puc, String credentialId) {
        return findCredential(puc, credentialId).map(WebauthnCredential::isActive).orElse(false);
    }

    public Optional<WebauthnCredential> findCredential(String puc, String credentialId) {
        String normalizedPuc = normalize(puc);
        String normalizedCred = normalize(credentialId);

        // Check in-memory first
        String key = normalizedPuc + ":" + normalizedCred;
        WebauthnCredential inMemory = inMemoryCredentials.get(key);
        if (inMemory != null) {
            return Optional.of(inMemory);
        }

        // Fall back to database if available
        if (jdbcTemplate == null) {
            return Optional.empty();
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

    public List<WebauthnCredential> getCredentials(String puc) {
        String normalizedPuc = normalize(puc);
        String keyPrefix = normalizedPuc + ":";

        // Collect from in-memory
        List<WebauthnCredential> result = new ArrayList<>();
        for (var entry : inMemoryCredentials.entrySet()) {
            if (entry.getKey().startsWith(keyPrefix)) {
                result.add(entry.getValue());
            }
        }

        // If no database, return in-memory results
        if (jdbcTemplate == null) {
            return result;
        }

        // Merge with database results (database may have credentials from previous sessions)
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
            
            // Add DB credentials not already in memory
            for (WebauthnCredential dbCred : dbCredentials) {
                String key = normalizedPuc + ":" + dbCred.getCredentialId();
                if (!inMemoryCredentials.containsKey(key)) {
                    result.add(dbCred);
                }
            }
            return result;
        } catch (DataAccessException ex) {
            log.warn("webAuthn DB fetch all failed, returning in-memory only: {}", ex.getMessage());
            return result;
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
                .map(String::trim)
                .map(String::toLowerCase)
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
                .map(String::trim)
                .map(String::toLowerCase)
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
