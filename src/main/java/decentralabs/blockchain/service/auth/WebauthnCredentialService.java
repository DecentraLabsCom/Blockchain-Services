package decentralabs.blockchain.service.auth;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class WebauthnCredentialService {

    @Value("${webauthn.credentials.table:webauthn_credentials}")
    private String credentialsTable;

    private final JdbcTemplate jdbcTemplate;

    public WebauthnCredentialService(ObjectProvider<JdbcTemplate> jdbcTemplateProvider) {
        this.jdbcTemplate = jdbcTemplateProvider.getIfAvailable();
        if (this.jdbcTemplate == null) {
            throw new IllegalStateException("WebauthnCredentialService requires a configured datasource/JdbcTemplate");
        }
    }

    public synchronized void register(String puc, String credentialId, String publicKey, String aaguid, Long signCount) {
        String normalizedPuc = normalize(puc);
        String normalizedCred = normalize(credentialId);
        long now = Instant.now().getEpochSecond();
        try {
            String sql = "INSERT INTO " + credentialsTable + " (puc, credential_id, public_key, aaguid, sign_count, active, created_at, updated_at) " +
                "VALUES (?, ?, ?, ?, ?, TRUE, FROM_UNIXTIME(?), FROM_UNIXTIME(?)) " +
                "ON DUPLICATE KEY UPDATE " +
                "public_key=VALUES(public_key), " +
                "aaguid=VALUES(aaguid), " +
                "sign_count=VALUES(sign_count), " +
                "active=TRUE, " +
                "revoked_at=NULL, " +
                "updated_at=VALUES(updated_at)";
            jdbcTemplate.update(sql,
                normalizedPuc,
                normalizedCred,
                publicKey,
                aaguid,
                signCount != null ? signCount : 0L,
                now,
                now
            );
        } catch (DataAccessException ex) {
            log.warn("webAuthn DB persistence failed: {}", ex.getMessage());
            throw ex;
        }
    }

    public synchronized void revoke(String puc, String credentialId) {
        String normalizedPuc = normalize(puc);
        String normalizedCred = normalize(credentialId);
        long now = Instant.now().getEpochSecond();
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
            throw ex;
        }
    }

    public boolean isCredentialActive(String puc, String credentialId) {
        return findCredential(puc, credentialId).map(WebauthnCredential::isActive).orElse(false);
    }

    public Optional<WebauthnCredential> findCredential(String puc, String credentialId) {
        String normalizedPuc = normalize(puc);
        String normalizedCred = normalize(credentialId);
        try {
            String sql = "SELECT credential_id, public_key, aaguid, sign_count, active, " +
                "UNIX_TIMESTAMP(created_at), UNIX_TIMESTAMP(updated_at), UNIX_TIMESTAMP(revoked_at) " +
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
                        rs.getObject(8) != null ? rs.getLong(8) : null
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
        try {
            String sql = "SELECT credential_id, public_key, aaguid, sign_count, active, " +
                "UNIX_TIMESTAMP(created_at), UNIX_TIMESTAMP(updated_at), UNIX_TIMESTAMP(revoked_at) " +
                "FROM " + credentialsTable + " " +
                "WHERE puc = ?";
            return jdbcTemplate.query(sql,
                ps -> ps.setString(1, normalizedPuc),
                (rs, rowNum) -> new WebauthnCredential(
                    rs.getString(1),
                    rs.getString(2),
                    rs.getString(3),
                    rs.getLong(4),
                    rs.getBoolean(5),
                    rs.getLong(6),
                    rs.getLong(7),
                    rs.getObject(8) != null ? rs.getLong(8) : null
                )
            );
        } catch (DataAccessException ex) {
            log.warn("webAuthn DB fetch all failed: {}", ex.getMessage());
            throw ex;
        }
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim();
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
    }
}
