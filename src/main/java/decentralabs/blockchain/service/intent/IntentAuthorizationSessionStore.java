package decentralabs.blockchain.service.intent;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.dto.intent.IntentSubmission;
import decentralabs.blockchain.service.auth.AccessCodeTokenCipher;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/** Durable, encrypted store for short-lived WebAuthn intent ceremonies. */
@Service
@Slf4j
public class IntentAuthorizationSessionStore {
    private final JdbcTemplate jdbcTemplate;
    private final AccessCodeTokenCipher cipher;
    private final ObjectMapper objectMapper = new ObjectMapper().findAndRegisterModules();

    public IntentAuthorizationSessionStore(
        ObjectProvider<JdbcTemplate> jdbcTemplateProvider,
        AccessCodeTokenCipher cipher
    ) {
        this.jdbcTemplate = jdbcTemplateProvider.getIfAvailable();
        this.cipher = cipher;
    }

    public void savePending(IntentAuthorizationService.AuthorizationSession session) {
        if (jdbcTemplate == null) {
            return;
        }
        try {
            String submission = objectMapper.writeValueAsString(session.getSubmission());
            String credentialIds = objectMapper.writeValueAsString(session.getCredentialIds());
            jdbcTemplate.update(
                """
                INSERT INTO intent_authorization_sessions (
                    session_id, request_id, status, submission_ciphertext, credential_ids_json,
                    challenge, return_url, expires_at, version
                ) VALUES (?, ?, 'PENDING', ?, ?, ?, ?, ?, 0)
                """,
                session.getSessionId(),
                session.getSubmission().getMeta().getRequestId(),
                cipher.encrypt(submission),
                credentialIds,
                session.getChallenge(),
                session.getReturnUrl(),
                Timestamp.from(session.getExpiresAt())
            );
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to persist intent authorization session", ex);
        }
    }

    public boolean isConfigured() {
        return jdbcTemplate != null;
    }

    public Optional<IntentAuthorizationService.AuthorizationSession> findPending(String sessionId) {
        return loadSession(sessionId, "PENDING");
    }

    /** Atomically consumes a pending session across backend replicas. */
    public Optional<IntentAuthorizationService.AuthorizationSession> claimPending(String sessionId) {
        if (jdbcTemplate == null) {
            return Optional.empty();
        }
        int updated = jdbcTemplate.update(
            """
            UPDATE intent_authorization_sessions
            SET status = 'PROCESSING', version = version + 1, updated_at = CURRENT_TIMESTAMP(6)
            WHERE session_id = ? AND status = 'PENDING' AND expires_at > CURRENT_TIMESTAMP(6)
            """,
            sessionId
        );
        return updated == 1 ? loadSession(sessionId, "PROCESSING") : Optional.empty();
    }

    public Optional<PersistedResult> findResult(String sessionId) {
        if (jdbcTemplate == null) {
            return Optional.empty();
        }
        return jdbcTemplate.query(
            """
            SELECT request_id, status, error, completed_at
            FROM intent_authorization_sessions
            WHERE session_id = ? AND status IN ('SUCCESS', 'FAILED')
            """,
            (rs, rowNum) -> new PersistedResult(
                rs.getString("status"),
                rs.getString("request_id"),
                rs.getString("error"),
                rs.getTimestamp("completed_at").toInstant()
            ),
            sessionId
        ).stream().findFirst();
    }

    public Optional<String> findActiveRequestId(String sessionId) {
        if (jdbcTemplate == null) {
            return Optional.empty();
        }
        return jdbcTemplate.queryForList(
            """
            SELECT request_id FROM intent_authorization_sessions
            WHERE session_id = ? AND status IN ('PENDING', 'PROCESSING')
            """,
            String.class,
            sessionId
        ).stream().findFirst();
    }

    public void saveResult(String sessionId, String requestId, String status, String error) {
        if (jdbcTemplate == null) {
            return;
        }
        jdbcTemplate.update(
            """
            UPDATE intent_authorization_sessions
            SET status = ?, error = ?, completed_at = CURRENT_TIMESTAMP(6),
                submission_ciphertext = NULL, credential_ids_json = NULL, challenge = NULL,
                version = version + 1, updated_at = CURRENT_TIMESTAMP(6)
            WHERE session_id = ? AND request_id = ? AND status = 'PROCESSING'
            """,
            status, error, sessionId, requestId
        );
    }

    public void deleteExpired(Instant completedBefore) {
        if (jdbcTemplate == null) {
            return;
        }
        jdbcTemplate.update(
            """
            DELETE FROM intent_authorization_sessions
            WHERE expires_at < CURRENT_TIMESTAMP(6)
               OR (completed_at IS NOT NULL AND completed_at < ?)
            """,
            Timestamp.from(completedBefore)
        );
    }

    private Optional<IntentAuthorizationService.AuthorizationSession> loadSession(
        String sessionId,
        String expectedStatus
    ) {
        if (jdbcTemplate == null) {
            return Optional.empty();
        }
        return jdbcTemplate.query(
            """
            SELECT session_id, submission_ciphertext, credential_ids_json, challenge, return_url, expires_at
            FROM intent_authorization_sessions
            WHERE session_id = ? AND status = ?
            """,
            (rs, rowNum) -> {
                try {
                    IntentSubmission submission = objectMapper.readValue(
                        cipher.decrypt(rs.getString("submission_ciphertext")),
                        IntentSubmission.class
                    );
                    List<String> credentialIds = objectMapper.readValue(
                        rs.getString("credential_ids_json"),
                        new TypeReference<List<String>>() { }
                    );
                    return new IntentAuthorizationService.AuthorizationSession(
                        rs.getString("session_id"),
                        submission,
                        credentialIds,
                        rs.getString("challenge"),
                        rs.getString("return_url"),
                        rs.getTimestamp("expires_at").toInstant()
                    );
                } catch (Exception ex) {
                    throw new java.sql.SQLException("Unable to load intent authorization session", ex);
                }
            },
            sessionId,
            expectedStatus
        ).stream().findFirst();
    }

    public record PersistedResult(String status, String requestId, String error, Instant completedAt) { }
}
