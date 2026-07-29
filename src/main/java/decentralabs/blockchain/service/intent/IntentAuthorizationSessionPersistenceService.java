package decentralabs.blockchain.service.intent;

import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.dto.intent.IntentAckResponse;
import decentralabs.blockchain.dto.intent.IntentSubmission;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Durable MySQL store for WebAuthn intent authorization sessions.
 *
 * The encrypted payload is the only source for ceremony state.  Ownership of
 * completion is fenced with a database claim and lease so two backend replicas
 * cannot finalize the same session concurrently.
 */
@Service
@Slf4j
public class IntentAuthorizationSessionPersistenceService {

    private static final Set<String> TERMINAL_STATUSES = Set.of("SUCCESS", "FAILED_TERMINAL");
    private static final Set<String> VALID_RESULT_STATUSES = Set.of(
        "SUCCESS", "FAILED_RETRYABLE", "FAILED_TERMINAL"
    );
    private static final String SELECT_COLUMNS = """
        SELECT session_id, expires_at, payload_ciphertext, status,
               result_error, result_http_status, result_ack_json, completed_at,
               version, claim_id, claimed_by, claim_version, claim_expires_at
        FROM intent_authorization_sessions
        WHERE session_id = ?
        """;

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;
    private final IntentPayloadCipher payloadCipher;
    private final String workerId = UUID.randomUUID().toString();

    public IntentAuthorizationSessionPersistenceService(
        ObjectProvider<JdbcTemplate> jdbcTemplateProvider,
        ObjectMapper objectMapper,
        IntentPayloadCipher payloadCipher
    ) {
        this.jdbcTemplate = jdbcTemplateProvider.getIfAvailable();
        this.objectMapper = objectMapper;
        this.payloadCipher = payloadCipher;
    }

    public void create(IntentAuthorizationService.AuthorizationSession session) {
        if (session == null || session.getSessionId() == null || session.getSessionId().isBlank()) {
            throw new IllegalArgumentException("Authorization session is required");
        }
        try {
            requireJdbcTemplate().update(
                """
                INSERT INTO intent_authorization_sessions (
                    session_id, request_id, status, expires_at, payload_ciphertext,
                    version, created_at, updated_at
                ) VALUES (?, ?, 'PENDING', ?, ?, 0, CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6))
                """,
                session.getSessionId(),
                session.getSubmission().getMeta().getRequestId(),
                Timestamp.from(session.getExpiresAt()),
                encryptPayload(session)
            );
        } catch (Exception ex) {
            throw wrap("Unable to persist intent authorization session", ex);
        }
    }

    public Optional<StoredSession> find(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            return Optional.empty();
        }
        try {
            return requireJdbcTemplate().query(
                SELECT_COLUMNS,
                (rs, rowNum) -> mapRow(rs, sessionId),
                sessionId
            ).stream().findFirst();
        } catch (Exception ex) {
            throw wrap("Unable to load intent authorization session", ex);
        }
    }

    /**
     * Claims a pending or retryable session, or recovers an expired processing
     * lease.  The compare-and-set is the UPDATE predicate, not a JVM lock.
     */
    public Optional<ClaimedSession> claim(String sessionId, long leaseSeconds) {
        if (sessionId == null || sessionId.isBlank()) {
            return Optional.empty();
        }
        long effectiveLeaseSeconds = Math.max(1L, leaseSeconds);
        try {
            int updated = requireJdbcTemplate().update(
                """
                UPDATE intent_authorization_sessions
                SET status = 'PROCESSING',
                    result_error = NULL,
                    result_http_status = NULL,
                    result_ack_json = NULL,
                    completed_at = NULL,
                    retention_expires_at = NULL,
                    claim_id = ?,
                    claimed_by = ?,
                    claim_version = COALESCE(claim_version, 0) + 1,
                    claim_expires_at = TIMESTAMPADD(SECOND, ?, CURRENT_TIMESTAMP(6)),
                    version = version + 1,
                    updated_at = CURRENT_TIMESTAMP(6)
                WHERE session_id = ?
                  AND expires_at > CURRENT_TIMESTAMP(6)
                  AND (
                      status IN ('PENDING', 'FAILED_RETRYABLE')
                      OR (status = 'PROCESSING' AND (
                          claim_expires_at IS NULL OR claim_expires_at <= CURRENT_TIMESTAMP(6)
                      ))
                  )
                """,
                UUID.randomUUID().toString(),
                workerId,
                effectiveLeaseSeconds,
                sessionId
            );
            if (updated != 1) {
                return Optional.empty();
            }

            Optional<StoredSession> stored = findClaimed(sessionId);
            return stored.map(value -> new ClaimedSession(
                value,
                value.claimId(),
                value.claimedBy(),
                value.claimVersion()
            ));
        } catch (Exception ex) {
            throw wrap("Unable to claim intent authorization session", ex);
        }
    }

    /**
     * Atomically records a durable result only for the worker that owns the
     * current lease.  A false return means the lease was lost or another worker
     * already finalized the row.
     */
    public boolean complete(
        ClaimedSession claim,
        String status,
        IntentAckResponse ack,
        String error,
        int httpStatus,
        Instant completedAt,
        long resultRetentionSeconds
    ) {
        if (claim == null || !VALID_RESULT_STATUSES.contains(status)) {
            throw new IllegalArgumentException("Invalid authorization session result");
        }
        Instant resultTime = completedAt == null ? Instant.now() : completedAt;
        Timestamp retention = "SUCCESS".equals(status) || "FAILED_TERMINAL".equals(status)
            ? Timestamp.from(resultTime.plusSeconds(Math.max(1L, resultRetentionSeconds)))
            : null;
        try {
            return requireJdbcTemplate().update(
                """
                UPDATE intent_authorization_sessions
                SET status = ?,
                    result_error = ?,
                    result_http_status = ?,
                    result_ack_json = ?,
                    completed_at = ?,
                    retention_expires_at = ?,
                    claim_id = NULL,
                    claimed_by = NULL,
                    claim_expires_at = NULL,
                    version = version + 1,
                    updated_at = CURRENT_TIMESTAMP(6)
                WHERE session_id = ?
                  AND status = 'PROCESSING'
                  AND claim_id = ?
                  AND claimed_by = ?
                  AND claim_version = ?
                  AND claim_expires_at > CURRENT_TIMESTAMP(6)
                """,
                status,
                error,
                httpStatus,
                serializeAck(ack),
                Timestamp.from(resultTime),
                retention,
                claim.stored().session().getSessionId(),
                claim.claimId(),
                claim.claimedBy(),
                claim.claimVersion()
            ) == 1;
        } catch (Exception ex) {
            throw wrap("Unable to persist intent authorization session result", ex);
        }
    }

    /** Marks an expired non-terminal session as a durable terminal result. */
    public boolean expireIfNeeded(String sessionId, long resultRetentionSeconds) {
        if (sessionId == null || sessionId.isBlank()) {
            return false;
        }
        try {
            return requireJdbcTemplate().update(
                """
                UPDATE intent_authorization_sessions
                SET status = 'FAILED_TERMINAL',
                    result_error = 'Session expired',
                    result_http_status = 410,
                    result_ack_json = NULL,
                    completed_at = COALESCE(completed_at, CURRENT_TIMESTAMP(6)),
                    retention_expires_at = TIMESTAMPADD(SECOND, ?, CURRENT_TIMESTAMP(6)),
                    claim_id = NULL,
                    claimed_by = NULL,
                    claim_expires_at = NULL,
                    version = version + 1,
                    updated_at = CURRENT_TIMESTAMP(6)
                WHERE session_id = ?
                  AND expires_at <= CURRENT_TIMESTAMP(6)
                  AND status IN ('PENDING', 'PROCESSING', 'FAILED_RETRYABLE')
                """,
                Math.max(1L, resultRetentionSeconds),
                sessionId
            ) == 1;
        } catch (Exception ex) {
            throw wrap("Unable to expire intent authorization session", ex);
        }
    }

    /** Expires abandoned sessions and removes only rows past result retention. */
    @Transactional
    public void cleanupExpiredSessions(long resultRetentionSeconds) {
        try {
            JdbcTemplate jdbc = requireJdbcTemplate();
            jdbc.update(
                """
                UPDATE intent_authorization_sessions
                SET status = 'FAILED_TERMINAL',
                    result_error = 'Session expired',
                    result_http_status = 410,
                    result_ack_json = NULL,
                    completed_at = COALESCE(completed_at, CURRENT_TIMESTAMP(6)),
                    retention_expires_at = TIMESTAMPADD(SECOND, ?, CURRENT_TIMESTAMP(6)),
                    claim_id = NULL,
                    claimed_by = NULL,
                    claim_expires_at = NULL,
                    version = version + 1,
                    updated_at = CURRENT_TIMESTAMP(6)
                WHERE expires_at <= CURRENT_TIMESTAMP(6)
                  AND status IN ('PENDING', 'PROCESSING', 'FAILED_RETRYABLE')
                """,
                Math.max(1L, resultRetentionSeconds)
            );
            jdbc.update(
                """
                DELETE FROM intent_authorization_sessions
                WHERE status IN ('SUCCESS', 'FAILED_TERMINAL')
                  AND retention_expires_at IS NOT NULL
                  AND retention_expires_at <= CURRENT_TIMESTAMP(6)
                """
            );
        } catch (Exception ex) {
            throw wrap("Unable to clean up intent authorization sessions", ex);
        }
    }

    private Optional<StoredSession> findClaimed(String sessionId) {
        try {
            return requireJdbcTemplate().query(
                SELECT_COLUMNS + " AND claim_id IS NOT NULL AND claimed_by = ? AND claim_expires_at > CURRENT_TIMESTAMP(6)",
                (rs, rowNum) -> mapRow(rs, sessionId),
                sessionId,
                workerId
            ).stream().findFirst();
        } catch (Exception ex) {
            throw wrap("Unable to read claimed intent authorization session", ex);
        }
    }

    private StoredSession mapRow(ResultSet rs, String sessionId) throws SQLException {
        try {
            String payloadJson = payloadCipher.decrypt(rs.getString("payload_ciphertext"));
            DurablePayload payload = objectMapper.readValue(payloadJson, DurablePayload.class);
            List<IntentAuthorizationService.AllowedCredential> allowedCredentials =
                payload.allowedCredentials() == null ? List.of() : payload.allowedCredentials();
            IntentAuthorizationService.AuthorizationSession session = new IntentAuthorizationService.AuthorizationSession(
                sessionId,
                payload.submission(),
                allowedCredentials,
                payload.challenge(),
                payload.returnUrl(),
                toInstant(rs.getTimestamp("expires_at"))
            );
            IntentAckResponse ack = deserializeAck(rs.getString("result_ack_json"));
            return new StoredSession(
                session,
                rs.getString("status"),
                rs.getString("result_error"),
                rs.getObject("result_http_status", Integer.class),
                ack,
                toInstant(rs.getTimestamp("completed_at")),
                rs.getLong("version"),
                rs.getString("claim_id"),
                rs.getString("claimed_by"),
                rs.getObject("claim_version", Long.class) == null ? 0L : rs.getLong("claim_version"),
                toInstant(rs.getTimestamp("claim_expires_at"))
            );
        } catch (Exception ex) {
            throw new SQLException("Unable to decrypt or deserialize authorization session", ex);
        }
    }

    private String encryptPayload(IntentAuthorizationService.AuthorizationSession session) {
        try {
            DurablePayload payload = new DurablePayload(
                session.getSubmission(),
                session.getAllowedCredentials(),
                session.getChallenge(),
                session.getReturnUrl()
            );
            return payloadCipher.encrypt(objectMapper.writeValueAsString(payload));
        } catch (Exception ex) {
            throw new IntentAuthorizationSessionPersistenceException(
                "Unable to encrypt intent authorization session", ex
            );
        }
    }

    private String serializeAck(IntentAckResponse ack) {
        if (ack == null) {
            return null;
        }
        try {
            return objectMapper.writeValueAsString(ack);
        } catch (Exception ex) {
            throw new IntentAuthorizationSessionPersistenceException(
                "Unable to serialize intent authorization result", ex
            );
        }
    }

    private IntentAckResponse deserializeAck(String ackJson) throws Exception {
        return ackJson == null || ackJson.isBlank()
            ? null
            : objectMapper.readValue(ackJson, IntentAckResponse.class);
    }

    private JdbcTemplate requireJdbcTemplate() {
        if (jdbcTemplate == null) {
            throw new IntentAuthorizationSessionPersistenceException(
                "Intent authorization session persistence is unavailable"
            );
        }
        if (payloadCipher == null) {
            throw new IntentAuthorizationSessionPersistenceException(
                "Intent authorization session encryption is unavailable"
            );
        }
        return jdbcTemplate;
    }

    private IntentAuthorizationSessionPersistenceException wrap(String message, Exception ex) {
        if (ex instanceof IntentAuthorizationSessionPersistenceException persistenceException) {
            return persistenceException;
        }
        log.warn("{}: {}", message, ex.getMessage());
        return new IntentAuthorizationSessionPersistenceException(message, ex);
    }

    private Instant toInstant(Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toInstant();
    }

    public record StoredSession(
        IntentAuthorizationService.AuthorizationSession session,
        String status,
        String resultError,
        Integer resultHttpStatus,
        IntentAckResponse resultAck,
        Instant completedAt,
        long version,
        String claimId,
        String claimedBy,
        long claimVersion,
        Instant claimExpiresAt
    ) {
        public boolean isTerminal() {
            return TERMINAL_STATUSES.contains(status);
        }
    }

    public record ClaimedSession(
        StoredSession stored,
        String claimId,
        String claimedBy,
        long claimVersion
    ) {}

    public record DurablePayload(
        IntentSubmission submission,
        List<IntentAuthorizationService.AllowedCredential> allowedCredentials,
        String challenge,
        String returnUrl
    ) {}
}
