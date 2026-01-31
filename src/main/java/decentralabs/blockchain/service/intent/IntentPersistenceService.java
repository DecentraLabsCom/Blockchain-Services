package decentralabs.blockchain.service.intent;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import javax.sql.DataSource;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import decentralabs.blockchain.dto.intent.IntentSubmission;
import decentralabs.blockchain.dto.intent.IntentStatus;
import decentralabs.blockchain.util.LogSanitizer;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class IntentPersistenceService {

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public IntentPersistenceService(DataSource dataSource) {
        this.jdbcTemplate = dataSource != null ? new JdbcTemplate(dataSource) : null;
    }

    public void upsert(IntentRecord record) {
        if (jdbcTemplate == null) {
            log.debug("Skipping intent persistence (no datasource)");
            return;
        }
        try {
            jdbcTemplate.update(
                """
                INSERT INTO intents (
                    request_id, status, action, provider, lab_id, reservation_key,
                    tx_hash, block_number, error, reason, updated_at, created_at,
                    nonce, expires_at, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE
                    status = VALUES(status),
                    tx_hash = VALUES(tx_hash),
                    block_number = VALUES(block_number),
                    error = VALUES(error),
                    reason = VALUES(reason),
                    updated_at = VALUES(updated_at),
                    lab_id = VALUES(lab_id),
                    reservation_key = VALUES(reservation_key),
                    nonce = VALUES(nonce),
                    expires_at = VALUES(expires_at),
                    payload_json = VALUES(payload_json)
                """,
                record.getRequestId(),
                record.getStatus().getWireValue(),
                record.getAction(),
                record.getProvider(),
                record.getLabId(),
                record.getReservationKey(),
                record.getTxHash(),
                record.getBlockNumber(),
                record.getError(),
                record.getReason(),
                Timestamp.from(record.getUpdatedAt()),
                Timestamp.from(record.getCreatedAt()),
                record.getNonce(),
                record.getExpiresAt(),
                record.getPayloadJson()
            );
        } catch (Exception e) {
            log.warn("Intent persistence skipped for {}: {}", LogSanitizer.sanitize(record.getRequestId()), LogSanitizer.sanitize(e.getMessage()));
        }
    }

    public Optional<IntentRecord> findByRequestId(String requestId) {
        if (jdbcTemplate == null) {
            return Optional.empty();
        }
        try {
            return jdbcTemplate.query(
                "SELECT * FROM intents WHERE request_id = ? LIMIT 1",
                this::mapRow,
                requestId
            ).stream().findFirst();
        } catch (Exception e) {
            log.warn("Intent lookup skipped for {}: {}", LogSanitizer.sanitize(requestId), LogSanitizer.sanitize(e.getMessage()));
            return Optional.empty();
        }
    }

    public List<IntentRecord> findPending() {
        if (jdbcTemplate == null) {
            return List.of();
        }
        try {
            return jdbcTemplate.query(
                "SELECT * FROM intents WHERE status IN ('queued', 'in_progress')",
                this::mapRow
            );
        } catch (Exception e) {
            log.warn("Intent pending lookup skipped: {}", LogSanitizer.sanitize(e.getMessage()));
            return List.of();
        }
    }

    public List<String> findExecutedReservationRequestKeys(Instant olderThan, int limit) {
        if (jdbcTemplate == null) {
            return List.of();
        }
        if (olderThan == null || limit <= 0) {
            return List.of();
        }
        try {
            return jdbcTemplate.queryForList(
                """
                SELECT reservation_key
                FROM intents
                WHERE status = 'executed'
                  AND action = 'RESERVATION_REQUEST'
                  AND reservation_key IS NOT NULL
                  AND reservation_key <> ''
                  AND updated_at <= ?
                ORDER BY updated_at ASC
                LIMIT ?
                """,
                String.class,
                Timestamp.from(olderThan),
                limit
            );
        } catch (Exception e) {
            log.warn("Executed reservation intents lookup skipped: {}", LogSanitizer.sanitize(e.getMessage()));
            return List.of();
        }
    }

    public Optional<IntentRecord> findByReservationKey(String reservationKey) {
        if (jdbcTemplate == null) {
            return Optional.empty();
        }
        try {
            return jdbcTemplate.query(
                "SELECT * FROM intents WHERE reservation_key = ? ORDER BY updated_at DESC LIMIT 1",
                this::mapRow,
                reservationKey
            ).stream().findFirst();
        } catch (Exception e) {
            log.warn(
                "Intent lookup by reservationKey skipped for {}: {}",
                LogSanitizer.sanitize(reservationKey),
                LogSanitizer.sanitize(e.getMessage())
            );
            return Optional.empty();
        }
    }

    private IntentRecord mapRow(ResultSet rs, int rowNum) throws SQLException {
        IntentRecord record = new IntentRecord(
            rs.getString("request_id"),
            rs.getString("action"),
            rs.getString("provider")
        );
        record.setStatus(IntentStatus.valueOf(rs.getString("status").toUpperCase()));
        record.setLabId(rs.getString("lab_id"));
        record.setReservationKey(rs.getString("reservation_key"));
        record.setTxHash(rs.getString("tx_hash"));
        record.setBlockNumber(rs.getObject("block_number", Long.class));
        record.setError(rs.getString("error"));
        record.setReason(rs.getString("reason"));

        Timestamp updatedAt = rs.getTimestamp("updated_at");
        Timestamp createdAt = rs.getTimestamp("created_at");
        record.setNonce(rs.getObject("nonce", Long.class));
        record.setExpiresAt(rs.getObject("expires_at", Long.class));
        record.setPayloadJson(rs.getString("payload_json"));
        hydrateFromPayloadJson(record);

        if (createdAt != null) {
            record.setCreatedAt(createdAt.toInstant());
        }
        if (updatedAt != null) {
            record.setUpdatedAt(updatedAt.toInstant());
        } else if (createdAt != null) {
            record.setUpdatedAt(createdAt.toInstant());
        }
        return record;
    }

    private void hydrateFromPayloadJson(IntentRecord record) {
        String payloadJson = record.getPayloadJson();
        if (payloadJson == null || payloadJson.isBlank()) {
            return;
        }
        try {
            IntentSubmission submission = objectMapper.readValue(payloadJson, IntentSubmission.class);
            record.setActionPayload(submission.getActionPayload());
            record.setReservationPayload(submission.getReservationPayload());
            record.setSignature(submission.getSignature());

            if (submission.getMeta() != null) {
                record.setSigner(submission.getMeta().getSigner());
                record.setExecutor(submission.getMeta().getExecutor());
                record.setActionId(submission.getMeta().getAction());
                record.setPayloadHash(submission.getMeta().getPayloadHash());
                record.setNonce(submission.getMeta().getNonce());
                record.setRequestedAt(submission.getMeta().getRequestedAt());
                record.setExpiresAt(submission.getMeta().getExpiresAt());
            }

            if (record.getReservationPayload() != null) {
                record.setPuc(record.getReservationPayload().getPuc());
            } else if (record.getActionPayload() != null) {
                record.setPuc(record.getActionPayload().getPuc());
            }

            if (record.getLabId() == null) {
                if (record.getReservationPayload() != null && record.getReservationPayload().getLabId() != null) {
                    record.setLabId(record.getReservationPayload().getLabId().toString());
                } else if (record.getActionPayload() != null && record.getActionPayload().getLabId() != null) {
                    record.setLabId(record.getActionPayload().getLabId().toString());
                }
            }

            if (record.getReservationKey() == null) {
                if (record.getReservationPayload() != null && record.getReservationPayload().getReservationKey() != null) {
                    record.setReservationKey(record.getReservationPayload().getReservationKey());
                } else if (record.getActionPayload() != null && record.getActionPayload().getReservationKey() != null) {
                    record.setReservationKey(record.getActionPayload().getReservationKey());
                }
            }
        } catch (Exception ex) {
            log.warn("Unable to hydrate intent {} payload: {}", LogSanitizer.sanitize(record.getRequestId()), LogSanitizer.sanitize(ex.getMessage()));
        }
    }
}
