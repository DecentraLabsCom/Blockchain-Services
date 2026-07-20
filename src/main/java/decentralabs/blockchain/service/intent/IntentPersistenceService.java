package decentralabs.blockchain.service.intent;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.sql.DataSource;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import decentralabs.blockchain.dto.intent.IntentStatus;
import decentralabs.blockchain.util.LogSanitizer;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class IntentPersistenceService {

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final IntentPayloadCipher payloadCipher;

    /** Constructor retained for isolated unit tests that do not load Spring. */
    public IntentPersistenceService(DataSource dataSource) {
        this(dataSource, null);
    }

    @Autowired
    public IntentPersistenceService(DataSource dataSource, IntentPayloadCipher payloadCipher) {
        this.jdbcTemplate = dataSource != null ? new JdbcTemplate(dataSource) : null;
        this.payloadCipher = payloadCipher;
    }

    public void upsert(IntentRecord record) {
        try {
            requireJdbcTemplate().update(
                """
                INSERT INTO intents (
                    request_id, status, action, provider, lab_id, reservation_key,
                    puc_hash,
                    tx_hash, block_number, error, reason, updated_at, created_at,
                    nonce, expires_at, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE
                    status = VALUES(status),
                    tx_hash = VALUES(tx_hash),
                    block_number = VALUES(block_number),
                    error = VALUES(error),
                    reason = VALUES(reason),
                    updated_at = VALUES(updated_at),
                    lab_id = VALUES(lab_id),
                    reservation_key = VALUES(reservation_key),
                    puc_hash = VALUES(puc_hash),
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
                record.getPucHash(),
                record.getTxHash(),
                record.getBlockNumber(),
                record.getError(),
                record.getReason(),
                Timestamp.from(record.getUpdatedAt()),
                Timestamp.from(record.getCreatedAt()),
                record.getNonce(),
                record.getExpiresAt(),
                protectPayload(record.getPayloadJson())
            );
        } catch (Exception e) {
            log.warn("Intent persistence failed during upsert: {}", LogSanitizer.sanitize(e.getMessage()));
            if (e instanceof IntentPersistenceException persistenceException) {
                throw persistenceException;
            }
            throw new IntentPersistenceException("Intent persistence is unavailable", e);
        }
    }

    public Optional<IntentRecord> findByRequestId(String requestId) {
        try {
            return requireJdbcTemplate().query(
                "SELECT * FROM intents WHERE request_id = ? LIMIT 1",
                (rs, rowNum) -> mapRow(rs),
                requestId
            ).stream().findFirst();
        } catch (Exception e) {
            log.warn("Intent lookup failed: {}", LogSanitizer.sanitize(e.getMessage()));
            if (e instanceof IntentPersistenceException persistenceException) {
                throw persistenceException;
            }
            throw new IntentPersistenceException("Intent persistence is unavailable", e);
        }
    }

    public List<IntentRecord> findPending() {
        try {
            return requireJdbcTemplate().query(
                "SELECT * FROM intents WHERE status IN ('queued', 'authorized_pending_registration', 'in_progress')",
                (rs, rowNum) -> mapRow(rs)
            );
        } catch (Exception e) {
            log.warn("Intent pending lookup failed: {}", LogSanitizer.sanitize(e.getMessage()));
            if (e instanceof IntentPersistenceException persistenceException) {
                throw persistenceException;
            }
            throw new IntentPersistenceException("Intent persistence is unavailable", e);
        }
    }

    public List<String> findExecutedReservationRequestKeys(Instant olderThan, int limit) {
        if (olderThan == null || limit <= 0) {
            return List.of();
        }
        try {
            return requireJdbcTemplate().queryForList(
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
            log.warn("Executed reservation intents lookup failed: {}", LogSanitizer.sanitize(e.getMessage()));
            if (e instanceof IntentPersistenceException persistenceException) {
                throw persistenceException;
            }
            throw new IntentPersistenceException("Intent persistence is unavailable", e);
        }
    }

    public Optional<IntentRecord> findByReservationKey(String reservationKey) {
        try {
            return requireJdbcTemplate().query(
                "SELECT * FROM intents WHERE reservation_key = ? ORDER BY updated_at DESC LIMIT 1",
                (rs, rowNum) -> mapRow(rs),
                reservationKey
            ).stream().findFirst();
        } catch (Exception e) {
            log.warn(
                "Intent lookup by reservationKey failed for {}: {}",
                LogSanitizer.sanitize(reservationKey),
                LogSanitizer.sanitize(e.getMessage())
            );
            if (e instanceof IntentPersistenceException persistenceException) {
                throw persistenceException;
            }
            throw new IntentPersistenceException("Intent persistence is unavailable", e);
        }
    }

    private JdbcTemplate requireJdbcTemplate() {
        if (jdbcTemplate == null) {
            throw new IntentPersistenceException("Intent persistence is unavailable");
        }
        return jdbcTemplate;
    }

    private IntentRecord mapRow(ResultSet rs) throws SQLException {
        IntentRecord record = new IntentRecord(
            rs.getString("request_id"),
            rs.getString("action"),
            rs.getString("provider")
        );
        record.setStatus(IntentStatus.valueOf(rs.getString("status").toUpperCase().replace('-', '_')));
        record.setLabId(rs.getString("lab_id"));
        record.setReservationKey(rs.getString("reservation_key"));
        record.setPucHash(rs.getString("puc_hash"));
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
            IntentPersistencePayload payload = objectMapper.readValue(unprotectPayload(payloadJson), IntentPersistencePayload.class);
            record.setActionPayload(payload.actionPayload());
            record.setReservationPayload(payload.reservationPayload());

            if (record.getPucHash() == null) {
                if (record.getReservationPayload() != null) {
                    record.setPucHash(record.getReservationPayload().getPucHash());
                } else if (record.getActionPayload() != null) {
                    record.setPucHash(record.getActionPayload().getPucHash());
                }
            }

            if (payload.meta() != null) {
                record.setSigner(payload.meta().getSigner());
                record.setExecutor(payload.meta().getExecutor());
                record.setActionId(payload.meta().getAction());
                record.setPayloadHash(payload.meta().getPayloadHash());
                record.setNonce(payload.meta().getNonce());
                record.setRequestedAt(payload.meta().getRequestedAt());
                record.setExpiresAt(payload.meta().getExpiresAt());
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

    private String protectPayload(String payloadJson) {
        if (payloadJson == null || payloadJson.isBlank() || payloadCipher == null) {
            return payloadJson;
        }
        try {
            return objectMapper.writeValueAsString(Map.of("ciphertext", payloadCipher.encrypt(payloadJson)));
        } catch (Exception ex) {
            throw new IntentPersistenceException("Unable to protect intent payload", ex);
        }
    }

    private String unprotectPayload(String persistedPayload) {
        if (persistedPayload == null || persistedPayload.isBlank() || payloadCipher == null) {
            return persistedPayload;
        }
        try {
            JsonNode node = objectMapper.readTree(persistedPayload);
            if (node.isObject() && node.has("ciphertext")) {
                return payloadCipher.decrypt(node.get("ciphertext").asText());
            }
            // Legacy rows are accepted only long enough for the migration/next write
            // to remove or encrypt them; no new row is written in this form.
            return persistedPayload;
        } catch (Exception ex) {
            throw new IntentPersistenceException("Unable to unprotect intent payload", ex);
        }
    }
}
