package decentralabs.blockchain.service.auth;

import java.time.Duration;
import java.time.Instant;
import java.sql.Timestamp;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/** Durable, short-lived lease for provisional Guacamole access per reservation. */
@Service
@Slf4j
public class AccessAuthorizationProvisioningService {
    private final JdbcTemplate jdbcTemplate;

    private static final Duration LEASE_DURATION = Duration.ofSeconds(35);

    public AccessAuthorizationProvisioningService(ObjectProvider<JdbcTemplate> jdbcTemplateProvider) {
        this.jdbcTemplate = jdbcTemplateProvider.getIfAvailable();
    }

    public ProvisioningLease tryStart(String reservationKey) {
        requireDatabase();
        if (reservationKey == null || reservationKey.isBlank()) {
            throw new IllegalArgumentException("reservationKey is required");
        }
        String fencingToken = UUID.randomUUID().toString();
        Instant now = Instant.now();
        Timestamp heartbeatAt = Timestamp.from(now);
        Timestamp expiresAt = Timestamp.from(now.plus(LEASE_DURATION));

        int reclaimed = jdbcTemplate.update(
            """
            UPDATE access_authorization_provisioning
            SET status = 'PREPARING',
                fencing_token = ?,
                generation = generation + 1,
                heartbeat_at = ?,
                expires_at = ?,
                updated_at = ?
            WHERE reservation_key = ?
              AND (status IN ('ROLLED_BACK', 'FAILED', 'DELIVERED')
                   OR (status IN ('PREPARING', 'WAITING_AUTHORIZATION', 'ROLLING_BACK')
                       AND expires_at < ?))
            """,
            fencingToken,
            heartbeatAt,
            expiresAt,
            heartbeatAt,
            reservationKey,
            heartbeatAt
        );
        if (reclaimed > 0) {
            return currentLease(reservationKey, fencingToken);
        }

        int inserted = jdbcTemplate.update(
            "INSERT IGNORE INTO access_authorization_provisioning "
                + "(reservation_key, status, fencing_token, generation, heartbeat_at, expires_at) "
                + "VALUES (?, 'PREPARING', ?, 1, ?, ?)",
            reservationKey,
            fencingToken,
            heartbeatAt,
            expiresAt
        );
        return inserted > 0 ? new ProvisioningLease(reservationKey, fencingToken, 1L) : null;
    }

    public boolean markWaiting(ProvisioningLease lease) {
        return updateStatus(lease, "WAITING_AUTHORIZATION", "PREPARING");
    }

    public boolean markDelivered(ProvisioningLease lease) {
        return updateStatus(lease, "DELIVERED", "PREPARING", "WAITING_AUTHORIZATION");
    }

    public boolean markRolledBack(ProvisioningLease lease) {
        return updateStatus(lease, "ROLLED_BACK", "ROLLING_BACK");
    }

    public boolean markFailed(ProvisioningLease lease) {
        return updateStatus(lease, "FAILED", "PREPARING", "WAITING_AUTHORIZATION", "ROLLING_BACK");
    }

    /** Extends the active lease while the request is still polling on-chain. */
    public boolean heartbeat(ProvisioningLease lease) {
        if (jdbcTemplate == null || lease == null) {
            return false;
        }
        Instant now = Instant.now();
        return jdbcTemplate.update(
            "UPDATE access_authorization_provisioning "
                + "SET heartbeat_at = ?, expires_at = ?, updated_at = ? "
                + "WHERE reservation_key = ? AND fencing_token = ? "
                + "AND status IN ('PREPARING', 'WAITING_AUTHORIZATION') AND expires_at >= ?",
            Timestamp.from(now),
            Timestamp.from(now.plus(LEASE_DURATION)),
            Timestamp.from(now),
            lease.reservationKey(),
            lease.fencingToken(),
            Timestamp.from(now)
        ) > 0;
    }

    /**
     * Atomically transitions this lease into cleanup ownership. Callers must
     * only delete their provisional Guacamole user after this succeeds.
     */
    public boolean beginRollback(ProvisioningLease lease) {
        return updateStatus(lease, "ROLLING_BACK", "PREPARING", "WAITING_AUTHORIZATION");
    }

    public boolean isCurrent(ProvisioningLease lease) {
        if (jdbcTemplate == null || lease == null) {
            return false;
        }
        Integer count = jdbcTemplate.queryForObject(
            """
            SELECT COUNT(*) FROM access_authorization_provisioning
            WHERE reservation_key = ? AND fencing_token = ?
              AND status IN ('PREPARING', 'WAITING_AUTHORIZATION')
              AND expires_at >= ?
            """,
            Integer.class,
            lease.reservationKey(),
            lease.fencingToken(),
            Timestamp.from(Instant.now())
        );
        return count != null && count == 1;
    }

    private ProvisioningLease currentLease(String reservationKey, String fencingToken) {
        Long generation = jdbcTemplate.queryForObject(
            "SELECT generation FROM access_authorization_provisioning WHERE reservation_key = ? AND fencing_token = ?",
            Long.class,
            reservationKey,
            fencingToken
        );
        if (generation == null) {
            throw new IllegalStateException("Could not resolve acquired provisioning lease");
        }
        return new ProvisioningLease(reservationKey, fencingToken, generation);
    }

    private boolean updateStatus(ProvisioningLease lease, String status, String... allowedStatuses) {
        if (jdbcTemplate == null || lease == null) {
            return false;
        }
        String placeholders = String.join(", ", java.util.Collections.nCopies(allowedStatuses.length, "?"));
        Object[] parameters = new Object[4 + allowedStatuses.length];
        parameters[0] = status;
        parameters[1] = lease.reservationKey();
        parameters[2] = lease.fencingToken();
        parameters[3] = Timestamp.from(Instant.now());
        System.arraycopy(allowedStatuses, 0, parameters, 4, allowedStatuses.length);
        return jdbcTemplate.update(
            "UPDATE access_authorization_provisioning SET status = ?, updated_at = CURRENT_TIMESTAMP "
                + "WHERE reservation_key = ? AND fencing_token = ? AND expires_at >= ? AND status IN (" + placeholders + ")",
            parameters
        ) > 0;
    }

    private void requireDatabase() {
        if (jdbcTemplate == null) {
            throw new IllegalStateException("Durable access provisioning requires a datasource");
        }
    }

    public record ProvisioningLease(String reservationKey, String fencingToken, long generation) { }
}
