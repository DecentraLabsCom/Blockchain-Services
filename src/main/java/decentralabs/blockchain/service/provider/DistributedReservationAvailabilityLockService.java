package decentralabs.blockchain.service.provider;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/**
 * Serializes provider reservation-capacity decisions across backend replicas.
 *
 * <p>The action runs while the same MySQL connection owns a named advisory lock.
 * Keeping the connection inside one JdbcTemplate callback is essential: acquiring
 * and releasing GET_LOCK through separate JdbcTemplate calls could use different
 * pooled connections and would not protect the critical section.</p>
 */
@Service
@Slf4j
public class DistributedReservationAvailabilityLockService {

    private static final String ACQUIRE_LOCK_SQL = "SELECT GET_LOCK(?, ?)";
    private static final String RELEASE_LOCK_SQL = "SELECT RELEASE_LOCK(?)";
    private static final int MYSQL_LOCK_NAME_LENGTH = 64;

    private final ObjectProvider<JdbcTemplate> jdbcTemplateProvider;

    /** A blocked provider worker is retried; it must not deny the reservation. */
    @Value("${provider.reservation.availability.lock-timeout.seconds:60}")
    private int lockTimeoutSeconds = 60;

    public DistributedReservationAvailabilityLockService(ObjectProvider<JdbcTemplate> jdbcTemplateProvider) {
        this.jdbcTemplateProvider = jdbcTemplateProvider;
    }

    public <T> T withLock(ReservationAvailabilityLockKey key, LockAction<T> action) throws Exception {
        if (key == null) {
            throw new IllegalArgumentException("Reservation availability lock key is required");
        }
        if (action == null) {
            throw new IllegalArgumentException("Reservation availability lock action is required");
        }

        JdbcTemplate jdbcTemplate = jdbcTemplateProvider.getIfAvailable();
        if (jdbcTemplate == null) {
            throw new DistributedLockException(
                "Provider reservation availability requires a configured JdbcTemplate"
            );
        }

        String lockName = lockNameFor(key);
        try {
            return jdbcTemplate.execute((ConnectionCallback<T>) connection ->
                executeWhileLocked(connection, lockName, key, action));
        } catch (ActionFailureException failure) {
            return rethrowActionFailure(failure.getCause());
        } catch (DataAccessException ex) {
            throw new DistributedLockException(
                "Unable to acquire provider reservation availability lock for lab " + key.labId(), ex
            );
        }
    }

    /** Exposed package-wide for deterministic tests and operational diagnostics. */
    String lockNameFor(ReservationAvailabilityLockKey key) {
        String material = "decentralabs:provider-reservation-availability:v1|"
            + key.chainId() + "|" + key.contractAddress() + "|" + key.labId();
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(material.getBytes(StandardCharsets.UTF_8));
            String lockName = java.util.HexFormat.of().formatHex(digest);
            if (lockName.length() != MYSQL_LOCK_NAME_LENGTH) {
                throw new IllegalStateException("Unexpected MySQL advisory lock name length");
            }
            return lockName;
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is unavailable", ex);
        }
    }

    private <T> T executeWhileLocked(
        Connection connection,
        String lockName,
        ReservationAvailabilityLockKey key,
        LockAction<T> action
    ) throws java.sql.SQLException {
        Integer result = executeLockQuery(connection, ACQUIRE_LOCK_SQL, lockName, lockTimeoutSeconds());
        if (result == null) {
            throw new DistributedLockException(
                "MySQL GET_LOCK returned NULL for provider reservation lab " + key.labId()
            );
        }
        if (result != 1) {
            throw new DistributedLockException(
                "Provider reservation availability lock timeout for lab " + key.labId()
            );
        }

        try {
            try {
                return action.run();
            } catch (Throwable failure) {
                throw new ActionFailureException(failure);
            }
        } finally {
            releaseLock(connection, lockName, key);
        }
    }

    private Integer executeLockQuery(
        Connection connection,
        String sql,
        String lockName,
        int timeoutSeconds
    ) throws java.sql.SQLException {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, lockName);
            if (ACQUIRE_LOCK_SQL.equals(sql)) {
                statement.setInt(2, timeoutSeconds);
            }
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    return null;
                }
                int value = result.getInt(1);
                return result.wasNull() ? null : value;
            }
        }
    }

    private void releaseLock(
        Connection connection,
        String lockName,
        ReservationAvailabilityLockKey key
    ) throws java.sql.SQLException {
        try {
            Integer result = executeLockQuery(connection, RELEASE_LOCK_SQL, lockName, 0);
            if (result == null || result != 1) {
                log.warn(
                    "MySQL RELEASE_LOCK did not confirm release for provider reservation lab {}",
                    key.labId()
                );
            }
        } catch (java.sql.SQLException ex) {
            // Connection termination releases GET_LOCK implicitly. Do not turn a
            // completed on-chain confirmation into an auto-denial because cleanup
            // could not run on a broken connection.
            log.warn(
                "Unable to explicitly release provider reservation availability lock for lab {}: {}",
                key.labId(),
                ex.getMessage()
            );
        }
    }

    private int lockTimeoutSeconds() {
        return Math.max(0, lockTimeoutSeconds);
    }

    private <T> T rethrowActionFailure(Throwable failure) throws Exception {
        if (failure instanceof Error error) {
            throw error;
        }
        if (failure instanceof Exception exception) {
            throw exception;
        }
        throw new IllegalStateException("Provider reservation availability action failed", failure);
    }

    @FunctionalInterface
    public interface LockAction<T> {
        T run() throws Exception;
    }

    public static class DistributedLockException extends RuntimeException {
        public DistributedLockException(String message) {
            super(message);
        }

        public DistributedLockException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    private static final class ActionFailureException extends RuntimeException {
        private ActionFailureException(Throwable cause) {
            super(cause);
        }
    }
}
