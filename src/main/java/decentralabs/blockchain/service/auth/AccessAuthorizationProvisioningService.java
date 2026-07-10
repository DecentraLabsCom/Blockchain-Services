package decentralabs.blockchain.service.auth;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/** Durable, short-lived lease for provisional Guacamole access per reservation. */
@Service
@Slf4j
public class AccessAuthorizationProvisioningService {
    private final JdbcTemplate jdbcTemplate;

    public AccessAuthorizationProvisioningService(ObjectProvider<JdbcTemplate> jdbcTemplateProvider) {
        this.jdbcTemplate = jdbcTemplateProvider.getIfAvailable();
    }

    public boolean tryStart(String reservationKey) {
        requireDatabase();
        int inserted = jdbcTemplate.update(
            "INSERT INTO access_authorization_provisioning (reservation_key, status) VALUES (?, 'PREPARING') "
                + "ON DUPLICATE KEY UPDATE reservation_key = VALUES(reservation_key)",
            reservationKey
        );
        if (inserted > 0) {
            return true;
        }

        int reclaimed = jdbcTemplate.update(
            """
            UPDATE access_authorization_provisioning
            SET status = 'PREPARING', updated_at = CURRENT_TIMESTAMP
            WHERE reservation_key = ?
              AND (status IN ('ROLLED_BACK', 'FAILED')
                   OR (status IN ('PREPARING', 'WAITING_AUTHORIZATION')
                       AND updated_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL 35 SECOND)))
            """,
            reservationKey
        );
        return reclaimed > 0;
    }

    public void markWaiting(String reservationKey) {
        updateStatus(reservationKey, "WAITING_AUTHORIZATION");
    }

    public void markDelivered(String reservationKey) {
        updateStatus(reservationKey, "DELIVERED");
    }

    public void markRolledBack(String reservationKey) {
        updateStatus(reservationKey, "ROLLED_BACK");
    }

    public void markFailed(String reservationKey) {
        updateStatus(reservationKey, "FAILED");
    }

    private void updateStatus(String reservationKey, String status) {
        if (jdbcTemplate == null || reservationKey == null || reservationKey.isBlank()) {
            return;
        }
        jdbcTemplate.update(
            "UPDATE access_authorization_provisioning SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE reservation_key = ?",
            status, reservationKey
        );
    }

    private void requireDatabase() {
        if (jdbcTemplate == null) {
            throw new IllegalStateException("Durable access provisioning requires a datasource");
        }
    }
}
