package decentralabs.blockchain.service.persistence;

import decentralabs.blockchain.domain.MicaOfferVolume;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.sql.Date;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Persistence for MiCA Art 4(3) offer-volume monitoring snapshots.
 */
@Service
@Slf4j
public class MicaVolumePersistenceService {

    private final JdbcTemplate jdbcTemplate;
    private final AtomicBoolean tableMissing = new AtomicBoolean(false);

    public MicaVolumePersistenceService(ObjectProvider<JdbcTemplate> provider) {
        this.jdbcTemplate = provider.getIfAvailable();
    }

    private static final RowMapper<MicaOfferVolume> VOLUME_MAPPER = (rs, rowNum) ->
        MicaOfferVolume.builder()
            .id(rs.getLong("id"))
            .periodStart(rs.getObject("period_start", LocalDate.class))
            .periodEnd(rs.getObject("period_end", LocalDate.class))
            .eurVolume(rs.getBigDecimal("eur_volume"))
            .creditVolume(rs.getBigDecimal("credit_volume"))
            .transactionCount(rs.getInt("transaction_count"))
            .computedAt(toInstant(rs.getTimestamp("computed_at")))
            .build();

    @Transactional
    public void recordSnapshot(MicaOfferVolume snapshot) {
        if (jdbcTemplate == null) return;
        try {
            jdbcTemplate.update(
                """
                INSERT INTO mica_offer_volume (period_start, period_end, eur_volume, credit_volume, transaction_count)
                VALUES (?, ?, ?, ?, ?)
                """,
                Date.valueOf(snapshot.getPeriodStart()),
                Date.valueOf(snapshot.getPeriodEnd()),
                snapshot.getEurVolume(),
                snapshot.getCreditVolume(),
                snapshot.getTransactionCount()
            );
        } catch (DataAccessException ex) {
            logMissing("mica_offer_volume", ex);
        }
    }

    public List<MicaOfferVolume> findRecentSnapshots(int limit) {
        if (jdbcTemplate == null) return List.of();
        try {
            return jdbcTemplate.query(
                "SELECT * FROM mica_offer_volume ORDER BY computed_at DESC LIMIT ?",
                VOLUME_MAPPER, limit);
        } catch (DataAccessException ex) {
            logMissing("mica_offer_volume", ex);
            return List.of();
        }
    }

    /**
     * Compute the latest rolling 12-month EUR volume from persisted snapshots.
     */
    public BigDecimal getLatestRollingVolume() {
        if (jdbcTemplate == null) return BigDecimal.ZERO;
        try {
            BigDecimal result = jdbcTemplate.queryForObject(
                """
                SELECT COALESCE(SUM(eur_volume), 0) FROM mica_offer_volume
                WHERE period_start >= DATE_SUB(CURDATE(), INTERVAL 12 MONTH)
                """,
                BigDecimal.class);
            return result != null ? result : BigDecimal.ZERO;
        } catch (DataAccessException ex) {
            logMissing("mica_offer_volume", ex);
            return BigDecimal.ZERO;
        }
    }

    private static Instant toInstant(Timestamp ts) {
        return ts != null ? ts.toInstant() : null;
    }

    private void logMissing(String table, DataAccessException ex) {
        if (tableMissing.compareAndSet(false, true)) {
            log.warn("{} persistence skipped (table or schema missing): {}", table, ex.getMessage());
        }
    }
}
