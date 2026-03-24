package decentralabs.blockchain.service.persistence;

import decentralabs.blockchain.domain.ProviderNetworkMembership;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.*;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Persistence for limited-network provider membership registry.
 */
@Service
@Slf4j
public class ProviderNetworkPersistenceService {

    private final JdbcTemplate jdbcTemplate;
    private final AtomicBoolean tableMissing = new AtomicBoolean(false);

    public ProviderNetworkPersistenceService(ObjectProvider<JdbcTemplate> provider) {
        this.jdbcTemplate = provider.getIfAvailable();
    }

    private static final RowMapper<ProviderNetworkMembership> MEMBERSHIP_MAPPER = (rs, rowNum) ->
        ProviderNetworkMembership.builder()
            .id(rs.getLong("id"))
            .providerAddress(rs.getString("provider_address"))
            .contractId(rs.getString("contract_id"))
            .agreementVersion(rs.getString("agreement_version"))
            .effectiveDate(rs.getObject("effective_date", LocalDate.class))
            .expiryDate(rs.getObject("expiry_date", LocalDate.class))
            .status(ProviderNetworkMembership.Status.valueOf(rs.getString("status")))
            .suspensionReason(rs.getString("suspension_reason"))
            .actionBy(rs.getString("action_by"))
            .createdAt(toInstant(rs.getTimestamp("created_at")))
            .updatedAt(toInstant(rs.getTimestamp("updated_at")))
            .build();

    @Transactional
    public ProviderNetworkMembership createMembership(ProviderNetworkMembership membership) {
        if (jdbcTemplate == null) return membership;
        try {
            KeyHolder keyHolder = new GeneratedKeyHolder();
            jdbcTemplate.update(con -> {
                PreparedStatement ps = con.prepareStatement(
                    """
                    INSERT INTO provider_network_registry
                        (provider_address, contract_id, agreement_version, effective_date, expiry_date, status, suspension_reason, action_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    new String[]{"id"}
                );
                ps.setString(1, membership.getProviderAddress());
                ps.setString(2, membership.getContractId());
                ps.setString(3, membership.getAgreementVersion());
                ps.setDate(4, Date.valueOf(membership.getEffectiveDate()));
                ps.setDate(5, membership.getExpiryDate() != null ? Date.valueOf(membership.getExpiryDate()) : null);
                ps.setString(6, membership.getStatus().name());
                ps.setString(7, membership.getSuspensionReason());
                ps.setString(8, membership.getActionBy());
                return ps;
            }, keyHolder);
            membership.setId(keyHolder.getKey().longValue());
            return membership;
        } catch (DataAccessException ex) {
            logMissing("provider_network_registry", ex);
            return membership;
        }
    }

    @Transactional
    public void updateMembershipStatus(long id, ProviderNetworkMembership.Status status, String reason, String actionBy) {
        if (jdbcTemplate == null) return;
        try {
            jdbcTemplate.update(
                "UPDATE provider_network_registry SET status = ?, suspension_reason = ?, action_by = ? WHERE id = ?",
                status.name(), reason, actionBy, id);
        } catch (DataAccessException ex) {
            logMissing("provider_network_registry", ex);
        }
    }

    public List<ProviderNetworkMembership> findAllActive() {
        if (jdbcTemplate == null) return List.of();
        try {
            return jdbcTemplate.query(
                "SELECT * FROM provider_network_registry WHERE status = 'ACTIVE' ORDER BY provider_address",
                MEMBERSHIP_MAPPER);
        } catch (DataAccessException ex) {
            logMissing("provider_network_registry", ex);
            return List.of();
        }
    }

    public Optional<ProviderNetworkMembership> findByProvider(String providerAddress) {
        if (jdbcTemplate == null) return Optional.empty();
        try {
            List<ProviderNetworkMembership> results = jdbcTemplate.query(
                "SELECT * FROM provider_network_registry WHERE provider_address = ? AND status = 'ACTIVE'",
                MEMBERSHIP_MAPPER, providerAddress);
            return results.stream().findFirst();
        } catch (DataAccessException ex) {
            logMissing("provider_network_registry", ex);
            return Optional.empty();
        }
    }

    public List<ProviderNetworkMembership> findExpiringBefore(LocalDate date) {
        if (jdbcTemplate == null) return List.of();
        try {
            return jdbcTemplate.query(
                """
                SELECT * FROM provider_network_registry
                WHERE status = 'ACTIVE' AND expiry_date IS NOT NULL AND expiry_date <= ?
                ORDER BY expiry_date ASC
                """,
                MEMBERSHIP_MAPPER, Date.valueOf(date));
        } catch (DataAccessException ex) {
            logMissing("provider_network_registry", ex);
            return List.of();
        }
    }

    public List<ProviderNetworkMembership> findAll() {
        if (jdbcTemplate == null) return List.of();
        try {
            return jdbcTemplate.query(
                "SELECT * FROM provider_network_registry ORDER BY provider_address",
                MEMBERSHIP_MAPPER);
        } catch (DataAccessException ex) {
            logMissing("provider_network_registry", ex);
            return List.of();
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
