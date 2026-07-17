package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;

class InstitutionalCheckInOutboxServiceTest {

    @Test
    @SuppressWarnings("unchecked")
    void enqueueDoesNotResetAnExistingOutboxTransaction() {
        ObjectProvider<JdbcTemplate> provider = mock(ObjectProvider.class);
        JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);
        when(provider.getIfAvailable()).thenReturn(jdbcTemplate);
        when(jdbcTemplate.queryForObject(
            any(String.class),
            any(org.springframework.jdbc.core.RowMapper.class),
            org.mockito.ArgumentMatchers.eq("0xreservation")
        ))
            .thenReturn(record());
        InstitutionalCheckInOutboxService service = new InstitutionalCheckInOutboxService(provider);

        service.enqueueAccessGranted(
            "0xreservation", "42", "0xpayer", "0xsigner", "0xpuc", "session"
        );

        ArgumentCaptor<String> sql = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Object> values = ArgumentCaptor.forClass(Object.class);
        verify(jdbcTemplate).update(
            sql.capture(), values.capture(), values.capture(), values.capture(),
            values.capture(), values.capture(), values.capture()
        );
        assertThat(sql.getValue()).contains("reservation_key = VALUES(reservation_key)");
        assertThat(sql.getValue())
            .contains("WHEN chain_id IS NULL AND nonce IS NULL")
            .contains("AND tx_hash IS NULL AND signed_raw_transaction IS NULL")
            .contains("THEN VALUES(wallet_address)")
            .contains("ELSE wallet_address");
        assertThat(sql.getValue()).contains("institutional_wallet, wallet_address");
        assertThat(sql.getValue()).doesNotContain("status =").doesNotContain("attempts =").doesNotContain("nonce =");
        assertThat(values.getAllValues()).containsExactly(
            "0xreservation", "42", "0xpayer", "0xsigner", "0xpuc", "session"
        );
    }

    @Test
    @SuppressWarnings("unchecked")
    void terminalRestartPreservesNonceWhenFailedAfterReservation() {
        ObjectProvider<JdbcTemplate> provider = mock(ObjectProvider.class);
        JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);
        when(provider.getIfAvailable()).thenReturn(jdbcTemplate);
        when(jdbcTemplate.queryForObject(any(String.class), any(org.springframework.jdbc.core.RowMapper.class), anyLong()))
            .thenReturn(record());
        InstitutionalCheckInOutboxService service = new InstitutionalCheckInOutboxService(provider);

        service.restartTerminalFailure(7L);

        ArgumentCaptor<String> sql = ArgumentCaptor.forClass(String.class);
        verify(jdbcTemplate).update(sql.capture(), org.mockito.Mockito.eq(7L));
        assertThat(sql.getValue())
            .contains("status IN ('MINED_FAILED', 'FAILED')")
            .contains("tx_hash = CASE")
            .contains("signed_raw_transaction = CASE")
            .contains("original_gas_price = CASE")
            .contains("current_gas_price = CASE")
            .contains("generation = CASE")
            .contains("nonce = CASE")
            .contains("status = 'FAILED'")
            .contains("submitted_at = NULL");
    }

    @Test
    @SuppressWarnings("unchecked")
    void dueLookupRequiresTheActiveChainAndWalletContext() {
        ObjectProvider<JdbcTemplate> provider = mock(ObjectProvider.class);
        JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);
        when(provider.getIfAvailable()).thenReturn(jdbcTemplate);
        when(jdbcTemplate.query(
            any(String.class), any(org.springframework.jdbc.core.RowMapper.class), any(Object[].class)
        )).thenReturn(java.util.List.of());
        InstitutionalCheckInOutboxService service = new InstitutionalCheckInOutboxService(provider);

        BigInteger chainId = BigInteger.valueOf(11155111);
        service.findDue(chainId, "0xwallet", Instant.now(), 10);

        ArgumentCaptor<String> sql = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Object[]> parameters = ArgumentCaptor.forClass(Object[].class);
        verify(jdbcTemplate).query(
            sql.capture(), any(org.springframework.jdbc.core.RowMapper.class), parameters.capture()
        );
        assertThat(sql.getValue())
            .contains("(chain_id = ? AND LOWER(wallet_address) = LOWER(?))")
            .contains("LOWER(wallet_address) = LOWER(?)")
            .contains("claim_expires_at <= CURRENT_TIMESTAMP")
            .contains("claim_expires_at IS NULL AND updated_at <= ?");
        assertThat(parameters.getValue()[2]).isEqualTo(chainId);
        assertThat(parameters.getValue()[3]).isEqualTo("0xwallet");
        assertThat(parameters.getValue()[4]).isEqualTo("0xwallet");
    }

    @Test
    @SuppressWarnings("unchecked")
    void claimPersistsOwnerLeaseAndClaimVersionBeforeReturningTheRow() {
        ObjectProvider<JdbcTemplate> provider = mock(ObjectProvider.class);
        JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);
        when(provider.getIfAvailable()).thenReturn(jdbcTemplate);
        when(jdbcTemplate.update(any(String.class), any(Object[].class))).thenReturn(1);
        when(jdbcTemplate.queryForObject(
            any(String.class), any(org.springframework.jdbc.core.RowMapper.class), any(), any(), any()
        )).thenReturn(record());
        InstitutionalCheckInOutboxService service = new InstitutionalCheckInOutboxService(provider);

        InstitutionalCheckInOutboxClaim claim = service.claim(7L);

        assertThat(claim).isNotNull();
        ArgumentCaptor<String> sql = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Object[]> parameters = ArgumentCaptor.forClass(Object[].class);
        verify(jdbcTemplate).update(sql.capture(), parameters.capture());
        assertThat(sql.getValue())
            .contains("claim_id = ?")
            .contains("claimed_by = ?")
            .contains("claim_version = version + 1")
            .contains("claim_expires_at = TIMESTAMPADD(MICROSECOND, ?, CURRENT_TIMESTAMP(6))")
            .contains("claim_expires_at <= CURRENT_TIMESTAMP");
        assertThat(parameters.getValue()[2]).isEqualTo(900_000_000L);
    }

    @Test
    @SuppressWarnings("unchecked")
    void failedHistoricalReceiptRecordsTheMiningTimestamp() {
        ObjectProvider<JdbcTemplate> provider = mock(ObjectProvider.class);
        JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);
        when(provider.getIfAvailable()).thenReturn(jdbcTemplate);
        InstitutionalCheckInOutboxService service = new InstitutionalCheckInOutboxService(provider);

        service.markUnknownMinedFailed(record(), "0xmined", "reverted");

        ArgumentCaptor<String> sql = ArgumentCaptor.forClass(String.class);
        verify(jdbcTemplate).update(sql.capture(), any(Object[].class));
        assertThat(sql.getValue()).contains("mined_at = CURRENT_TIMESTAMP");
    }

    @Test
    @SuppressWarnings("unchecked")
    void quarantinesARecordWithoutChangingItsPreviousTransactionContext() {
        ObjectProvider<JdbcTemplate> provider = mock(ObjectProvider.class);
        JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);
        when(provider.getIfAvailable()).thenReturn(jdbcTemplate);
        when(jdbcTemplate.update(any(String.class), any(Object[].class))).thenReturn(1);
        InstitutionalCheckInOutboxService service = new InstitutionalCheckInOutboxService(provider);

        boolean quarantined = service.quarantineContextMismatch(
            record(), BigInteger.valueOf(11155111), "0xactive-wallet"
        );

        assertThat(quarantined).isTrue();
        ArgumentCaptor<String> sql = ArgumentCaptor.forClass(String.class);
        verify(jdbcTemplate).update(sql.capture(), any(Object[].class));
        assertThat(sql.getValue())
            .contains("status = 'MANUAL_INTERVENTION'")
            .contains("version = version + 1")
            .contains("status = 'SUBMITTED'")
            .contains("claim_expires_at IS NULL OR claim_expires_at <= CURRENT_TIMESTAMP")
            .doesNotContain("wallet_address = NULL")
            .doesNotContain("chain_id = NULL")
            .doesNotContain("nonce = NULL")
            .doesNotContain("tx_hash = NULL")
            .doesNotContain("signed_raw_transaction = NULL");
    }

    private InstitutionalCheckInOutboxRecord record() {
        return new InstitutionalCheckInOutboxRecord(
            7L, "0xreservation", "42", "0xwallet", "0xpuc", "session", "SUBMITTED", 1,
            Instant.now(), "0xtx", "0xwallet", BigInteger.valueOf(40), Instant.now()
        );
    }
}
