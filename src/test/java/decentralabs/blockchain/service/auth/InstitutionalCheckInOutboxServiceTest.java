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
        when(jdbcTemplate.queryForObject("SELECT LAST_INSERT_ID()", Long.class)).thenReturn(7L);
        when(jdbcTemplate.queryForObject(any(String.class), any(org.springframework.jdbc.core.RowMapper.class), anyLong()))
            .thenReturn(record());
        InstitutionalCheckInOutboxService service = new InstitutionalCheckInOutboxService(provider);

        service.enqueueAccessGranted("0xreservation", "42", "0xwallet", "0xpuc", "session");

        ArgumentCaptor<String> sql = ArgumentCaptor.forClass(String.class);
        verify(jdbcTemplate).update(sql.capture(), any(), any(), any(), any(), any(), any());
        assertThat(sql.getValue()).contains("id = LAST_INSERT_ID(id)");
        assertThat(sql.getValue()).doesNotContain("status =").doesNotContain("attempts =").doesNotContain("nonce =");
    }

    @Test
    @SuppressWarnings("unchecked")
    void explicitTerminalRestartClearsThePreviousNonceAndTransactionHash() {
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
            .contains("tx_hash = NULL")
            .contains("nonce = NULL")
            .contains("submitted_at = NULL");
    }

    private InstitutionalCheckInOutboxRecord record() {
        return new InstitutionalCheckInOutboxRecord(
            7L, "0xreservation", "42", "0xwallet", "0xpuc", "session", "SUBMITTED", 1,
            Instant.now(), "0xtx", "0xwallet", BigInteger.valueOf(40), Instant.now()
        );
    }
}
