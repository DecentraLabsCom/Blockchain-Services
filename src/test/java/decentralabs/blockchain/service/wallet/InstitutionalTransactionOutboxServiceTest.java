package decentralabs.blockchain.service.wallet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.exception.IdempotencyKeyPayloadMismatchException;
import decentralabs.blockchain.service.auth.InstitutionalWalletNonceReservationService;
import java.math.BigInteger;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

@ExtendWith(MockitoExtension.class)
class InstitutionalTransactionOutboxServiceTest {

    @Mock
    private JdbcTemplate jdbcTemplate;

    @Mock
    private ObjectProvider<JdbcTemplate> jdbcTemplateProvider;

    @Mock
    private InstitutionalWalletNonceReservationService nonceReservationService;

    private InstitutionalTransactionOutboxService service;

    @BeforeEach
    void setUp() {
        when(jdbcTemplateProvider.getIfAvailable()).thenReturn(jdbcTemplate);
        service = new InstitutionalTransactionOutboxService(jdbcTemplateProvider, nonceReservationService);
    }

    @Test
    void rejectsReuseOfAnIdempotencyKeyForADifferentPayload() {
        InstitutionalTransactionOutboxService.Attempt existing = attempt(
            "0x1111111111111111111111111111111111111111",
            BigInteger.valueOf(21000),
            BigInteger.ZERO,
            "0x1234"
        );
        stubExisting(existing);

        assertThatThrownBy(() -> service.reserveOrLoad(
            existing.walletAddress(), existing.chainId(), BigInteger.TEN, existing.operationKey(),
            BigInteger.valueOf(2_000_000_000L), BigInteger.valueOf(21001),
            existing.toAddress(), existing.value(), "0x5678"
        ))
            .isInstanceOf(IdempotencyKeyPayloadMismatchException.class)
            .hasMessageContaining("different transaction payload");

        verifyNoInteractions(nonceReservationService);
    }

    @Test
    void reusesAnIdempotencyKeyWhenOnlyGasLimitChanges() {
        InstitutionalTransactionOutboxService.Attempt existing = attempt(
            "0x1111111111111111111111111111111111111111",
            BigInteger.valueOf(21000),
            BigInteger.ZERO,
            "0x1234"
        );
        stubExisting(existing);

        InstitutionalTransactionOutboxService.Attempt result = service.reserveOrLoad(
            existing.walletAddress(), existing.chainId(), BigInteger.TEN, existing.operationKey(),
            BigInteger.valueOf(2_000_000_000L), BigInteger.valueOf(21001),
            existing.toAddress(), existing.value(), existing.data()
        );

        assertThat(result).isSameAs(existing);
        verifyNoInteractions(nonceReservationService);
    }

    @Test
    void reusesAnIdempotencyKeyWhenThePayloadIsIdentical() {
        InstitutionalTransactionOutboxService.Attempt existing = attempt(
            "0x1111111111111111111111111111111111111111",
            BigInteger.valueOf(21000),
            BigInteger.ZERO,
            "0x1234"
        );
        stubExisting(existing);

        InstitutionalTransactionOutboxService.Attempt result = service.reserveOrLoad(
            existing.walletAddress(), existing.chainId(), BigInteger.TEN, existing.operationKey(),
            BigInteger.valueOf(2_000_000_000L), BigInteger.valueOf(21000),
            existing.toAddress().toUpperCase(), existing.value(), existing.data().toUpperCase()
        );

        assertThat(result).isSameAs(existing);
        verifyNoInteractions(nonceReservationService);
    }

    @Test
    void fencesSubmissionByTheObservedHashAndVersion() {
        InstitutionalTransactionOutboxService.Attempt attempt = new InstitutionalTransactionOutboxService.Attempt(
            9L,
            BigInteger.valueOf(11155111L),
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "same-operation",
            BigInteger.TEN,
            BigInteger.ONE,
            BigInteger.ONE,
            BigInteger.valueOf(21000),
            "0x1111111111111111111111111111111111111111",
            BigInteger.ZERO,
            "0x1234",
            "RETRYABLE",
            "0xf861-old",
            "0x" + "1".repeat(64),
            null,
            2,
            null,
            7L
        );
        when(jdbcTemplate.update(anyString(), any(Object[].class))).thenReturn(1);

        service.markSubmitted(attempt, "0x" + "2".repeat(64));

        verify(jdbcTemplate).update(
            org.mockito.ArgumentMatchers.contains("tx_hash = ? AND version = ?"),
            org.mockito.ArgumentMatchers.eq("0x" + "2".repeat(64)),
            org.mockito.ArgumentMatchers.eq(9L),
            org.mockito.ArgumentMatchers.eq("0x" + "2".repeat(64)),
            org.mockito.ArgumentMatchers.eq(8L)
        );
    }

    @Test
    void promotesTheHistoricalHashThatActuallyMined() {
        String currentHash = "0x" + "2".repeat(64);
        String minedHash = "0x" + "1".repeat(64);
        InstitutionalTransactionOutboxService.Attempt attempt = new InstitutionalTransactionOutboxService.Attempt(
            10L,
            BigInteger.valueOf(11155111L),
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "same-operation",
            BigInteger.TEN,
            BigInteger.ONE,
            BigInteger.valueOf(2),
            BigInteger.valueOf(21000),
            "0x1111111111111111111111111111111111111111",
            BigInteger.ZERO,
            "0x1234",
            "SUBMITTED",
            "0xf861",
            currentHash,
            null,
            2,
            null,
            4L
        );
        when(jdbcTemplate.update(anyString(), any(Object[].class))).thenReturn(1);

        service.markMinedSuccess(attempt, minedHash);

        verify(jdbcTemplate).update(
            org.mockito.ArgumentMatchers.contains("tx_hash = COALESCE(?, tx_hash)"),
            eq("MINED_SUCCESS"), eq(minedHash), isNull(), eq(10L), eq(4L)
        );
    }

    private void stubExisting(InstitutionalTransactionOutboxService.Attempt existing) {
        when(jdbcTemplate.query(
            anyString(),
            org.mockito.ArgumentMatchers.<RowMapper<InstitutionalTransactionOutboxService.Attempt>>any(),
            any(), any(), any()
        ))
            .thenReturn(List.of(existing));
    }

    private InstitutionalTransactionOutboxService.Attempt attempt(
        String toAddress,
        BigInteger gasLimit,
        BigInteger value,
        String data
    ) {
        return new InstitutionalTransactionOutboxService.Attempt(
            1L,
            BigInteger.valueOf(11155111L),
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "same-operation",
            BigInteger.TEN,
            BigInteger.valueOf(2_000_000_000L),
            gasLimit,
            toAddress,
            value,
            data,
            "RESERVED",
            null,
            null
        );
    }
}
