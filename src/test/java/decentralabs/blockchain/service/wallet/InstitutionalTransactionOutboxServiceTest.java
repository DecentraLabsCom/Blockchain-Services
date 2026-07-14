package decentralabs.blockchain.service.wallet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verifyNoInteractions;
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
            existing.toAddress(), existing.value(), existing.data()
        ))
            .isInstanceOf(IdempotencyKeyPayloadMismatchException.class)
            .hasMessageContaining("different transaction payload");

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
