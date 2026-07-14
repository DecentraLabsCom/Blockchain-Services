package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.doReturn;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;

import java.math.BigInteger;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

@ExtendWith(MockitoExtension.class)
class InstitutionalWalletNonceReservationServiceTest {
    @Mock private InstitutionalCheckInOutboxService nonceStore;
    @Mock private JdbcTemplate jdbcTemplate;
    @Mock private ObjectProvider<JdbcTemplate> jdbcTemplateProvider;

    @Test
    void reservesAndAssociatesNonceBeforeReturningToTheBroadcaster() {
        var service = new InstitutionalWalletNonceReservationService(nonceStore);
        var persisted = new AtomicReference<BigInteger>();
        var persistedChain = new AtomicReference<BigInteger>();
        when(nonceStore.reserveNextNonce(BigInteger.valueOf(11155111), "0xwallet", BigInteger.valueOf(45)))
            .thenReturn(BigInteger.valueOf(47));

        BigInteger nonce = service.reserveAndPersist(
            "0xwallet", BigInteger.valueOf(11155111), BigInteger.valueOf(45), (chainId, value) -> {
                persistedChain.set(chainId);
                persisted.set(value);
            }
        );

        assertThat(nonce).isEqualTo(BigInteger.valueOf(47));
        assertThat(persistedChain.get()).isEqualTo(BigInteger.valueOf(11155111));
        assertThat(persisted.get()).isEqualTo(nonce);
        InOrder order = inOrder(nonceStore);
        order.verify(nonceStore).reserveNextNonce(BigInteger.valueOf(11155111), "0xwallet", BigInteger.valueOf(45));
    }

    @Test
    void reservesGenericInstitutionalTransactionsFromTheSameChainScopedAllocator() {
        var service = new InstitutionalWalletNonceReservationService(nonceStore);
        when(nonceStore.reserveNextNonce(BigInteger.ONE, "0xwallet", BigInteger.valueOf(8)))
            .thenReturn(BigInteger.valueOf(10));

        assertThat(service.reserve("0xwallet", BigInteger.ONE, BigInteger.valueOf(8)))
            .isEqualTo(BigInteger.valueOf(10));
    }

    @Test
    void sharedAllocatorRefusesToSkipAnUnresolvedGenericAttempt() {
        when(jdbcTemplateProvider.getIfAvailable()).thenReturn(jdbcTemplate);
        doReturn(List.of("blocker")).when(jdbcTemplate).query(
            anyString(),
            org.mockito.ArgumentMatchers.<RowMapper<Object>>any(),
            any(),
            any()
        );
        when(nonceStore.reserveNextNonce(BigInteger.ONE, "0xwallet", BigInteger.valueOf(8)))
            .thenReturn(BigInteger.TEN);

        var service = new InstitutionalWalletNonceReservationService(nonceStore, jdbcTemplateProvider);

        assertThatThrownBy(() -> service.reserve("0xwallet", BigInteger.ONE, BigInteger.valueOf(8)))
            .isInstanceOf(InstitutionalWalletNonceReservationService.TransactionBlockedException.class);
    }
}
