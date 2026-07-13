package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class InstitutionalWalletNonceReservationServiceTest {
    @Mock private InstitutionalCheckInOutboxService nonceStore;

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
}
