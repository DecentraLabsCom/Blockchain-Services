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
        when(nonceStore.reserveNextNonce("0xwallet", BigInteger.valueOf(45)))
            .thenReturn(BigInteger.valueOf(47));

        BigInteger nonce = service.reserveAndPersist(
            "0xwallet", BigInteger.valueOf(45), persisted::set
        );

        assertThat(nonce).isEqualTo(BigInteger.valueOf(47));
        assertThat(persisted.get()).isEqualTo(nonce);
        InOrder order = inOrder(nonceStore);
        order.verify(nonceStore).reserveNextNonce("0xwallet", BigInteger.valueOf(45));
    }
}
