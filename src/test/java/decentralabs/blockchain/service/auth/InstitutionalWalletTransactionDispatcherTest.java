package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.service.wallet.WalletService;
import java.math.BigInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameter;
import org.web3j.protocol.core.Request;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;

@ExtendWith(MockitoExtension.class)
class InstitutionalWalletTransactionDispatcherTest {
    @Mock private InstitutionalWalletNonceReservationService nonceReservationService;
    @Mock private WalletService walletService;
    @Mock private Web3j web3j;
    @Mock private Request<?, EthGetTransactionCount> nonceRequest;

    @Test
    void reservesPersistsBroadcastsAndStoresHashInsideOneDispatch() throws Exception {
        EthGetTransactionCount response = new EthGetTransactionCount();
        response.setResult("0x2d");
        when(walletService.getWeb3jInstance()).thenReturn(web3j);
        doReturn(nonceRequest).when(web3j)
            .ethGetTransactionCount(eq("0xwallet"), any(DefaultBlockParameter.class));
        when(nonceRequest.send()).thenReturn(response);
        when(nonceReservationService.reserveAndPersist(eq("0xwallet"), eq(BigInteger.valueOf(45)), any()))
            .thenAnswer(invocation -> {
                BigInteger nonce = BigInteger.valueOf(47);
                invocation.<java.util.function.Consumer<BigInteger>>getArgument(2).accept(nonce);
                return nonce;
            });
        AtomicReference<BigInteger> persistedNonce = new AtomicReference<>();
        AtomicReference<String> persistedHash = new AtomicReference<>();
        InstitutionalWalletTransactionDispatcher dispatcher =
            new InstitutionalWalletTransactionDispatcher(nonceReservationService, walletService);

        String hash = dispatcher.dispatch(
            "0xwallet",
            null,
            persistedNonce::set,
            nonce -> "0x" + "a".repeat(64),
            persistedHash::set
        );

        assertThat(persistedNonce.get()).isEqualTo(BigInteger.valueOf(47));
        assertThat(persistedHash.get()).isEqualTo(hash);
    }

    @Test
    void reusesExistingNonceAndClassifiesLostRpcResponseAsUncertain() {
        InstitutionalWalletTransactionDispatcher dispatcher =
            new InstitutionalWalletTransactionDispatcher(nonceReservationService, walletService);

        assertThatThrownBy(() -> dispatcher.dispatch(
            "0xwallet",
            BigInteger.valueOf(48),
            ignored -> { },
            ignored -> { throw new IllegalStateException("rpc response lost"); },
            ignored -> { }
        )).isInstanceOf(InstitutionalWalletDispatchException.class)
            .hasCauseInstanceOf(IllegalStateException.class);

        verify(nonceReservationService, never()).reserveAndPersist(eq("0xwallet"), any(), any());
        verify(walletService, never()).getWeb3jInstance();
    }
}
