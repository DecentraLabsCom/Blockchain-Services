package decentralabs.blockchain.service.wallet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;

import java.math.BigInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.Request;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.tx.response.PollingTransactionReceiptProcessor;
import org.web3j.tx.response.TransactionReceiptProcessor;
import decentralabs.blockchain.service.auth.InstitutionalWalletNonceReservationService;

@ExtendWith(MockitoExtension.class)
class PendingNonceFastRawTransactionManagerTest {

    private static final Credentials CREDENTIALS =
        Credentials.create("4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f7f8f2f0d9f7d4c001");

    @Mock
    private Web3j web3j;

    @Mock
    private InstitutionalWalletNonceReservationService nonceReservationService;

    @Mock
    private InstitutionalTransactionOutboxService transactionOutboxService;

    private TestPendingNonceFastRawTransactionManager manager;

    @BeforeEach
    void setUp() {
        manager = new TestPendingNonceFastRawTransactionManager(web3j, CREDENTIALS, 11155111L);
    }

    @Test
    void getNonce_readsPendingNonceFromWeb3j() throws Exception {
        stubPendingCount(BigInteger.valueOf(7));

        BigInteger nonce = manager.readNonce();

        assertThat(nonce).isEqualTo(BigInteger.valueOf(7));
    }

    @Test
    void secondConstructor_usesProvidedReceiptProcessorAndStillReadsPendingNonce() throws Exception {
        TransactionReceiptProcessor receiptProcessor = new PollingTransactionReceiptProcessor(web3j, 10, 2);
        TestPendingNonceFastRawTransactionManager customManager =
            new TestPendingNonceFastRawTransactionManager(web3j, CREDENTIALS, 1L, receiptProcessor);
        stubPendingCount(BigInteger.valueOf(11));

        BigInteger nonce = customManager.readNonce();

        assertThat(nonce).isEqualTo(BigInteger.valueOf(11));
    }

    @Test
    void durableConstructorUsesTheSharedChainScopedAllocator() throws Exception {
        TransactionReceiptProcessor receiptProcessor = new PollingTransactionReceiptProcessor(web3j, 10, 2);
        TestPendingNonceFastRawTransactionManager durableManager =
            new TestPendingNonceFastRawTransactionManager(
                web3j, CREDENTIALS, 11155111L, receiptProcessor, nonceReservationService
            );
        stubPendingCount(BigInteger.valueOf(11));
        when(nonceReservationService.reserve(
            CREDENTIALS.getAddress(), BigInteger.valueOf(11155111L), BigInteger.valueOf(11)
        )).thenReturn(BigInteger.valueOf(14));

        assertThat(durableManager.readNonce()).isEqualTo(BigInteger.valueOf(14));
    }

    @Test
    void durableConstructorReservesEveryTransactionInsteadOfCachingLocally() throws Exception {
        TransactionReceiptProcessor receiptProcessor = new PollingTransactionReceiptProcessor(web3j, 10, 2);
        TestPendingNonceFastRawTransactionManager durableManager =
            new TestPendingNonceFastRawTransactionManager(
                web3j, CREDENTIALS, 11155111L, receiptProcessor, nonceReservationService
            );
        stubPendingCount(BigInteger.valueOf(11));
        when(nonceReservationService.reserve(
            CREDENTIALS.getAddress(), BigInteger.valueOf(11155111L), BigInteger.valueOf(11)
        )).thenReturn(BigInteger.valueOf(14), BigInteger.valueOf(15));

        assertThat(durableManager.readNonce()).isEqualTo(BigInteger.valueOf(14));
        assertThat(durableManager.readNonce()).isEqualTo(BigInteger.valueOf(15));
        verify(nonceReservationService, times(2)).reserve(
            CREDENTIALS.getAddress(), BigInteger.valueOf(11155111L), BigInteger.valueOf(11)
        );
    }

    @Test
    void durableTransactionManagerReusesTheSameNonceForAnUncertainRetry() throws Exception {
        PendingNonceFastRawTransactionManager durableManager =
            new PendingNonceFastRawTransactionManager(
                web3j, CREDENTIALS, 11155111L, transactionOutboxService
            );
        InstitutionalTransactionOutboxService.Attempt attempt = new InstitutionalTransactionOutboxService.Attempt(
            7L, BigInteger.valueOf(11155111L), CREDENTIALS.getAddress(), "operation-key",
            BigInteger.valueOf(14), "RETRYABLE", null, null
        );
        when(transactionOutboxService.reserveOrLoad(
            anyString(), any(), any(), anyString(), any(), any(), anyString(), any(), anyString()
        )).thenReturn(attempt);
        stubPendingCount(BigInteger.valueOf(14));
        EthSendTransaction accepted = new EthSendTransaction();
        accepted.setResult("0x" + "a".repeat(64));
        Request<?, EthSendTransaction> sendRequest = requestReturning(accepted);
        doThrow(new RuntimeException("rpc unavailable"))
            .doReturn(sendRequest)
            .when(web3j)
            .ethSendRawTransaction(any());

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> durableManager.sendTransaction(
            BigInteger.valueOf(2_000_000_000L), BigInteger.valueOf(300_000),
            "0x0000000000000000000000000000000000000001", "0x1234", BigInteger.ZERO
        )).isInstanceOf(RuntimeException.class);

        EthSendTransaction retry = durableManager.sendTransaction(
            BigInteger.valueOf(2_100_000_000L), BigInteger.valueOf(300_000),
            "0x0000000000000000000000000000000000000001", "0x1234", BigInteger.ZERO
        );

        assertThat(retry.getTransactionHash()).isEqualTo("0x" + "a".repeat(64));
        EthSendTransaction nextOperation = durableManager.sendTransaction(
            BigInteger.valueOf(2_200_000_000L), BigInteger.valueOf(300_000),
            "0x0000000000000000000000000000000000000001", "0x1234", BigInteger.ZERO
        );
        assertThat(nextOperation.getTransactionHash()).isEqualTo("0x" + "a".repeat(64));
        ArgumentCaptor<String> operationKeys = ArgumentCaptor.forClass(String.class);
        verify(transactionOutboxService, times(3)).reserveOrLoad(
            anyString(), eq(BigInteger.valueOf(11155111L)), eq(BigInteger.valueOf(14)),
            operationKeys.capture(), any(), any(), anyString(), any(), anyString()
        );
        assertThat(operationKeys.getAllValues().get(0)).isEqualTo(operationKeys.getAllValues().get(1));
        assertThat(operationKeys.getAllValues().get(2)).isNotEqualTo(operationKeys.getAllValues().get(0));

        verify(transactionOutboxService, times(3)).markSigned(any(), anyString(), anyString());
        verify(transactionOutboxService).markRetryable(any(), anyString());
        verify(transactionOutboxService, times(2)).markSubmitted(any(), anyString());
    }

    private void stubPendingCount(BigInteger transactionCount) throws Exception {
        EthGetTransactionCount response = mock(EthGetTransactionCount.class);
        Request<?, EthGetTransactionCount> request = requestReturning(response);
        doReturn(request).when(web3j)
            .ethGetTransactionCount(CREDENTIALS.getAddress(), DefaultBlockParameterName.PENDING);
        when(response.getTransactionCount()).thenReturn(transactionCount);
    }

    private static <T extends org.web3j.protocol.core.Response<?>> Request<?, T> requestReturning(T response) {
        return new Request<Object, T>() {
            @Override
            public T send() {
                return response;
            }
        };
    }

    private static final class TestPendingNonceFastRawTransactionManager extends PendingNonceFastRawTransactionManager {

        private TestPendingNonceFastRawTransactionManager(Web3j web3j, Credentials credentials, long chainId) {
            super(web3j, credentials, chainId);
        }

        private TestPendingNonceFastRawTransactionManager(
            Web3j web3j,
            Credentials credentials,
            long chainId,
            TransactionReceiptProcessor receiptProcessor
        ) {
            super(web3j, credentials, chainId, receiptProcessor);
        }

        private TestPendingNonceFastRawTransactionManager(
            Web3j web3j,
            Credentials credentials,
            long chainId,
            TransactionReceiptProcessor receiptProcessor,
            InstitutionalWalletNonceReservationService nonceReservationService
        ) {
            super(web3j, credentials, chainId, receiptProcessor, nonceReservationService);
        }

        private BigInteger readNonce() throws java.io.IOException {
            return super.getNonce();
        }
    }
}
