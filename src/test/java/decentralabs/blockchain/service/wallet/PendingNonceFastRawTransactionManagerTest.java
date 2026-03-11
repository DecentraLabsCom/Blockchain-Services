package decentralabs.blockchain.service.wallet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.Request;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.tx.response.PollingTransactionReceiptProcessor;
import org.web3j.tx.response.TransactionReceiptProcessor;

@ExtendWith(MockitoExtension.class)
class PendingNonceFastRawTransactionManagerTest {

    private static final Credentials CREDENTIALS =
        Credentials.create("4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f7f8f2f0d9f7d4c001");

    @Mock
    private Web3j web3j;

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

    @SuppressWarnings({"unchecked", "rawtypes"})
    private void stubPendingCount(BigInteger transactionCount) throws Exception {
        Request<?, EthGetTransactionCount> request = (Request<?, EthGetTransactionCount>) mock(Request.class);
        EthGetTransactionCount response = mock(EthGetTransactionCount.class);
        when(web3j.ethGetTransactionCount(CREDENTIALS.getAddress(), DefaultBlockParameterName.PENDING))
            .thenReturn((Request) request);
        when(request.send()).thenReturn(response);
        when(response.getTransactionCount()).thenReturn(transactionCount);
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

        private BigInteger readNonce() throws java.io.IOException {
            return super.getNonce();
        }
    }
}
