package decentralabs.blockchain.service.wallet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.math.BigInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.junit.jupiter.MockitoExtension;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.Request;
import org.web3j.protocol.core.methods.response.EthChainId;
import org.web3j.tx.TransactionManager;

@ExtendWith(MockitoExtension.class)
class InstitutionalTxManagerProviderTest {

    private static final Credentials CREDENTIALS =
        Credentials.create("4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f7f8f2f0d9f7d4c001");

    @Mock
    private InstitutionalWalletService institutionalWalletService;

    @Mock
    private Web3j web3j;

    @Mock
    private Web3j otherWeb3j;

    private InstitutionalTxManagerProvider provider;

    @BeforeEach
    void setUp() {
        provider = new InstitutionalTxManagerProvider(institutionalWalletService);
    }

    @Test
    void get_rejectsNullWeb3j() {
        assertThatThrownBy(() -> provider.get(null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("web3j is required");
    }

    @Test
    void get_reusesCachedManagerForSameWeb3jAndChainId() throws Exception {
        when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(CREDENTIALS);
        stubChainId(web3j, 11155111L);

        try (MockedConstruction<PendingNonceFastRawTransactionManager> construction =
                 mockConstruction(PendingNonceFastRawTransactionManager.class)) {

            TransactionManager first = provider.get(web3j);
            TransactionManager second = provider.get(web3j);

            assertThat(first).isSameAs(second);
            assertThat(construction.constructed()).hasSize(1);
            verify(institutionalWalletService, times(1)).getInstitutionalCredentials();
        }
    }

    @Test
    void get_reinitializesWhenWeb3jInstanceChanges() throws Exception {
        when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(CREDENTIALS);
        stubChainId(web3j, 11155111L);
        stubChainId(otherWeb3j, 11155111L);

        try (MockedConstruction<PendingNonceFastRawTransactionManager> construction =
                 mockConstruction(PendingNonceFastRawTransactionManager.class)) {

            TransactionManager first = provider.get(web3j);
            TransactionManager second = provider.get(otherWeb3j);

            assertThat(first).isNotSameAs(second);
            assertThat(construction.constructed()).hasSize(2);
            verify(institutionalWalletService, times(2)).getInstitutionalCredentials();
        }
    }

    @Test
    void get_reinitializesWhenChainIdChanges() throws Exception {
        when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(CREDENTIALS);
        stubChainIdSequence(web3j, 11155111L, 11155112L);

        try (MockedConstruction<PendingNonceFastRawTransactionManager> construction =
                 mockConstruction(PendingNonceFastRawTransactionManager.class)) {

            TransactionManager first = provider.get(web3j);
            TransactionManager second = provider.get(web3j);

            assertThat(first).isNotSameAs(second);
            assertThat(construction.constructed()).hasSize(2);
            verify(institutionalWalletService, times(2)).getInstitutionalCredentials();
        }
    }

    @Test
    void get_fallsBackToChainIdZeroWhenLookupFailsAndStillCaches() throws Exception {
        when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(CREDENTIALS);
        stubChainIdFailure(web3j);

        try (MockedConstruction<PendingNonceFastRawTransactionManager> construction =
                 mockConstruction(PendingNonceFastRawTransactionManager.class)) {

            TransactionManager first = provider.get(web3j);
            TransactionManager second = provider.get(web3j);

            assertThat(first).isSameAs(second);
            assertThat(construction.constructed()).hasSize(1);
            verify(institutionalWalletService, times(1)).getInstitutionalCredentials();
        }
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private void stubChainId(Web3j client, long chainId) throws Exception {
        Request<?, EthChainId> request = (Request<?, EthChainId>) mock(Request.class);
        EthChainId response = mock(EthChainId.class);
        when(client.ethChainId()).thenReturn((Request) request);
        when(request.send()).thenReturn(response);
        when(response.getChainId()).thenReturn(BigInteger.valueOf(chainId));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private void stubChainIdSequence(Web3j client, long firstChainId, long secondChainId) throws Exception {
        Request<?, EthChainId> firstRequest = (Request<?, EthChainId>) mock(Request.class);
        Request<?, EthChainId> secondRequest = (Request<?, EthChainId>) mock(Request.class);
        EthChainId firstResponse = mock(EthChainId.class);
        EthChainId secondResponse = mock(EthChainId.class);
        when(client.ethChainId()).thenReturn((Request) firstRequest, (Request) secondRequest);
        when(firstRequest.send()).thenReturn(firstResponse);
        when(secondRequest.send()).thenReturn(secondResponse);
        when(firstResponse.getChainId()).thenReturn(BigInteger.valueOf(firstChainId));
        when(secondResponse.getChainId()).thenReturn(BigInteger.valueOf(secondChainId));
    }

    @SuppressWarnings({ "unchecked", "rawtypes" })
    private void stubChainIdFailure(Web3j client) throws Exception {
        Request<?, EthChainId> request = (Request<?, EthChainId>) mock(Request.class);
        when(client.ethChainId()).thenReturn((Request) request);
        when(request.send()).thenThrow(new IOException("chain unavailable"));
    }
}
