package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.dto.auth.CheckInRequest;
import decentralabs.blockchain.dto.auth.CheckInResponse;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Hash;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.Request;
import org.web3j.protocol.core.methods.response.EthChainId;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.tx.FastRawTransactionManager;
import org.web3j.utils.Numeric;

@ExtendWith(MockitoExtension.class)
class CheckInOnChainServiceTest {

    @Mock
    private CheckInAuthService checkInAuthService;

    @Mock
    private WalletService walletService;

    @Mock
    private InstitutionalWalletService institutionalWalletService;

    @Mock
    private Web3j web3j;

    @InjectMocks
    private CheckInOnChainService service;

    private Credentials credentials;

    @BeforeEach
    void setUp() {
        credentials = Credentials.create("4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f7f8f2f0d9f7d4c001");
        ReflectionTestUtils.setField(service, "contractAddress", "0x2222222222222222222222222222222222222222");
        ReflectionTestUtils.setField(service, "gasLimit", BigInteger.valueOf(300000));
        ReflectionTestUtils.setField(service, "gasPriceGwei", BigInteger.valueOf(2));
    }

    @Test
    void verifyAndSubmit_buildsTransactionAndReturnsTxHash() throws Exception {
        CheckInRequest request = validRequest();
        CheckInResponse authResponse = new CheckInResponse();
        authResponse.setValid(true);
        authResponse.setSigner(credentials.getAddress());
        authResponse.setReservationKey("0xabc");
        authResponse.setTimestamp(1234L);

        when(checkInAuthService.verifyCheckIn(request)).thenReturn(authResponse);
        when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(credentials);
        when(walletService.getWeb3jInstance()).thenReturn(web3j);
        stubNonceChecks(BigInteger.ONE, BigInteger.ONE);
        stubChainId(11155111L);

        EthSendTransaction sendTransaction = mock(EthSendTransaction.class);
        when(sendTransaction.getTransactionHash()).thenReturn("0xtx123");
        when(sendTransaction.hasError()).thenReturn(false);

        try (MockedConstruction<FastRawTransactionManager> ignored =
                 mockConstruction(FastRawTransactionManager.class, (mock, context) ->
                     when(mock.sendTransaction(
                         eq(toWei(BigInteger.valueOf(2))),
                         eq(BigInteger.valueOf(300000)),
                         eq("0x2222222222222222222222222222222222222222"),
                         any(String.class),
                         eq(BigInteger.ZERO)
                     )).thenReturn(sendTransaction))) {

            CheckInResponse response = service.verifyAndSubmit(request);

            assertThat(response).isSameAs(authResponse);
            assertThat(response.getTxHash()).isEqualTo("0xtx123");
            verify(checkInAuthService).verifyCheckIn(request);
        }
    }

    @Test
    void verifyAndSubmit_rejectsPendingNonceCollision() throws Exception {
        CheckInRequest request = validRequest();
        CheckInResponse authResponse = new CheckInResponse();
        authResponse.setValid(true);
        authResponse.setSigner(credentials.getAddress());
        authResponse.setReservationKey("0xabc");
        authResponse.setTimestamp(1234L);

        when(checkInAuthService.verifyCheckIn(request)).thenReturn(authResponse);
        when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(credentials);
        when(walletService.getWeb3jInstance()).thenReturn(web3j);
        stubNonceChecks(BigInteger.valueOf(3), BigInteger.ONE);

        assertThatThrownBy(() -> service.verifyAndSubmit(request))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("still pending confirmation");
    }

    @Test
    void verifyAndSubmit_ignoresNonceLookupErrorsAndFallsBackToChainIdZero() throws Exception {
        CheckInRequest request = validRequest();
        CheckInResponse authResponse = new CheckInResponse();
        authResponse.setValid(true);
        authResponse.setSigner(credentials.getAddress());
        authResponse.setReservationKey("0xabc");
        authResponse.setTimestamp(1234L);

        when(checkInAuthService.verifyCheckIn(request)).thenReturn(authResponse);
        when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(credentials);
        when(walletService.getWeb3jInstance()).thenReturn(web3j);

        @SuppressWarnings("unchecked")
        Request<?, EthGetTransactionCount> pendingRequest = (Request<?, EthGetTransactionCount>) mock(Request.class);
        when(web3j.ethGetTransactionCount(credentials.getAddress(), DefaultBlockParameterName.PENDING))
            .thenAnswer(invocation -> pendingRequest);
        when(pendingRequest.send()).thenThrow(new RuntimeException("rpc timeout"));

        @SuppressWarnings("unchecked")
        Request<?, EthChainId> chainIdRequest = (Request<?, EthChainId>) mock(Request.class);
        when(web3j.ethChainId()).thenAnswer(invocation -> chainIdRequest);
        when(chainIdRequest.send()).thenThrow(new IOException("chain unavailable"));

        EthSendTransaction sendTransaction = mock(EthSendTransaction.class);
        when(sendTransaction.getTransactionHash()).thenReturn("0xtx123");
        when(sendTransaction.hasError()).thenReturn(false);

        try (MockedConstruction<FastRawTransactionManager> construction =
                 mockConstruction(FastRawTransactionManager.class, (mock, context) ->
                     when(mock.sendTransaction(any(), any(), any(), any(), any())).thenReturn(sendTransaction))) {

            CheckInResponse response = service.verifyAndSubmit(request);

            assertThat(response.getTxHash()).isEqualTo("0xtx123");
            assertThat(construction.constructed()).hasSize(1);
            assertThat(construction.constructed()).first().isNotNull();
        }
    }

    @Test
    void verifyAndSubmit_wrapsIoFailureFromSendTransaction() throws Exception {
        CheckInRequest request = validRequest();
        CheckInResponse authResponse = new CheckInResponse();
        authResponse.setValid(true);
        authResponse.setSigner(credentials.getAddress());
        authResponse.setReservationKey("0xabc");
        authResponse.setTimestamp(1234L);

        when(checkInAuthService.verifyCheckIn(request)).thenReturn(authResponse);
        when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(credentials);
        when(walletService.getWeb3jInstance()).thenReturn(web3j);
        stubNonceChecks(BigInteger.ONE, BigInteger.ONE);
        stubChainId(1L);

        try (MockedConstruction<FastRawTransactionManager> ignored =
                 mockConstruction(FastRawTransactionManager.class, (mock, context) ->
                     when(mock.sendTransaction(any(), any(), any(), any(), any()))
                         .thenThrow(new IOException("rpc write failed")))) {

            assertThatThrownBy(() -> service.verifyAndSubmit(request))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Failed to send check-in transaction");
        }
    }

    @Test
    void verifyAndSubmit_rejectsMissingTxHashOrRpcError() throws Exception {
        CheckInRequest request = validRequest();
        CheckInResponse authResponse = new CheckInResponse();
        authResponse.setValid(true);
        authResponse.setSigner(credentials.getAddress());
        authResponse.setReservationKey("0xabc");
        authResponse.setTimestamp(1234L);

        when(checkInAuthService.verifyCheckIn(request)).thenReturn(authResponse);
        when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(credentials);
        when(walletService.getWeb3jInstance()).thenReturn(web3j);
        stubNonceChecks(BigInteger.ONE, BigInteger.ONE);
        stubChainId(1L);

        EthSendTransaction sendTransaction = mock(EthSendTransaction.class);
        when(sendTransaction.getTransactionHash()).thenReturn("0xtx123");
        when(sendTransaction.hasError()).thenReturn(true);
        org.web3j.protocol.core.Response.Error error = new org.web3j.protocol.core.Response.Error(1, "execution reverted");
        when(sendTransaction.getError()).thenReturn(error);

        try (MockedConstruction<FastRawTransactionManager> ignored =
                 mockConstruction(FastRawTransactionManager.class, (mock, context) ->
                     when(mock.sendTransaction(any(), any(), any(), any(), any())).thenReturn(sendTransaction))) {

            assertThatThrownBy(() -> service.verifyAndSubmit(request))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Check-in transaction failed: execution reverted");
        }
    }

    @Test
    void helpers_coverBytes32HashAndGweiConversions() {
        assertThat((BigInteger) ReflectionTestUtils.invokeMethod(service, "toWei", BigInteger.valueOf(2)))
            .isEqualTo(new BigInteger("2000000000"));
        assertThat((BigInteger) ReflectionTestUtils.invokeMethod(service, "toWei", new Object[] { null }))
            .isEqualTo(BigInteger.ZERO);

        String normalized = (String) ReflectionTestUtils.invokeMethod(service, "normalizeBytes32", "0xabc");
        assertThat(normalized).hasSize(66).endsWith("0abc");

        String zeroHash = (String) ReflectionTestUtils.invokeMethod(service, "computePucHash", " ");
        assertThat(zeroHash).isEqualTo("0x" + "0".repeat(64));

        String pucHash = (String) ReflectionTestUtils.invokeMethod(service, "computePucHash", "puc-123");
        assertThat(pucHash).isEqualTo(normalizeBytes32(Numeric.toHexString(Hash.sha3("puc-123".getBytes(StandardCharsets.UTF_8)))));

        assertThatCode(() -> ReflectionTestUtils.invokeMethod(service, "checkForPendingTransactions", web3j, credentials.getAddress()))
            .doesNotThrowAnyException();
    }

    private void stubNonceChecks(BigInteger pendingNonce, BigInteger latestNonce) throws Exception {
        @SuppressWarnings("unchecked")
        Request<?, EthGetTransactionCount> pendingRequest = (Request<?, EthGetTransactionCount>) mock(Request.class);
        @SuppressWarnings("unchecked")
        Request<?, EthGetTransactionCount> latestRequest = (Request<?, EthGetTransactionCount>) mock(Request.class);
        EthGetTransactionCount pendingResponse = mock(EthGetTransactionCount.class);
        EthGetTransactionCount latestResponse = mock(EthGetTransactionCount.class);

        when(web3j.ethGetTransactionCount(credentials.getAddress(), DefaultBlockParameterName.PENDING))
            .thenAnswer(invocation -> pendingRequest);
        when(web3j.ethGetTransactionCount(credentials.getAddress(), DefaultBlockParameterName.LATEST))
            .thenAnswer(invocation -> latestRequest);
        when(pendingRequest.send()).thenReturn(pendingResponse);
        when(latestRequest.send()).thenReturn(latestResponse);
        when(pendingResponse.getTransactionCount()).thenReturn(pendingNonce);
        when(latestResponse.getTransactionCount()).thenReturn(latestNonce);
    }

    private void stubChainId(long chainId) throws Exception {
        @SuppressWarnings("unchecked")
        Request<?, EthChainId> request = (Request<?, EthChainId>) mock(Request.class);
        EthChainId response = mock(EthChainId.class);
        when(web3j.ethChainId()).thenAnswer(invocation -> request);
        when(request.send()).thenReturn(response);
        when(response.getChainId()).thenReturn(BigInteger.valueOf(chainId));
    }

    private CheckInRequest validRequest() {
        CheckInRequest request = new CheckInRequest();
        request.setReservationKey("0xabc");
        request.setSigner(credentials.getAddress());
        request.setSignature("0xsig");
        request.setTimestamp(1234L);
        request.setPuc("puc-123");
        return request;
    }

    private BigInteger toWei(BigInteger gwei) {
        return org.web3j.utils.Convert.toWei(gwei.toString(), org.web3j.utils.Convert.Unit.GWEI).toBigInteger();
    }

    private static String normalizeBytes32(String value) {
        String clean = Numeric.cleanHexPrefix(value == null ? "" : value);
        if (clean.length() > 64) {
            clean = clean.substring(clean.length() - 64);
        }
        if (clean.length() < 64) {
            clean = "0".repeat(64 - clean.length()) + clean;
        }
        return "0x" + clean;
    }
}
