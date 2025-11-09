package decentralabs.blockchain.service.treasury;

import decentralabs.blockchain.dto.treasury.InstitutionalAdminRequest;
import decentralabs.blockchain.dto.treasury.InstitutionalAdminRequest.AdminOperation;
import decentralabs.blockchain.dto.treasury.InstitutionalAdminResponse;
import decentralabs.blockchain.service.RateLimitService;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.Request;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.core.methods.response.EthSendTransaction;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class InstitutionalAdminServiceTest {

    @Mock
    private Web3j web3j;
    @Mock
    private HttpServletRequest httpServletRequest;
    @Mock
    private RateLimitService rateLimitService;
    @Mock
    private InstitutionalWalletService institutionalWalletService;
    @Mock
    private InstitutionalAnalyticsService analyticsService;

    private InstitutionalAdminService adminService;

    @BeforeEach
    void setUp() {
        adminService = new InstitutionalAdminService(web3j, httpServletRequest, rateLimitService, institutionalWalletService, analyticsService);
        ReflectionTestUtils.setField(adminService, "contractAddress", "0xABC");
    }

    @Test
    void executeAdminOperationRejectsNonLocalhostRequests() {
        when(httpServletRequest.getRemoteAddr()).thenReturn("10.0.0.5");
        when(httpServletRequest.getHeader("X-Forwarded-For")).thenReturn(null);

        InstitutionalAdminRequest request = new InstitutionalAdminRequest("0x123", AdminOperation.AUTHORIZE_BACKEND, null, null, null, null, null);
        InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

        assertThat(response.isSuccess()).isFalse();
        assertThat(response.getMessage()).contains("localhost");
    }

    @Test
    void executeAdminOperationRejectsUnauthorizedWallet() {
        when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn("0xABCDEF");

        InstitutionalAdminRequest request = new InstitutionalAdminRequest("0x123", AdminOperation.AUTHORIZE_BACKEND, null, null, null, null, null);
        InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

        assertThat(response.isSuccess()).isFalse();
        assertThat(response.getMessage()).contains("wallet address does not match");
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void authorizeBackendExecutesTransactionWhenValid() throws Exception {
        Credentials credentials = Credentials.create("0x1");
        when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(credentials.getAddress());
        when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(credentials);
        when(rateLimitService.allowTransaction(credentials.getAddress())).thenReturn(true);

        Request<?, EthGetTransactionCount> txCountRequest = (Request<?, EthGetTransactionCount>) mock(Request.class);
        EthGetTransactionCount txCountResponse = new EthGetTransactionCount();
        txCountResponse.setResult("0x1");
        when(txCountRequest.send()).thenReturn(txCountResponse);
        when(web3j.ethGetTransactionCount(eq(credentials.getAddress()), eq(DefaultBlockParameterName.LATEST))).thenReturn((Request) txCountRequest);

        Request<?, EthSendTransaction> sendRequest = (Request<?, EthSendTransaction>) mock(Request.class);
        EthSendTransaction sendResponse = new EthSendTransaction();
        sendResponse.setResult("0xabc");
        when(sendRequest.send()).thenReturn(sendResponse);
        when(web3j.ethSendRawTransaction(any())).thenReturn((Request) sendRequest);

        InstitutionalAdminRequest request = new InstitutionalAdminRequest(
            credentials.getAddress(),
            AdminOperation.AUTHORIZE_BACKEND,
            null,
            "0x1234567890123456789012345678901234567890",
            null,
            null,
            null
        );

        InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getTransactionHash()).isEqualTo("0xabc");
        assertThat(response.getOperationType()).isEqualTo("AUTHORIZE_BACKEND");
    }
}
