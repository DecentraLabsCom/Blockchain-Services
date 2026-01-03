package decentralabs.blockchain.service.treasury;

import decentralabs.blockchain.dto.treasury.InstitutionalAdminRequest;
import decentralabs.blockchain.dto.treasury.InstitutionalAdminRequest.AdminOperation;
import decentralabs.blockchain.dto.treasury.InstitutionalAdminResponse;
import decentralabs.blockchain.service.RateLimitService;
import decentralabs.blockchain.service.persistence.AntiReplayService;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
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
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("InstitutionalAdminService Tests")
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
    @Mock
    private Eip712TreasuryAdminVerifier adminVerifier;
    @Mock
    private AntiReplayService antiReplayService;

    private InstitutionalAdminService adminService;

    @BeforeEach
    void setUp() {
        adminService = new InstitutionalAdminService(
            web3j,
            httpServletRequest,
            rateLimitService,
            institutionalWalletService,
            analyticsService,
            adminVerifier,
            antiReplayService
        );
        ReflectionTestUtils.setField(adminService, "contractAddress", "0xABC");
        when(adminVerifier.verify(any(), any()))
            .thenReturn(new Eip712TreasuryAdminVerifier.VerificationResult(true, "0xabc", null));
        when(antiReplayService.isTimestampUsed(any(), anyLong())).thenReturn(false);
    }

    @Nested
    @DisplayName("Localhost Access Validation Tests")
    class LocalhostAccessValidationTests {

        @Test
        @DisplayName("Should reject requests from non-localhost IP")
        void executeAdminOperationRejectsNonLocalhostRequests() {
            when(httpServletRequest.getRemoteAddr()).thenReturn("10.0.0.5");

            InstitutionalAdminRequest request = buildRequest("0x123", AdminOperation.AUTHORIZE_BACKEND, null, null, null, null, null);
            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            assertThat(response.isSuccess()).isFalse();
            assertThat(response.getMessage()).contains("localhost");
        }

        @Test
        @DisplayName("Should allow requests from 127.0.0.1")
        void shouldAllowRequestsFrom127001() {
            when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn("0xABCDEF");

            InstitutionalAdminRequest request = buildRequest("0x123", AdminOperation.AUTHORIZE_BACKEND, null, null, null, null, null);
            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            // Should pass localhost check but fail wallet check
            assertThat(response.getMessage()).doesNotContain("only allowed from localhost");
        }

        @Test
        @DisplayName("Should allow requests from IPv6 localhost")
        void shouldAllowRequestsFromIpv6Localhost() {
            when(httpServletRequest.getRemoteAddr()).thenReturn("::1");
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn("0xABCDEF");

            InstitutionalAdminRequest request = buildRequest("0x123", AdminOperation.AUTHORIZE_BACKEND, null, null, null, null, null);
            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            // Should pass localhost check
            assertThat(response.getMessage()).doesNotContain("only allowed from localhost");
        }

        @Test
        @DisplayName("Should allow requests from 127.x.x.x range")
        void shouldAllowRequestsFrom127Range() {
            when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.2");
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn("0xABCDEF");

            InstitutionalAdminRequest request = buildRequest("0x123", AdminOperation.AUTHORIZE_BACKEND, null, null, null, null, null);
            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            assertThat(response.getMessage()).doesNotContain("only allowed from localhost");
        }

        @Test
        @DisplayName("Should reject requests from public IP")
        void shouldRejectRequestsFromPublicIp() {
            when(httpServletRequest.getRemoteAddr()).thenReturn("203.0.113.50");

            InstitutionalAdminRequest request = buildRequest("0x123", AdminOperation.AUTHORIZE_BACKEND, null, null, null, null, null);
            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            assertThat(response.isSuccess()).isFalse();
            assertThat(response.getMessage()).contains("localhost");
        }

        @Test
        @DisplayName("Should reject requests from private network IP")
        void shouldRejectRequestsFromPrivateNetworkIp() {
            when(httpServletRequest.getRemoteAddr()).thenReturn("192.168.1.100");

            InstitutionalAdminRequest request = buildRequest("0x123", AdminOperation.AUTHORIZE_BACKEND, null, null, null, null, null);
            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            assertThat(response.isSuccess()).isFalse();
            assertThat(response.getMessage()).contains("localhost");
        }

        @Test
        @DisplayName("Should allow private network with valid internal token when enabled")
        void shouldAllowPrivateNetworkWithTokenWhenEnabled() {
            ReflectionTestUtils.setField(adminService, "adminDashboardAllowPrivate", true);
            ReflectionTestUtils.setField(adminService, "allowPrivateNetworks", true);
            ReflectionTestUtils.setField(adminService, "internalToken", "test-token");
            ReflectionTestUtils.setField(adminService, "internalTokenHeader", "X-Internal-Token");
            ReflectionTestUtils.setField(adminService, "internalTokenRequired", true);

            when(httpServletRequest.getRemoteAddr()).thenReturn("10.0.0.5");
            when(httpServletRequest.getHeader("X-Internal-Token")).thenReturn("test-token");
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn("0xABCDEF");

            InstitutionalAdminRequest request = buildRequest("0x123", AdminOperation.AUTHORIZE_BACKEND, null, null, null, null, null);
            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            assertThat(response.getMessage()).doesNotContain("only allowed from localhost");
        }

        @Test
        @DisplayName("Should allow private network when token is not required")
        void shouldAllowPrivateNetworkWhenTokenNotRequired() {
            ReflectionTestUtils.setField(adminService, "adminDashboardAllowPrivate", true);
            ReflectionTestUtils.setField(adminService, "allowPrivateNetworks", true);
            ReflectionTestUtils.setField(adminService, "internalTokenRequired", false);

            when(httpServletRequest.getRemoteAddr()).thenReturn("10.0.0.5");
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn("0xABCDEF");

            InstitutionalAdminRequest request = buildRequest("0x123", AdminOperation.AUTHORIZE_BACKEND, null, null, null, null, null);
            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            assertThat(response.getMessage()).doesNotContain("only allowed from localhost");
        }
    }

    @Nested
    @DisplayName("Wallet Authorization Tests")
    class WalletAuthorizationTests {

        @Test
        @DisplayName("Should reject requests with unauthorized wallet")
        void executeAdminOperationRejectsUnauthorizedWallet() {
            when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn("0xABCDEF");

            InstitutionalAdminRequest request = buildRequest("0x123", AdminOperation.AUTHORIZE_BACKEND, null, null, null, null, null);
            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            assertThat(response.isSuccess()).isFalse();
            assertThat(response.getMessage()).contains("wallet address does not match");
        }

        @Test
        @DisplayName("Should reject requests with null wallet address")
        void shouldRejectRequestsWithNullWalletAddress() {
            when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");

            InstitutionalAdminRequest request = buildRequest(null, AdminOperation.AUTHORIZE_BACKEND, null, null, null, null, null);
            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            assertThat(response.isSuccess()).isFalse();
        }

        @Test
        @DisplayName("Should reject requests with empty wallet address")
        void shouldRejectRequestsWithEmptyWalletAddress() {
            when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");

            InstitutionalAdminRequest request = buildRequest("", AdminOperation.AUTHORIZE_BACKEND, null, null, null, null, null);
            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            assertThat(response.isSuccess()).isFalse();
        }

        @Test
        @DisplayName("Should reject when institutional wallet not configured")
        void shouldRejectWhenInstitutionalWalletNotConfigured() {
            when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(null);

            InstitutionalAdminRequest request = buildRequest("0x123", AdminOperation.AUTHORIZE_BACKEND, null, null, null, null, null);
            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            assertThat(response.isSuccess()).isFalse();
        }

        @Test
        @DisplayName("Should match wallet addresses case-insensitively")
        void shouldMatchWalletAddressesCaseInsensitively() {
            when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn("0xABCDEF1234567890ABCDEF1234567890ABCDEF12");
            when(institutionalWalletService.getInstitutionalCredentials()).thenThrow(new RuntimeException("Missing target"));

            // Request with different case
            InstitutionalAdminRequest request = buildRequest(
                "0xabcdef1234567890abcdef1234567890abcdef12",
                AdminOperation.AUTHORIZE_BACKEND, null,
                "0x1234567890123456789012345678901234567890",
                null, null, null
            );
            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            // Should pass wallet check (fail later due to missing credentials setup)
            assertThat(response.getMessage()).doesNotContain("wallet address does not match");
        }
    }

    @Nested
    @DisplayName("Operation Execution Tests")
    class OperationExecutionTests {

        @Test
        @SuppressWarnings({"unchecked", "rawtypes"})
        @DisplayName("Should execute AUTHORIZE_BACKEND operation successfully")
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

            InstitutionalAdminRequest request = buildRequest(
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

        @Test
        @DisplayName("Should reject when rate limit exceeded")
        void shouldRejectWhenRateLimitExceeded() {
            Credentials credentials = Credentials.create("0x1");
            when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(credentials.getAddress());
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(credentials);
            when(rateLimitService.allowTransaction(credentials.getAddress())).thenReturn(false);

            InstitutionalAdminRequest request = buildRequest(
                credentials.getAddress(),
                AdminOperation.AUTHORIZE_BACKEND,
                null,
                "0x1234567890123456789012345678901234567890",
                null,
                null,
                null
            );

            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            assertThat(response.isSuccess()).isFalse();
            assertThat(response.getMessage()).containsIgnoringCase("rate limit");
        }
    }

    @Nested
    @DisplayName("Response Structure Tests")
    class ResponseStructureTests {

        @Test
        @DisplayName("Error response should contain helpful message")
        void errorResponseShouldContainHelpfulMessage() {
            when(httpServletRequest.getRemoteAddr()).thenReturn("10.0.0.1");

            InstitutionalAdminRequest request = buildRequest("0x123", AdminOperation.AUTHORIZE_BACKEND, null, null, null, null, null);
            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            assertThat(response.isSuccess()).isFalse();
            assertThat(response.getMessage()).isNotEmpty();
            assertThat(response.getTransactionHash()).isNull();
        }
    }

    private InstitutionalAdminRequest buildRequest(
        String adminWalletAddress,
        AdminOperation operation,
        String providerAddress,
        String backendAddress,
        String spendingLimit,
        String spendingPeriod,
        String amount
    ) {
        InstitutionalAdminRequest request = new InstitutionalAdminRequest();
        request.setAdminWalletAddress(adminWalletAddress);
        request.setOperation(operation);
        request.setProviderAddress(providerAddress);
        request.setBackendAddress(backendAddress);
        request.setSpendingLimit(spendingLimit);
        request.setSpendingPeriod(spendingPeriod);
        request.setAmount(amount);
        request.setTimestamp(System.currentTimeMillis());
        request.setSignature("0x" + "11".repeat(65));
        return request;
    }
}
