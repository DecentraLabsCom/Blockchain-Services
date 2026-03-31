package decentralabs.blockchain.service.billing;

import decentralabs.blockchain.dto.billing.InstitutionalAdminRequest;
import decentralabs.blockchain.dto.billing.InstitutionalAdminRequest.AdminOperation;
import decentralabs.blockchain.dto.billing.InstitutionalAdminResponse;
import decentralabs.blockchain.service.RateLimitService;
import decentralabs.blockchain.service.persistence.AntiReplayService;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
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
import org.web3j.protocol.core.methods.response.EthChainId;
import org.web3j.protocol.core.methods.response.EthEstimateGas;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.core.methods.response.EthSendTransaction;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
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
    private WalletService walletService;
    @Mock
    private InstitutionalAnalyticsService analyticsService;
    @Mock
    private Eip712BillingAdminVerifier adminVerifier;
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
            walletService,
            analyticsService,
            adminVerifier,
            antiReplayService
        );
        ReflectionTestUtils.setField(adminService, "contractAddress", "0xABC");
        ReflectionTestUtils.setField(adminService, "defaultCollectMaxBatch", 50);
        ReflectionTestUtils.setField(adminService, "defaultGasPriceGwei", java.math.BigInteger.valueOf(20));
        ReflectionTestUtils.setField(adminService, "defaultContractGasLimit", java.math.BigInteger.valueOf(300000));
        lenient().when(adminVerifier.verify(any(), any()))
            .thenReturn(new Eip712BillingAdminVerifier.VerificationResult(true, "0xabc", null));
        lenient().when(antiReplayService.isTimestampUsed(any(), anyLong())).thenReturn(false);
        lenient().when(walletService.isInstitution(any())).thenReturn(true);
        lenient().when(walletService.isDefaultAdmin(any())).thenReturn(true);
        lenient().when(walletService.isLabProvider(any())).thenReturn(true);
        lenient().when(walletService.isLabOwnedByProvider(any(), any())).thenReturn(true);
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
        @DisplayName("Should allow private network with valid access token when enabled")
        void shouldAllowPrivateNetworkWithTokenWhenEnabled() {
            ReflectionTestUtils.setField(adminService, "adminDashboardAllowPrivate", true);
            ReflectionTestUtils.setField(adminService, "allowPrivateNetworks", true);
            ReflectionTestUtils.setField(adminService, "accessToken", "test-token");
            ReflectionTestUtils.setField(adminService, "accessTokenHeader", "X-Access-Token");
            ReflectionTestUtils.setField(adminService, "accessTokenRequired", true);

            when(httpServletRequest.getRemoteAddr()).thenReturn("10.0.0.5");
            when(httpServletRequest.getHeader("X-Access-Token")).thenReturn("test-token");
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
            ReflectionTestUtils.setField(adminService, "accessTokenRequired", false);

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

            Request<?, EthChainId> chainIdRequest = (Request<?, EthChainId>) mock(Request.class);
            EthChainId chainIdResponse = new EthChainId();
            chainIdResponse.setResult("0xaa36a7"); // Sepolia
            when(chainIdRequest.send()).thenReturn(chainIdResponse);
            when(web3j.ethChainId()).thenReturn((Request) chainIdRequest);

            Request<?, EthEstimateGas> estimateRequest = (Request<?, EthEstimateGas>) mock(Request.class);
            EthEstimateGas estimateResponse = new EthEstimateGas();
            estimateResponse.setResult("0x5208");
            when(estimateRequest.send()).thenReturn(estimateResponse);
            when(web3j.ethEstimateGas(any(org.web3j.protocol.core.methods.request.Transaction.class)))
                .thenReturn((Request) estimateRequest);

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

        @Test
        @SuppressWarnings({"unchecked", "rawtypes"})
        @DisplayName("Should execute COLLECT_LAB_PAYOUT operation successfully")
        void requestProviderPayoutExecutesTransactionWhenValid() throws Exception {
            Credentials credentials = Credentials.create("0x1");
            when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(credentials.getAddress());
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(credentials);
            when(rateLimitService.allowTransaction(credentials.getAddress())).thenReturn(true);
            mockSuccessfulTransaction(credentials, "0xcollect");

            InstitutionalAdminRequest request = buildRequest(
                credentials.getAddress(),
                AdminOperation.COLLECT_LAB_PAYOUT,
                null,
                null,
                null,
                null,
                null
            );
            request.setLabId("3");
            request.setMaxBatch("50");

            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getTransactionHash()).isEqualTo("0xcollect");
            assertThat(response.getOperationType()).isEqualTo("COLLECT_LAB_PAYOUT");
        }

        @Test
        @DisplayName("Should reject COLLECT_LAB_PAYOUT when labId is missing")
        void requestProviderPayoutRejectsMissingLabId() {
            Credentials credentials = Credentials.create("0x1");
            when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(credentials.getAddress());
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(credentials);

            InstitutionalAdminRequest request = buildRequest(
                credentials.getAddress(),
                AdminOperation.COLLECT_LAB_PAYOUT,
                null,
                null,
                null,
                null,
                null
            );
            request.setLabId(null);
            request.setMaxBatch("50");

            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            assertThat(response.isSuccess()).isFalse();
            assertThat(response.getMessage()).contains("Lab ID required");
        }

        @Test
        @DisplayName("Should reject COLLECT_LAB_PAYOUT when labId is invalid")
        void requestProviderPayoutRejectsInvalidLabId() {
            Credentials credentials = Credentials.create("0x1");
            when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(credentials.getAddress());
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(credentials);

            InstitutionalAdminRequest request = buildRequest(
                credentials.getAddress(),
                AdminOperation.COLLECT_LAB_PAYOUT,
                null,
                null,
                null,
                null,
                null
            );
            request.setLabId("-1");
            request.setMaxBatch("50");

            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            assertThat(response.isSuccess()).isFalse();
            assertThat(response.getMessage()).contains("Lab ID must be greater than zero");
        }

        @Test
        @DisplayName("Should reject COLLECT_LAB_PAYOUT when maxBatch is out of range")
        void requestProviderPayoutRejectsOutOfRangeBatch() {
            Credentials credentials = Credentials.create("0x1");
            when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(credentials.getAddress());
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(credentials);

            InstitutionalAdminRequest zeroBatch = buildRequest(
                credentials.getAddress(),
                AdminOperation.COLLECT_LAB_PAYOUT,
                null,
                null,
                null,
                null,
                null
            );
            zeroBatch.setLabId("3");
            zeroBatch.setMaxBatch("0");

            InstitutionalAdminResponse zeroBatchResponse = adminService.executeAdminOperation(zeroBatch);
            assertThat(zeroBatchResponse.isSuccess()).isFalse();
            assertThat(zeroBatchResponse.getMessage()).contains("maxBatch must be between 1 and 100");

            InstitutionalAdminRequest overBatch = buildRequest(
                credentials.getAddress(),
                AdminOperation.COLLECT_LAB_PAYOUT,
                null,
                null,
                null,
                null,
                null
            );
            overBatch.setLabId("3");
            overBatch.setMaxBatch("101");

            InstitutionalAdminResponse overBatchResponse = adminService.executeAdminOperation(overBatch);
            assertThat(overBatchResponse.isSuccess()).isFalse();
            assertThat(overBatchResponse.getMessage()).contains("maxBatch must be between 1 and 100");
        }

        @Test
        @SuppressWarnings({"unchecked", "rawtypes"})
        @DisplayName("Should execute ISSUE_SERVICE_CREDITS operation successfully")
        void issueServiceCreditsExecutesTransactionWhenValid() throws Exception {
            Credentials credentials = Credentials.create("0x1");
            when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(credentials.getAddress());
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(credentials);
            when(rateLimitService.allowTransaction(credentials.getAddress())).thenReturn(true);
            mockSuccessfulTransaction(credentials, "0xissue");

            InstitutionalAdminRequest request = buildRequest(
                credentials.getAddress(),
                AdminOperation.ISSUE_SERVICE_CREDITS,
                null,
                null,
                null,
                null,
                "1250000"
            );
            request.setCreditAccount("0x1234567890123456789012345678901234567890");
            request.setReference("invoice-2026-03-20");

            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getTransactionHash()).isEqualTo("0xissue");
            assertThat(response.getOperationType()).isEqualTo("ISSUE_SERVICE_CREDITS");
        }

        @Test
        @DisplayName("Should reject ISSUE_SERVICE_CREDITS when creditAccount is missing")
        void issueServiceCreditsRejectsMissingCreditAccount() {
            Credentials credentials = Credentials.create("0x1");
            when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(credentials.getAddress());
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(credentials);

            InstitutionalAdminRequest request = buildRequest(
                credentials.getAddress(),
                AdminOperation.ISSUE_SERVICE_CREDITS,
                null,
                null,
                null,
                null,
                "1000000"
            );

            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            assertThat(response.isSuccess()).isFalse();
            assertThat(response.getMessage()).contains("Credit account required");
        }

        @Test
        @DisplayName("Should reject ISSUE_SERVICE_CREDITS when amount is zero")
        void issueServiceCreditsRejectsZeroAmount() {
            Credentials credentials = Credentials.create("0x1");
            when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(credentials.getAddress());
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(credentials);

            InstitutionalAdminRequest request = buildRequest(
                credentials.getAddress(),
                AdminOperation.ISSUE_SERVICE_CREDITS,
                null,
                null,
                null,
                null,
                "0"
            );
            request.setCreditAccount("0x1234567890123456789012345678901234567890");

            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            assertThat(response.isSuccess()).isFalse();
            assertThat(response.getMessage()).contains("Amount must be greater than zero");
        }

        @Test
        @SuppressWarnings({"unchecked", "rawtypes"})
        @DisplayName("Should execute ADJUST_SERVICE_CREDITS operation successfully")
        void adjustServiceCreditsExecutesTransactionWhenValid() throws Exception {
            Credentials credentials = Credentials.create("0x1");
            when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(credentials.getAddress());
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(credentials);
            when(rateLimitService.allowTransaction(credentials.getAddress())).thenReturn(true);
            mockSuccessfulTransaction(credentials, "0xadjust");

            InstitutionalAdminRequest request = buildRequest(
                credentials.getAddress(),
                AdminOperation.ADJUST_SERVICE_CREDITS,
                null,
                null,
                null,
                null,
                null
            );
            request.setCreditAccount("0x1234567890123456789012345678901234567890");
            request.setCreditDelta("-250000");
            request.setReference("manual-writeoff");

            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getTransactionHash()).isEqualTo("0xadjust");
            assertThat(response.getOperationType()).isEqualTo("ADJUST_SERVICE_CREDITS");
        }

        @Test
        @SuppressWarnings({"unchecked", "rawtypes"})
        @DisplayName("Should execute TRANSITION_PROVIDER_RECEIVABLE_STATE operation successfully")
        void transitionProviderReceivableStateExecutesTransactionWhenValid() throws Exception {
            Credentials credentials = Credentials.create("0x1");
            when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(credentials.getAddress());
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(credentials);
            when(rateLimitService.allowTransaction(credentials.getAddress())).thenReturn(true);
            mockSuccessfulTransaction(credentials, "0xtransition");

            InstitutionalAdminRequest request = buildRequest(
                credentials.getAddress(),
                AdminOperation.TRANSITION_PROVIDER_RECEIVABLE_STATE,
                null,
                null,
                null,
                null,
                "1250000"
            );
            request.setLabId("7");
            request.setFromReceivableState("2");
            request.setToReceivableState("3");
            request.setReference("invoice-2026-03-21");

            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getTransactionHash()).isEqualTo("0xtransition");
            assertThat(response.getOperationType()).isEqualTo("TRANSITION_PROVIDER_RECEIVABLE_STATE");
        }

        @Test
        @DisplayName("Should reject TRANSITION_PROVIDER_RECEIVABLE_STATE when lifecycle state is invalid")
        void transitionProviderReceivableStateRejectsInvalidState() {
            Credentials credentials = Credentials.create("0x1");
            when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(credentials.getAddress());
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(credentials);

            InstitutionalAdminRequest request = buildRequest(
                credentials.getAddress(),
                AdminOperation.TRANSITION_PROVIDER_RECEIVABLE_STATE,
                null,
                null,
                null,
                null,
                "1250000"
            );
            request.setLabId("7");
            request.setFromReceivableState("0");
            request.setToReceivableState("3");

            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            assertThat(response.isSuccess()).isFalse();
            assertThat(response.getMessage()).contains("Invalid provider receivable lifecycle state");
        }

        @Test
        @DisplayName("Should reject TRANSITION_PROVIDER_RECEIVABLE_STATE when transition is not allowed")
        void transitionProviderReceivableStateRejectsInvalidTransition() {
            Credentials credentials = Credentials.create("0x1");
            when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(credentials.getAddress());
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(credentials);

            InstitutionalAdminRequest request = buildRequest(
                credentials.getAddress(),
                AdminOperation.TRANSITION_PROVIDER_RECEIVABLE_STATE,
                null,
                null,
                null,
                null,
                "1250000"
            );
            request.setLabId("7");
            request.setFromReceivableState("2");
            request.setToReceivableState("5");

            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            assertThat(response.isSuccess()).isFalse();
            assertThat(response.getMessage()).contains("Invalid provider receivable lifecycle transition");
        }

        @Test
        @DisplayName("Should reject TRANSITION_PROVIDER_RECEIVABLE_STATE when amount is zero")
        void transitionProviderReceivableStateRejectsZeroAmount() {
            Credentials credentials = Credentials.create("0x1");
            when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(credentials.getAddress());
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(credentials);

            InstitutionalAdminRequest request = buildRequest(
                credentials.getAddress(),
                AdminOperation.TRANSITION_PROVIDER_RECEIVABLE_STATE,
                null,
                null,
                null,
                null,
                "0"
            );
            request.setLabId("7");
            request.setFromReceivableState("2");
            request.setToReceivableState("3");

            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            assertThat(response.isSuccess()).isFalse();
            assertThat(response.getMessage()).contains("Amount must be greater than zero");
        }

        @Test
        @DisplayName("Should reject ADJUST_SERVICE_CREDITS when creditDelta is missing")
        void adjustServiceCreditsRejectsMissingDelta() {
            Credentials credentials = Credentials.create("0x1");
            when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(credentials.getAddress());
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(credentials);

            InstitutionalAdminRequest request = buildRequest(
                credentials.getAddress(),
                AdminOperation.ADJUST_SERVICE_CREDITS,
                null,
                null,
                null,
                null,
                null
            );
            request.setCreditAccount("0x1234567890123456789012345678901234567890");

            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            assertThat(response.isSuccess()).isFalse();
            assertThat(response.getMessage()).contains("creditDelta required");
        }

        @Test
        @DisplayName("Should reject ADJUST_SERVICE_CREDITS when creditDelta is zero")
        void adjustServiceCreditsRejectsZeroDelta() {
            Credentials credentials = Credentials.create("0x1");
            when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(credentials.getAddress());
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(credentials);

            InstitutionalAdminRequest request = buildRequest(
                credentials.getAddress(),
                AdminOperation.ADJUST_SERVICE_CREDITS,
                null,
                null,
                null,
                null,
                null
            );
            request.setCreditAccount("0x1234567890123456789012345678901234567890");
            request.setCreditDelta("0");

            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            assertThat(response.isSuccess()).isFalse();
            assertThat(response.getMessage()).contains("creditDelta must not be zero");
        }

        @Test
        @SuppressWarnings({"unchecked", "rawtypes"})
        @DisplayName("Should execute SET_USER_LIMIT operation successfully")
        void setUserLimitExecutesTransactionWhenValid() throws Exception {
            Credentials credentials = Credentials.create("0x1");
            when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(credentials.getAddress());
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(credentials);
            when(rateLimitService.allowTransaction(credentials.getAddress())).thenReturn(true);
            mockSuccessfulTransaction(credentials, "0xlimit");

            InstitutionalAdminRequest request = buildRequest(
                credentials.getAddress(),
                AdminOperation.SET_USER_LIMIT,
                null, null,
                "5000000",
                null, null
            );

            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getTransactionHash()).isEqualTo("0xlimit");
            assertThat(response.getOperationType()).isEqualTo("SET_USER_LIMIT");
        }

        @Test
        @DisplayName("Should reject SET_USER_LIMIT when spendingLimit is missing")
        void setUserLimitRejectsMissingLimit() {
            Credentials credentials = Credentials.create("0x1");
            when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(credentials.getAddress());
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(credentials);

            InstitutionalAdminRequest request = buildRequest(
                credentials.getAddress(),
                AdminOperation.SET_USER_LIMIT,
                null, null, null, null, null
            );

            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            assertThat(response.isSuccess()).isFalse();
            assertThat(response.getMessage()).contains("Spending limit required");
        }

        @Test
        @SuppressWarnings({"unchecked", "rawtypes"})
        @DisplayName("Should execute SET_SPENDING_PERIOD operation successfully")
        void setSpendingPeriodExecutesTransactionWhenValid() throws Exception {
            Credentials credentials = Credentials.create("0x1");
            when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(credentials.getAddress());
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(credentials);
            when(rateLimitService.allowTransaction(credentials.getAddress())).thenReturn(true);
            mockSuccessfulTransaction(credentials, "0xperiod");

            InstitutionalAdminRequest request = buildRequest(
                credentials.getAddress(),
                AdminOperation.SET_SPENDING_PERIOD,
                null, null, null,
                "2592000",
                null
            );

            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getTransactionHash()).isEqualTo("0xperiod");
            assertThat(response.getOperationType()).isEqualTo("SET_SPENDING_PERIOD");
        }

        @Test
        @DisplayName("Should reject SET_SPENDING_PERIOD when spendingPeriod is missing")
        void setSpendingPeriodRejectsMissingPeriod() {
            Credentials credentials = Credentials.create("0x1");
            when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(credentials.getAddress());
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(credentials);

            InstitutionalAdminRequest request = buildRequest(
                credentials.getAddress(),
                AdminOperation.SET_SPENDING_PERIOD,
                null, null, null, null, null
            );

            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            assertThat(response.isSuccess()).isFalse();
            assertThat(response.getMessage()).contains("Spending period required");
        }

        @Test
        @SuppressWarnings({"unchecked", "rawtypes"})
        @DisplayName("Should execute RESET_SPENDING_PERIOD operation successfully")
        void resetSpendingPeriodExecutesTransactionWhenValid() throws Exception {
            Credentials credentials = Credentials.create("0x1");
            when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(credentials.getAddress());
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(credentials);
            when(rateLimitService.allowTransaction(credentials.getAddress())).thenReturn(true);
            mockSuccessfulTransaction(credentials, "0xresetperiod");

            InstitutionalAdminRequest request = buildRequest(
                credentials.getAddress(),
                AdminOperation.RESET_SPENDING_PERIOD,
                null, null, null, null, null
            );

            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getTransactionHash()).isEqualTo("0xresetperiod");
            assertThat(response.getOperationType()).isEqualTo("RESET_SPENDING_PERIOD");
        }

        @Test
        @SuppressWarnings({"unchecked", "rawtypes"})
        @DisplayName("Should execute REVOKE_BACKEND operation successfully")
        void revokeBackendExecutesTransactionWhenValid() throws Exception {
            Credentials credentials = Credentials.create("0x1");
            when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(credentials.getAddress());
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(credentials);
            when(rateLimitService.allowTransaction(credentials.getAddress())).thenReturn(true);
            mockSuccessfulTransaction(credentials, "0xrevoke");

            InstitutionalAdminRequest request = buildRequest(
                credentials.getAddress(),
                AdminOperation.REVOKE_BACKEND,
                null, null, null, null, null
            );

            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getTransactionHash()).isEqualTo("0xrevoke");
            assertThat(response.getOperationType()).isEqualTo("REVOKE_BACKEND");
        }

        @Test
        @SuppressWarnings({"unchecked", "rawtypes"})
        @DisplayName("Should execute ADMIN_RESET_BACKEND operation successfully")
        void adminResetBackendExecutesTransactionWhenValid() throws Exception {
            Credentials credentials = Credentials.create("0x1");
            when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(credentials.getAddress());
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(credentials);
            when(rateLimitService.allowTransaction(credentials.getAddress())).thenReturn(true);
            mockSuccessfulTransaction(credentials, "0xreset");

            InstitutionalAdminRequest request = buildRequest(
                credentials.getAddress(),
                AdminOperation.ADMIN_RESET_BACKEND,
                "0x7777777777777777777777777777777777777777",
                "0x8888888888888888888888888888888888888888",
                null, null, null
            );

            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getTransactionHash()).isEqualTo("0xreset");
            assertThat(response.getOperationType()).isEqualTo("ADMIN_RESET_BACKEND");
        }

        @Test
        @DisplayName("Should reject ADMIN_RESET_BACKEND when providerAddress is missing")
        void adminResetBackendRejectsMissingProviderAddress() {
            Credentials credentials = Credentials.create("0x1");
            when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(credentials.getAddress());
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(credentials);

            InstitutionalAdminRequest request = buildRequest(
                credentials.getAddress(),
                AdminOperation.ADMIN_RESET_BACKEND,
                null, null, null, null, null
            );

            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            assertThat(response.isSuccess()).isFalse();
            assertThat(response.getMessage()).contains("Provider address required for admin reset");
        }
    }

    @Nested
    @DisplayName("Receivable Lifecycle State Machine Tests")
    class ReceivableLifecycleStateMachineTests {

        private Credentials credentials;

        @BeforeEach
        void setUpCredentials() {
            credentials = Credentials.create("0x1");
            when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(credentials.getAddress());
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(credentials);
        }

        private void mockForSuccess() throws Exception {
            lenient().when(rateLimitService.allowTransaction(credentials.getAddress())).thenReturn(true);
            mockSuccessfulTransaction(credentials, "0xlifecycle");
        }

        private InstitutionalAdminResponse transitionState(String from, String to) {
            InstitutionalAdminRequest request = buildRequest(
                credentials.getAddress(),
                AdminOperation.TRANSITION_PROVIDER_RECEIVABLE_STATE,
                null, null, null, null, "1000000"
            );
            request.setLabId("1");
            request.setFromReceivableState(from);
            request.setToReceivableState(to);
            request.setReference("test-ref");
            return adminService.executeAdminOperation(request);
        }

        // ---- ACCRUED (1) valid transitions ----
        @Test
        @SuppressWarnings({"unchecked", "rawtypes"})
        @DisplayName("ACCRUED → QUEUED is valid")
        void accruedToQueuedIsValid() throws Exception {
            mockForSuccess();
            assertThat(transitionState("1", "2").isSuccess()).isTrue();
        }

        @Test
        @SuppressWarnings({"unchecked", "rawtypes"})
        @DisplayName("ACCRUED → DISPUTED is valid")
        void accruedToDisputedIsValid() throws Exception {
            mockForSuccess();
            assertThat(transitionState("1", "7").isSuccess()).isTrue();
        }

        @Test
        @SuppressWarnings({"unchecked", "rawtypes"})
        @DisplayName("ACCRUED → REVERSED is valid")
        void accruedToReversedIsValid() throws Exception {
            mockForSuccess();
            assertThat(transitionState("1", "6").isSuccess()).isTrue();
        }

        @Test
        @DisplayName("ACCRUED → INVOICED is forbidden")
        void accruedToInvoicedIsForbidden() {
            InstitutionalAdminResponse resp = transitionState("1", "3");
            assertThat(resp.isSuccess()).isFalse();
            assertThat(resp.getMessage()).contains("Invalid provider receivable lifecycle transition");
        }

        @Test
        @DisplayName("ACCRUED → PAID is forbidden")
        void accruedToPaidIsForbidden() {
            assertThat(transitionState("1", "5").isSuccess()).isFalse();
        }

        // ---- QUEUED (2) valid transitions ----
        @Test
        @SuppressWarnings({"unchecked", "rawtypes"})
        @DisplayName("QUEUED → INVOICED is valid")
        void queuedToInvoicedIsValid() throws Exception {
            mockForSuccess();
            assertThat(transitionState("2", "3").isSuccess()).isTrue();
        }

        @Test
        @SuppressWarnings({"unchecked", "rawtypes"})
        @DisplayName("QUEUED → APPROVED is valid (fast-track)")
        void queuedToApprovedIsValid() throws Exception {
            mockForSuccess();
            assertThat(transitionState("2", "4").isSuccess()).isTrue();
        }

        @Test
        @SuppressWarnings({"unchecked", "rawtypes"})
        @DisplayName("QUEUED → DISPUTED is valid")
        void queuedToDisputedIsValid() throws Exception {
            mockForSuccess();
            assertThat(transitionState("2", "7").isSuccess()).isTrue();
        }

        @Test
        @SuppressWarnings({"unchecked", "rawtypes"})
        @DisplayName("QUEUED → REVERSED is valid")
        void queuedToReversedIsValid() throws Exception {
            mockForSuccess();
            assertThat(transitionState("2", "6").isSuccess()).isTrue();
        }

        @Test
        @DisplayName("QUEUED → PAID is forbidden")
        void queuedToPaidIsForbidden() {
            assertThat(transitionState("2", "5").isSuccess()).isFalse();
        }

        // ---- INVOICED (3) valid transitions ----
        @Test
        @SuppressWarnings({"unchecked", "rawtypes"})
        @DisplayName("INVOICED → APPROVED is valid")
        void invoicedToApprovedIsValid() throws Exception {
            mockForSuccess();
            assertThat(transitionState("3", "4").isSuccess()).isTrue();
        }

        @Test
        @SuppressWarnings({"unchecked", "rawtypes"})
        @DisplayName("INVOICED → DISPUTED is valid")
        void invoicedToDisputedIsValid() throws Exception {
            mockForSuccess();
            assertThat(transitionState("3", "7").isSuccess()).isTrue();
        }

        @Test
        @SuppressWarnings({"unchecked", "rawtypes"})
        @DisplayName("INVOICED → REVERSED is valid")
        void invoicedToReversedIsValid() throws Exception {
            mockForSuccess();
            assertThat(transitionState("3", "6").isSuccess()).isTrue();
        }

        @Test
        @DisplayName("INVOICED → PAID is forbidden")
        void invoicedToPaidIsForbidden() {
            assertThat(transitionState("3", "5").isSuccess()).isFalse();
        }

        // ---- APPROVED (4) valid transitions ----
        @Test
        @SuppressWarnings({"unchecked", "rawtypes"})
        @DisplayName("APPROVED → PAID is valid")
        void approvedToPaidIsValid() throws Exception {
            mockForSuccess();
            assertThat(transitionState("4", "5").isSuccess()).isTrue();
        }

        @Test
        @SuppressWarnings({"unchecked", "rawtypes"})
        @DisplayName("APPROVED → DISPUTED is valid")
        void approvedToDisputedIsValid() throws Exception {
            mockForSuccess();
            assertThat(transitionState("4", "7").isSuccess()).isTrue();
        }

        @Test
        @SuppressWarnings({"unchecked", "rawtypes"})
        @DisplayName("APPROVED → REVERSED is valid")
        void approvedToReversedIsValid() throws Exception {
            mockForSuccess();
            assertThat(transitionState("4", "6").isSuccess()).isTrue();
        }

        // ---- DISPUTED (7) valid transitions ----
        @Test
        @SuppressWarnings({"unchecked", "rawtypes"})
        @DisplayName("DISPUTED → INVOICED is valid (re-invoice)")
        void disputedToInvoicedIsValid() throws Exception {
            mockForSuccess();
            assertThat(transitionState("7", "3").isSuccess()).isTrue();
        }

        @Test
        @SuppressWarnings({"unchecked", "rawtypes"})
        @DisplayName("DISPUTED → APPROVED is valid (resolve)")
        void disputedToApprovedIsValid() throws Exception {
            mockForSuccess();
            assertThat(transitionState("7", "4").isSuccess()).isTrue();
        }

        @Test
        @SuppressWarnings({"unchecked", "rawtypes"})
        @DisplayName("DISPUTED → REVERSED is valid (cancel)")
        void disputedToReversedIsValid() throws Exception {
            mockForSuccess();
            assertThat(transitionState("7", "6").isSuccess()).isTrue();
        }

        @Test
        @DisplayName("DISPUTED → PAID is forbidden")
        void disputedToPaidIsForbidden() {
            assertThat(transitionState("7", "5").isSuccess()).isFalse();
        }

        // ---- Terminal states ----
        @Test
        @DisplayName("PAID → any is forbidden (terminal state)")
        void paidIsTerminalState() {
            assertThat(transitionState("5", "1").isSuccess()).isFalse();
            assertThat(transitionState("5", "6").isSuccess()).isFalse();
            assertThat(transitionState("5", "7").isSuccess()).isFalse();
        }

        @Test
        @DisplayName("REVERSED → any is forbidden (terminal state)")
        void reversedIsTerminalState() {
            assertThat(transitionState("6", "1").isSuccess()).isFalse();
            assertThat(transitionState("6", "3").isSuccess()).isFalse();
            assertThat(transitionState("6", "7").isSuccess()).isFalse();
        }

        // ---- Field validation ----
        @Test
        @DisplayName("Should reject transition when labId is missing")
        void transitionRejectsMissingLabId() {
            InstitutionalAdminRequest request = buildRequest(
                credentials.getAddress(),
                AdminOperation.TRANSITION_PROVIDER_RECEIVABLE_STATE,
                null, null, null, null, "1000000"
            );
            request.setFromReceivableState("1");
            request.setToReceivableState("2");

            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);
            assertThat(response.isSuccess()).isFalse();
            assertThat(response.getMessage()).contains("Lab ID required for provider receivable transition");
        }

        @Test
        @DisplayName("Should reject transition when fromReceivableState is missing")
        void transitionRejectsMissingFromState() {
            InstitutionalAdminRequest request = buildRequest(
                credentials.getAddress(),
                AdminOperation.TRANSITION_PROVIDER_RECEIVABLE_STATE,
                null, null, null, null, "1000000"
            );
            request.setLabId("1");
            request.setToReceivableState("2");

            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);
            assertThat(response.isSuccess()).isFalse();
            assertThat(response.getMessage()).contains("fromReceivableState required for provider receivable transition");
        }

        @Test
        @DisplayName("Should reject transition when toReceivableState is missing")
        void transitionRejectsMissingToState() {
            InstitutionalAdminRequest request = buildRequest(
                credentials.getAddress(),
                AdminOperation.TRANSITION_PROVIDER_RECEIVABLE_STATE,
                null, null, null, null, "1000000"
            );
            request.setLabId("1");
            request.setFromReceivableState("1");

            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);
            assertThat(response.isSuccess()).isFalse();
            assertThat(response.getMessage()).contains("toReceivableState required for provider receivable transition");
        }

        @Test
        @DisplayName("Should reject unknown state value (state 0)")
        void transitionRejectsStateZero() {
            assertThat(transitionState("0", "1").isSuccess()).isFalse();
            assertThat(transitionState("0", "1").getMessage()).contains("Invalid provider receivable lifecycle state");
        }

        @Test
        @DisplayName("Should reject unknown state value (state 8+)")
        void transitionRejectsStateOutOfRange() {
            assertThat(transitionState("1", "8").isSuccess()).isFalse();
            assertThat(transitionState("8", "1").isSuccess()).isFalse();
        }
    }

    @Nested
    @DisplayName("Security Guard Tests")
    class SecurityGuardTests {

        @Test
        @DisplayName("Should reject when EIP-712 signature verification fails")
        void shouldRejectWhenSignatureVerificationFails() {
            Credentials credentials = Credentials.create("0x1");
            when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(credentials.getAddress());
            when(adminVerifier.verify(any(), any()))
                .thenReturn(new Eip712BillingAdminVerifier.VerificationResult(false, null, "signature_mismatch"));

            InstitutionalAdminRequest request = buildRequest(
                credentials.getAddress(),
                AdminOperation.AUTHORIZE_BACKEND,
                null,
                "0x1234567890123456789012345678901234567890",
                null, null, null
            );

            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            assertThat(response.isSuccess()).isFalse();
            assertThat(response.getMessage()).contains("Invalid admin signature");
        }

        @Test
        @DisplayName("Should reject when timestamp replay is detected")
        void shouldRejectWhenTimestampReplayDetected() {
            Credentials credentials = Credentials.create("0x1");
            when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(credentials.getAddress());
            when(antiReplayService.isTimestampUsed(any(), anyLong())).thenReturn(true);

            InstitutionalAdminRequest request = buildRequest(
                credentials.getAddress(),
                AdminOperation.AUTHORIZE_BACKEND,
                null,
                "0x1234567890123456789012345678901234567890",
                null, null, null
            );

            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);

            assertThat(response.isSuccess()).isFalse();
            assertThat(response.getMessage()).contains("Replay detected for admin signature");
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
        request.setLabId(null);
        request.setMaxBatch(null);
        request.setTimestamp(System.currentTimeMillis());
        request.setSignature("0x" + "11".repeat(65));
        return request;
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private void mockSuccessfulTransaction(Credentials credentials, String txHash) throws Exception {
        Request<?, EthGetTransactionCount> txCountRequest = (Request<?, EthGetTransactionCount>) mock(Request.class);
        EthGetTransactionCount txCountResponse = new EthGetTransactionCount();
        txCountResponse.setResult("0x1");
        when(txCountRequest.send()).thenReturn(txCountResponse);
        when(web3j.ethGetTransactionCount(eq(credentials.getAddress()), eq(DefaultBlockParameterName.LATEST)))
            .thenReturn((Request) txCountRequest);

        Request<?, EthChainId> chainIdRequest = (Request<?, EthChainId>) mock(Request.class);
        EthChainId chainIdResponse = new EthChainId();
        chainIdResponse.setResult("0xaa36a7");
        when(chainIdRequest.send()).thenReturn(chainIdResponse);
        when(web3j.ethChainId()).thenReturn((Request) chainIdRequest);

        Request<?, EthEstimateGas> estimateRequest = (Request<?, EthEstimateGas>) mock(Request.class);
        EthEstimateGas estimateResponse = new EthEstimateGas();
        estimateResponse.setResult("0x5208");
        when(estimateRequest.send()).thenReturn(estimateResponse);
        when(web3j.ethEstimateGas(any(org.web3j.protocol.core.methods.request.Transaction.class)))
            .thenReturn((Request) estimateRequest);

        Request<?, EthSendTransaction> sendRequest = (Request<?, EthSendTransaction>) mock(Request.class);
        EthSendTransaction sendResponse = new EthSendTransaction();
        sendResponse.setResult(txHash);
        when(sendRequest.send()).thenReturn(sendResponse);
        when(web3j.ethSendRawTransaction(any())).thenReturn((Request) sendRequest);
    }
}
