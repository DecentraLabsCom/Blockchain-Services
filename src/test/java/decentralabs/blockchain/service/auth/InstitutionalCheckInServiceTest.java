package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.dto.auth.CheckInRequest;
import decentralabs.blockchain.dto.auth.CheckInResponse;
import decentralabs.blockchain.dto.auth.InstitutionalCheckInRequest;
import decentralabs.blockchain.service.wallet.BlockchainBookingService;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Hash;
import org.web3j.utils.Numeric;

@ExtendWith(MockitoExtension.class)
class InstitutionalCheckInServiceTest {

    @Mock
    private SamlValidationService samlValidationService;

    @Mock
    private MarketplaceEndpointAuthService marketplaceEndpointAuthService;

    @Mock
    private BlockchainBookingService bookingService;

    @Mock
    private InstitutionalWalletService institutionalWalletService;

    @Mock
    private WalletService walletService;

    @Mock
    private Eip712CheckInVerifier checkInVerifier;

    @Mock
    private CheckInOnChainService checkInOnChainService;

    @Mock
    private InstitutionalCheckInDirectoryService directoryService;

    @Mock
    private RemoteInstitutionalCheckInClient remoteCheckInClient;

    @Mock
    private InstitutionalCheckInOutboxService outboxService;

    @Mock
    private InstitutionalWalletNonceDispatcher nonceDispatcher;

    @InjectMocks
    private InstitutionalCheckInService service;

    private Credentials credentials;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(service, "contractAddress", "0x2222222222222222222222222222222222222222");
        ReflectionTestUtils.setField(service, "delegationEnabled", true);
        credentials = Credentials.create("4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f7f8f2f0d9f7d4c001");
    }

    @Test
    void checkInShouldQueueAndDispatchWithDurableNonceCoordination() throws Exception {
        InstitutionalCheckInRequest request = validRequest();
        SamlAssertionAttributes saml = samlAttributes();
        CheckInResponse onChainResponse = new CheckInResponse();
        onChainResponse.setValid(true);
        onChainResponse.setTxHash("0xtx123");

        when(samlValidationService.validateSamlAssertionDetailed("valid-saml")).thenReturn(saml);
        when(marketplaceEndpointAuthService.enforceToken("market-token", null)).thenReturn(marketplaceClaims());
        when(bookingService.getCheckInBookingInfo("0x1111111111111111111111111111111111111111", "0xabc", "42", "puc-123"))
            .thenReturn(Map.of("reservationKey", "0xabc"));
        when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(credentials.getAddress());
        when(directoryService.isAuthorizedCheckInSigner("0x1111111111111111111111111111111111111111", credentials.getAddress()))
            .thenReturn(true);
        InstitutionalCheckInOutboxRecord record = queuedRecord();
        when(outboxService.enqueueAccessGranted(eq("0xabc"), eq("42"), eq("0x1111111111111111111111111111111111111111"), any(), eq("0xabc")))
            .thenReturn(record);
        when(outboxService.claim(record.id())).thenReturn(true);
        when(nonceDispatcher.dispatch(record)).thenReturn(onChainResponse);

        CheckInResponse response = service.checkIn(request);

        assertThat(response).isSameAs(onChainResponse);
        verify(bookingService).getCheckInBookingInfo("0x1111111111111111111111111111111111111111", "0xabc", "42", "puc-123");

        verify(outboxService).claim(record.id());
        verify(nonceDispatcher).dispatch(record);
    }

    @Test
    void checkInShouldKeepLocalFlowWhenPayerAndProviderUseLocalWallet() throws Exception {
        InstitutionalCheckInRequest request = validRequest();
        request.setPayerInstitutionWallet(credentials.getAddress());
        SamlAssertionAttributes saml = samlAttributes();
        CheckInResponse onChainResponse = new CheckInResponse();
        onChainResponse.setValid(true);
        onChainResponse.setTxHash("0xsame");

        when(samlValidationService.validateSamlAssertionDetailed("valid-saml")).thenReturn(saml);
        when(marketplaceEndpointAuthService.enforceToken("market-token", null))
            .thenReturn(marketplaceClaims(Map.of("payerInstitutionWallet", credentials.getAddress())));
        when(bookingService.getCheckInBookingInfo(credentials.getAddress(), "0xabc", "42", "puc-123"))
            .thenReturn(Map.of("reservationKey", "0xabc"));
        when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(credentials.getAddress());
        when(directoryService.isAuthorizedCheckInSigner(credentials.getAddress(), credentials.getAddress()))
            .thenReturn(true);
        InstitutionalCheckInOutboxRecord record = queuedRecord();
        when(outboxService.enqueueAccessGranted(eq("0xabc"), eq("42"), eq(credentials.getAddress()), any(), eq("0xabc")))
            .thenReturn(record);
        when(outboxService.claim(record.id())).thenReturn(true);
        when(nonceDispatcher.dispatch(record)).thenReturn(onChainResponse);

        CheckInResponse response = service.checkIn(request);

        assertThat(response).isSameAs(onChainResponse);
        verify(remoteCheckInClient, never()).submit(any(), any());
        verify(nonceDispatcher).dispatch(record);
    }

    @Test
    void checkInMarksBroadcastOutcomeUnknownInsteadOfRetryingWithNewMaterial() throws Exception {
        InstitutionalCheckInRequest request = validRequest();
        when(samlValidationService.validateSamlAssertionDetailed("valid-saml")).thenReturn(samlAttributes());
        when(marketplaceEndpointAuthService.enforceToken("market-token", null)).thenReturn(marketplaceClaims());
        when(bookingService.getCheckInBookingInfo(any(), eq("0xabc"), eq("42"), eq("puc-123")))
            .thenReturn(Map.of("reservationKey", "0xabc"));
        when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(credentials.getAddress());
        when(directoryService.isAuthorizedCheckInSigner(any(), any())).thenReturn(true);
        InstitutionalCheckInOutboxRecord record = queuedRecord();
        when(outboxService.enqueueAccessGranted(any(), any(), any(), any(), any())).thenReturn(record);
        when(outboxService.claim(record.id())).thenReturn(true);
        when(nonceDispatcher.dispatch(record)).thenThrow(new InstitutionalWalletDispatchException(
            "uncertain", new IllegalStateException("response lost after broadcast")
        ));

        assertThatThrownBy(() -> service.checkIn(request)).isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("could not be confirmed");

        verify(outboxService).markBroadcastUncertain(
            eq(record.id()), eq(record.attempts() + 1), eq("Initial institutional check-in broadcast outcome is uncertain")
        );
        verify(outboxService, never()).markRetry(any(Long.class), any(Integer.class), any(), any());
    }

    @Test
    void checkInMarksPreBroadcastFailureAsRetryable() throws Exception {
        InstitutionalCheckInRequest request = validRequest();
        when(samlValidationService.validateSamlAssertionDetailed("valid-saml")).thenReturn(samlAttributes());
        when(marketplaceEndpointAuthService.enforceToken("market-token", null)).thenReturn(marketplaceClaims());
        when(bookingService.getCheckInBookingInfo(any(), eq("0xabc"), eq("42"), eq("puc-123")))
            .thenReturn(Map.of("reservationKey", "0xabc"));
        when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(credentials.getAddress());
        when(directoryService.isAuthorizedCheckInSigner(any(), any())).thenReturn(true);
        InstitutionalCheckInOutboxRecord record = queuedRecord();
        when(outboxService.enqueueAccessGranted(any(), any(), any(), any(), any())).thenReturn(record);
        when(outboxService.claim(record.id())).thenReturn(true);
        when(nonceDispatcher.dispatch(record)).thenThrow(new InstitutionalWalletDispatchException(
            "blocked", InstitutionalWalletDispatchException.Outcome.PRE_BROADCAST_RETRYABLE,
            new IllegalStateException("allocator blocked")
        ));

        assertThatThrownBy(() -> service.checkIn(request)).isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("could not be prepared");

        verify(outboxService).markRetry(
            eq(record.id()), eq(record.attempts() + 1), any(),
            eq("Initial institutional check-in transaction was not broadcast; retrying")
        );
        verify(outboxService, never()).markBroadcastUncertain(any(Long.class), any(Integer.class), any());
    }

    @Test
    void checkInShouldReturnSuccessWhenReservationAccessAlreadyAuthorized() throws Exception {
        InstitutionalCheckInRequest request = validRequest();

        when(samlValidationService.validateSamlAssertionDetailed("valid-saml")).thenReturn(samlAttributes());
        when(marketplaceEndpointAuthService.enforceToken("market-token", null)).thenReturn(marketplaceClaims());
        when(bookingService.getCheckInBookingInfo("0x1111111111111111111111111111111111111111", "0xabc", "42", "puc-123"))
            .thenReturn(Map.of(
                "reservationKey", "0xabc",
                "reservationStatus", BigInteger.valueOf(2)
            ));

        CheckInResponse response = service.checkIn(request);

        assertThat(response.isValid()).isTrue();
        assertThat(response.getReservationKey()).isEqualTo("0xabc");
        assertThat(response.getReason()).isEqualTo("Access already authorized");
        assertThat(response.getTimestamp()).isNotNull();
        verify(checkInOnChainService, never()).verifyAndSubmit(any(CheckInRequest.class));
        verify(institutionalWalletService, never()).getInstitutionalCredentials();
        verify(remoteCheckInClient, never()).submit(any(), any());
    }

    @Test
    void checkInShouldResolveSamlIdentityWithMarketplaceStableUserIdMode() throws Exception {
        InstitutionalCheckInRequest request = validRequest();
        request.setPuc("user@university.edu");
        SamlAssertionAttributes saml = new SamlAssertionAttributes(
            "issuer",
            "user@university.edu|targeted-user",
            "org.example",
            "user@example.org",
            "User Example",
            List.of("org.example"),
            Map.of(
                "puc", List.of("user@university.edu|targeted-user"),
                "eduPersonPrincipalName", List.of("user@university.edu"),
                "eduPersonTargetedID", List.of("targeted-user")
            )
        );

        when(samlValidationService.validateSamlAssertionDetailed("valid-saml")).thenReturn(saml);
        when(marketplaceEndpointAuthService.enforceToken("market-token", null))
            .thenReturn(marketplaceClaims(Map.of(
                "puc", "user@university.edu",
                "stableUserIdMode", "principal"
            )));
        when(samlValidationService.resolveStableUserId(any(), eq("principal"), eq(null)))
            .thenReturn("user@university.edu");
        when(bookingService.getCheckInBookingInfo("0x1111111111111111111111111111111111111111", "0xabc", "42", "user@university.edu"))
            .thenReturn(Map.of(
                "reservationKey", "0xabc",
                "reservationStatus", BigInteger.valueOf(2)
            ));

        CheckInResponse response = service.checkIn(request);

        assertThat(response.isValid()).isTrue();
        verify(bookingService).getCheckInBookingInfo(
            "0x1111111111111111111111111111111111111111",
            "0xabc",
            "42",
            "user@university.edu"
        );
    }

    @Test
    void checkInShouldDelegateToInstitutionBackendWhenLocalWalletIsNotAuthorized() throws Exception {
        InstitutionalCheckInRequest request = validRequest();
        SamlAssertionAttributes saml = samlAttributes();
        CheckInResponse remoteResponse = new CheckInResponse();
        remoteResponse.setValid(true);
        remoteResponse.setTxHash("0xremote");

        when(samlValidationService.validateSamlAssertionDetailed("valid-saml")).thenReturn(saml);
        when(marketplaceEndpointAuthService.enforceToken("market-token", null)).thenReturn(marketplaceClaims());
        when(bookingService.getCheckInBookingInfo("0x1111111111111111111111111111111111111111", "0xabc", "42", "puc-123"))
            .thenReturn(Map.of("reservationKey", "0xabc"));
        when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn("0x9999999999999999999999999999999999999999");
        when(directoryService.isAuthorizedCheckInSigner(
            "0x1111111111111111111111111111111111111111",
            "0x9999999999999999999999999999999999999999"
        )).thenReturn(false);
        when(directoryService.resolveOrganizationBackendUrl("org.example")).thenReturn("https://consumer.example");
        when(remoteCheckInClient.submit("https://consumer.example", request)).thenReturn(remoteResponse);

        CheckInResponse response = service.checkIn(request);

        assertThat(response).isSameAs(remoteResponse);
        verify(remoteCheckInClient).submit("https://consumer.example", request);
    }

    @Test
    void checkInShouldRejectRequestPucMismatch() throws Exception {
        InstitutionalCheckInRequest request = validRequest();
        request.setPuc("other-puc");

        when(samlValidationService.validateSamlAssertionDetailed("valid-saml")).thenReturn(samlAttributes());
        when(marketplaceEndpointAuthService.enforceToken("market-token", null)).thenReturn(marketplaceClaims());

        assertThatThrownBy(() -> service.checkIn(request))
            .isInstanceOf(SecurityException.class)
            .hasMessageContaining("Request puc does not match authenticated user");
    }

    @Test
    void checkInShouldRejectMarketplaceInstitutionWalletMismatch() throws Exception {
        InstitutionalCheckInRequest request = validRequest();

        when(samlValidationService.validateSamlAssertionDetailed("valid-saml")).thenReturn(samlAttributes());
        when(marketplaceEndpointAuthService.enforceToken("market-token", null))
            .thenReturn(marketplaceClaims(Map.of("payerInstitutionWallet", "0x9999999999999999999999999999999999999999")));

        assertThatThrownBy(() -> service.checkIn(request))
            .isInstanceOf(SecurityException.class)
            .hasMessageContaining("payerInstitutionWallet mismatch");
    }

    @Test
    void checkInShouldRejectMarketplaceTokenWhenPucDoesNotMatchSamlUser() throws Exception {
        InstitutionalCheckInRequest request = validRequest();

        when(samlValidationService.validateSamlAssertionDetailed("valid-saml")).thenReturn(samlAttributes());
        when(marketplaceEndpointAuthService.enforceToken("market-token", null))
            .thenReturn(marketplaceClaims(Map.of("puc", "other-user")));

        assertThatThrownBy(() -> service.checkIn(request))
            .isInstanceOf(SecurityException.class)
            .hasMessageContaining("Marketplace token puc mismatch");
    }

    @Test
    void checkInShouldRejectMarketplaceSamlAssertionHashMismatch() throws Exception {
        InstitutionalCheckInRequest request = validRequest();

        when(samlValidationService.validateSamlAssertionDetailed("valid-saml")).thenReturn(samlAttributes());
        when(marketplaceEndpointAuthService.enforceToken("market-token", null))
            .thenReturn(marketplaceClaims(Map.of("samlAssertionHash", "0x" + "0".repeat(64))));

        assertThatThrownBy(() -> service.checkIn(request))
            .isInstanceOf(SecurityException.class)
            .hasMessageContaining("samlAssertionHash mismatch");
    }

    @Test
    void checkInShouldRejectMarketplaceTokenWithoutLabAccessPurpose() throws Exception {
        InstitutionalCheckInRequest request = validRequest();
        Map<String, Object> claims = marketplaceClaims();
        claims.remove("purpose");

        when(samlValidationService.validateSamlAssertionDetailed("valid-saml")).thenReturn(samlAttributes());
        when(marketplaceEndpointAuthService.enforceToken("market-token", null)).thenReturn(claims);

        assertThatThrownBy(() -> service.checkIn(request))
            .isInstanceOf(SecurityException.class)
            .hasMessageContaining("purpose is required");
    }

    @Test
    void checkInShouldRejectMarketplaceTokenWithoutReservationBinding() throws Exception {
        InstitutionalCheckInRequest request = validRequest();
        Map<String, Object> claims = marketplaceClaims();
        claims.remove("reservationKey");

        when(samlValidationService.validateSamlAssertionDetailed("valid-saml")).thenReturn(samlAttributes());
        when(marketplaceEndpointAuthService.enforceToken("market-token", null)).thenReturn(claims);

        assertThatThrownBy(() -> service.checkIn(request))
            .isInstanceOf(SecurityException.class)
            .hasMessageContaining("reservationKey is required");
    }

    @Test
    void checkInShouldRejectMarketplaceTokenWithoutSamlAssertionHash() throws Exception {
        InstitutionalCheckInRequest request = validRequest();
        Map<String, Object> claims = marketplaceClaims();
        claims.remove("samlAssertionHash");

        when(samlValidationService.validateSamlAssertionDetailed("valid-saml")).thenReturn(samlAttributes());
        when(marketplaceEndpointAuthService.enforceToken("market-token", null)).thenReturn(claims);

        assertThatThrownBy(() -> service.checkIn(request))
            .isInstanceOf(SecurityException.class)
            .hasMessageContaining("samlAssertionHash is required");
    }

    @Test
    void checkInShouldRejectMissingResolvedReservationKey() throws Exception {
        InstitutionalCheckInRequest request = validRequest();

        when(samlValidationService.validateSamlAssertionDetailed("valid-saml")).thenReturn(samlAttributes());
        when(marketplaceEndpointAuthService.enforceToken("market-token", null)).thenReturn(marketplaceClaims());
        when(bookingService.getCheckInBookingInfo("0x1111111111111111111111111111111111111111", "0xabc", "42", "puc-123"))
            .thenReturn(Map.of());

        assertThatThrownBy(() -> service.checkIn(request))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("Reservation key could not be resolved");
    }

    private InstitutionalCheckInRequest validRequest() {
        InstitutionalCheckInRequest request = new InstitutionalCheckInRequest();
        request.setMarketplaceToken("market-token");
        request.setSamlAssertion("valid-saml");
        request.setReservationKey("0xabc");
        request.setLabId("42");
        request.setPayerInstitutionWallet("0x1111111111111111111111111111111111111111");
        return request;
    }

    private SamlAssertionAttributes samlAttributes() {
        return new SamlAssertionAttributes(
            "issuer",
            "puc-123",
            "org.example",
            "user@example.org",
            "User Example",
            List.of("org.example"),
            Map.of()
        );
    }

    private Map<String, Object> marketplaceClaims() {
        return marketplaceClaims(Map.of());
    }

    private Map<String, Object> marketplaceClaims(Map<String, Object> overrides) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("affiliation", "org.example");
        claims.put("puc", "puc-123");
        claims.put("payerInstitutionWallet", "0x1111111111111111111111111111111111111111");
        claims.put("purpose", "lab_access");
        claims.put("reservationKey", "0xabc");
        claims.put("labId", "42");
        claims.put("samlAssertionHash", samlAssertionHash("valid-saml"));
        claims.putAll(overrides);
        return claims;
    }

    private InstitutionalCheckInOutboxRecord queuedRecord() {
        return new InstitutionalCheckInOutboxRecord(
            1L, "0xabc", "42", "0x1111111111111111111111111111111111111111",
            computePucHash("puc-123"), "0xabc", "PENDING", 0, java.time.Instant.now(), null,
            "0x1111111111111111111111111111111111111111", null, null
        );
    }

    private static String samlAssertionHash(String samlAssertion) {
        return Numeric.toHexString(Hash.sha3(samlAssertion.getBytes(StandardCharsets.UTF_8)));
    }

    private static String computePucHash(String puc) {
        byte[] hash = Hash.sha3(puc.getBytes(StandardCharsets.UTF_8));
        return normalizeBytes32(Numeric.toHexString(hash));
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
