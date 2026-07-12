package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import decentralabs.blockchain.dto.auth.AuthResponse;
import decentralabs.blockchain.dto.auth.ProviderAccessCredentialRequest;
import decentralabs.blockchain.dto.auth.SamlAuthRequest;
import decentralabs.blockchain.service.wallet.BlockchainBookingService;

@ExtendWith(MockitoExtension.class)
class SamlAuthServiceTest {

    @Mock
    private BlockchainBookingService blockchainService;

    @Mock
    private JwtService jwtService;

    @Mock
    private MarketplaceEndpointAuthService marketplaceEndpointAuthService;

    @Mock
    private SamlValidationService samlValidationService;

    @Mock
    private InstitutionalAccessCheckInCoordinator accessCheckInCoordinator;

    @Mock
    private AccessCredentialAuditService accessCredentialAuditService;

    @Mock
    private AccessAuthorizationProvisioningService accessAuthorizationProvisioningService;

    @Mock
    private CheckInOnChainService checkInOnChainService;

    @Mock
    private AccessCodeService accessCodeService;

    @InjectMocks
    private SamlAuthService samlAuthService;

    private static final String TEST_PUC = "user123";
    private static final String TEST_AFFILIATION = "test-university";

    @BeforeEach
    void setUp() throws Exception {
        lenient().when(marketplaceEndpointAuthService.enforceToken(anyString(), eq(null)))
            .thenReturn(Map.of("puc", TEST_PUC, "affiliation", TEST_AFFILIATION));
        lenient().when(jwtService.generateIssuedToken(eq(null), any()))
            .thenReturn(new JwtService.IssuedToken("booking-token", "jwt-jti-default", 1_700_000_000L, null));
    }

    @Nested
    @DisplayName("Provider Access Credential Tests")
    class ProviderAccessCredentialTests {

        @Test
        @DisplayName("Should issue provider credential only after access is authorized")
        void shouldIssueProviderCredentialOnlyAfterAccessIsAuthorized() throws Exception {
            ProviderAccessCredentialRequest request = new ProviderAccessCredentialRequest();
            request.setMarketplaceToken("provider-token");
            request.setReservationKey("0xreservation");
            request.setLabId("42");

            when(marketplaceEndpointAuthService.enforceToken(eq("provider-token"), eq(null)))
                .thenReturn(Map.of(
                    "puc", TEST_PUC, "affiliation", TEST_AFFILIATION,
                    "bookingInfoAllowed", true, "purpose", "lab_access",
                    "reservationKey", "0xreservation", "labId", "42",
                    "payerInstitutionWallet", "0xwallet"
                ));
            Map<String, Object> bookingInfo = new HashMap<>(Map.of(
                "labURL", "https://lab.example.com",
                "reservationKey", "0xreservation",
                "reservationStatus", java.math.BigInteger.valueOf(2),
                "resourceType", "lab"
            ));
            when(blockchainService.getBookingInfoForCredentialPreparation("0xwallet", "0xreservation", "42", TEST_PUC))
                .thenReturn(bookingInfo);
            when(jwtService.generateIssuedToken(eq(null), any())).thenReturn(
                new JwtService.IssuedToken("booking-token", "jwt-jti-provider", 1_700_000_000L, null)
            );
            when(accessCodeService.issue("booking-token", "0xreservation", 1L)).thenReturn(
                new decentralabs.blockchain.dto.auth.AccessCodeResponse("opaque-code", "https://lab.example.com/guacamole/")
            );
            var lease = new AccessAuthorizationProvisioningService.ProvisioningLease(
                "0xreservation", "fence-token", 1L
            );
            when(accessAuthorizationProvisioningService.tryStart("0xreservation")).thenReturn(lease);
            when(accessAuthorizationProvisioningService.isCurrent(lease)).thenReturn(true);
            when(accessAuthorizationProvisioningService.heartbeat(lease)).thenReturn(true);
            when(accessAuthorizationProvisioningService.markDelivered(lease)).thenReturn(true);

            AuthResponse response = samlAuthService.issueAccessCredential(request);

            assertThat(response.getToken()).isNull();
            assertThat(response.getAccessCode()).isEqualTo("opaque-code");
            assertThat(response.getLabURL()).isEqualTo("https://lab.example.com/guacamole/");
            verify(accessCheckInCoordinator, never()).recordAccessGranted(any(), any(), any());
            verify(accessCredentialAuditService).recordJwtIssued(any(), any(), eq(bookingInfo), any());
            verify(accessCodeService).issue("booking-token", "0xreservation", 1L);
            var deliveryOrder = org.mockito.Mockito.inOrder(accessCodeService, accessCredentialAuditService);
            deliveryOrder.verify(accessCodeService).issue("booking-token", "0xreservation", 1L);
            deliveryOrder.verify(accessCredentialAuditService).recordJwtIssued(any(), any(), eq(bookingInfo), any());
        }

        @Test
        @DisplayName("Should reject provider credential token with mismatched reservation key")
        void shouldRejectProviderCredentialTokenWithMismatchedReservationKey() {
            ProviderAccessCredentialRequest request = new ProviderAccessCredentialRequest();
            request.setMarketplaceToken("provider-token-mismatch");
            request.setReservationKey("0xreservation");

            when(marketplaceEndpointAuthService.enforceToken(eq("provider-token-mismatch"), eq(null)))
                .thenReturn(Map.of(
                    "puc", TEST_PUC, "affiliation", TEST_AFFILIATION,
                    "bookingInfoAllowed", true, "purpose", "lab_access",
                    "reservationKey", "0xother", "payerInstitutionWallet", "0xwallet"
                ));

            assertThatThrownBy(() -> samlAuthService.issueAccessCredential(request))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("reservationKey mismatch");
        }

        @Test
        @DisplayName("Should remove a prepared Guacamole user when access authorization times out")
        void shouldRemovePreparedGuacamoleUserWhenAccessAuthorizationTimesOut() throws Exception {
            ProviderAccessCredentialRequest request = new ProviderAccessCredentialRequest();
            request.setMarketplaceToken("provider-token-timeout");
            request.setReservationKey("0xreservation");
            request.setLabId("42");
            when(marketplaceEndpointAuthService.enforceToken(eq("provider-token-timeout"), eq(null)))
                .thenReturn(Map.of(
                    "puc", TEST_PUC, "affiliation", TEST_AFFILIATION,
                    "bookingInfoAllowed", true, "purpose", "lab_access",
                    "reservationKey", "0xreservation", "labId", "42",
                    "payerInstitutionWallet", "0xwallet"
                ));
            Map<String, Object> bookingInfo = new HashMap<>(Map.of(
                "labURL", "https://lab.example.com", "reservationKey", "0xreservation",
                "reservationStatus", java.math.BigInteger.ONE, "resourceType", "lab"
            ));
            when(blockchainService.getBookingInfoForCredentialPreparation("0xwallet", "0xreservation", "42", TEST_PUC))
                .thenReturn(bookingInfo);
            when(blockchainService.getAccessAuthorizationState("0xwallet", "0xreservation", "42", TEST_PUC))
                .thenReturn(Map.of("reservationStatus", java.math.BigInteger.ONE));
            var lease = new AccessAuthorizationProvisioningService.ProvisioningLease(
                "0xreservation", "fence-token", 1L
            );
            when(accessAuthorizationProvisioningService.tryStart("0xreservation")).thenReturn(lease);
            when(accessAuthorizationProvisioningService.isCurrent(lease)).thenReturn(true);
            when(accessAuthorizationProvisioningService.markWaiting(lease)).thenReturn(true);
            when(accessAuthorizationProvisioningService.heartbeat(lease)).thenReturn(true);
            when(accessAuthorizationProvisioningService.beginRollback(lease)).thenReturn(true);
            ReflectionTestUtils.setField(samlAuthService, "accessAuthorizationWaitTimeoutMs", 0L);

            assertThatThrownBy(() -> samlAuthService.issueAccessCredential(request))
                .isInstanceOf(decentralabs.blockchain.exception.AccessAuthorizationPendingException.class);

            verify(blockchainService).provisionGuacamoleAccess(bookingInfo, false, "fence-token");
            verify(blockchainService).deletePreparedGuacamoleAccess(bookingInfo);
            verify(accessAuthorizationProvisioningService).markRolledBack(lease);
            verify(jwtService, never()).generateIssuedToken(eq(null), any());
            verify(accessCredentialAuditService, never()).recordJwtIssued(any(), any(), any(), any());
        }

        @Test
        @DisplayName("Should not activate a prepared Guacamole user after its provisioning lease is fenced out")
        void shouldNotActivateWhenProvisioningLeaseIsSuperseded() throws Exception {
            ProviderAccessCredentialRequest request = new ProviderAccessCredentialRequest();
            request.setMarketplaceToken("provider-token-fenced");
            request.setReservationKey("0xreservation");
            request.setLabId("42");
            when(marketplaceEndpointAuthService.enforceToken(eq("provider-token-fenced"), eq(null)))
                .thenReturn(Map.of(
                    "puc", TEST_PUC, "affiliation", TEST_AFFILIATION,
                    "bookingInfoAllowed", true, "purpose", "lab_access",
                    "reservationKey", "0xreservation", "labId", "42",
                    "payerInstitutionWallet", "0xwallet"
                ));
            Map<String, Object> bookingInfo = new HashMap<>(Map.of(
                "labURL", "https://lab.example.com", "reservationKey", "0xreservation",
                "reservationStatus", java.math.BigInteger.ONE, "resourceType", "lab"
            ));
            var lease = new AccessAuthorizationProvisioningService.ProvisioningLease(
                "0xreservation", "fence-token", 1L
            );
            when(blockchainService.getBookingInfoForCredentialPreparation("0xwallet", "0xreservation", "42", TEST_PUC))
                .thenReturn(bookingInfo);
            when(blockchainService.getAccessAuthorizationState("0xwallet", "0xreservation", "42", TEST_PUC))
                .thenReturn(Map.of("reservationStatus", java.math.BigInteger.valueOf(2)));
            when(accessAuthorizationProvisioningService.tryStart("0xreservation")).thenReturn(lease);
            when(accessAuthorizationProvisioningService.isCurrent(lease)).thenReturn(true, false);
            when(accessAuthorizationProvisioningService.markWaiting(lease)).thenReturn(true);
            when(accessAuthorizationProvisioningService.heartbeat(lease)).thenReturn(true);
            when(accessAuthorizationProvisioningService.beginRollback(lease)).thenReturn(true);

            assertThatThrownBy(() -> samlAuthService.issueAccessCredential(request))
                .isInstanceOf(decentralabs.blockchain.exception.AccessAuthorizationPendingException.class);

            verify(blockchainService).provisionGuacamoleAccess(bookingInfo, false, "fence-token");
            verify(blockchainService, never()).activatePreparedGuacamoleAccess(bookingInfo, "fence-token");
            verify(blockchainService).deletePreparedGuacamoleAccess(bookingInfo);
        }

        @Test
        @DisplayName("Should fence the already-authorized Guacamole fast path")
        void shouldFenceAlreadyAuthorizedGuacamoleAccess() throws Exception {
            ProviderAccessCredentialRequest request = new ProviderAccessCredentialRequest();
            request.setMarketplaceToken("provider-token-authorized");
            request.setReservationKey("0xreservation");
            request.setLabId("42");
            when(marketplaceEndpointAuthService.enforceToken(eq("provider-token-authorized"), eq(null)))
                .thenReturn(Map.of(
                    "puc", TEST_PUC, "affiliation", TEST_AFFILIATION,
                    "bookingInfoAllowed", true, "purpose", "lab_access",
                    "reservationKey", "0xreservation", "labId", "42",
                    "payerInstitutionWallet", "0xwallet"
                ));
            Map<String, Object> bookingInfo = new HashMap<>(Map.of(
                "labURL", "https://lab.example.com/guacamole/", "reservationKey", "0xreservation",
                "reservationStatus", java.math.BigInteger.valueOf(2), "resourceType", "lab"
            ));
            var lease = new AccessAuthorizationProvisioningService.ProvisioningLease(
                "0xreservation", "fence-token", 2L
            );
            when(blockchainService.getBookingInfoForCredentialPreparation("0xwallet", "0xreservation", "42", TEST_PUC))
                .thenReturn(bookingInfo);
            when(accessAuthorizationProvisioningService.tryStart("0xreservation")).thenReturn(lease);
            when(accessAuthorizationProvisioningService.isCurrent(lease)).thenReturn(true);
            when(accessAuthorizationProvisioningService.heartbeat(lease)).thenReturn(true);
            when(accessAuthorizationProvisioningService.markDelivered(lease)).thenReturn(true);
            when(accessCodeService.issue("booking-token", "0xreservation", 2L)).thenReturn(
                new decentralabs.blockchain.dto.auth.AccessCodeResponse("opaque-code", "https://lab.example.com/guacamole/")
            );

            samlAuthService.issueAccessCredential(request);

            verify(blockchainService).provisionGuacamoleAccess(bookingInfo, false, "fence-token");
            verify(blockchainService).activatePreparedGuacamoleAccess(bookingInfo, "fence-token");
            verify(accessAuthorizationProvisioningService).markDelivered(lease);
        }
    }

    @Test
    void combinedFlowBroadcastsCheckInBeforeProviderProvisioning() throws Exception {
        SamlAuthRequest request = new SamlAuthRequest();
        request.setMarketplaceToken("combined-token");
        request.setSamlAssertion("signed-saml");
        request.setReservationKey("0xreservation");
        request.setLabId("42");
        Map<String, Object> claims = Map.of(
            "puc", TEST_PUC,
            "affiliation", TEST_AFFILIATION,
            "bookingInfoAllowed", true,
            "purpose", "lab_access",
            "reservationKey", "0xreservation",
            "labId", "42",
            "payerInstitutionWallet", "0xwallet"
        );
        Map<String, Object> bookingInfo = new HashMap<>(Map.of(
            "labURL", "https://lab.example.com/guacamole/",
            "reservationKey", "0xreservation",
            "reservationStatus", java.math.BigInteger.valueOf(2),
            "resourceType", "lab"
        ));
        var lease = new AccessAuthorizationProvisioningService.ProvisioningLease(
            "0xreservation", "fence-token", 1L
        );
        when(marketplaceEndpointAuthService.enforceToken("combined-token", null)).thenReturn(claims);
        when(samlValidationService.validateSamlAssertionWithSignature("signed-saml"))
            .thenReturn(Map.of("puc", TEST_PUC, "affiliation", TEST_AFFILIATION));
        when(blockchainService.getBookingInfoForCredentialPreparation(
            "0xwallet", "0xreservation", "42", TEST_PUC
        )).thenReturn(bookingInfo);
        when(accessAuthorizationProvisioningService.tryStart("0xreservation")).thenReturn(lease);
        when(accessAuthorizationProvisioningService.isCurrent(lease)).thenReturn(true);
        when(accessAuthorizationProvisioningService.heartbeat(lease)).thenReturn(true);
        when(accessAuthorizationProvisioningService.markDelivered(lease)).thenReturn(true);
        when(accessCodeService.issue("booking-token", "0xreservation", 1L)).thenReturn(
            new decentralabs.blockchain.dto.auth.AccessCodeResponse(
                "opaque-code", "https://lab.example.com/guacamole/"
            )
        );

        samlAuthService.authorizeAndIssue(request);

        var order = org.mockito.Mockito.inOrder(accessCheckInCoordinator, blockchainService);
        order.verify(accessCheckInCoordinator).recordAccessGranted(request, claims, bookingInfo);
        order.verify(blockchainService).provisionGuacamoleAccess(bookingInfo, false, "fence-token");
    }
}
