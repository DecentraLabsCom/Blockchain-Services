package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
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
import decentralabs.blockchain.dto.auth.CheckInResponse;
import decentralabs.blockchain.dto.auth.ProviderAccessCredentialRequest;
import decentralabs.blockchain.dto.auth.SamlAuthRequest;
import decentralabs.blockchain.exception.AccessAuthorizationManualInterventionException;
import decentralabs.blockchain.dto.auth.InstitutionalCheckInStatusRequest;
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
    private InstitutionalCheckInOutboxService institutionalCheckInOutboxService;

    @Mock
    private InstitutionalCheckInDirectoryService institutionalCheckInDirectoryService;

    @Mock
    private RemoteInstitutionalCheckInClient remoteInstitutionalCheckInClient;

    @Mock
    private AccessCredentialDeliveryService accessCredentialDeliveryService;

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
        lenient().when(accessAuthorizationProvisioningService.markActivated(any())).thenReturn(true);
    }

    @Nested
    @DisplayName("Provider Access Credential Tests")
    class ProviderAccessCredentialTests {

        @Test
        @DisplayName("Should stop provider-only retries when consumer check-in requires manual intervention")
        void shouldRejectProviderOnlyRetryForManualIntervention() {
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
                "reservationKey", "0xreservation",
                "reservationStatus", java.math.BigInteger.ONE,
                "resourceType", "lab"
            ));
            when(blockchainService.getBookingInfoForCredentialPreparation("0xwallet", "0xreservation", "42", TEST_PUC))
                .thenReturn(bookingInfo);
            when(institutionalCheckInOutboxService.findStateByReservationKeyIfConfigured("0xreservation"))
                .thenReturn(new InstitutionalCheckInOutboxService.CheckInOutboxState(
                    "MANUAL_INTERVENTION", "operator intervention required", "0xhash"
                ));

            assertThatThrownBy(() -> samlAuthService.issueAccessCredential(request))
                .isInstanceOf(AccessAuthorizationManualInterventionException.class);
            verify(accessAuthorizationProvisioningService, never()).tryStart(anyString());
        }

        @Test
        @DisplayName("Should reject provider-only retry when delegated consumer reports terminal intervention")
        void shouldRejectProviderOnlyRetryForRemoteManualIntervention() {
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
                "reservationKey", "0xreservation",
                "reservationStatus", java.math.BigInteger.ONE,
                "resourceType", "lab"
            ));
            when(blockchainService.getBookingInfoForCredentialPreparation("0xwallet", "0xreservation", "42", TEST_PUC))
                .thenReturn(bookingInfo);
            when(institutionalCheckInDirectoryService.resolveOrganizationBackendUrl(TEST_AFFILIATION))
                .thenReturn("https://consumer.example");
            CheckInResponse remoteBody = new CheckInResponse();
            remoteBody.setReason("CHECKIN_MANUAL_INTERVENTION");
            remoteBody.setRetryable(false);
            when(remoteInstitutionalCheckInClient.queryStatus(
                eq("https://consumer.example"), any(InstitutionalCheckInStatusRequest.class)
            )).thenReturn(new RemoteInstitutionalCheckInClient.RemoteCheckInResult(409, remoteBody, null));

            assertThatThrownBy(() -> samlAuthService.issueAccessCredential(request))
                .isInstanceOf(AccessAuthorizationManualInterventionException.class);
            verify(accessAuthorizationProvisioningService, never()).tryStart(anyString());
        }

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
            when(accessCredentialDeliveryService.deliver(any(), any(), eq(bookingInfo), any())).thenReturn(
                AuthResponse.opaqueAccess("opaque-code", "https://lab.example.com/guacamole/", "lab", "0xreservation")
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
            assertThat(response.getReservationKey()).isEqualTo("0xreservation");
            verify(accessCheckInCoordinator, never()).recordAccessGranted(any(), any(), any());
            verify(accessCredentialDeliveryService).deliver(any(), any(), eq(bookingInfo), eq(lease));
        }

        @Test
        @DisplayName("Should use the booking canonical reservation key throughout a labId-only request")
        void shouldUseCanonicalReservationKeyForLabIdFallback() throws Exception {
            ProviderAccessCredentialRequest request = new ProviderAccessCredentialRequest();
            request.setMarketplaceToken("provider-token-lab-only");
            request.setLabId("42");

            when(marketplaceEndpointAuthService.enforceToken(eq("provider-token-lab-only"), eq(null)))
                .thenReturn(Map.of(
                    "puc", TEST_PUC,
                    "affiliation", TEST_AFFILIATION,
                    "bookingInfoAllowed", true,
                    "purpose", "lab_access",
                    "labId", "42",
                    "payerInstitutionWallet", "0xwallet"
                ));
            Map<String, Object> bookingInfo = new HashMap<>(Map.of(
                "labURL", "https://lab.example.com/fmu/",
                "reservationKey", "0xcanonical",
                "reservationStatus", java.math.BigInteger.valueOf(2),
                "resourceType", "fmu"
            ));
            when(blockchainService.getBookingInfoForCredentialPreparation("0xwallet", null, "42", TEST_PUC))
                .thenReturn(bookingInfo);
            var lease = new AccessAuthorizationProvisioningService.ProvisioningLease(
                "0xcanonical", "fence-token", 7L
            );
            when(accessAuthorizationProvisioningService.tryStart("0xcanonical")).thenReturn(lease);
            when(accessAuthorizationProvisioningService.markDelivered(lease)).thenReturn(true);
            when(accessCredentialDeliveryService.deliver(any(), any(), eq(bookingInfo), eq(lease))).thenReturn(
                AuthResponse.opaqueAccess("opaque-code", "https://lab.example.com/fmu/", "fmu", "0xcanonical")
            );

            AuthResponse response = samlAuthService.issueAccessCredential(request);

            assertThat(request.getReservationKey()).isEqualTo("0xcanonical");
            assertThat(response.getReservationKey()).isEqualTo("0xcanonical");
            assertThat(response.getResourceType()).isEqualTo("fmu");
            verify(accessAuthorizationProvisioningService).recoverableProvisioning("0xcanonical");
            verify(accessAuthorizationProvisioningService).tryStart("0xcanonical");
            verify(accessCredentialDeliveryService).deliver(any(), any(), eq(bookingInfo), eq(lease));
        }

        @Test
        @DisplayName("Should recover a code-persisted generation without activating another user")
        void shouldRecoverCodePersistedGenerationAfterLostResponse() throws Exception {
            ProviderAccessCredentialRequest request = new ProviderAccessCredentialRequest();
            request.setMarketplaceToken("provider-token-recovery");
            request.setReservationKey("0xreservation");
            request.setLabId("42");
            when(marketplaceEndpointAuthService.enforceToken(eq("provider-token-recovery"), eq(null)))
                .thenReturn(Map.of(
                    "puc", TEST_PUC,
                    "affiliation", TEST_AFFILIATION,
                    "bookingInfoAllowed", true,
                    "purpose", "lab_access",
                    "reservationKey", "0xreservation",
                    "labId", "42",
                    "payerInstitutionWallet", "0xwallet"
                ));
            Map<String, Object> bookingInfo = new HashMap<>(Map.of(
                "labURL", "https://lab.example.com/guacamole/",
                "reservationKey", "0xreservation",
                "reservationStatus", java.math.BigInteger.valueOf(2),
                "resourceType", "lab"
            ));
            when(blockchainService.getBookingInfoForCredentialPreparation(
                "0xwallet", "0xreservation", "42", TEST_PUC
            )).thenReturn(bookingInfo);
            when(accessAuthorizationProvisioningService.recoverableProvisioning("0xreservation"))
                .thenReturn(new AccessAuthorizationProvisioningService.RecoverableProvisioning(4L, "CODE_PERSISTED"));
            when(accessCodeService.recoverDelivery("0xreservation", 4L)).thenReturn(
                new decentralabs.blockchain.dto.auth.AccessCodeResponse(
                    "recovered-code", "https://lab.example.com/guacamole/", "lab"
                )
            );
            when(accessAuthorizationProvisioningService.promoteRecoveredDelivery("0xreservation", 4L))
                .thenReturn(true);

            AuthResponse response = samlAuthService.issueAccessCredential(request);

            assertThat(response.getAccessCode()).isEqualTo("recovered-code");
            assertThat(response.getResourceType()).isEqualTo("lab");
            assertThat(response.getReservationKey()).isEqualTo("0xreservation");
            verify(accessAuthorizationProvisioningService, never()).tryStart(any());
            verify(blockchainService, never()).provisionGuacamoleAccess(any());
            verify(jwtService, never()).generateIssuedToken(eq(null), any());
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
            verify(accessCredentialDeliveryService, never()).deliver(any(), any(), any(), any());
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
            when(accessCredentialDeliveryService.deliver(any(), any(), eq(bookingInfo), eq(lease))).thenReturn(
                AuthResponse.opaqueAccess("opaque-code", "https://lab.example.com/guacamole/", "lab", "0xreservation")
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
        when(accessCredentialDeliveryService.deliver(any(), any(), eq(bookingInfo), eq(lease))).thenReturn(
            AuthResponse.opaqueAccess("opaque-code", "https://lab.example.com/guacamole/", "lab", "0xreservation")
        );

        samlAuthService.authorizeAndIssue(request);

        var order = org.mockito.Mockito.inOrder(accessCheckInCoordinator, blockchainService);
        order.verify(accessCheckInCoordinator).recordAccessGranted(request, claims, bookingInfo);
        order.verify(blockchainService).provisionGuacamoleAccess(bookingInfo, false, "fence-token");
    }

    @Test
    void combinedFlowStopsBeforeProvisioningWhenCheckInContextIsQuarantined() throws Exception {
        SamlAuthRequest request = new SamlAuthRequest();
        request.setMarketplaceToken("combined-quarantined-token");
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
            "reservationStatus", java.math.BigInteger.ONE,
            "resourceType", "lab"
        ));
        when(marketplaceEndpointAuthService.enforceToken("combined-quarantined-token", null)).thenReturn(claims);
        when(samlValidationService.validateSamlAssertionWithSignature("signed-saml"))
            .thenReturn(Map.of("puc", TEST_PUC, "affiliation", TEST_AFFILIATION));
        when(blockchainService.getBookingInfoForCredentialPreparation(
            "0xwallet", "0xreservation", "42", TEST_PUC
        )).thenReturn(bookingInfo);
        when(accessCheckInCoordinator.recordAccessGranted(request, claims, bookingInfo))
            .thenReturn(InstitutionalAccessCheckInCoordinator.AccessGrantedResult.CONTEXT_MISMATCH);

        assertThatThrownBy(() -> samlAuthService.authorizeAndIssue(request))
            .isInstanceOf(decentralabs.blockchain.exception.AccessAuthorizationContextMismatchException.class)
            .hasMessageContaining("different chain or signer");

        verify(accessAuthorizationProvisioningService, never()).tryStart(any());
        verify(blockchainService, never()).provisionGuacamoleAccess(any(), anyBoolean(), anyString());
        verify(accessCredentialDeliveryService, never()).deliver(any(), any(), any(), any());
    }

    @Test
    void combinedFlowStopsBeforeProvisioningForManualIntervention() throws Exception {
        SamlAuthRequest request = new SamlAuthRequest();
        request.setMarketplaceToken("combined-manual-token");
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
            "reservationStatus", java.math.BigInteger.ONE,
            "resourceType", "lab"
        ));
        when(marketplaceEndpointAuthService.enforceToken("combined-manual-token", null)).thenReturn(claims);
        when(samlValidationService.validateSamlAssertionWithSignature("signed-saml"))
            .thenReturn(Map.of("puc", TEST_PUC, "affiliation", TEST_AFFILIATION));
        when(blockchainService.getBookingInfoForCredentialPreparation(
            "0xwallet", "0xreservation", "42", TEST_PUC
        )).thenReturn(bookingInfo);
        when(accessCheckInCoordinator.recordAccessGranted(request, claims, bookingInfo))
            .thenReturn(InstitutionalAccessCheckInCoordinator.AccessGrantedResult.MANUAL_INTERVENTION);

        assertThatThrownBy(() -> samlAuthService.authorizeAndIssue(request))
            .isInstanceOf(decentralabs.blockchain.exception.AccessAuthorizationManualInterventionException.class)
            .hasMessageContaining("manual intervention");

        verify(accessAuthorizationProvisioningService, never()).tryStart(any());
        verify(blockchainService, never()).provisionGuacamoleAccess(any(), anyBoolean(), anyString());
        verify(accessCredentialDeliveryService, never()).deliver(any(), any(), any(), any());
    }
}
