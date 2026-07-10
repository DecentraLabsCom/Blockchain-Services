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
    private InstitutionalAccessCheckInCoordinator accessCheckInCoordinator;

    @Mock
    private AccessCredentialAuditService accessCredentialAuditService;

    @Mock
    private AccessAuthorizationProvisioningService accessAuthorizationProvisioningService;

    @Mock
    private CheckInOnChainService checkInOnChainService;

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
                "reservationStatus", java.math.BigInteger.valueOf(2)
            ));
            when(blockchainService.getBookingInfoForCredentialPreparation("0xwallet", "0xreservation", "42", TEST_PUC))
                .thenReturn(bookingInfo);
            when(jwtService.generateIssuedToken(eq(null), any())).thenReturn(
                new JwtService.IssuedToken("booking-token", "jwt-jti-provider", 1_700_000_000L, null)
            );

            AuthResponse response = samlAuthService.issueAccessCredential(request);

            assertThat(response.getToken()).isEqualTo("booking-token");
            assertThat(response.getLabURL()).isEqualTo("https://lab.example.com");
            verify(accessCheckInCoordinator, never()).recordAccessGranted(any(), any(), any());
            verify(accessCredentialAuditService).recordJwtIssued(any(), any(), eq(bookingInfo), any());
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
            when(accessAuthorizationProvisioningService.tryStart("0xreservation")).thenReturn(true);
            ReflectionTestUtils.setField(samlAuthService, "accessAuthorizationWaitTimeoutMs", 0L);

            assertThatThrownBy(() -> samlAuthService.issueAccessCredential(request))
                .isInstanceOf(decentralabs.blockchain.exception.AccessAuthorizationPendingException.class);

            verify(blockchainService).provisionGuacamoleAccess(bookingInfo, false);
            verify(blockchainService).deletePreparedGuacamoleAccess(bookingInfo);
            verify(accessAuthorizationProvisioningService).markRolledBack("0xreservation");
            verify(jwtService, never()).generateIssuedToken(eq(null), any());
            verify(accessCredentialAuditService, never()).recordJwtIssued(any(), any(), any(), any());
        }
    }
}
