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

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ResponseStatusException;

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

    @InjectMocks
    private SamlAuthService samlAuthService;

    private static final String TEST_USER_ID = "user123";
    private static final String TEST_PUC = TEST_USER_ID;
    private static final String TEST_AFFILIATION = "test-university";

    @BeforeEach
    void setUp() throws Exception {
        ReflectionTestUtils.setField(samlAuthService, "requireBookingScope", true);
        ReflectionTestUtils.setField(samlAuthService, "requiredBookingScope", "booking:read");
        lenient().when(marketplaceEndpointAuthService.enforceToken(anyString(), eq(null)))
            .thenReturn(Map.of("puc", TEST_PUC, "affiliation", TEST_AFFILIATION));
        lenient().when(jwtService.generateIssuedToken(eq(null), any()))
            .thenReturn(new JwtService.IssuedToken("booking-token", "jwt-jti-default", 1_700_000_000L, null));
    }

    @Nested
    @DisplayName("Input Validation Tests")
    class InputValidationTests {

        @Test
        @DisplayName("Should throw exception when marketplace token is null")
        void shouldThrowExceptionWhenMarketplaceTokenIsNull() {
            SamlAuthRequest request = new SamlAuthRequest();
            request.setMarketplaceToken(null);
            request.setSamlAssertion("valid-saml");

            assertThatThrownBy(() -> samlAuthService.handleAuthentication(request, false))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Missing marketplaceToken");
        }

        @Test
        @DisplayName("Should throw exception when marketplace token is empty")
        void shouldThrowExceptionWhenMarketplaceTokenIsEmpty() {
            SamlAuthRequest request = new SamlAuthRequest();
            request.setMarketplaceToken("");
            request.setSamlAssertion("valid-saml");

            assertThatThrownBy(() -> samlAuthService.handleAuthentication(request, false))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Missing marketplaceToken");
        }

        @Test
        @DisplayName("Should throw exception when SAML assertion is null")
        void shouldThrowExceptionWhenSamlAssertionIsNull() {
            SamlAuthRequest request = new SamlAuthRequest();
            request.setMarketplaceToken("valid-token");
            request.setSamlAssertion(null);

            assertThatThrownBy(() -> samlAuthService.handleAuthentication(request, false))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Missing samlAssertion");
        }

        @Test
        @DisplayName("Should throw exception when SAML assertion is empty")
        void shouldThrowExceptionWhenSamlAssertionIsEmpty() {
            SamlAuthRequest request = new SamlAuthRequest();
            request.setMarketplaceToken("valid-token");
            request.setSamlAssertion("");

            assertThatThrownBy(() -> samlAuthService.handleAuthentication(request, false))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Missing samlAssertion");
        }
    }

    @Nested
    @DisplayName("JWT Validation Tests")
    class JwtValidationTests {

        @Test
        @DisplayName("Should throw exception when JWT validation fails")
        void shouldThrowExceptionWhenJwtValidationFails() throws Exception {
            SamlAuthRequest request = createValidRequest();
            when(marketplaceEndpointAuthService.enforceToken(eq("test-marketplace-token"), eq(null)))
                .thenThrow(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid_marketplace_token"));

            assertThatThrownBy(() -> samlAuthService.handleAuthentication(request, false))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("Invalid marketplace token");
        }

        @Test
        @DisplayName("Should throw exception when marketplace key unavailable")
        void shouldThrowExceptionWhenMarketplaceKeyUnavailable() throws Exception {
            SamlAuthRequest request = createValidRequest();
            when(marketplaceEndpointAuthService.enforceToken(eq("test-marketplace-token"), eq(null)))
                .thenThrow(new RuntimeException("Key not available"));

            assertThatThrownBy(() -> samlAuthService.handleAuthentication(request, false))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("Invalid marketplace token");
        }
    }

    @Nested
    @DisplayName("Cross-Validation Tests")
    class CrossValidationTests {

        @Test
        @DisplayName("Should throw exception when JWT puc and SAML identity mismatch")
        void shouldThrowExceptionWhenPucMismatch() throws Exception {
            SamlAuthRequest request = createValidRequest();
            request.setMarketplaceToken("jwt-puc-mismatch");
            when(marketplaceEndpointAuthService.enforceToken(eq("jwt-puc-mismatch"), eq(null)))
                .thenReturn(Map.of("puc", TEST_PUC, "affiliation", TEST_AFFILIATION));
            when(samlValidationService.validateSamlAssertionWithSignature(anyString()))
                .thenReturn(Map.of("puc", "different-user", "affiliation", TEST_AFFILIATION));

            assertThatThrownBy(() -> samlAuthService.handleAuthentication(request, false))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("puc mismatch");
        }

        @Test
        @DisplayName("Should throw exception when JWT and SAML affiliation mismatch")
        void shouldThrowExceptionWhenAffiliationMismatch() throws Exception {
            SamlAuthRequest request = createValidRequest();
            request.setMarketplaceToken("jwt-affiliation-mismatch");
            when(marketplaceEndpointAuthService.enforceToken(eq("jwt-affiliation-mismatch"), eq(null)))
                .thenReturn(Map.of("puc", TEST_PUC, "affiliation", TEST_AFFILIATION));
            when(samlValidationService.validateSamlAssertionWithSignature(anyString()))
                .thenReturn(Map.of("puc", TEST_USER_ID, "affiliation", "different-affiliation"));

            assertThatThrownBy(() -> samlAuthService.handleAuthentication(request, false))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("affiliation mismatch");
        }

        @Test
        @DisplayName("Should throw exception when JWT puc is null")
        void shouldThrowExceptionWhenJwtPucIsNull() throws Exception {
            SamlAuthRequest request = createValidRequest();
            request.setMarketplaceToken("jwt-without-puc");
            when(marketplaceEndpointAuthService.enforceToken(eq("jwt-without-puc"), eq(null)))
                .thenReturn(Map.of("affiliation", TEST_AFFILIATION));
            when(samlValidationService.validateSamlAssertionWithSignature(anyString()))
                .thenReturn(Map.of("puc", TEST_USER_ID, "affiliation", TEST_AFFILIATION));

            assertThatThrownBy(() -> samlAuthService.handleAuthentication(request, false))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("puc mismatch");
        }

        @Test
        @DisplayName("Should throw exception when JWT affiliation is null")
        void shouldThrowExceptionWhenJwtAffiliationIsNull() throws Exception {
            SamlAuthRequest request = createValidRequest();
            request.setMarketplaceToken("jwt-without-affiliation");
            when(marketplaceEndpointAuthService.enforceToken(eq("jwt-without-affiliation"), eq(null)))
                .thenReturn(Map.of("puc", TEST_PUC));
            when(samlValidationService.validateSamlAssertionWithSignature(anyString()))
                .thenReturn(Map.of("puc", TEST_USER_ID, "affiliation", TEST_AFFILIATION));

            assertThatThrownBy(() -> samlAuthService.handleAuthentication(request, false))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("affiliation mismatch");
        }

        @Test
        @DisplayName("Should accept composite puc when JWT and SAML both use ePPN plus targeted ID")
        void shouldAcceptCompositePucWhenBothSourcesMatch() throws Exception {
            SamlAuthRequest request = createValidRequest();
            String compositePuc = "user@university.edu|targeted-user-1";
            request.setMarketplaceToken("jwt-composite-puc");
            when(marketplaceEndpointAuthService.enforceToken(eq("jwt-composite-puc"), eq(null)))
                .thenReturn(Map.of("puc", compositePuc, "affiliation", TEST_AFFILIATION));
            when(samlValidationService.validateSamlAssertionWithSignature(anyString()))
                .thenReturn(Map.of("puc", compositePuc, "affiliation", TEST_AFFILIATION));
            when(jwtService.generateToken(any(), eq(null))).thenReturn("generated-token");

            AuthResponse response = samlAuthService.handleAuthentication(request, false);

            assertThat(response).isNotNull();
            assertThat(response.getToken()).isEqualTo("generated-token");
        }

        @Test
        @DisplayName("Should accept puc mismatch in case only after normalization")
        void shouldAcceptPucWithDifferentCaseAfterNormalization() throws Exception {
            SamlAuthRequest request = createValidRequest();
            request.setMarketplaceToken("jwt-case-diff");
            when(marketplaceEndpointAuthService.enforceToken(eq("jwt-case-diff"), eq(null)))
                .thenReturn(Map.of("puc", "User@University.EDU|Targeted-User", "affiliation", TEST_AFFILIATION));
            when(samlValidationService.validateSamlAssertionWithSignature(anyString()))
                .thenReturn(Map.of("puc", "user@university.edu|targeted-user", "affiliation", TEST_AFFILIATION));
            when(jwtService.generateToken(any(), eq(null))).thenReturn("generated-token");

            AuthResponse response = samlAuthService.handleAuthentication(request, false);

            assertThat(response).isNotNull();
            assertThat(response.getToken()).isEqualTo("generated-token");
        }

        @Test
        @DisplayName("Should accept ePPN-only puc when JWT and SAML both use ePPN")
        void shouldAcceptEppnOnlyPucWhenBothSourcesMatch() throws Exception {
            SamlAuthRequest request = createValidRequest();
            String eppnOnlyPuc = "user@university.edu";
            request.setMarketplaceToken("jwt-eppn-only-puc");
            when(marketplaceEndpointAuthService.enforceToken(eq("jwt-eppn-only-puc"), eq(null)))
                .thenReturn(Map.of("puc", eppnOnlyPuc, "affiliation", TEST_AFFILIATION));
            when(samlValidationService.validateSamlAssertionWithSignature(anyString()))
                .thenReturn(Map.of("puc", eppnOnlyPuc, "affiliation", TEST_AFFILIATION));
            when(jwtService.generateToken(any(), eq(null))).thenReturn("generated-token");

            AuthResponse response = samlAuthService.handleAuthentication(request, false);

            assertThat(response).isNotNull();
            assertThat(response.getToken()).isEqualTo("generated-token");
        }
    }

    @Nested
    @DisplayName("Booking Scope Enforcement Tests")
    class BookingScopeTests {

        @Test
        @DisplayName("Should generate simple token when booking info not requested")
        void shouldGenerateSimpleTokenWhenBookingInfoNotRequested() throws Exception {
            SamlAuthRequest request = createValidRequest();
            request.setMarketplaceToken("jwt-simple-token");
            when(marketplaceEndpointAuthService.enforceToken(eq("jwt-simple-token"), eq(null)))
                .thenReturn(Map.of("puc", TEST_PUC, "affiliation", TEST_AFFILIATION));
            when(samlValidationService.validateSamlAssertionWithSignature(anyString()))
                .thenReturn(Map.of("puc", TEST_USER_ID, "affiliation", TEST_AFFILIATION));
            when(jwtService.generateToken(any(), eq(null))).thenReturn("generated-token");

            AuthResponse response = samlAuthService.handleAuthentication(request, false);

            assertThat(response).isNotNull();
            assertThat(response.getToken()).isEqualTo("generated-token");
        }

        @Test
        @DisplayName("Should throw exception when booking scope required but missing")
        void shouldThrowExceptionWhenBookingScopeRequiredButMissing() throws Exception {
            SamlAuthRequest request = createValidRequest();
            request.setMarketplaceToken("jwt-missing-scope");
            when(marketplaceEndpointAuthService.enforceToken(eq("jwt-missing-scope"), eq(null)))
                .thenReturn(Map.of("puc", TEST_PUC, "affiliation", TEST_AFFILIATION));
            when(samlValidationService.validateSamlAssertionWithSignature(anyString()))
                .thenReturn(Map.of("puc", TEST_USER_ID, "affiliation", TEST_AFFILIATION));

            assertThatThrownBy(() -> samlAuthService.handleAuthentication(request, true))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("missing required scope");
        }

        @Test
        @DisplayName("Should allow booking info when bookingInfoAllowed claim is true")
        void shouldAllowBookingInfoWhenClaimIsTrue() throws Exception {
            SamlAuthRequest request = createValidRequest();
            request.setReservationKey("0xreservation");
            request.setMarketplaceToken("jwt-booking-allowed");
            when(marketplaceEndpointAuthService.enforceToken(eq("jwt-booking-allowed"), eq(null)))
                .thenReturn(Map.of(
                    "puc", TEST_PUC,
                    "affiliation", TEST_AFFILIATION,
                    "bookingInfoAllowed", true,
                    "institutionalProviderWallet", "0xwallet"
                ));
            when(samlValidationService.validateSamlAssertionWithSignature(anyString()))
                .thenReturn(Map.of("puc", TEST_USER_ID, "affiliation", TEST_AFFILIATION));
            Map<String, Object> bookingInfo = Map.of(
                "labURL", "https://lab.example.com",
                "reservationKey", "0xreservation",
                "reservationStatus", java.math.BigInteger.ONE
            );
            when(blockchainService.getBookingInfo(anyString(), anyString(), any(), anyString()))
                .thenReturn(bookingInfo);
            when(jwtService.generateIssuedToken(eq(null), any())).thenReturn(
                new JwtService.IssuedToken("booking-token", "jwt-jti-1", 1_700_000_000L, null)
            );

            AuthResponse response = samlAuthService.handleAuthentication(request, true);

            assertThat(response).isNotNull();
            assertThat(response.getToken()).isEqualTo("booking-token");
            verify(accessCheckInCoordinator).recordAccessGranted(eq(request), any(), eq(bookingInfo));
            verify(accessCredentialAuditService).recordJwtIssued(eq(request), any(), eq(bookingInfo), any());
        }

        @Test
        @DisplayName("Should allow booking info when reservation access is already authorized")
        void shouldAllowBookingInfoWhenReservationAccessAlreadyAuthorized() throws Exception {
            SamlAuthRequest request = createValidRequest();
            request.setReservationKey("0xreservation");
            request.setMarketplaceToken("jwt-booking-access-authorized");
            when(marketplaceEndpointAuthService.enforceToken(eq("jwt-booking-access-authorized"), eq(null)))
                .thenReturn(Map.of(
                    "puc", TEST_PUC,
                    "affiliation", TEST_AFFILIATION,
                    "bookingInfoAllowed", true,
                    "institutionalProviderWallet", "0xwallet"
                ));
            when(samlValidationService.validateSamlAssertionWithSignature(anyString()))
                .thenReturn(Map.of("puc", TEST_USER_ID, "affiliation", TEST_AFFILIATION));
            Map<String, Object> bookingInfo = Map.of(
                "labURL", "https://lab.example.com",
                "reservationKey", "0xreservation",
                "reservationStatus", java.math.BigInteger.valueOf(2)
            );
            when(blockchainService.getBookingInfo(anyString(), anyString(), any(), anyString()))
                .thenReturn(bookingInfo);
            when(jwtService.generateIssuedToken(eq(null), any())).thenReturn(
                new JwtService.IssuedToken("booking-token", "jwt-jti-access-authorized", 1_700_000_000L, null)
            );

            AuthResponse response = samlAuthService.handleAuthentication(request, true);

            assertThat(response).isNotNull();
            assertThat(response.getToken()).isEqualTo("booking-token");
            verify(accessCheckInCoordinator).recordAccessGranted(eq(request), any(), eq(bookingInfo));
        }

        @Test
        @DisplayName("Should not issue JWT if durable check-in coordination fails")
        void shouldNotIssueJwtWhenCheckInCoordinationFails() throws Exception {
            SamlAuthRequest request = createValidRequest();
            request.setReservationKey("0xreservation");
            request.setMarketplaceToken("jwt-outbox-fail");
            when(marketplaceEndpointAuthService.enforceToken(eq("jwt-outbox-fail"), eq(null)))
                .thenReturn(Map.of(
                    "puc", TEST_PUC,
                    "affiliation", TEST_AFFILIATION,
                    "bookingInfoAllowed", true,
                    "institutionalProviderWallet", "0xwallet"
                ));
            when(samlValidationService.validateSamlAssertionWithSignature(anyString()))
                .thenReturn(Map.of("puc", TEST_USER_ID, "affiliation", TEST_AFFILIATION));
            Map<String, Object> bookingInfo = Map.of(
                "labURL", "https://lab.example.com",
                "reservationKey", "0xreservation",
                "reservationStatus", java.math.BigInteger.ONE
            );
            when(blockchainService.getBookingInfo(anyString(), anyString(), any(), anyString()))
                .thenReturn(bookingInfo);
            org.mockito.Mockito.doThrow(new IllegalStateException("outbox unavailable"))
                .when(accessCheckInCoordinator).recordAccessGranted(eq(request), any(), any());

            assertThatThrownBy(() -> samlAuthService.handleAuthentication(request, true))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("outbox unavailable");
        }

        @Test
        @DisplayName("Should allow booking info when scope contains required scope as string")
        void shouldAllowBookingInfoWhenScopeContainsRequired() throws Exception {
            SamlAuthRequest request = createValidRequest();
            request.setReservationKey("0xreservation");
            request.setMarketplaceToken("jwt-with-scope");
            when(marketplaceEndpointAuthService.enforceToken(eq("jwt-with-scope"), eq(null)))
                .thenReturn(Map.of(
                    "puc", TEST_PUC,
                    "affiliation", TEST_AFFILIATION,
                    "scope", "read booking:read write",
                    "institutionalProviderWallet", "0xwallet"
                ));
            when(samlValidationService.validateSamlAssertionWithSignature(anyString()))
                .thenReturn(Map.of("puc", TEST_USER_ID, "affiliation", TEST_AFFILIATION));
            when(blockchainService.getBookingInfo(anyString(), anyString(), any(), anyString()))
                .thenReturn(Map.of("labURL", "https://lab.example.com"));
            when(jwtService.generateIssuedToken(eq(null), any())).thenReturn(
                new JwtService.IssuedToken("booking-token", "jwt-jti-scope", 1_700_000_000L, null)
            );

            AuthResponse response = samlAuthService.handleAuthentication(request, true);

            assertThat(response).isNotNull();
        }

        @Test
        @DisplayName("Should allow booking info when scopes list contains required scope")
        void shouldAllowBookingInfoWhenScopesListContainsRequired() throws Exception {
            SamlAuthRequest request = createValidRequest();
            request.setReservationKey("0xreservation");
            request.setMarketplaceToken("jwt-with-scopes");
            when(marketplaceEndpointAuthService.enforceToken(eq("jwt-with-scopes"), eq(null)))
                .thenReturn(Map.of(
                    "puc", TEST_PUC,
                    "affiliation", TEST_AFFILIATION,
                    "scopes", List.of("read", "booking:read", "write"),
                    "institutionalProviderWallet", "0xwallet"
                ));
            when(samlValidationService.validateSamlAssertionWithSignature(anyString()))
                .thenReturn(Map.of("puc", TEST_USER_ID, "affiliation", TEST_AFFILIATION));
            when(blockchainService.getBookingInfo(anyString(), anyString(), any(), anyString()))
                .thenReturn(Map.of("labURL", "https://lab.example.com"));
            when(jwtService.generateIssuedToken(eq(null), any())).thenReturn(
                new JwtService.IssuedToken("booking-token", "jwt-jti-scopes", 1_700_000_000L, null)
            );

            AuthResponse response = samlAuthService.handleAuthentication(request, true);

            assertThat(response).isNotNull();
        }

        @Test
        @DisplayName("Should skip scope check when requireBookingScope is false")
        void shouldSkipScopeCheckWhenNotRequired() throws Exception {
            ReflectionTestUtils.setField(samlAuthService, "requireBookingScope", false);

            SamlAuthRequest request = createValidRequest();
            request.setReservationKey("0xreservation");
            request.setMarketplaceToken("jwt-no-scope-required");
            when(marketplaceEndpointAuthService.enforceToken(eq("jwt-no-scope-required"), eq(null)))
                .thenReturn(Map.of(
                    "puc", TEST_PUC,
                    "affiliation", TEST_AFFILIATION,
                    "institutionalProviderWallet", "0xwallet"
                ));
            when(samlValidationService.validateSamlAssertionWithSignature(anyString()))
                .thenReturn(Map.of("puc", TEST_USER_ID, "affiliation", TEST_AFFILIATION));
            when(blockchainService.getBookingInfo(anyString(), anyString(), any(), anyString()))
                .thenReturn(Map.of("labURL", "https://lab.example.com"));
            when(jwtService.generateIssuedToken(eq(null), any())).thenReturn(
                new JwtService.IssuedToken("booking-token", "jwt-jti-no-scope-required", 1_700_000_000L, null)
            );

            AuthResponse response = samlAuthService.handleAuthentication(request, true);

            assertThat(response).isNotNull();
        }
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
                    "puc", TEST_PUC,
                    "affiliation", TEST_AFFILIATION,
                    "bookingInfoAllowed", true,
                    "purpose", "lab_access",
                    "reservationKey", "0xreservation",
                    "labId", "42",
                    "institutionalProviderWallet", "0xwallet"
                ));
            Map<String, Object> bookingInfo = Map.of(
                "labURL", "https://lab.example.com",
                "reservationKey", "0xreservation",
                "reservationStatus", java.math.BigInteger.valueOf(2)
            );
            when(blockchainService.getAccessAuthorizedBookingInfo("0xwallet", "0xreservation", "42", TEST_PUC))
                .thenReturn(bookingInfo);
            when(jwtService.generateIssuedToken(eq(null), any())).thenReturn(
                new JwtService.IssuedToken("booking-token", "jwt-jti-provider", 1_700_000_000L, null)
            );

            AuthResponse response = samlAuthService.issueAccessCredential(request);

            assertThat(response).isNotNull();
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
                    "puc", TEST_PUC,
                    "affiliation", TEST_AFFILIATION,
                    "bookingInfoAllowed", true,
                    "purpose", "lab_access",
                    "reservationKey", "0xother",
                    "institutionalProviderWallet", "0xwallet"
                ));

            assertThatThrownBy(() -> samlAuthService.issueAccessCredential(request))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("reservationKey mismatch");
        }
    }

    // Helper methods

    private SamlAuthRequest createValidRequest() {
        SamlAuthRequest request = new SamlAuthRequest();
        request.setMarketplaceToken("test-marketplace-token");
        request.setSamlAssertion("dGVzdC1zYW1sLWFzc2VydGlvbg=="); // base64 encoded
        return request;
    }
}
