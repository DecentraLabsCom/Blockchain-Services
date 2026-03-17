package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
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

    @InjectMocks
    private SamlAuthService samlAuthService;

    private static final String TEST_USER_ID = "user123";
    private static final String TEST_AFFILIATION = "test-university";

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(samlAuthService, "requireBookingScope", true);
        ReflectionTestUtils.setField(samlAuthService, "requiredBookingScope", "booking:read");
        lenient().when(marketplaceEndpointAuthService.enforceToken(anyString(), eq(null)))
            .thenReturn(Map.of("userid", TEST_USER_ID, "affiliation", TEST_AFFILIATION));
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
        @DisplayName("Should throw exception when JWT and SAML userid mismatch")
        void shouldThrowExceptionWhenUserIdMismatch() throws Exception {
            SamlAuthRequest request = createValidRequest();
            request.setMarketplaceToken("jwt-user-mismatch");
            when(marketplaceEndpointAuthService.enforceToken(eq("jwt-user-mismatch"), eq(null)))
                .thenReturn(Map.of("userid", TEST_USER_ID, "affiliation", TEST_AFFILIATION));
            when(samlValidationService.validateSamlAssertionWithSignature(anyString()))
                .thenReturn(Map.of("userid", "different-user", "affiliation", TEST_AFFILIATION));

            assertThatThrownBy(() -> samlAuthService.handleAuthentication(request, false))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("userid mismatch");
        }

        @Test
        @DisplayName("Should throw exception when JWT and SAML affiliation mismatch")
        void shouldThrowExceptionWhenAffiliationMismatch() throws Exception {
            SamlAuthRequest request = createValidRequest();
            request.setMarketplaceToken("jwt-affiliation-mismatch");
            when(marketplaceEndpointAuthService.enforceToken(eq("jwt-affiliation-mismatch"), eq(null)))
                .thenReturn(Map.of("userid", TEST_USER_ID, "affiliation", TEST_AFFILIATION));
            when(samlValidationService.validateSamlAssertionWithSignature(anyString()))
                .thenReturn(Map.of("userid", TEST_USER_ID, "affiliation", "different-affiliation"));

            assertThatThrownBy(() -> samlAuthService.handleAuthentication(request, false))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("affiliation mismatch");
        }

        @Test
        @DisplayName("Should throw exception when JWT userid is null")
        void shouldThrowExceptionWhenJwtUserIdIsNull() throws Exception {
            SamlAuthRequest request = createValidRequest();
            request.setMarketplaceToken("jwt-without-userid");
            when(marketplaceEndpointAuthService.enforceToken(eq("jwt-without-userid"), eq(null)))
                .thenReturn(Map.of("affiliation", TEST_AFFILIATION));
            when(samlValidationService.validateSamlAssertionWithSignature(anyString()))
                .thenReturn(Map.of("userid", TEST_USER_ID, "affiliation", TEST_AFFILIATION));

            assertThatThrownBy(() -> samlAuthService.handleAuthentication(request, false))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("userid mismatch");
        }

        @Test
        @DisplayName("Should throw exception when JWT affiliation is null")
        void shouldThrowExceptionWhenJwtAffiliationIsNull() throws Exception {
            SamlAuthRequest request = createValidRequest();
            request.setMarketplaceToken("jwt-without-affiliation");
            when(marketplaceEndpointAuthService.enforceToken(eq("jwt-without-affiliation"), eq(null)))
                .thenReturn(Map.of("userid", TEST_USER_ID));
            when(samlValidationService.validateSamlAssertionWithSignature(anyString()))
                .thenReturn(Map.of("userid", TEST_USER_ID, "affiliation", TEST_AFFILIATION));

            assertThatThrownBy(() -> samlAuthService.handleAuthentication(request, false))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("affiliation mismatch");
        }

        @Test
        @DisplayName("Should accept composite userid when JWT and SAML both use ePPN plus targeted ID")
        void shouldAcceptCompositeUserIdWhenBothSourcesMatch() throws Exception {
            SamlAuthRequest request = createValidRequest();
            String compositeUserId = "user@university.edu|targeted-user-1";
            request.setMarketplaceToken("jwt-composite-userid");
            when(marketplaceEndpointAuthService.enforceToken(eq("jwt-composite-userid"), eq(null)))
                .thenReturn(Map.of("userid", compositeUserId, "affiliation", TEST_AFFILIATION));
            when(samlValidationService.validateSamlAssertionWithSignature(anyString()))
                .thenReturn(Map.of("userid", compositeUserId, "affiliation", TEST_AFFILIATION));
            when(jwtService.generateToken(any(), eq(null))).thenReturn("generated-token");

            AuthResponse response = samlAuthService.handleAuthentication(request, false);

            assertThat(response).isNotNull();
            assertThat(response.getToken()).isEqualTo("generated-token");
        }

        @Test
        @DisplayName("Should accept userid mismatch in case only after normalization")
        void shouldAcceptUserIdWithDifferentCaseAfterNormalization() throws Exception {
            SamlAuthRequest request = createValidRequest();
            request.setMarketplaceToken("jwt-case-diff");
            when(marketplaceEndpointAuthService.enforceToken(eq("jwt-case-diff"), eq(null)))
                .thenReturn(Map.of("userid", "User@University.EDU|Targeted-User", "affiliation", TEST_AFFILIATION));
            when(samlValidationService.validateSamlAssertionWithSignature(anyString()))
                .thenReturn(Map.of("userid", "user@university.edu|targeted-user", "affiliation", TEST_AFFILIATION));
            when(jwtService.generateToken(any(), eq(null))).thenReturn("generated-token");

            AuthResponse response = samlAuthService.handleAuthentication(request, false);

            assertThat(response).isNotNull();
            assertThat(response.getToken()).isEqualTo("generated-token");
        }

        @Test
        @DisplayName("Should accept ePPN-only userid when JWT and SAML both use ePPN")
        void shouldAcceptEppnOnlyUserIdWhenBothSourcesMatch() throws Exception {
            SamlAuthRequest request = createValidRequest();
            String eppnOnlyUserId = "user@university.edu";
            request.setMarketplaceToken("jwt-eppn-only-userid");
            when(marketplaceEndpointAuthService.enforceToken(eq("jwt-eppn-only-userid"), eq(null)))
                .thenReturn(Map.of("userid", eppnOnlyUserId, "affiliation", TEST_AFFILIATION));
            when(samlValidationService.validateSamlAssertionWithSignature(anyString()))
                .thenReturn(Map.of("userid", eppnOnlyUserId, "affiliation", TEST_AFFILIATION));
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
                .thenReturn(Map.of("userid", TEST_USER_ID, "affiliation", TEST_AFFILIATION));
            when(samlValidationService.validateSamlAssertionWithSignature(anyString()))
                .thenReturn(Map.of("userid", TEST_USER_ID, "affiliation", TEST_AFFILIATION));
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
                .thenReturn(Map.of("userid", TEST_USER_ID, "affiliation", TEST_AFFILIATION));
            when(samlValidationService.validateSamlAssertionWithSignature(anyString()))
                .thenReturn(Map.of("userid", TEST_USER_ID, "affiliation", TEST_AFFILIATION));

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
                    "userid", TEST_USER_ID,
                    "affiliation", TEST_AFFILIATION,
                    "bookingInfoAllowed", true,
                    "institutionalProviderWallet", "0xwallet",
                    "puc", "puc123"
                ));
            when(samlValidationService.validateSamlAssertionWithSignature(anyString()))
                .thenReturn(Map.of("userid", TEST_USER_ID, "affiliation", TEST_AFFILIATION));
            when(blockchainService.getBookingInfo(anyString(), anyString(), any(), anyString()))
                .thenReturn(Map.of("labURL", "https://lab.example.com"));
            when(jwtService.generateToken(eq(null), any())).thenReturn("booking-token");

            AuthResponse response = samlAuthService.handleAuthentication(request, true);

            assertThat(response).isNotNull();
            assertThat(response.getToken()).isEqualTo("booking-token");
        }

        @Test
        @DisplayName("Should allow booking info when scope contains required scope as string")
        void shouldAllowBookingInfoWhenScopeContainsRequired() throws Exception {
            SamlAuthRequest request = createValidRequest();
            request.setReservationKey("0xreservation");
            request.setMarketplaceToken("jwt-with-scope");
            when(marketplaceEndpointAuthService.enforceToken(eq("jwt-with-scope"), eq(null)))
                .thenReturn(Map.of(
                    "userid", TEST_USER_ID,
                    "affiliation", TEST_AFFILIATION,
                    "scope", "read booking:read write",
                    "institutionalProviderWallet", "0xwallet",
                    "puc", "puc123"
                ));
            when(samlValidationService.validateSamlAssertionWithSignature(anyString()))
                .thenReturn(Map.of("userid", TEST_USER_ID, "affiliation", TEST_AFFILIATION));
            when(blockchainService.getBookingInfo(anyString(), anyString(), any(), anyString()))
                .thenReturn(Map.of("labURL", "https://lab.example.com"));
            when(jwtService.generateToken(eq(null), any())).thenReturn("booking-token");

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
                    "userid", TEST_USER_ID,
                    "affiliation", TEST_AFFILIATION,
                    "scopes", List.of("read", "booking:read", "write"),
                    "institutionalProviderWallet", "0xwallet",
                    "puc", "puc123"
                ));
            when(samlValidationService.validateSamlAssertionWithSignature(anyString()))
                .thenReturn(Map.of("userid", TEST_USER_ID, "affiliation", TEST_AFFILIATION));
            when(blockchainService.getBookingInfo(anyString(), anyString(), any(), anyString()))
                .thenReturn(Map.of("labURL", "https://lab.example.com"));
            when(jwtService.generateToken(eq(null), any())).thenReturn("booking-token");

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
                    "userid", TEST_USER_ID,
                    "affiliation", TEST_AFFILIATION,
                    "institutionalProviderWallet", "0xwallet",
                    "puc", "puc123"
                ));
            when(samlValidationService.validateSamlAssertionWithSignature(anyString()))
                .thenReturn(Map.of("userid", TEST_USER_ID, "affiliation", TEST_AFFILIATION));
            when(blockchainService.getBookingInfo(anyString(), anyString(), any(), anyString()))
                .thenReturn(Map.of("labURL", "https://lab.example.com"));
            when(jwtService.generateToken(eq(null), any())).thenReturn("booking-token");

            AuthResponse response = samlAuthService.handleAuthentication(request, true);

            assertThat(response).isNotNull();
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
