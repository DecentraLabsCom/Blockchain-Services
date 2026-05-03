package decentralabs.blockchain.controller.auth;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.service.auth.JwtService;
import decentralabs.blockchain.service.auth.MarketplaceEndpointAuthService;
import java.util.Collections;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.server.ResponseStatusException;

/**
 * Unit tests for {@link FmuProviderDescribeController}.
 *
 * <p>Uses standaloneSetup so the full Spring context is not required; security
 * is handled by the controller itself via {@link MarketplaceEndpointAuthService}.
 */
class FmuProviderDescribeControllerTest {

    private MarketplaceEndpointAuthService authService;
    private JwtService jwtService;
    private FmuProviderDescribeController controller;
    private MockMvc mockMvc;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        authService = mock(MarketplaceEndpointAuthService.class);
        jwtService = mock(JwtService.class);
        controller = new FmuProviderDescribeController(authService, jwtService);
        ReflectionTestUtils.setField(controller, "ttlSeconds", 60);
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    // ── Authorization failures ─────────────────────────────────────────────

    @Test
    void missingAuthorizationHeaderReturns401() throws Exception {
        when(authService.enforceAuthorization(isNull(), isNull()))
            .thenThrow(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "missing_marketplace_token"));

        mockMvc.perform(post("/auth/fmu/provider-describe-token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("fmuFileName", "Test.fmu"))))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.error").value("missing_marketplace_token"));
    }

    @Test
    void invalidMarketplaceTokenReturns401() throws Exception {
        when(authService.enforceAuthorization(any(), isNull()))
            .thenThrow(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid_marketplace_token"));

        mockMvc.perform(post("/auth/fmu/provider-describe-token")
                .header("Authorization", "Bearer expired.token.here")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("fmuFileName", "Test.fmu"))))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.error").value("invalid_marketplace_token"));
    }

    // ── Validation failures ────────────────────────────────────────────────

    @Test
    void missingBodyReturns400() throws Exception {
        when(authService.enforceAuthorization(any(), isNull())).thenReturn(Collections.emptyMap());

        mockMvc.perform(post("/auth/fmu/provider-describe-token")
                .header("Authorization", "Bearer valid.token")
                .contentType(MediaType.APPLICATION_JSON))
            .andExpect(status().isBadRequest());
    }

    @Test
    void missingFmuFileNameReturns400() throws Exception {
        when(authService.enforceAuthorization(any(), isNull())).thenReturn(Collections.emptyMap());

        mockMvc.perform(post("/auth/fmu/provider-describe-token")
                .header("Authorization", "Bearer valid.token")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value("Missing fmuFileName"));
    }

    @Test
    void blankFmuFileNameReturns400() throws Exception {
        when(authService.enforceAuthorization(any(), isNull())).thenReturn(Collections.emptyMap());

        mockMvc.perform(post("/auth/fmu/provider-describe-token")
                .header("Authorization", "Bearer valid.token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("fmuFileName", "   "))))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value("Missing fmuFileName"));
    }

    @Test
    void fmuFileNameWithoutDotFmuExtensionReturns400() throws Exception {
        when(authService.enforceAuthorization(any(), isNull())).thenReturn(Collections.emptyMap());

        mockMvc.perform(post("/auth/fmu/provider-describe-token")
                .header("Authorization", "Bearer valid.token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("fmuFileName", "BouncingBall.zip"))))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value("fmuFileName must end with .fmu"));
    }

    @Test
    void fmuFileNameCaseInsensitiveExtensionAccepted() throws Exception {
        when(authService.enforceAuthorization(any(), isNull())).thenReturn(Collections.emptyMap());
        when(jwtService.generateToken(any(), isNull())).thenReturn("signed.jwt.token");

        mockMvc.perform(post("/auth/fmu/provider-describe-token")
                .header("Authorization", "Bearer valid.token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("fmuFileName", "BouncingBall.FMU"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.token").value("signed.jwt.token"))
            .andExpect(jsonPath("$.expiresIn").value(60));
    }

    // ── Success path ───────────────────────────────────────────────────────

    @Test
    void validRequestReturnsTokenAndExpiresIn() throws Exception {
        when(authService.enforceAuthorization(any(), isNull())).thenReturn(Collections.emptyMap());
        when(jwtService.generateToken(any(), isNull())).thenReturn("signed.jwt.token");

        mockMvc.perform(post("/auth/fmu/provider-describe-token")
                .header("Authorization", "Bearer valid.token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("fmuFileName", "Dahlquist.fmu"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.token").value("signed.jwt.token"))
            .andExpect(jsonPath("$.expiresIn").value(60));
    }

    @Test
    void tokenClaimsContainAccessKeyAndResourceType() throws Exception {
        when(authService.enforceAuthorization(any(), isNull())).thenReturn(Collections.emptyMap());

        @SuppressWarnings("unchecked")
        java.util.concurrent.atomic.AtomicReference<Map<String, Object>> capturedClaims =
            new java.util.concurrent.atomic.AtomicReference<>();

        when(jwtService.generateToken(any(), isNull())).thenAnswer(inv -> {
            capturedClaims.set(inv.getArgument(0));
            return "token";
        });

        mockMvc.perform(post("/auth/fmu/provider-describe-token")
                .header("Authorization", "Bearer valid.token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("fmuFileName", "BouncingBall.fmu"))))
            .andExpect(status().isOk());

        Map<String, Object> claims = capturedClaims.get();
        assert "BouncingBall.fmu".equals(claims.get("accessKey")) :
            "Expected accessKey=BouncingBall.fmu, got " + claims.get("accessKey");
        assert "fmu".equals(claims.get("resourceType")) :
            "Expected resourceType=fmu, got " + claims.get("resourceType");
    }

    @Test
    void fmuFileNameIsTrimmedBeforeStoringInClaims() throws Exception {
        when(authService.enforceAuthorization(any(), isNull())).thenReturn(Collections.emptyMap());

        @SuppressWarnings("unchecked")
        java.util.concurrent.atomic.AtomicReference<Map<String, Object>> capturedClaims =
            new java.util.concurrent.atomic.AtomicReference<>();

        when(jwtService.generateToken(any(), isNull())).thenAnswer(inv -> {
            capturedClaims.set(inv.getArgument(0));
            return "token";
        });

        mockMvc.perform(post("/auth/fmu/provider-describe-token")
                .header("Authorization", "Bearer valid.token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("fmuFileName", "  BouncingBall.fmu  "))))
            .andExpect(status().isOk());

        assert "BouncingBall.fmu".equals(capturedClaims.get().get("accessKey")) :
            "Expected trimmed accessKey, got " + capturedClaims.get().get("accessKey");
    }
}
