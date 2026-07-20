package decentralabs.blockchain.controller.auth;

import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Collections;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import com.fasterxml.jackson.databind.ObjectMapper;

import decentralabs.blockchain.service.auth.MarketplaceEndpointAuthService;
import decentralabs.blockchain.dto.auth.WebauthnRevokeRequest;
import decentralabs.blockchain.service.auth.WebauthnCredentialService;

/**
 * Unit tests for WebauthnController.
 * Tests WebAuthn credential registration and revocation endpoints.
 */
@ExtendWith(MockitoExtension.class)
class WebauthnControllerTest {

    @Mock
    private WebauthnCredentialService credentialService;

    @Mock
    private MarketplaceEndpointAuthService marketplaceEndpointAuthService;

    @InjectMocks
    private WebauthnController webauthnController;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(webauthnController).build();
        objectMapper = new ObjectMapper();
        lenient().when(marketplaceEndpointAuthService.enforceAuthorization(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any()))
            .thenReturn(Collections.emptyMap());
    }

    @Nested
    @DisplayName("Revoke Credential Endpoint Tests")
    class RevokeCredentialTests {

        @Test
        @DisplayName("Should revoke credential successfully")
        void shouldRevokeCredentialSuccessfully() throws Exception {
            WebauthnRevokeRequest request = createValidRevokeRequest();

            doNothing().when(credentialService).revoke(
                request.getPuc(),
                request.getCredentialId()
            );

            mockMvc.perform(post("/webauthn/revoke")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());

            verify(credentialService).revoke(request.getPuc(), request.getCredentialId());
        }

        @Test
        @DisplayName("Should reject revocation with missing puc")
        void shouldRejectRevocationWithMissingPuc() throws Exception {
            WebauthnRevokeRequest request = createValidRevokeRequest();
            request.setPuc(null);

            mockMvc.perform(post("/webauthn/revoke")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
        }

        @Test
        @DisplayName("Should reject revocation with empty credentialId")
        void shouldRejectRevocationWithEmptyCredentialId() throws Exception {
            WebauthnRevokeRequest request = createValidRevokeRequest();
            request.setCredentialId("");

            mockMvc.perform(post("/webauthn/revoke")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
        }
    }

    private WebauthnRevokeRequest createValidRevokeRequest() {
        WebauthnRevokeRequest request = new WebauthnRevokeRequest();
        request.setPuc("user-principal-claim-123");
        request.setCredentialId("credential-id-abc");
        return request;
    }
}
