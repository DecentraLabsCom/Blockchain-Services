package decentralabs.blockchain.controller.auth;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import decentralabs.blockchain.service.BackendUrlResolver;
import decentralabs.blockchain.service.auth.InstitutionalCheckInService;
import decentralabs.blockchain.service.auth.KeyService;
import decentralabs.blockchain.service.auth.SamlAuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@ExtendWith(MockitoExtension.class)
class LegacyWalletAuthEndpointAbsenceTest {

    private MockMvc mockMvc;

    @InjectMocks
    private AuthController authController;

    @InjectMocks
    private SamlAuthController samlAuthController;

    @Mock
    private KeyService keyService;

    @Mock
    private BackendUrlResolver backendUrlResolver;

    @Mock
    private SamlAuthService samlAuthService;

    @Mock
    private InstitutionalCheckInService institutionalCheckInService;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(authController, "authPath", "/auth");
        ReflectionTestUtils.setField(authController, "samlAuth2Endpoint", "/auth/saml-auth2");
        ReflectionTestUtils.setField(authController, "jwksEndpoint", "/auth/jwks");

        mockMvc = MockMvcBuilders.standaloneSetup(authController, samlAuthController).build();
    }

    @Test
    void shouldNotExposeLegacyWalletMessageEndpoint() throws Exception {
        mockMvc.perform(get("/auth/message"))
            .andExpect(status().isNotFound());
    }

    @Test
    void shouldNotExposeLegacyWalletAuthEndpoint() throws Exception {
        mockMvc.perform(post("/auth/wallet-auth")
                .contentType("application/json")
                .content("{}"))
            .andExpect(status().isNotFound());
    }

    @Test
    void shouldNotExposeLegacyWalletAuth2Endpoint() throws Exception {
        mockMvc.perform(post("/auth/wallet-auth2")
                .contentType("application/json")
                .content("{}"))
            .andExpect(status().isNotFound());
    }
}
