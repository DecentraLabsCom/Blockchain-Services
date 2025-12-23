package decentralabs.blockchain.controller.auth;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;

import decentralabs.blockchain.dto.auth.AuthResponse;
import decentralabs.blockchain.dto.auth.CheckInResponse;
import decentralabs.blockchain.dto.auth.InstitutionalCheckInRequest;
import decentralabs.blockchain.dto.auth.SamlAuthRequest;
import decentralabs.blockchain.service.auth.InstitutionalCheckInService;
import decentralabs.blockchain.service.auth.SamlAuthService;

@WebMvcTest(controllers = SamlAuthController.class)
@AutoConfigureMockMvc(addFilters = false)
class SamlAuthControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private SamlAuthService samlAuthService;

    @MockitoBean
    private InstitutionalCheckInService institutionalCheckInService;

    @Test
    void shouldAuthenticateSaml() throws Exception {
        SamlAuthRequest request = createBaseRequest();

        when(samlAuthService.handleAuthentication(any(SamlAuthRequest.class), eq(false)))
            .thenReturn(new AuthResponse("jwt-token"));

        mockMvc.perform(post("/auth/saml-auth")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.token").value("jwt-token"));
    }

    @Test
    void shouldAuthenticateSamlWithLabId() throws Exception {
        SamlAuthRequest request = createBaseRequest();
        request.setLabId("lab-123");

        when(samlAuthService.handleAuthentication(any(SamlAuthRequest.class), eq(true)))
            .thenReturn(new AuthResponse("jwt-with-booking", "https://lab.example.com"));

        mockMvc.perform(post("/auth/saml-auth2")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.token").value("jwt-with-booking"))
            .andExpect(jsonPath("$.labURL").value("https://lab.example.com"));
    }

    @Test
    void shouldAuthenticateSamlWithReservationKey() throws Exception {
        SamlAuthRequest request = createBaseRequest();
        request.setReservationKey("0x" + "b".repeat(64));

        when(samlAuthService.handleAuthentication(any(SamlAuthRequest.class), eq(true)))
            .thenReturn(new AuthResponse("jwt-with-reservation"));

        mockMvc.perform(post("/auth/saml-auth2")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.token").value("jwt-with-reservation"));
    }

    @Test
    void shouldAcceptInstitutionalCheckIn() throws Exception {
        InstitutionalCheckInRequest request = new InstitutionalCheckInRequest();
        request.setReservationKey("0x" + "c".repeat(64));
        request.setSamlAssertion("assertion");

        CheckInResponse response = new CheckInResponse();
        response.setValid(true);

        when(institutionalCheckInService.checkIn(any(InstitutionalCheckInRequest.class)))
            .thenReturn(response);

        mockMvc.perform(post("/auth/checkin-institutional")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.valid").value(true));
    }

    private SamlAuthRequest createBaseRequest() {
        SamlAuthRequest request = new SamlAuthRequest();
        request.setMarketplaceToken("eyJhbGciOiJSUzI1NiJ9.token");
        request.setSamlAssertion("PHNhbWw+PC9zYW1sPg==");
        request.setTimestamp(System.currentTimeMillis());
        return request;
    }
}
