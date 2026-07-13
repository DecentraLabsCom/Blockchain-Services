package decentralabs.blockchain.controller.auth;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.dto.auth.FmuSessionTicketIssueRequest;
import decentralabs.blockchain.dto.auth.FmuSessionTicketIssueResponse;
import decentralabs.blockchain.dto.auth.FmuSessionTicketRedeemRequest;
import decentralabs.blockchain.dto.auth.FmuSessionTicketRedeemResponse;
import decentralabs.blockchain.service.auth.AccessCredentialAuditService;
import decentralabs.blockchain.service.auth.FmuSessionTicketService;
import decentralabs.blockchain.service.auth.JwtService;
import decentralabs.blockchain.service.auth.SessionTicketException;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class FmuSessionTicketControllerTest {

    private StubFmuSessionTicketService sessionTicketService;
    private FmuSessionTicketController controller;
    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        sessionTicketService = new StubFmuSessionTicketService();
        controller = new FmuSessionTicketController(sessionTicketService);
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
        objectMapper = new ObjectMapper();
    }

    @Test
    void shouldIssueTicket() throws Exception {
        FmuSessionTicketIssueResponse response = new FmuSessionTicketIssueResponse();
        response.setSessionTicket("st_test");
        response.setExpiresAt(12345);
        response.setLabId("42");
        response.setReservationKey("0xabc");
        response.setOneTimeUse(true);
        sessionTicketService.issueResponse = response;

        FmuSessionTicketIssueRequest request = new FmuSessionTicketIssueRequest();
        request.setLabId("42");
        request.setReservationKey("0xabc");

        mockMvc.perform(post("/auth/fmu/session-ticket/issue")
                .header("Authorization", "Bearer token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.sessionTicket").value("st_test"));
    }

    @Test
    void shouldMapIssueErrors() throws Exception {
        sessionTicketService.issueException = new SessionTicketException(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "Invalid token");

        mockMvc.perform(post("/auth/fmu/session-ticket/issue")
                .header("Authorization", "Bearer token")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
    }

    @Test
    void shouldRedeemTicket() throws Exception {
        FmuSessionTicketRedeemResponse response = new FmuSessionTicketRedeemResponse();
        response.setClaims(Map.of("resourceType", "fmu", "accessKey", "test.fmu"));
        response.setExpiresAt(12345);
        sessionTicketService.redeemResponse = response;

        FmuSessionTicketRedeemRequest request = new FmuSessionTicketRedeemRequest();
        request.setSessionTicket("st_test");

        mockMvc.perform(post("/auth/fmu/session-ticket/redeem")
                .principal(new UsernamePasswordAuthenticationToken("lab.example", null))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.claims.resourceType").value("fmu"))
            .andExpect(jsonPath("$.expiresAt").value(12345));
        org.assertj.core.api.Assertions.assertThat(sessionTicketService.redeemGatewayId)
            .isEqualTo("lab.example");
    }

    private static final class StubFmuSessionTicketService extends FmuSessionTicketService {

        private FmuSessionTicketIssueResponse issueResponse;
        private FmuSessionTicketRedeemResponse redeemResponse;
        private RuntimeException issueException;
        private RuntimeException redeemException;
        private String redeemGatewayId;

        private StubFmuSessionTicketService() {
            super(
                Mockito.mock(JwtService.class),
                new StaticListableBeanFactory().getBeanProvider(org.springframework.jdbc.core.JdbcTemplate.class),
                Mockito.mock(AccessCredentialAuditService.class),
                Mockito.mock(decentralabs.blockchain.service.auth.AccessCodeTokenCipher.class)
            );
        }

        @Override
        public FmuSessionTicketIssueResponse issue(String bearerToken, FmuSessionTicketIssueRequest request) {
            if (issueException != null) {
                throw issueException;
            }
            return issueResponse;
        }

        @Override
        public FmuSessionTicketRedeemResponse redeem(
            FmuSessionTicketRedeemRequest request,
            String authenticatedGatewayId
        ) {
            if (redeemException != null) {
                throw redeemException;
            }
            redeemGatewayId = authenticatedGatewayId;
            return redeemResponse;
        }
    }
}
