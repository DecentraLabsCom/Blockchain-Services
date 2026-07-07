package decentralabs.blockchain.controller.auth;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.dto.auth.AccessCredentialSessionObservedRequest;
import decentralabs.blockchain.service.auth.AccessCredentialAuditService;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class AccessCredentialAuditControllerTest {

    private AccessCredentialAuditService auditService;
    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        auditService = Mockito.mock(AccessCredentialAuditService.class);
        mockMvc = MockMvcBuilders
            .standaloneSetup(new AccessCredentialAuditController(auditService))
            .build();
        objectMapper = new ObjectMapper();
    }

    @Test
    void shouldRecordSessionObserved() throws Exception {
        when(auditService.recordSessionObserved(any(AccessCredentialSessionObservedRequest.class))).thenReturn(true);

        AccessCredentialSessionObservedRequest request = new AccessCredentialSessionObservedRequest();
        request.setReservationKey("0xabc");
        request.setJwtJti("jwt-jti");
        request.setSessionId("guac-session-1");
        request.setGatewayId("gateway-a");
        request.setAccessType("guacamole");

        mockMvc.perform(post("/access-audit/internal/session-observed")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.recorded").value(true));

        verify(auditService).recordSessionObserved(any(AccessCredentialSessionObservedRequest.class));
    }

    @Test
    void shouldRejectObservationWithoutReservationKey() throws Exception {
        AccessCredentialSessionObservedRequest request = new AccessCredentialSessionObservedRequest();
        request.setJwtJti("jwt-jti");

        mockMvc.perform(post("/access-audit/internal/session-observed")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.code").value("INVALID_REQUEST"));
    }

    @Test
    void shouldRejectObservationWithoutCredentialIdentifier() throws Exception {
        AccessCredentialSessionObservedRequest request = new AccessCredentialSessionObservedRequest();
        request.setReservationKey("0xabc");

        mockMvc.perform(post("/access-audit/internal/session-observed")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.code").value("INVALID_REQUEST"));
    }

    @Test
    void shouldReturnReservationAuditSummary() throws Exception {
        AccessCredentialAuditService.AuditEntry entry = new AccessCredentialAuditService.AuditEntry(
            "0xabc",
            "42",
            "0xpuc",
            "guacamole",
            "jwt-jti",
            "user",
            null,
            "guac-session-1",
            "gateway-a",
            1_700_000_000L,
            1_700_003_600L,
            1_700_010_000L,
            "guacamole",
            "backend-a",
            "a".repeat(64)
        );
        when(auditService.findByReservationKey("0xabc")).thenReturn(List.of(entry));

        mockMvc.perform(get("/access-audit/internal/reservations/{reservationKey}", "0xabc"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.reservationKey").value("0xabc"))
            .andExpect(jsonPath("$.credentialIssued").value(true))
            .andExpect(jsonPath("$.sessionObserved").value(true))
            .andExpect(jsonPath("$.entries[0].credentialHash").value("a".repeat(64)))
            .andExpect(jsonPath("$.entries[0].sessionId").value("guac-session-1"));

        verify(auditService).findByReservationKey(eq("0xabc"));
    }
}
