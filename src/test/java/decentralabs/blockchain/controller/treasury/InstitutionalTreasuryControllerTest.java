package decentralabs.blockchain.controller.treasury;

import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.controller.TestSecurityConfig;
import decentralabs.blockchain.dto.treasury.InstitutionalAdminRequest;
import decentralabs.blockchain.dto.treasury.InstitutionalAdminRequest.AdminOperation;
import decentralabs.blockchain.dto.treasury.InstitutionalAdminResponse;
import decentralabs.blockchain.dto.treasury.InstitutionalReservationRequest;
import decentralabs.blockchain.service.treasury.InstitutionalAdminService;
import decentralabs.blockchain.service.treasury.InstitutionalReservationService;
import java.math.BigInteger;
import java.time.LocalDateTime;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = InstitutionalTreasuryController.class)
@Import(TestSecurityConfig.class)
@WithMockUser
class InstitutionalTreasuryControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private InstitutionalReservationService reservationService;

    @MockitoBean
    private InstitutionalAdminService adminService;

    @Test
    void createInstitutionalReservationReturnsSuccessPayload() throws Exception {
        Map<String, Object> response = Map.of("success", true, "transactionHash", "0x123");
        when(reservationService.processReservation(any(InstitutionalReservationRequest.class))).thenReturn(response);

        InstitutionalReservationRequest request = InstitutionalReservationRequest.builder()
            .marketplaceToken("token")
            .samlAssertion("saml")
            .userId("user")
            .institutionId("inst")
            .labId(BigInteger.ONE)
            .startTime(LocalDateTime.now())
            .endTime(LocalDateTime.now().plusHours(1))
            .userCount(1)
            .timestamp(System.currentTimeMillis())
            .build();

        mockMvc.perform(post("/treasury/reservations")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.transactionHash").value("0x123"));
    }

    @Test
    void createInstitutionalReservationReturnsBadRequestOnFailure() throws Exception {
        when(reservationService.processReservation(any(InstitutionalReservationRequest.class)))
            .thenThrow(new IllegalStateException("failure"));

        InstitutionalReservationRequest request = InstitutionalReservationRequest.builder()
            .marketplaceToken("token")
            .samlAssertion("saml")
            .userId("user")
            .institutionId("inst")
            .labId(BigInteger.ONE)
            .startTime(LocalDateTime.now())
            .endTime(LocalDateTime.now().plusHours(1))
            .userCount(1)
            .timestamp(System.currentTimeMillis())
            .build();

        mockMvc.perform(post("/treasury/reservations")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.success").value(false))
            .andExpect(jsonPath("$.error").value("failure"));
    }

    @Test
    void executeAdminOperationPropagatesServiceResponses() throws Exception {
        InstitutionalAdminResponse success = InstitutionalAdminResponse.success("ok", "0x1", "AUTHORIZE_BACKEND");
        when(adminService.executeAdminOperation(any(InstitutionalAdminRequest.class))).thenReturn(success);

        InstitutionalAdminRequest request = new InstitutionalAdminRequest("0x123", AdminOperation.AUTHORIZE_BACKEND, null, "0xbackend", null, null, null);

        mockMvc.perform(post("/treasury/admin/execute")
                .with(csrf())
                .with(request1 -> {
                    request1.setRemoteAddr("127.0.0.1");
                    return request1;
                })
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.transactionHash").value("0x1"));
    }

    @Test
    void executeAdminOperationReturnsBadRequestWhenServiceRejects() throws Exception {
        InstitutionalAdminResponse failure = InstitutionalAdminResponse.error("nope");
        when(adminService.executeAdminOperation(any(InstitutionalAdminRequest.class))).thenReturn(failure);

        InstitutionalAdminRequest request = new InstitutionalAdminRequest("0x123", AdminOperation.AUTHORIZE_BACKEND, null, "0xbackend", null, null, null);

        mockMvc.perform(post("/treasury/admin/execute")
                .with(csrf())
                .with(request1 -> {
                    request1.setRemoteAddr("127.0.0.1");
                    return request1;
                })
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.success").value(false))
            .andExpect(jsonPath("$.message").value("nope"));
    }

    @Test
    void executeAdminOperationReturnsServerErrorOnException() throws Exception {
        when(adminService.executeAdminOperation(any(InstitutionalAdminRequest.class)))
            .thenThrow(new RuntimeException("boom"));

        InstitutionalAdminRequest request = new InstitutionalAdminRequest("0x123", AdminOperation.AUTHORIZE_BACKEND, null, "0xbackend", null, null, null);

        mockMvc.perform(post("/treasury/admin/execute")
                .with(csrf())
                .with(request1 -> {
                    request1.setRemoteAddr("127.0.0.1");
                    return request1;
                })
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isInternalServerError())
            .andExpect(jsonPath("$.success").value(false))
            .andExpect(jsonPath("$.message").value("Internal server error: boom"));
    }
}
