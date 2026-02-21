package decentralabs.blockchain.controller.treasury;


import decentralabs.blockchain.controller.TestSecurityConfig;
import decentralabs.blockchain.dto.treasury.InstitutionalAdminRequest;
import decentralabs.blockchain.dto.treasury.InstitutionalAdminRequest.AdminOperation;
import decentralabs.blockchain.dto.treasury.InstitutionalAdminResponse;
import decentralabs.blockchain.service.treasury.InstitutionalAdminService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.ArgumentMatchers.any; 
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = InstitutionalTreasuryController.class)
@Import(TestSecurityConfig.class)
@WithMockUser
class InstitutionalTreasuryControllerTest {

    @Autowired
    private WebApplicationContext wac;

    private MockMvc mockMvc;

    @BeforeEach
    public void setup() {
        InstitutionalTreasuryController controller = this.wac.getBean(InstitutionalTreasuryController.class);
        this.mockMvc = MockMvcBuilders.standaloneSetup(controller)
            .setMessageConverters(new decentralabs.blockchain.config.JacksonHttpMessageConverter(objectMapper))
            .setControllerAdvice(new decentralabs.blockchain.exception.GlobalExceptionHandler())
            .defaultRequest(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/").accept(org.springframework.http.MediaType.APPLICATION_JSON))
            .build();
    }

    private com.fasterxml.jackson.databind.ObjectMapper objectMapper = new com.fasterxml.jackson.databind.ObjectMapper();

    @MockitoBean
    private InstitutionalAdminService adminService;

    @Test
    void executeAdminOperationPropagatesServiceResponses() throws Exception {
        InstitutionalAdminResponse success = InstitutionalAdminResponse.success("ok", "0x1", "AUTHORIZE_BACKEND");
        when(adminService.executeAdminOperation(any(InstitutionalAdminRequest.class))).thenReturn(success);

        InstitutionalAdminRequest request = new InstitutionalAdminRequest();
        request.setAdminWalletAddress("0x123");
        request.setOperation(AdminOperation.AUTHORIZE_BACKEND);
        request.setBackendAddress("0xbackend");
        request.setTimestamp(System.currentTimeMillis());
        request.setSignature("0x" + "11".repeat(65));

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

        InstitutionalAdminRequest request = new InstitutionalAdminRequest();
        request.setAdminWalletAddress("0x123");
        request.setOperation(AdminOperation.AUTHORIZE_BACKEND);
        request.setBackendAddress("0xbackend");
        request.setTimestamp(System.currentTimeMillis());
        request.setSignature("0x" + "11".repeat(65));

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

        InstitutionalAdminRequest request = new InstitutionalAdminRequest();
        request.setAdminWalletAddress("0x123");
        request.setOperation(AdminOperation.AUTHORIZE_BACKEND);
        request.setBackendAddress("0xbackend");
        request.setTimestamp(System.currentTimeMillis());
        request.setSignature("0x" + "11".repeat(65));

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

    @Test
    void collectLabPayoutPropagatesServiceResponses() throws Exception {
        InstitutionalAdminResponse success = InstitutionalAdminResponse.success("ok", "0xcollect", "COLLECT_LAB_PAYOUT");
        when(adminService.collectLabPayoutWithConfiguredWallet("3", "50")).thenReturn(success);

        InstitutionalAdminRequest request = new InstitutionalAdminRequest();
        request.setLabId("3");
        request.setMaxBatch("50");

        mockMvc.perform(post("/treasury/admin/collect-lab-payout")
                .with(csrf())
                .with(request1 -> {
                    request1.setRemoteAddr("127.0.0.1");
                    return request1;
                })
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.transactionHash").value("0xcollect"));
    }

    @Test
    void collectLabPayoutReturnsBadRequestWhenServiceRejects() throws Exception {
        InstitutionalAdminResponse failure = InstitutionalAdminResponse.error("collect failed");
        when(adminService.collectLabPayoutWithConfiguredWallet("3", "50")).thenReturn(failure);

        InstitutionalAdminRequest request = new InstitutionalAdminRequest();
        request.setLabId("3");
        request.setMaxBatch("50");

        mockMvc.perform(post("/treasury/admin/collect-lab-payout")
                .with(csrf())
                .with(request1 -> {
                    request1.setRemoteAddr("127.0.0.1");
                    return request1;
                })
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.success").value(false))
            .andExpect(jsonPath("$.message").value("collect failed"));
    }
}
