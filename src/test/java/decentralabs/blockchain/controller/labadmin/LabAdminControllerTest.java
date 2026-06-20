package decentralabs.blockchain.controller.labadmin;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import decentralabs.blockchain.dto.labadmin.LabAdminPublishRequest;
import decentralabs.blockchain.service.auth.JwtService;
import decentralabs.blockchain.service.labadmin.LabAdminService;
import decentralabs.blockchain.service.labadmin.LabAdminService.LabAdminDeleteAssetResponse;
import java.io.FileNotFoundException;
import java.math.BigInteger;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class LabAdminControllerTest {

    private LabAdminService labAdminService;
    private JwtService jwtService;
    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        labAdminService = mock(LabAdminService.class);
        jwtService = mock(JwtService.class);
        mockMvc = MockMvcBuilders
            .standaloneSetup(new LabAdminController(labAdminService, jwtService))
            .build();
    }

    @Test
    void statusReturnsGatewayStatus() throws Exception {
        when(labAdminService.status()).thenReturn(Map.of(
            "success", true,
            "providerAddress", "0x123"
        ));

        mockMvc.perform(get("/lab-admin/status"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.providerAddress").value("0x123"));
    }

    @Test
    void publishValidationErrorsReturnBadRequest() throws Exception {
        when(labAdminService.publish(any(LabAdminPublishRequest.class)))
            .thenThrow(new IllegalArgumentException("Metadata URL is required"));

        mockMvc.perform(post("/lab-admin/labs")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"setupMode\":\"quick\"}"))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.success").value(false))
            .andExpect(jsonPath("$.error").value("Metadata URL is required"));
    }

    @Test
    void missingLabContentReturnsNotFound() throws Exception {
        when(labAdminService.loadContentResource(anyString()))
            .thenThrow(new FileNotFoundException("missing"));

        mockMvc.perform(get("/lab-content/content/demo/missing.pdf"))
            .andExpect(status().isNotFound());
    }

    @Test
    void listValidationErrorsReturnBadRequest() throws Exception {
        when(labAdminService.listLab(BigInteger.valueOf(5), true))
            .thenThrow(new IllegalStateException("Lab is not owned by this provider wallet"));

        mockMvc.perform(post("/lab-admin/labs/5/list"))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.success").value(false))
            .andExpect(jsonPath("$.error").value("Lab is not owned by this provider wallet"));
    }

    @Test
    void fmuProviderDescribeTokenReturnsJwt() throws Exception {
        when(jwtService.generateToken(any(), any())).thenReturn("token-value");

        mockMvc.perform(post("/lab-admin/fmu/provider-describe-token")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"fmuFileName\":\"spring.fmu\"}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.token").value("token-value"))
            .andExpect(jsonPath("$.expiresIn").value(60));
    }

    @Test
    void deleteAssetReturnsSuccess() throws Exception {
        when(labAdminService.deleteAsset("/content/lab-demo/images/cover.png"))
            .thenReturn(new LabAdminDeleteAssetResponse(true, true, "/content/lab-demo/images/cover.png"));

        mockMvc.perform(delete("/lab-admin/assets")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"path\":\"/content/lab-demo/images/cover.png\"}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.deleted").value(true));
    }

    @Test
    void deleteAssetValidationErrorsReturnBadRequest() throws Exception {
        when(labAdminService.deleteAsset("../metadata.json"))
            .thenThrow(new IllegalArgumentException("Invalid asset path"));

        mockMvc.perform(delete("/lab-admin/assets")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"path\":\"../metadata.json\"}"))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.success").value(false))
            .andExpect(jsonPath("$.error").value("Invalid asset path"));
    }
}
