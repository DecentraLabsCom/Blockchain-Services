package decentralabs.blockchain.controller.labadmin;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import decentralabs.blockchain.dto.labadmin.LabAdminPublishRequest;
import decentralabs.blockchain.exception.IdempotencyKeyPayloadMismatchException;
import decentralabs.blockchain.service.auth.JwtService;
import decentralabs.blockchain.service.labadmin.LabAdminService;
import decentralabs.blockchain.service.labadmin.LabAdminService.LabAdminDeleteAssetResponse;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
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
    void publishRejectsIdempotencyKeyPayloadMismatch() throws Exception {
        when(labAdminService.publish(any(LabAdminPublishRequest.class), anyString()))
            .thenThrow(new IdempotencyKeyPayloadMismatchException());

        mockMvc.perform(post("/lab-admin/labs")
                .header("Idempotency-Key", "publish-command-1")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"metadataUrl\":\"https://lab.example.edu/metadata.json\"}"))
            .andExpect(status().isConflict())
            .andExpect(jsonPath("$.success").value(false))
            .andExpect(jsonPath("$.code").value("IDEMPOTENCY_KEY_PAYLOAD_MISMATCH"))
            .andExpect(jsonPath("$.status").value(409));
    }

    @Test
    void creatorBindingForwardsHashAndIdempotencyKey() throws Exception {
        String pucHash = "0x" + "1".repeat(64);
        when(labAdminService.bindCreatorPucHash(BigInteger.valueOf(5), pucHash, "bind-command-1"))
            .thenReturn(new decentralabs.blockchain.dto.labadmin.LabAdminTransactionResponse(
                true,
                "bindLabCreatorPucHash",
                "0xtx",
                "0x1",
                BigInteger.valueOf(5),
                "https://lab.example.edu/metadata.json"
            ));

        mockMvc.perform(post("/lab-admin/labs/5/creator-binding")
                .header("Idempotency-Key", "bind-command-1")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"creatorPucHash\":\"" + pucHash + "\"}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.action").value("bindLabCreatorPucHash"))
            .andExpect(jsonPath("$.labId").value(5));

        verify(labAdminService).bindCreatorPucHash(BigInteger.valueOf(5), pucHash, "bind-command-1");
    }

    @Test
    void missingLabContentReturnsNotFound() throws Exception {
        when(labAdminService.loadContentResource(anyString()))
            .thenThrow(new FileNotFoundException("missing"));

        mockMvc.perform(get("/lab-content/content/demo/missing.pdf"))
            .andExpect(status().isNotFound());
    }

    @Test
    void labContentReturnsPublicReadHeaders() throws Exception {
        when(labAdminService.loadContentResource("content/demo/metadata.json"))
            .thenReturn(new ByteArrayResource("{\"name\":\"Demo\"}".getBytes()));
        when(labAdminService.contentTypeFor("content/demo/metadata.json"))
            .thenReturn("application/json");

        mockMvc.perform(get("/lab-content/content/demo/metadata.json"))
            .andExpect(status().isOk())
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.header().string("Access-Control-Allow-Origin", "*"))
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.header().string("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS"))
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.header().string("Access-Control-Allow-Headers", "Content-Type"))
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.header().string("X-Content-Type-Options", "nosniff"))
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.header().string("Cache-Control", "max-age=3600, public"));
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
    void forwardsIdempotencyKeyForDistinctLabAdminCommandInstances() throws Exception {
        when(labAdminService.listLab(BigInteger.valueOf(5), true, "list-command-2"))
            .thenReturn(new decentralabs.blockchain.dto.labadmin.LabAdminTransactionResponse(
                true, "listLab", "0xtx", "0x1", BigInteger.valueOf(5), "https://lab.example.edu/metadata.json"
            ));

        mockMvc.perform(post("/lab-admin/labs/5/list")
                .header("Idempotency-Key", "list-command-2"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.action").value("listLab"));

        verify(labAdminService).listLab(BigInteger.valueOf(5), true, "list-command-2");
    }

    @Test
    void updateLabDelegatesToService() throws Exception {
        when(labAdminService.update(eq(BigInteger.valueOf(7)), any(LabAdminPublishRequest.class)))
            .thenReturn(new decentralabs.blockchain.dto.labadmin.LabAdminTransactionResponse(
                true,
                "updateLab",
                "0xtx",
                "0x1",
                BigInteger.valueOf(7),
                "https://lab.example.edu/metadata.json"
            ));

        mockMvc.perform(put("/lab-admin/labs/7")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                      "setupMode": "quick",
                      "metadataUrl": "https://lab.example.edu/metadata.json",
                      "price": 1,
                      "accessURI": "https://lab.example.edu/guacamole",
                      "accessKey": "guac:id:42",
                      "resourceType": 0
                    }
                    """))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.action").value("updateLab"))
            .andExpect(jsonPath("$.labId").value(7));
    }

    @Test
    void deleteLabValidationErrorsReturnBadRequest() throws Exception {
        when(labAdminService.deleteLab(BigInteger.valueOf(7)))
            .thenThrow(new IllegalArgumentException("Lab is not owned by this provider wallet"));

        mockMvc.perform(delete("/lab-admin/labs/7"))
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

    @Test
    void uploadAssetStorageIoErrorsReturnActionableMessage() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
            "file",
            "cover.png",
            "image/png",
            "png".getBytes()
        );
        when(labAdminService.saveAsset(eq("lab-demo"), eq("images"), any()))
            .thenThrow(new IOException("Permission denied"));

        mockMvc.perform(multipart("/lab-admin/assets")
                .file(file)
                .param("contentId", "lab-demo")
                .param("kind", "images"))
            .andExpect(status().isInternalServerError())
            .andExpect(jsonPath("$.success").value(false))
            .andExpect(jsonPath("$.error").value("Lab content storage is not writable. Check LAB_CONTENT_BASE_PATH and lab-content volume permissions."))
            .andExpect(jsonPath("$.details").value("Permission denied"));
    }
}
