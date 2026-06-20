package decentralabs.blockchain.service.labadmin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.service.BackendUrlResolver;
import decentralabs.blockchain.service.wallet.InstitutionalTxManagerProvider;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.util.ReflectionTestUtils;
import org.web3j.protocol.Web3j;

class LabAdminServiceTest {

    @TempDir
    Path tempDir;

    private LabAdminService service;

    @BeforeEach
    void setUp() {
        BackendUrlResolver resolver = mock(BackendUrlResolver.class);
        when(resolver.resolveBaseDomain()).thenReturn("https://lab.example.edu");

        service = new LabAdminService(
            mock(InstitutionalWalletService.class),
            mock(InstitutionalTxManagerProvider.class),
            mock(WalletService.class),
            resolver,
            new ObjectMapper(),
            mock(Web3j.class)
        );
        ReflectionTestUtils.setField(service, "contentBasePath", tempDir.resolve("lab-content").toString());
        ReflectionTestUtils.setField(service, "fmuDataPath", tempDir.resolve("fmu-data").toString());
    }

    @Test
    void saveAssetStoresImageUnderContentIdAndReturnsPublicUrl() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
            "file",
            "cover.png",
            "image/png",
            "png".getBytes(StandardCharsets.UTF_8)
        );

        var response = service.saveAsset("lab-demo", "images", file);

        assertThat(response.success()).isTrue();
        assertThat(response.contentId()).isEqualTo("lab-demo");
        assertThat(response.url()).startsWith("https://lab.example.edu/lab-content/content/lab-demo/images/");
        assertThat(Files.exists(tempDir.resolve("lab-content").resolve(response.path().substring(1)))).isTrue();
    }

    @Test
    void saveAssetRejectsInvalidImageMimeType() {
        MockMultipartFile file = new MockMultipartFile(
            "file",
            "cover.svg",
            "image/svg+xml",
            "<svg/>".getBytes(StandardCharsets.UTF_8)
        );

        assertThatThrownBy(() -> service.saveAsset("lab-demo", "images", file))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Only JPEG, PNG, WebP or GIF");
    }

    @Test
    void saveAssetRejectsTraversalContentId() {
        MockMultipartFile file = new MockMultipartFile(
            "file",
            "manual.pdf",
            "application/pdf",
            "%PDF".getBytes(StandardCharsets.UTF_8)
        );

        assertThatThrownBy(() -> service.saveAsset("../outside", "docs", file))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Invalid contentId");
    }

    @Test
    void deleteAssetRemovesUploadedAsset() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
            "file",
            "manual.pdf",
            "application/pdf",
            "%PDF".getBytes(StandardCharsets.UTF_8)
        );
        var response = service.saveAsset("lab-demo", "docs", file);
        Path storedPath = tempDir.resolve("lab-content").resolve(response.path().substring(1));

        assertThat(Files.exists(storedPath)).isTrue();

        assertThat(service.deleteAsset(response.path()).deleted()).isTrue();
        assertThat(Files.exists(storedPath)).isFalse();
    }

    @Test
    void deleteAssetRejectsMetadataPath() {
        assertThatThrownBy(() -> service.deleteAsset("/content/lab-demo/metadata.json"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Only uploaded image and document assets can be deleted");
    }

    @Test
    void deleteAssetRejectsTraversalPath() {
        assertThatThrownBy(() -> service.deleteAsset("/content/lab-demo/images/../../metadata.json"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Invalid asset path");
    }
}
