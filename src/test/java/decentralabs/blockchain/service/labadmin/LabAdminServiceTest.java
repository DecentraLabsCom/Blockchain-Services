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
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
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
    private WalletService walletService;

    @BeforeEach
    void setUp() {
        BackendUrlResolver resolver = mock(BackendUrlResolver.class);
        when(resolver.resolveBaseDomain()).thenReturn("https://lab.example.edu");

        walletService = mock(WalletService.class);
        service = new LabAdminService(
            mock(InstitutionalWalletService.class),
            mock(InstitutionalTxManagerProvider.class),
            walletService,
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

    @Test
    void normalizeGeneratedMetadataAddsMarketplaceTopLevelFields() {
        Map<String, Object> metadata = new java.util.LinkedHashMap<>();
        metadata.put("name", "Circuit Lab");
        metadata.put("description", "Remote electronics lab");
        metadata.put("image", "https://lab.example.edu/lab-content/content/lab-demo/images/cover.png");
        metadata.put("attributes", List.of(
            Map.of("trait_type", "category", "value", List.of("Electrical Engineering")),
            Map.of("trait_type", "keywords", "value", List.of("circuits", "remote")),
            Map.of("trait_type", "additionalImages", "value", List.of("https://lab.example.edu/lab-content/content/lab-demo/images/side.png")),
            Map.of("trait_type", "docs", "value", List.of("https://lab.example.edu/lab-content/content/lab-demo/docs/manual.pdf"))
        ));

        service.normalizeGeneratedMetadata(metadata);

        assertThat(metadata.get("category")).isEqualTo(List.of("Electrical Engineering"));
        assertThat(metadata.get("keywords")).isEqualTo(List.of("circuits", "remote"));
        assertThat(metadata.get("images")).isEqualTo(List.of(
            "https://lab.example.edu/lab-content/content/lab-demo/images/cover.png",
            "https://lab.example.edu/lab-content/content/lab-demo/images/side.png"
        ));
        assertThat(metadata.get("docs")).isEqualTo(List.of(
            "https://lab.example.edu/lab-content/content/lab-demo/docs/manual.pdf"
        ));
    }

    @Test
    void findOwnedLabByUriReturnsExistingLabId() {
        when(walletService.getLabTokenUri(BigInteger.valueOf(4)))
            .thenReturn(Optional.of("https://lab.example.edu/lab-content/content/lab-demo/metadata.json"));

        Optional<BigInteger> existing = service.findOwnedLabByUri(
            "0xprovider",
            "https://lab.example.edu/lab-content/content/lab-demo/metadata.json",
            List.of(BigInteger.valueOf(4), BigInteger.valueOf(5))
        );

        assertThat(existing).contains(BigInteger.valueOf(4));
    }
}
