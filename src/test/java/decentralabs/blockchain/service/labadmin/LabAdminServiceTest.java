package decentralabs.blockchain.service.labadmin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.contract.Diamond;
import decentralabs.blockchain.service.BackendUrlResolver;
import decentralabs.blockchain.service.guacamole.GuacamoleProvisioningService;
import decentralabs.blockchain.service.health.LabMetadataService;
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
import java.util.Arrays;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.util.ReflectionTestUtils;
import org.web3j.protocol.core.methods.response.Log;
import org.web3j.protocol.core.methods.response.TransactionReceipt;

class LabAdminServiceTest {

    @TempDir
    Path tempDir;

    private LabAdminService service;
    private WalletService walletService;
    private LabMetadataService labMetadataService;
    private LabContentRetentionService contentRetentionService;

    @BeforeEach
    void setUp() {
        BackendUrlResolver resolver = mock(BackendUrlResolver.class);
        when(resolver.resolveBaseDomain()).thenReturn("https://lab.example.edu");

        walletService = mock(WalletService.class);
        labMetadataService = mock(LabMetadataService.class);
        contentRetentionService = new LabContentRetentionService();
        ReflectionTestUtils.setField(contentRetentionService, "contentBasePath", tempDir.resolve("lab-content").toString());
        service = new LabAdminService(
            mock(InstitutionalWalletService.class),
            mock(InstitutionalTxManagerProvider.class),
            walletService,
            resolver,
            new ObjectMapper(),
            mock(GuacamoleProvisioningService.class),
            contentRetentionService,
            labMetadataService
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
    void normalizeGeneratedMetadataKeepsErc721AttributeShape() {
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

        assertThat(metadata).doesNotContainKeys("category", "keywords", "images", "docs");
        assertThat(metadata.get("image")).isEqualTo("https://lab.example.edu/lab-content/content/lab-demo/images/cover.png");
        assertThat(metadata.get("attributes")).isNotNull();
    }

    @Test
    void findOwnedLabByUriReturnsExistingLabId() {
        when(walletService.getLabTokenUri(BigInteger.valueOf(4)))
            .thenReturn(Optional.of("https://lab.example.edu/lab-content/content/lab-demo/metadata.json"));

        Optional<BigInteger> existing = service.findOwnedLabByUri(
            "https://lab.example.edu/lab-content/content/lab-demo/metadata.json",
            List.of(BigInteger.valueOf(4), BigInteger.valueOf(5))
        );

        assertThat(existing).contains(BigInteger.valueOf(4));
    }

    @Test
    void unchangedOnChainLabComparisonPreservesRawRoundedPrice() {
        Diamond.LabBase current = new Diamond.LabBase(
            "https://lab.example.edu/lab-content/content/lab-demo/metadata.json",
            BigInteger.valueOf(8),
            "https://lab.example.edu/fmu",
            "BouncingBall.fmu",
            BigInteger.ZERO,
            BigInteger.ONE
        );

        assertThat(service.isOnChainLabUnchanged(
            current,
            "https://lab.example.edu/lab-content/content/lab-demo/metadata.json",
            BigInteger.valueOf(8),
            "https://lab.example.edu/fmu",
            "BouncingBall.fmu",
            BigInteger.ONE
        )).isTrue();

        assertThat(service.isOnChainLabUnchanged(
            current,
            "https://lab.example.edu/lab-content/content/lab-demo/metadata.json",
            BigInteger.valueOf(9),
            "https://lab.example.edu/fmu",
            "BouncingBall.fmu",
            BigInteger.ONE
        )).isFalse();
    }

    @Test
    void labAdminOperationKeyChangesPerCommandInstance() {
        String first = ReflectionTestUtils.invokeMethod(
            service, "operationKey", "list", BigInteger.valueOf(4), "list-command-1"
        );
        String retry = ReflectionTestUtils.invokeMethod(
            service, "operationKey", "list", BigInteger.valueOf(4), "list-command-1"
        );
        String next = ReflectionTestUtils.invokeMethod(
            service, "operationKey", "list", BigInteger.valueOf(4), "list-command-2"
        );

        assertThat(first).isEqualTo(retry);
        assertThat(next).isNotEqualTo(first);
    }

    @Test
    void creatorPucHashRequiresNonZeroBytes32() {
        String validHash = "0x" + "ab".repeat(32);

        assertThat((String) ReflectionTestUtils.invokeMethod(service, "requireCreatorPucHash", validHash))
            .isEqualTo(validHash);
        assertThat((String) ReflectionTestUtils.invokeMethod(service, "requireCreatorPucHash", "0x" + "AB".repeat(32)))
            .isEqualTo(validHash);

        assertThatThrownBy(() -> ReflectionTestUtils.invokeMethod(
            service, "requireCreatorPucHash", "0x" + "0".repeat(64)
        )).isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("non-zero");
        assertThatThrownBy(() -> ReflectionTestUtils.invokeMethod(
            service, "requireCreatorPucHash", "0x1234"
        )).isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("bytes32");
    }

    @Test
    void extractsCreatedLabIdFromTheSubmittedMintReceipt() {
        ReflectionTestUtils.setField(service, "contractAddress", "0x00000000000000000000000000000000000000aa");
        String providerWallet = "0x1111111111111111111111111111111111111111";
        Log transfer = new Log();
        transfer.setAddress("0x00000000000000000000000000000000000000AA");
        transfer.setTopics(Arrays.asList(
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
            "0x" + "0".repeat(64),
            "0x" + "0".repeat(24) + providerWallet.substring(2),
            "0x" + "0".repeat(63) + "2a"
        ));
        TransactionReceipt receipt = new TransactionReceipt();
        receipt.setLogs(List.of(transfer));

        assertThat(service.extractCreatedLabId(receipt, providerWallet)).isEqualTo(BigInteger.valueOf(42));
    }

    @Test
    void rejectsSuccessfulReceiptWithoutItsOwnMintTransfer() {
        ReflectionTestUtils.setField(service, "contractAddress", "0x00000000000000000000000000000000000000aa");
        TransactionReceipt receipt = new TransactionReceipt();
        receipt.setLogs(List.of());

        assertThatThrownBy(() -> service.extractCreatedLabId(
            receipt, "0x1111111111111111111111111111111111111111"
        )).isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("mint Transfer event");
    }

    @Test
    void metadataPreflightReadsGeneratedGatewayDocumentBeforeListing() throws Exception {
        Path metadataFile = tempDir.resolve("lab-content/content/lab-demo/metadata.json");
        Files.createDirectories(metadataFile.getParent());
        new ObjectMapper().writeValue(metadataFile.toFile(), Map.of(
            "name", "Circuit Lab",
            "description", "Remote electronics lab",
            "image", "https://lab.example.edu/lab-content/content/lab-demo/images/cover.png"
        ));

        ReflectionTestUtils.invokeMethod(
            service,
            "preflightMetadataUri",
            "https://lab.example.edu/lab-content/content/lab-demo/metadata.json"
        );
    }

    @Test
    void metadataPreflightRejectsUnavailableExternalDocument() {
        when(labMetadataService.getLabMetadata("https://metadata.example/lab.json"))
            .thenThrow(new RuntimeException("upstream unavailable"));

        assertThatThrownBy(() -> ReflectionTestUtils.invokeMethod(
            service,
            "preflightMetadataUri",
            "https://metadata.example/lab.json"
        )).isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Metadata preflight failed");
    }

    @Test
    void publicationRequiresAStableIdempotencyKey() {
        assertThatThrownBy(() -> service.publish(null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Idempotency-Key is required");
    }
}
