package decentralabs.blockchain.service.labadmin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.ArgumentMatchers.eq;

import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.contract.Diamond;
import decentralabs.blockchain.dto.health.LabMetadata;
import decentralabs.blockchain.dto.labadmin.LabAdminReservation;
import decentralabs.blockchain.dto.labadmin.LabAdminPublishRequest;
import decentralabs.blockchain.service.BackendUrlResolver;
import decentralabs.blockchain.service.guacamole.GuacamoleProvisioningService;
import decentralabs.blockchain.service.health.LabMetadataService;
import decentralabs.blockchain.service.provider.StationCapacityService;
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
import org.web3j.protocol.core.RemoteFunctionCall;
import org.web3j.utils.Numeric;

class LabAdminServiceTest {

    @TempDir
    Path tempDir;

    private LabAdminService service;
    private WalletService walletService;
    private InstitutionalWalletService institutionalWalletService;
    private LabMetadataService labMetadataService;
    private LabContentRetentionService contentRetentionService;

    @BeforeEach
    void setUp() {
        BackendUrlResolver resolver = mock(BackendUrlResolver.class);
        when(resolver.resolveBaseDomain()).thenReturn("https://lab.example.edu");

        walletService = mock(WalletService.class);
        institutionalWalletService = mock(InstitutionalWalletService.class);
        labMetadataService = mock(LabMetadataService.class);
        contentRetentionService = new LabContentRetentionService();
        ReflectionTestUtils.setField(contentRetentionService, "contentBasePath", tempDir.resolve("lab-content").toString());
        service = new LabAdminService(
            institutionalWalletService,
            mock(InstitutionalTxManagerProvider.class),
            walletService,
            resolver,
            new ObjectMapper(),
            mock(GuacamoleProvisioningService.class),
            contentRetentionService,
            labMetadataService,
            mock(StationCapacityService.class)
        );
        ReflectionTestUtils.setField(service, "contentBasePath", tempDir.resolve("lab-content").toString());
        ReflectionTestUtils.setField(service, "fmuDataPath", tempDir.resolve("fmu-data").toString());
        service = spy(service);
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
    void updatingOnlyMetadataConcurrencyDoesNotSubmitOnChainTransaction() throws Exception {
        String wallet = "0x1111111111111111111111111111111111111111";
        BigInteger labId = BigInteger.valueOf(7);
        String metadataUri = "https://lab.example.edu/lab-content/content/lab-concurrent/metadata.json";
        Diamond readonly = mock(Diamond.class);
        RemoteFunctionCall<Diamond.Lab> labCall = mockRemoteFunctionCall();
        Diamond.Lab current = new Diamond.Lab(
            labId,
            new Diamond.LabBase(
                metadataUri,
                BigInteger.valueOf(8),
                "https://lab.example.edu/fmu",
                "BouncingBall.fmu",
                BigInteger.ZERO,
                BigInteger.ONE
            )
        );
        when(institutionalWalletService.isConfigured()).thenReturn(true);
        when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(wallet);
        when(walletService.isLabProvider(wallet)).thenReturn(true);
        when(walletService.isLabOwnedByProvider(wallet, labId)).thenReturn(true);
        when(readonly.getLab(labId)).thenReturn(labCall);
        when(labCall.send()).thenReturn(current);
        doReturn(readonly).when(service).loadReadonlyDiamond();

        LabAdminPublishRequest request = new LabAdminPublishRequest(
            "full",
            true,
            null,
            Map.of(
                "contentId", "lab-concurrent",
                "name", "Concurrent FMU",
                "description", "FMU concurrency metadata",
                "attributes", List.of(Map.of(
                    "trait_type", "maxConcurrentUsers",
                    "value", 7
                ))
            ),
            BigInteger.valueOf(8),
            "https://lab.example.edu/fmu",
            "BouncingBall.fmu",
            1,
            null,
            null
        );

        var response = service.update(labId, request, "metadata-only-command");

        assertThat(response.action()).isEqualTo("metadataOnly");
        assertThat(response.transactionHash()).isNull();
        assertThat(response.status()).isEqualTo("offchain_updated");
        verify(service, org.mockito.Mockito.never()).loadWritableDiamond(org.mockito.ArgumentMatchers.anyString());
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
            "https://lab.example.edu/lab-content/content/lab-demo/metadata.json",
            "0xprovider"
        );
    }

    @Test
    void metadataPreflightRejectsUnavailableExternalDocument() {
        when(labMetadataService.getLabMetadataForProvider(
            eq("0xprovider"),
            eq("https://metadata.example/lab.json")
        ))
            .thenThrow(new RuntimeException("upstream unavailable"));

        assertThatThrownBy(() -> ReflectionTestUtils.invokeMethod(
            service,
            "preflightMetadataUri",
            "https://metadata.example/lab.json",
            "0xprovider"
        )).isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Metadata preflight failed");
    }

    @Test
    void publicationRequiresAStableIdempotencyKey() {
        assertThatThrownBy(() -> service.publish(null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Idempotency-Key is required");
    }

    @Test
    void reservationCancellationRequiresABytes32Key() {
        assertThatThrownBy(() -> service.cancelReservation("0x1234", 7, "cancel-command-1"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("reservationKey must be a 0x-prefixed bytes32 value");
    }

    @Test
    void reservationCancellationRequiresAValidReasonAndIdempotencyKey() {
        String reservationKey = "0x" + "ab".repeat(32);

        assertThatThrownBy(() -> service.cancelReservation(reservationKey, 0, "cancel-command-1"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("reasonCode must be between 1 and 255");
        assertThatThrownBy(() -> service.cancelReservation(reservationKey, 7, null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Idempotency-Key is required");
    }

    @Test
    void listsFutureProviderReservationsWithCreditValues() throws Exception {
        String wallet = "0x1111111111111111111111111111111111111111";
        String institution = "0x3333333333333333333333333333333333333333";
        BigInteger labId = BigInteger.valueOf(7);
        byte[] key = Numeric.hexStringToByteArray("0x" + "ab".repeat(32));
        long now = System.currentTimeMillis() / 1000;
        String metadataUri = "https://lab.example.edu/lab-content/content/lab-demo/metadata.json";
        Diamond.Reservation reservation = new Diamond.Reservation(
            labId,
            "0x2222222222222222222222222222222222222222",
            BigInteger.valueOf(25_000_000),
            wallet,
            BigInteger.ONE,
            BigInteger.valueOf(now + 3600),
            BigInteger.valueOf(now + 7200),
            BigInteger.ZERO,
            BigInteger.ZERO,
            institution,
            institution,
            BigInteger.valueOf(20_000_000)
        );
        Diamond diamond = mock(Diamond.class);
        Diamond.Lab lab = new Diamond.Lab(
            labId,
            new Diamond.LabBase(
                metadataUri,
                BigInteger.valueOf(25_000_000),
                "https://lab.example.edu/fmu",
                "BouncingBall.fmu",
                BigInteger.ZERO,
                BigInteger.ONE
            )
        );
        RemoteFunctionCall<BigInteger> count = mockRemoteFunctionCall();
        RemoteFunctionCall<byte[]> keyCall = mockRemoteFunctionCall();
        RemoteFunctionCall<Diamond.Reservation> reservationCall = mockRemoteFunctionCall();
        RemoteFunctionCall<Diamond.Lab> labCall = mockRemoteFunctionCall();
        RemoteFunctionCall<String[]> institutionCall = mockRemoteFunctionCall();
        when(institutionalWalletService.isConfigured()).thenReturn(true);
        when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(wallet);
        when(walletService.isLabProvider(wallet)).thenReturn(true);
        when(walletService.getLabsOwnedByProvider(wallet)).thenReturn(List.of(labId));
        when(diamond.getReservationsOfToken(labId)).thenReturn(count);
        when(count.send()).thenReturn(BigInteger.ONE);
        when(diamond.getReservationOfTokenByIndex(labId, BigInteger.ZERO)).thenReturn(keyCall);
        when(keyCall.send()).thenReturn(key);
        when(diamond.getReservation(key)).thenReturn(reservationCall);
        when(reservationCall.send()).thenReturn(reservation);
        when(diamond.getLab(labId)).thenReturn(labCall);
        when(labCall.send()).thenReturn(lab);
        when(labMetadataService.getLabMetadataForLab(eq(labId))).thenReturn(
            LabMetadata.builder().name("Circuit Lab").build()
        );
        when(diamond.getRegisteredSchacHomeOrganizations(institution)).thenReturn(institutionCall);
        when(institutionCall.send()).thenReturn(new String[] {"UNED"});
        doReturn(diamond).when(service).loadReadonlyDiamond();

        Map<String, Object> response = service.listUpcomingReservations();

        assertThat(response.get("count")).isEqualTo(1);
        List<?> reservations = (List<?>) response.get("reservations");
        assertThat(reservations).hasSize(1);
        LabAdminReservation listed = (LabAdminReservation) reservations.get(0);
        assertThat(listed.priceCredits()).isEqualTo("2.5");
        assertThat(listed.providerShareCredits()).isEqualTo("2");
        assertThat(listed.labName()).isEqualTo("Circuit Lab");
        assertThat(listed.institutionName()).isEqualTo("UNED");
        assertThat(listed.institutionAddress()).isEqualTo(institution);
        assertThat(listed.cancellable()).isTrue();
    }

    @Test
    void confirmedReservationUsesProviderCancellationTransaction() throws Exception {
        String wallet = "0x1111111111111111111111111111111111111111";
        BigInteger labId = BigInteger.valueOf(7);
        String keyHex = "0x" + "cd".repeat(32);
        long now = System.currentTimeMillis() / 1000;
        Diamond.Reservation reservation = new Diamond.Reservation(
            labId,
            "0x2222222222222222222222222222222222222222",
            BigInteger.valueOf(25_000_000),
            wallet,
            BigInteger.ONE,
            BigInteger.valueOf(now + 3600),
            BigInteger.valueOf(now + 7200),
            BigInteger.ZERO,
            BigInteger.ZERO,
            wallet,
            wallet,
            BigInteger.valueOf(20_000_000)
        );
        Diamond readonly = mock(Diamond.class);
        Diamond writable = mock(Diamond.class);
        RemoteFunctionCall<Diamond.Reservation> reservationCall = mockRemoteFunctionCall();
        RemoteFunctionCall<TransactionReceipt> transactionCall = mockRemoteFunctionCall();
        TransactionReceipt receipt = new TransactionReceipt();
        receipt.setStatus("0x1");
        receipt.setTransactionHash("0xtx");
        when(institutionalWalletService.isConfigured()).thenReturn(true);
        when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(wallet);
        when(walletService.isLabProvider(wallet)).thenReturn(true);
        when(walletService.isLabOwnedByProvider(wallet, labId)).thenReturn(true);
        when(readonly.getReservation(org.mockito.ArgumentMatchers.any(byte[].class))).thenReturn(reservationCall);
        when(reservationCall.send()).thenReturn(reservation);
        when(writable.cancelConfirmedBookingByProvider(
            org.mockito.ArgumentMatchers.any(byte[].class), eq(BigInteger.valueOf(7))
        )).thenReturn(transactionCall);
        when(transactionCall.send()).thenReturn(receipt);
        doReturn(readonly).when(service).loadReadonlyDiamond();
        doReturn(writable).when(service).loadWritableDiamond(org.mockito.ArgumentMatchers.anyString());

        var response = service.cancelReservation(keyHex, 7, "cancel-command-1");

        assertThat(response.action()).isEqualTo("cancelConfirmedBookingByProvider");
        assertThat(response.transactionHash()).isEqualTo("0xtx");
        verify(writable).cancelConfirmedBookingByProvider(
            org.mockito.ArgumentMatchers.any(byte[].class), eq(BigInteger.valueOf(7))
        );
    }

    @Test
    void serviceFailureCanCancelAnAlreadyStartedAccessAuthorizedReservation() throws Exception {
        String wallet = "0x1111111111111111111111111111111111111111";
        BigInteger labId = BigInteger.valueOf(7);
        String keyHex = "0x" + "ef".repeat(32);
        long now = System.currentTimeMillis() / 1000;
        Diamond.Reservation reservation = new Diamond.Reservation(
            labId,
            "0x2222222222222222222222222222222222222222",
            BigInteger.valueOf(25_000_000),
            wallet,
            BigInteger.valueOf(2),
            BigInteger.valueOf(now - 600),
            BigInteger.valueOf(now + 3_000),
            BigInteger.ZERO,
            BigInteger.ZERO,
            wallet,
            wallet,
            BigInteger.valueOf(20_000_000)
        );
        Diamond readonly = mock(Diamond.class);
        Diamond writable = mock(Diamond.class);
        RemoteFunctionCall<Diamond.Reservation> reservationCall = mockRemoteFunctionCall();
        RemoteFunctionCall<TransactionReceipt> transactionCall = mockRemoteFunctionCall();
        TransactionReceipt receipt = new TransactionReceipt();
        receipt.setStatus("0x1");
        receipt.setTransactionHash("0xservice-failure");
        when(institutionalWalletService.isConfigured()).thenReturn(true);
        when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(wallet);
        when(walletService.isLabProvider(wallet)).thenReturn(true);
        when(walletService.isLabOwnedByProvider(wallet, labId)).thenReturn(true);
        when(readonly.getReservation(org.mockito.ArgumentMatchers.any(byte[].class))).thenReturn(reservationCall);
        when(reservationCall.send()).thenReturn(reservation);
        when(writable.cancelConfirmedBookingByProvider(
            org.mockito.ArgumentMatchers.any(byte[].class), eq(BigInteger.valueOf(8))
        )).thenReturn(transactionCall);
        when(transactionCall.send()).thenReturn(receipt);
        doReturn(readonly).when(service).loadReadonlyDiamond();
        doReturn(writable).when(service).loadWritableDiamond(org.mockito.ArgumentMatchers.anyString());

        var response = service.cancelReservation(keyHex, 8, "service-failure-command-1");

        assertThat(response.action()).isEqualTo("cancelConfirmedBookingByProvider");
        assertThat(response.transactionHash()).isEqualTo("0xservice-failure");
        verify(writable).cancelConfirmedBookingByProvider(
            org.mockito.ArgumentMatchers.any(byte[].class), eq(BigInteger.valueOf(8))
        );
    }

    @Test
    void pendingReservationsOnlyAllowProviderDenialReasons() {
        assertThat((boolean) ReflectionTestUtils.invokeMethod(
            service, "isPendingProviderReason", BigInteger.ONE
        )).isTrue();
        assertThat((boolean) ReflectionTestUtils.invokeMethod(
            service, "isPendingProviderReason", BigInteger.valueOf(7)
        )).isTrue();
        assertThat((boolean) ReflectionTestUtils.invokeMethod(
            service, "isPendingProviderReason", BigInteger.valueOf(3)
        )).isFalse();
    }

    @SuppressWarnings("unchecked")
    private static <T> RemoteFunctionCall<T> mockRemoteFunctionCall() {
        return (RemoteFunctionCall<T>) mock(RemoteFunctionCall.class);
    }
}
