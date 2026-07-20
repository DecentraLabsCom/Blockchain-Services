package decentralabs.blockchain.service.labadmin;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.contract.Diamond;
import decentralabs.blockchain.dto.labadmin.LabAdminAssetResponse;
import decentralabs.blockchain.dto.labadmin.LabAdminPublishRequest;
import decentralabs.blockchain.dto.labadmin.LabAdminTransactionResponse;
import decentralabs.blockchain.service.BackendUrlResolver;
import decentralabs.blockchain.service.guacamole.GuacamoleProvisioningService;
import decentralabs.blockchain.service.health.LabMetadataService;
import decentralabs.blockchain.service.wallet.InstitutionalTxManagerProvider;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import decentralabs.blockchain.util.LogSanitizer;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.methods.response.Log;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.tx.TransactionManager;
import org.web3j.tx.gas.StaticGasProvider;
import org.web3j.utils.Convert;
import org.web3j.utils.Numeric;

@Service
@RequiredArgsConstructor
@Slf4j
public class LabAdminService {

    private static final long MAX_ASSET_BYTES = 10L * 1024L * 1024L;
    private static final List<String> IMAGE_TYPES = List.of("image/jpeg", "image/png", "image/webp", "image/gif");
    private static final List<String> DOC_TYPES = List.of("application/pdf");
    private static final Pattern BYTES32_PATTERN = Pattern.compile("0x[0-9a-fA-F]{64}");
    private static final String ZERO_BYTES32 = "0x" + "0".repeat(64);
    private static final String ERC721_TRANSFER_TOPIC =
        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

    public record LabAdminDeleteAssetResponse(boolean success, boolean deleted, String path) {}

    private final InstitutionalWalletService institutionalWalletService;
    private final InstitutionalTxManagerProvider txManagerProvider;
    private final WalletService walletService;
    private final BackendUrlResolver backendUrlResolver;
    private final ObjectMapper objectMapper;
    private final GuacamoleProvisioningService guacamoleProvisioningService;
    private final LabContentRetentionService contentRetentionService;
    private final LabMetadataService labMetadataService;

    @Value("${contract.address}")
    private String contractAddress;

    @Value("${lab.content.base-path:/app/lab-content}")
    private String contentBasePath;

    @Value("${fmu.data.path:/app/fmu-data}")
    private String fmuDataPath;

    @Value("${ethereum.gas.price.default:1}")
    private BigInteger defaultGasPriceGwei;

    @Value("${ethereum.gas.price.strategy:network}")
    private String gasPriceStrategy;

    @Value("${ethereum.gas.limit.contract:300000}")
    private BigInteger contractGasLimit;

    @Value("${provider.puc-hash:}")
    private String configuredCreatorPucHash;

    public Map<String, Object> status() {
        String wallet = institutionalWalletService.getInstitutionalWalletAddress();
        boolean walletConfigured = institutionalWalletService.isConfigured();
        boolean provider = walletConfigured && walletService.isLabProvider(wallet);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("walletConfigured", walletConfigured);
        result.put("providerAddress", wallet);
        result.put("isProvider", provider);
        result.put("creatorPucHashConfigured", hasText(configuredCreatorPucHash));
        result.put("publicBaseUrl", publicBaseUrl());
        result.put("contentBaseUrl", publicBaseUrl() + "/lab-content");
        result.put("recommendedRemoteAccessURI", publicBaseUrl() + "/guacamole");
        result.put("recommendedFmuAccessURI", publicBaseUrl() + "/fmu");
        result.put("fmuInventory", listFmus());
        result.put("guacamoleCatalogAvailable", guacamoleProvisioningService.isConfigured());
        return result;
    }

    public Map<String, Object> guacamoleConnections() {
        return Map.of(
            "success", true,
            "connections", guacamoleProvisioningService.listSafeConnections()
        );
    }

    public Map<String, Object> listLabs() {
        String wallet = requireProviderWallet();
        List<Map<String, Object>> labs = new ArrayList<>();
        for (BigInteger labId : walletService.getLabsOwnedByProvider(wallet)) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("labId", labId.toString());
            try {
                Diamond.Lab lab = loadReadonlyDiamond().getLab(labId).send();
                item.put("uri", lab.base.uri);
                item.put("price", lab.base.price.toString());
                item.put("accessURI", lab.base.accessURI);
                item.put("accessKey", lab.base.accessKey);
                item.put("resourceType", lab.base.resourceType.intValue());
                item.put("listed", loadReadonlyDiamond().isLabListed(labId).send());
            } catch (Exception ex) {
                log.debug("Unable to load details for lab {}", labId, ex);
                item.put("error", "Unable to load lab details");
            }
            labs.add(item);
        }
        return Map.of("success", true, "providerAddress", wallet, "labs", labs);
    }

    public LabAdminAssetResponse saveAsset(String requestedContentId, String kind, MultipartFile file) throws IOException {
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("File is required");
        }
        if (file.getSize() > MAX_ASSET_BYTES) {
            throw new IllegalArgumentException("File exceeds 10 MB limit");
        }
        String normalizedKind = normalizeAssetKind(kind);
        String contentType = Optional.ofNullable(file.getContentType()).orElse("").toLowerCase(Locale.ROOT);
        if ("images".equals(normalizedKind) && !IMAGE_TYPES.contains(contentType)) {
            throw new IllegalArgumentException("Only JPEG, PNG, WebP or GIF images are allowed");
        }
        if ("docs".equals(normalizedKind) && !DOC_TYPES.contains(contentType)) {
            throw new IllegalArgumentException("Only PDF documents are allowed");
        }

        String contentId = normalizeContentId(requestedContentId);
        String fileName = safeFileName(file.getOriginalFilename(), contentType, normalizedKind);
        Path targetDir = contentRoot().resolve("content").resolve(contentId).resolve(normalizedKind).normalize();
        ensureWithinContentRoot(targetDir);
        if (contentRetentionService.isTombstoned("content/" + contentId + "/metadata.json")) {
            throw new IllegalStateException("Lab content is retained after deletion");
        }
        Files.createDirectories(targetDir);
        Path target = targetDir.resolve(fileName).normalize();
        ensureWithinContentRoot(target);
        Files.copy(file.getInputStream(), target, StandardCopyOption.REPLACE_EXISTING);

        String relative = "content/" + contentId + "/" + normalizedKind + "/" + fileName;
        return new LabAdminAssetResponse(
            true,
            contentId,
            "/" + relative,
            publicBaseUrl() + "/lab-content/" + relative,
            contentType,
            file.getSize()
        );
    }

    public LabAdminDeleteAssetResponse deleteAsset(String assetPath) throws IOException {
        String relative = normalizeUploadedAssetPath(assetPath);
        Path target = contentRoot().resolve(relative).normalize();
        ensureWithinContentRoot(target);
        boolean deleted = Files.deleteIfExists(target);
        return new LabAdminDeleteAssetResponse(true, deleted, "/" + relative);
    }

    public LabAdminTransactionResponse publish(LabAdminPublishRequest request) throws Exception {
        return publish(request, null);
    }

    /**
     * Publishes one business command. The idempotency key belongs to the HTTP
     * command instance and is required so the durable outbox can coordinate
     * retries across replicas.
     */
    public LabAdminTransactionResponse publish(LabAdminPublishRequest request, String idempotencyKey) throws Exception {
        String commandKey = requirePublishIdempotencyKey(idempotencyKey);
        String wallet = requireProviderWallet();
        String creatorPucHash = resolveCreatorPucHash(request);
        String uri = resolveMetadataUri(request);
        BigInteger price = requireNonNegative(request.price(), "price");
        String accessURI = requireText(request.accessURI(), "accessURI", 500);
        String accessKey = requireText(request.accessKey(), "accessKey", 200);
        BigInteger resourceType = normalizeResourceType(request.resourceType());
        validatePhysicalAccessKey(accessKey, resourceType);
        boolean listImmediately = request.listImmediately() == null || request.listImmediately();
        boolean allowDuplicate = Boolean.TRUE.equals(request.allowDuplicate());

        if (listImmediately) {
            preflightMetadataUri(uri);
        }

        List<BigInteger> before = walletService.getLabsOwnedByProvider(wallet);
        if (!allowDuplicate) {
            Optional<BigInteger> existingLab = findOwnedLabByUri(uri, before);
            if (existingLab.isPresent()) {
                return existingLabResponse(existingLab.get(), uri);
            }
        }

        Diamond diamond = loadWritableDiamond(operationKey("publish", "request", commandKey));
        TransactionReceipt receipt = listImmediately
            ? diamond.addAndListLabWithPucHash(uri, price, accessURI, accessKey, resourceType, creatorPucHash).send()
            : diamond.addLabWithPucHash(uri, price, accessURI, accessKey, resourceType, creatorPucHash).send();
        if (receipt == null || !receipt.isStatusOK()) {
            throw new IllegalStateException("Lab publication transaction was reverted");
        }
        BigInteger labId = extractCreatedLabId(receipt, wallet);

        return new LabAdminTransactionResponse(
            true,
            listImmediately ? "addAndListLabWithPucHash" : "addLabWithPucHash",
            receipt.getTransactionHash(),
            receipt.getStatus(),
            labId,
            uri
        );
    }

    public LabAdminTransactionResponse bindCreatorPucHash(BigInteger labId, String creatorPucHash) throws Exception {
        return bindCreatorPucHash(labId, creatorPucHash, null);
    }

    public LabAdminTransactionResponse bindCreatorPucHash(
        BigInteger labId, String creatorPucHash, String idempotencyKey
    ) throws Exception {
        requireOwnedLab(labId);
        String normalizedPucHash = requireCreatorPucHash(creatorPucHash);
        TransactionReceipt receipt = loadWritableDiamond(operationKey("bind-creator", labId, idempotencyKey))
            .bindLabCreatorPucHash(labId, normalizedPucHash)
            .send();
        return new LabAdminTransactionResponse(
            true,
            "bindLabCreatorPucHash",
            receipt.getTransactionHash(),
            receipt.getStatus(),
            labId,
            walletService.getLabTokenUri(labId).orElse(null)
        );
    }

    public LabAdminTransactionResponse update(BigInteger labId, LabAdminPublishRequest request) throws Exception {
        return update(labId, request, null);
    }

    public LabAdminTransactionResponse update(
        BigInteger labId, LabAdminPublishRequest request, String idempotencyKey
    ) throws Exception {
        requireOwnedLab(labId);
        String uri = resolveMetadataUri(request);
        BigInteger price = requireNonNegative(request.price(), "price");
        String accessURI = requireText(request.accessURI(), "accessURI", 500);
        String accessKey = requireText(request.accessKey(), "accessKey", 200);
        BigInteger resourceType = normalizeResourceType(request.resourceType());
        validatePhysicalAccessKey(accessKey, resourceType);

        try {
            Diamond.Lab current = loadReadonlyDiamond().getLab(labId).send();
            if (isOnChainLabUnchanged(current.base, uri, price, accessURI, accessKey, resourceType)) {
                return new LabAdminTransactionResponse(
                    true,
                    "metadataOnly",
                    null,
                    "offchain_updated",
                    labId,
                    uri
                );
            }
        } catch (Exception ex) {
            log.debug("Unable to compare current on-chain lab state for lab {}; proceeding with updateLab", labId, ex);
        }

        TransactionReceipt receipt = loadWritableDiamond(operationKey("update", labId, idempotencyKey))
            .updateLab(labId, uri, price, accessURI, accessKey, resourceType)
            .send();
        return new LabAdminTransactionResponse(
            true,
            "updateLab",
            receipt.getTransactionHash(),
            receipt.getStatus(),
            labId,
            uri
        );
    }

    public LabAdminTransactionResponse deleteLab(BigInteger labId) throws Exception {
        return deleteLab(labId, null);
    }

    public LabAdminTransactionResponse deleteLab(BigInteger labId, String idempotencyKey) throws Exception {
        requireOwnedLab(labId);
        String uri = walletService.getLabTokenUri(labId).orElse(null);
        TransactionReceipt receipt = loadWritableDiamond(operationKey("delete", labId, idempotencyKey))
            .deleteLab(labId).send();
        if (receipt == null) {
            throw new IllegalStateException("Lab deletion transaction returned no receipt");
        }
        if (!receipt.isStatusOK()) {
            throw new IllegalStateException("Lab deletion transaction was reverted");
        }
        try {
            contentRetentionService.markDeleted(labId, uri, receipt.getTransactionHash());
        } catch (IOException ex) {
            // The chain is authoritative; retain the successful result and
            // let the scheduled reconciler retry the off-chain hand-off.
            log.error("Lab {} deleted on-chain but content tombstone could not be written: {}", labId, ex.getMessage(), ex);
        }
        return new LabAdminTransactionResponse(
            true,
            "deleteLab",
            receipt.getTransactionHash(),
            receipt.getStatus(),
            labId,
            uri
        );
    }

    public LabAdminTransactionResponse listLab(BigInteger labId, boolean listed) throws Exception {
        return listLab(labId, listed, null);
    }

    public LabAdminTransactionResponse listLab(
        BigInteger labId, boolean listed, String idempotencyKey
    ) throws Exception {
        requireOwnedLab(labId);
        String uri = walletService.getLabTokenUri(labId).orElse(null);
        if (listed) {
            preflightMetadataUri(uri);
        }
        TransactionReceipt receipt = listed
            ? loadWritableDiamond(operationKey("list", labId, idempotencyKey)).listLab(labId).send()
            : loadWritableDiamond(operationKey("unlist", labId, idempotencyKey)).unlistLab(labId).send();
        return new LabAdminTransactionResponse(
            true,
            listed ? "listLab" : "unlistLab",
            receipt.getTransactionHash(),
            receipt.getStatus(),
            labId,
            uri
        );
    }

    private void preflightMetadataUri(String metadataUri) throws IOException {
        String uri = requireText(metadataUri, "metadataUri", 1000);
        String gatewayPrefix = publicBaseUrl().replaceAll("/+$", "") + "/lab-content/";
        if (uri.startsWith(gatewayPrefix)) {
            String relativePath = uri.substring(gatewayPrefix.length());
            Path metadataFile = contentRoot().resolve(relativePath).normalize();
            ensureWithinContentRoot(metadataFile);
            if (!Files.isRegularFile(metadataFile) || Files.size(metadataFile) > 1024L * 1024L) {
                throw new IllegalArgumentException("Metadata preflight failed: document is unavailable");
            }
            try {
                Map<String, Object> metadata = objectMapper.readValue(
                    metadataFile.toFile(), new TypeReference<Map<String, Object>>() {}
                );
                normalizeGeneratedMetadata(metadata);
                validateGeneratedMetadata(metadata);
            } catch (IllegalArgumentException ex) {
                throw ex;
            } catch (Exception ex) {
                throw new IllegalArgumentException("Metadata preflight failed: document is not valid JSON", ex);
            }
            return;
        }

        try {
            labMetadataService.getLabMetadata(uri);
        } catch (RuntimeException ex) {
            throw new IllegalArgumentException("Metadata preflight failed: URI is not accessible", ex);
        }
    }

    public org.springframework.core.io.Resource loadContentResource(String relativePath) throws IOException {
        contentRetentionService.assertAvailable(relativePath);
        Path target = contentRoot().resolve(relativePath).normalize();
        ensureWithinContentRoot(target);
        if (!Files.isRegularFile(target)) {
            throw new java.io.FileNotFoundException("Content not found");
        }
        return new org.springframework.core.io.UrlResource(target.toUri());
    }

    public String contentTypeFor(String relativePath) {
        try {
            Path target = contentRoot().resolve(relativePath).normalize();
            ensureWithinContentRoot(target);
            String detected = Files.probeContentType(target);
            return detected != null ? detected : MediaType.APPLICATION_OCTET_STREAM_VALUE;
        } catch (Exception ignored) {
            log.debug("Unable to detect content type for requested lab content");
            return MediaType.APPLICATION_OCTET_STREAM_VALUE;
        }
    }

    private String resolveMetadataUri(LabAdminPublishRequest request) throws IOException {
        String setupMode = Optional.ofNullable(request.setupMode()).orElse("full").trim().toLowerCase(Locale.ROOT);
        if ("quick".equals(setupMode)) {
            return requireHttpsUrl(request.metadataUrl(), "metadataUrl");
        }

        Map<String, Object> metadata = request.metadata() == null
            ? new LinkedHashMap<>()
            : new LinkedHashMap<>(request.metadata());
        normalizeGeneratedMetadata(metadata);
        validateGeneratedMetadata(metadata);
        String contentId = normalizeContentId(objectsToString(metadata.get("contentId")));
        metadata.remove("contentId");
        Path targetDir = contentRoot().resolve("content").resolve(contentId).normalize();
        ensureWithinContentRoot(targetDir);
        Files.createDirectories(targetDir);
        Path metadataFile = targetDir.resolve("metadata.json").normalize();
        ensureWithinContentRoot(metadataFile);
        objectMapper.writerWithDefaultPrettyPrinter().writeValue(metadataFile.toFile(), metadata);
        return publicBaseUrl() + "/lab-content/content/" + contentId + "/metadata.json";
    }

    private void validateGeneratedMetadata(Map<String, Object> metadata) {
        requireMetadataText(metadata, "name", 160);
        requireMetadataText(metadata, "description", 4000);
        Object image = metadata.get("image");
        if (image != null && !objectsToString(image).isBlank()) {
            requireHttpsOrGatewayUrl(objectsToString(image), "image");
        }
        for (String url : stringList(metadata.get("images"))) {
            requireHttpsOrGatewayUrl(url, "images");
        }
        for (String url : stringList(metadata.get("docs"))) {
            requireHttpsOrGatewayUrl(url, "docs");
        }
    }

    private void requireMetadataText(Map<String, Object> metadata, String field, int max) {
        String value = objectsToString(metadata.get(field));
        if (value.isBlank() || value.length() > max) {
            throw new IllegalArgumentException("metadata." + field + " is required and must be under " + max + " characters");
        }
    }

    private String requireHttpsUrl(String value, String field) {
        String text = requireText(value, field, 1000);
        if (!text.startsWith("https://") && !text.startsWith(publicBaseUrl() + "/")) {
            throw new IllegalArgumentException(field + " must be an HTTPS URL");
        }
        return text;
    }

    private void requireHttpsOrGatewayUrl(String value, String field) {
        if (!value.startsWith("https://") && !value.startsWith(publicBaseUrl() + "/")) {
            throw new IllegalArgumentException("metadata." + field + " must be an HTTPS URL");
        }
    }

    BigInteger extractCreatedLabId(TransactionReceipt receipt, String providerWallet) {
        if (receipt == null || receipt.getLogs() == null) {
            throw new IllegalStateException("Successful lab publication has no receipt logs");
        }
        String expectedProviderTopic = indexedAddressTopic(providerWallet);
        for (Log logEntry : receipt.getLogs()) {
            if (logEntry == null || !isContractLog(logEntry) || logEntry.getTopics() == null) {
                continue;
            }
            List<String> topics = logEntry.getTopics();
            if (topics.size() < 4 || !ERC721_TRANSFER_TOPIC.equalsIgnoreCase(topics.get(0))) {
                continue;
            }
            if (!BigInteger.ZERO.equals(Numeric.toBigInt(topics.get(1)))) {
                continue;
            }
            if (!expectedProviderTopic.equalsIgnoreCase(topics.get(2))) {
                continue;
            }
            BigInteger tokenId = Numeric.toBigInt(topics.get(3));
            if (tokenId != null) {
                return tokenId;
            }
        }
        throw new IllegalStateException("Successful lab publication has no mint Transfer event for the provider wallet");
    }

    private boolean isContractLog(Log logEntry) {
        return logEntry.getAddress() == null
            || contractAddress == null
            || contractAddress.isBlank()
            || contractAddress.equalsIgnoreCase(logEntry.getAddress());
    }

    private String indexedAddressTopic(String address) {
        String normalized = Numeric.cleanHexPrefix(address == null ? "" : address).toLowerCase(Locale.ROOT);
        if (!normalized.matches("[0-9a-f]{40}")) {
            throw new IllegalArgumentException("provider wallet must be a valid address");
        }
        return "0x" + "0".repeat(24) + normalized;
    }

    Optional<BigInteger> findOwnedLabByUri(String uri, List<BigInteger> ownedLabs) {
        if (uri == null || uri.isBlank() || ownedLabs == null || ownedLabs.isEmpty()) {
            return Optional.empty();
        }
        return ownedLabs.stream()
            .filter(labId -> walletService.getLabTokenUri(labId)
                .map(existingUri -> existingUri.equalsIgnoreCase(uri))
                .orElse(false))
            .findFirst();
    }

    boolean isOnChainLabUnchanged(
        Diamond.LabBase current,
        String uri,
        BigInteger price,
        String accessURI,
        String accessKey,
        BigInteger resourceType
    ) {
        if (current == null) {
            return false;
        }
        return Objects.equals(current.uri, uri)
            && Objects.equals(current.price, price)
            && Objects.equals(current.accessURI, accessURI)
            && Objects.equals(current.accessKey, accessKey)
            && Objects.equals(current.resourceType, resourceType);
    }

    private LabAdminTransactionResponse existingLabResponse(BigInteger labId, String uri) {
        return new LabAdminTransactionResponse(
            true,
            "existingLab",
            null,
            "already_exists",
            labId,
            uri
        );
    }

    private String requirePublishIdempotencyKey(String idempotencyKey) {
        String normalized = idempotencyKey == null ? "" : idempotencyKey.trim();
        if (normalized.isBlank()) {
            throw new IllegalArgumentException("Idempotency-Key is required for lab publication");
        }
        if (normalized.length() > 128) {
            throw new IllegalArgumentException("Idempotency-Key must not exceed 128 characters");
        }
        return normalized;
    }

    private String resolveCreatorPucHash(LabAdminPublishRequest request) {
        String requested = request == null ? null : request.creatorPucHash();
        return requireCreatorPucHash(hasText(requested) ? requested : configuredCreatorPucHash);
    }

    private String requireCreatorPucHash(String value) {
        String normalized = value == null ? "" : value.trim();
        if (!BYTES32_PATTERN.matcher(normalized).matches() || ZERO_BYTES32.equalsIgnoreCase(normalized)) {
            throw new IllegalArgumentException("creatorPucHash must be a non-zero 0x-prefixed bytes32 value");
        }
        return normalized.toLowerCase(Locale.ROOT);
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private String operationKey(String action, Object businessId, String idempotencyKey) {
        String instance = idempotencyKey == null ? "" : idempotencyKey.trim();
        if (instance.isBlank()) {
            instance = UUID.randomUUID().toString();
        }
        return "lab-admin:" + action + ":" + String.valueOf(businessId) + ":" + instance;
    }

    private String requireProviderWallet() {
        if (!institutionalWalletService.isConfigured()) {
            throw new IllegalStateException("Institutional wallet is not configured");
        }
        String wallet = institutionalWalletService.getInstitutionalWalletAddress();
        if (!walletService.isLabProvider(wallet)) {
            throw new IllegalStateException("Institutional wallet is not registered as a lab provider");
        }
        return wallet;
    }

    private void requireOwnedLab(BigInteger labId) {
        if (labId == null || labId.compareTo(BigInteger.ZERO) <= 0) {
            throw new IllegalArgumentException("labId must be greater than zero");
        }
        String wallet = requireProviderWallet();
        if (!walletService.isLabOwnedByProvider(wallet, labId)) {
            throw new IllegalArgumentException("Lab is not owned by this provider wallet");
        }
    }

    private Diamond loadReadonlyDiamond() {
        Web3j currentWeb3j = walletService.getWeb3jInstance();
        return Diamond.load(
            contractAddress,
            currentWeb3j,
            new org.web3j.tx.ReadonlyTransactionManager(currentWeb3j, contractAddress),
            new StaticGasProvider(BigInteger.ZERO, BigInteger.ZERO)
        );
    }

    private Diamond loadWritableDiamond(String operationKey) {
        Web3j currentWeb3j = walletService.getWeb3jInstance();
        TransactionManager txManager = txManagerProvider.get(currentWeb3j, operationKey);
        return Diamond.load(
            contractAddress,
            currentWeb3j,
            txManager,
            new StaticGasProvider(resolveGasPriceWei(currentWeb3j), contractGasLimit)
        );
    }

    private BigInteger resolveGasPriceWei(Web3j currentWeb3j) {
        BigInteger fallback = Convert.toWei(
            Optional.ofNullable(defaultGasPriceGwei).orElse(BigInteger.ONE).toString(),
            Convert.Unit.GWEI
        ).toBigInteger();
        String strategy = Optional.ofNullable(gasPriceStrategy).orElse("network").trim().toLowerCase(Locale.ROOT);
        if ("fixed".equals(strategy)) {
            return fallback;
        }
        if (!"network".equals(strategy)) {
            log.warn("Unknown ethereum.gas.price.strategy '{}'; using network gas price with configured fallback", strategy);
        }
        try {
            var response = currentWeb3j.ethGasPrice().send();
            return response != null && response.getGasPrice() != null ? response.getGasPrice() : fallback;
        } catch (Exception ex) {
            log.warn("Unable to resolve gas price, using default: {}", LogSanitizer.sanitize(ex.getMessage()));
            return fallback;
        }
    }

    private List<Map<String, Object>> listFmus() {
        Path base = Path.of(fmuDataPath).normalize();
        if (!Files.isDirectory(base)) {
            return List.of();
        }
        List<Map<String, Object>> result = new ArrayList<>();
        try (var stream = Files.walk(base, 3)) {
            stream
                .filter(Files::isRegularFile)
                .filter(path -> path.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".fmu"))
                .limit(200)
                .forEach(path -> {
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("fileName", path.getFileName().toString());
                    item.put("relativePath", base.relativize(path).toString().replace('\\', '/'));
                    try {
                        item.put("size", Files.size(path));
                    } catch (IOException ignored) {
                        log.debug("Unable to determine file size for {}", path, ignored);
                        item.put("size", null);
                    }
                    result.add(item);
                });
        } catch (IOException ex) {
            log.warn("Unable to list FMU data path {}: {}", fmuDataPath, LogSanitizer.sanitize(ex.getMessage()));
        }
        return result;
    }

    private String publicBaseUrl() {
        return backendUrlResolver.resolveBaseDomain();
    }

    private Path contentRoot() throws IOException {
        Path root = Path.of(contentBasePath).toAbsolutePath().normalize();
        Files.createDirectories(root);
        return root;
    }

    private void ensureWithinContentRoot(Path path) throws IOException {
        if (!path.toAbsolutePath().normalize().startsWith(contentRoot())) {
            throw new IllegalArgumentException("Invalid content path");
        }
    }

    private String normalizeContentId(String value) {
        String text = value == null ? "" : value.trim();
        if (text.isBlank()) {
            return UUID.randomUUID().toString();
        }
        if (!text.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,80}")) {
            throw new IllegalArgumentException("Invalid contentId");
        }
        return text;
    }

    private String normalizeAssetKind(String value) {
        String text = Optional.ofNullable(value).orElse("").trim().toLowerCase(Locale.ROOT);
        if ("image".equals(text)) return "images";
        if ("doc".equals(text) || "document".equals(text)) return "docs";
        if (!"images".equals(text) && !"docs".equals(text)) {
            throw new IllegalArgumentException("Asset kind must be images or docs");
        }
        return text;
    }

    private String normalizeUploadedAssetPath(String value) {
        String text = Optional.ofNullable(value).orElse("").trim();
        if (text.isBlank()) {
            throw new IllegalArgumentException("Asset path is required");
        }
        if (text.startsWith("http://") || text.startsWith("https://")) {
            try {
                text = URI.create(text).getPath();
            } catch (IllegalArgumentException ex) {
                throw new IllegalArgumentException("Invalid asset path", ex);
            }
        }
        if (text.startsWith("/lab-content/")) {
            text = text.substring("/lab-content/".length());
        } else if (text.startsWith("lab-content/")) {
            text = text.substring("lab-content/".length());
        }
        while (text.startsWith("/")) {
            text = text.substring(1);
        }
        Path normalized = Path.of(text).normalize();
        if (normalized.isAbsolute() || normalized.startsWith("..")) {
            throw new IllegalArgumentException("Invalid asset path");
        }
        if (!"content".equals(normalized.getName(0).toString())) {
            throw new IllegalArgumentException("Invalid asset path");
        }
        if (normalized.getNameCount() == 3 && "metadata.json".equals(normalized.getName(2).toString())) {
            throw new IllegalArgumentException("Only uploaded image and document assets can be deleted");
        }
        if (normalized.getNameCount() < 4) {
            throw new IllegalArgumentException("Invalid asset path");
        }
        String kind = normalized.getName(2).toString();
        if (!"images".equals(kind) && !"docs".equals(kind)) {
            throw new IllegalArgumentException("Only uploaded image and document assets can be deleted");
        }
        if (normalized.getNameCount() != 4) {
            throw new IllegalArgumentException("Invalid asset path");
        }
        return normalized.toString().replace('\\', '/');
    }

    private String safeFileName(String original, String contentType, String kind) {
        String fallback = "images".equals(kind) ? "asset" : "document";
        String base = Optional.ofNullable(original).orElse(fallback).replace('\\', '/');
        int slash = base.lastIndexOf('/');
        if (slash >= 0) base = base.substring(slash + 1);
        base = base.replaceAll("[^A-Za-z0-9._-]", "_");
        if (base.isBlank() || ".".equals(base) || "..".equals(base)) {
            base = fallback;
        }
        if (!base.contains(".")) {
            base += switch (contentType) {
                case "image/png" -> ".png";
                case "image/webp" -> ".webp";
                case "image/gif" -> ".gif";
                case "application/pdf" -> ".pdf";
                default -> ".jpg";
            };
        }
        return UUID.randomUUID() + "-" + base;
    }

    private String requireText(String value, String field, int max) {
        if (!StringUtils.hasText(value) || value.trim().length() > max) {
            throw new IllegalArgumentException(field + " is required and must be under " + max + " characters");
        }
        return value.trim();
    }

    private BigInteger requireNonNegative(BigInteger value, String field) {
        if (value == null || value.compareTo(BigInteger.ZERO) < 0) {
            throw new IllegalArgumentException(field + " must be a non-negative integer");
        }
        BigInteger maxUint96 = BigInteger.ONE.shiftLeft(96).subtract(BigInteger.ONE);
        if (value.compareTo(maxUint96) > 0) {
            throw new IllegalArgumentException(field + " exceeds uint96");
        }
        return value;
    }

    private BigInteger normalizeResourceType(Integer value) {
        int type = value == null ? 0 : value;
        if (type < 0 || type > 1) {
            throw new IllegalArgumentException("resourceType must be 0 or 1");
        }
        return BigInteger.valueOf(type);
    }

    private void validatePhysicalAccessKey(String accessKey, BigInteger resourceType) {
        if (BigInteger.ONE.equals(resourceType)) {
            return;
        }
        GuacamoleProvisioningService.parseConnectionId(accessKey);
    }

    private String objectsToString(Object value) {
        return value == null ? "" : String.valueOf(value).trim();
    }

    void normalizeGeneratedMetadata(Map<String, Object> metadata) {
        String primaryImage = objectsToString(metadata.get("image"));
        List<String> images = new ArrayList<>();
        addDistinct(images, primaryImage);

        List<Map<String, Object>> attributes = metadataAttributes(metadata.get("attributes"));
        List<String> additionalImages = new ArrayList<>();

        for (Map<String, Object> attribute : attributes) {
            String traitType = objectsToString(attribute.get("trait_type"));
            if ("additionalImages".equals(traitType)) {
                addDistinct(additionalImages, stringList(attribute.get("value")));
            }
        }

        addDistinct(images, additionalImages);

        if (primaryImage.isBlank() && !images.isEmpty()) {
            metadata.put("image", images.get(0));
        }
    }

    private void addDistinct(List<String> target, List<String> values) {
        for (String value : values) {
            addDistinct(target, value);
        }
    }

    private void addDistinct(List<String> target, String value) {
        String text = objectsToString(value);
        if (!text.isBlank() && target.stream().noneMatch(text::equals)) {
            target.add(text);
        }
    }

    private List<Map<String, Object>> metadataAttributes(Object value) {
        if (!(value instanceof List<?> values)) {
            return List.of();
        }
        List<Map<String, Object>> attributes = new ArrayList<>();
        for (Object item : values) {
            if (item instanceof Map<?, ?> map) {
                Map<String, Object> normalized = new LinkedHashMap<>();
                for (Map.Entry<?, ?> entry : map.entrySet()) {
                    normalized.put(String.valueOf(entry.getKey()), entry.getValue());
                }
                attributes.add(normalized);
            }
        }
        return attributes;
    }

    private List<String> stringList(Object value) {
        List<String> result = new ArrayList<>();
        if (value instanceof List<?> values) {
            for (Object item : values) {
                String text = objectsToString(item);
                if (!text.isBlank()) {
                    result.add(text);
                }
            }
            return result;
        }
        String text = objectsToString(value);
        if (!text.isBlank()) {
            result.add(text);
        }
        return result;
    }
}
