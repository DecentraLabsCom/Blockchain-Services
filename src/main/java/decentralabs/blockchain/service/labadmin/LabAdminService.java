package decentralabs.blockchain.service.labadmin;

import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.contract.Diamond;
import decentralabs.blockchain.dto.labadmin.LabAdminAssetResponse;
import decentralabs.blockchain.dto.labadmin.LabAdminPublishRequest;
import decentralabs.blockchain.dto.labadmin.LabAdminTransactionResponse;
import decentralabs.blockchain.service.BackendUrlResolver;
import decentralabs.blockchain.service.wallet.InstitutionalTxManagerProvider;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import decentralabs.blockchain.util.LogSanitizer;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.tx.TransactionManager;
import org.web3j.tx.gas.StaticGasProvider;
import org.web3j.utils.Convert;

@Service
@RequiredArgsConstructor
@Slf4j
public class LabAdminService {

    private static final long MAX_ASSET_BYTES = 10L * 1024L * 1024L;
    private static final List<String> IMAGE_TYPES = List.of("image/jpeg", "image/png", "image/webp", "image/gif");
    private static final List<String> DOC_TYPES = List.of("application/pdf");

    private final InstitutionalWalletService institutionalWalletService;
    private final InstitutionalTxManagerProvider txManagerProvider;
    private final WalletService walletService;
    private final BackendUrlResolver backendUrlResolver;
    private final ObjectMapper objectMapper;
    private final Web3j web3j;

    @Value("${contract.address}")
    private String contractAddress;

    @Value("${lab.content.base-path:/app/lab-content}")
    private String contentBasePath;

    @Value("${fmu.data.path:/app/fmu-data}")
    private String fmuDataPath;

    @Value("${ethereum.gas.price.default:1}")
    private BigInteger defaultGasPriceGwei;

    @Value("${ethereum.gas.limit.contract:300000}")
    private BigInteger contractGasLimit;

    public Map<String, Object> status() {
        String wallet = institutionalWalletService.getInstitutionalWalletAddress();
        boolean walletConfigured = institutionalWalletService.isConfigured();
        boolean provider = walletConfigured && walletService.isLabProvider(wallet);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("walletConfigured", walletConfigured);
        result.put("providerAddress", wallet);
        result.put("isProvider", provider);
        result.put("publicBaseUrl", publicBaseUrl());
        result.put("contentBaseUrl", publicBaseUrl() + "/lab-content");
        result.put("recommendedRemoteAccessURI", publicBaseUrl() + "/guacamole");
        result.put("recommendedFmuAccessURI", publicBaseUrl() + "/fmu");
        result.put("fmuInventory", listFmus());
        return result;
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
            } catch (Exception ex) {
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

    public LabAdminTransactionResponse publish(LabAdminPublishRequest request) throws Exception {
        String wallet = requireProviderWallet();
        String uri = resolveMetadataUri(request);
        BigInteger price = requireNonNegative(request.price(), "price");
        String accessURI = requireText(request.accessURI(), "accessURI", 500);
        String accessKey = requireText(request.accessKey(), "accessKey", 200);
        BigInteger resourceType = normalizeResourceType(request.resourceType());
        boolean listImmediately = request.listImmediately() == null || request.listImmediately();

        List<BigInteger> before = walletService.getLabsOwnedByProvider(wallet);
        Diamond diamond = loadWritableDiamond();
        TransactionReceipt receipt = listImmediately
            ? diamond.addAndListLab(uri, price, accessURI, accessKey, resourceType).send()
            : diamond.addLab(uri, price, accessURI, accessKey, resourceType).send();
        BigInteger labId = inferCreatedLabId(wallet, before);

        return new LabAdminTransactionResponse(
            true,
            listImmediately ? "addAndListLab" : "addLab",
            receipt.getTransactionHash(),
            receipt.getStatus(),
            labId,
            uri
        );
    }

    public LabAdminTransactionResponse listLab(BigInteger labId, boolean listed) throws Exception {
        requireOwnedLab(labId);
        TransactionReceipt receipt = listed
            ? loadWritableDiamond().listLab(labId).send()
            : loadWritableDiamond().unlistLab(labId).send();
        return new LabAdminTransactionResponse(
            true,
            listed ? "listLab" : "unlistLab",
            receipt.getTransactionHash(),
            receipt.getStatus(),
            labId,
            walletService.getLabTokenUri(labId).orElse(null)
        );
    }

    public org.springframework.core.io.Resource loadContentResource(String relativePath) throws IOException {
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

    private BigInteger inferCreatedLabId(String wallet, List<BigInteger> before) {
        List<BigInteger> after = walletService.getLabsOwnedByProvider(wallet);
        after.removeAll(before);
        return after.stream().max(BigInteger::compareTo).orElse(null);
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
        return Diamond.load(
            contractAddress,
            web3j,
            new org.web3j.tx.ReadonlyTransactionManager(web3j, contractAddress),
            new StaticGasProvider(BigInteger.ZERO, BigInteger.ZERO)
        );
    }

    private Diamond loadWritableDiamond() {
        TransactionManager txManager = txManagerProvider.get(web3j);
        return Diamond.load(contractAddress, web3j, txManager, new StaticGasProvider(resolveGasPriceWei(), contractGasLimit));
    }

    private BigInteger resolveGasPriceWei() {
        BigInteger fallback = Convert.toWei(
            Optional.ofNullable(defaultGasPriceGwei).orElse(BigInteger.ONE).toString(),
            Convert.Unit.GWEI
        ).toBigInteger();
        try {
            var response = web3j.ethGasPrice().send();
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

    private String objectsToString(Object value) {
        return value == null ? "" : String.valueOf(value).trim();
    }
}
