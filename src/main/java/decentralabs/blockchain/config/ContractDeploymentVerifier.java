package decentralabs.blockchain.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.FunctionReturnDecoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.Bool;
import org.web3j.abi.datatypes.DynamicArray;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.abi.datatypes.generated.Bytes4;
import org.web3j.crypto.Hash;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.protocol.core.methods.response.EthCall;
import org.web3j.protocol.core.methods.response.EthGetCode;
import org.web3j.utils.Numeric;

/**
 * Fails startup when the configured RPC endpoint does not expose the Diamond
 * deployment for which this backend was built.
 *
 * <p>This is deliberately an application-runner rather than a health check:
 * a process connected to the wrong Diamond must never become ready.</p>
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
@ConditionalOnProperty(name = "contract.verification.enabled", havingValue = "true", matchIfMissing = true)
public class ContractDeploymentVerifier implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(ContractDeploymentVerifier.class);
    private static final String DIAMOND_LOUPE_INTERFACE_ID = "0x48e2b093";

    private final Web3j web3j;
    private final ObjectMapper objectMapper;
    private final String configuredAddress;
    private final String activeNetwork;
    private final String expectedAbiVersion;
    private final Resource deploymentManifestResource;
    private final Resource selectorManifestResource;
    private final Resource abiResource;

    public ContractDeploymentVerifier(
        Web3j web3j,
        ObjectMapper objectMapper,
        @Value("${contract.address}") String configuredAddress,
        @Value("${blockchain.network.active}") String activeNetwork,
        @Value("${contract.verification.abi-version:credit-ledger-v1}") String expectedAbiVersion,
        @Value("${contract.verification.deployment-manifest:classpath:contract/deployment-manifest.json}")
        Resource deploymentManifestResource,
        @Value("${contract.verification.selector-manifest:classpath:contract/selector-manifest.json}")
        Resource selectorManifestResource,
        @Value("${contract.verification.abi-resource:classpath:abi/Diamond.json}") Resource abiResource
    ) {
        this.web3j = web3j;
        this.objectMapper = objectMapper;
        this.configuredAddress = configuredAddress;
        this.activeNetwork = activeNetwork;
        this.expectedAbiVersion = expectedAbiVersion;
        this.deploymentManifestResource = deploymentManifestResource;
        this.selectorManifestResource = selectorManifestResource;
        this.abiResource = abiResource;
    }

    @Override
    public void run(ApplicationArguments args) throws Exception {
        DeploymentManifest manifest = readManifest(deploymentManifestResource, DeploymentManifest.class);
        SelectorManifest selectorManifest = readManifest(selectorManifestResource, SelectorManifest.class);
        String abiSha256 = sha256(abiResource);
        String selectorManifestSha256 = sha256(selectorManifestResource);

        ContractSnapshot snapshot = readSnapshot(manifest);
        validateSnapshot(
            configuredAddress,
            activeNetwork,
            expectedAbiVersion,
            abiSha256,
            selectorManifestSha256,
            manifest,
            selectorManifest,
            snapshot
        );

        log.info(
            "Verified Diamond deployment address={} network={} chainId={} facets={} abiVersion={}",
            normalizeAddress(configuredAddress),
            manifest.network(),
            snapshot.chainId(),
            manifest.facets().size(),
            manifest.abiVersion()
        );
    }

    private <T> T readManifest(Resource resource, Class<T> type) throws IOException {
        try (InputStream input = resource.getInputStream()) {
            return objectMapper.readValue(input, type);
        }
    }

    private ContractSnapshot readSnapshot(DeploymentManifest manifest) throws IOException {
        BigInteger chainId = web3j.ethChainId().send().getChainId();
        Map<String, String> codeHashes = new LinkedHashMap<>();

        String diamondAddress = normalizeAddress(manifest.diamondAddress());
        codeHashes.put(diamondAddress, codeHash(diamondAddress));

        for (String address : manifest.criticalAddresses().values()) {
            String normalized = normalizeAddress(address);
            codeHashes.put(normalized, codeHash(normalized));
        }
        for (FacetExpectation facet : manifest.facets()) {
            String normalized = normalizeAddress(facet.address());
            codeHashes.put(normalized, codeHash(normalized));
        }

        String owner = decodeAddress(call(new Function(
            "owner", List.of(), List.of(new TypeReference<Address>() {})
        )));
        String defaultAdminRole = decodeBytes32(call(new Function(
            "DEFAULT_ADMIN_ROLE", List.of(), List.of(new TypeReference<Bytes32>() {})
        )));
        boolean ownerHasDefaultAdminRole = decodeBool(call(new Function(
            "hasRole",
            List.of(new Bytes32(Numeric.hexStringToByteArray(defaultAdminRole)), new Address(owner)),
            List.of(new TypeReference<Bool>() {})
        )));
        boolean loupeSupported = decodeBool(call(new Function(
            "supportsInterface",
            List.of(new Bytes4(Numeric.hexStringToByteArray(DIAMOND_LOUPE_INTERFACE_ID))),
            List.of(new TypeReference<Bool>() {})
        )));

        List<String> facetAddresses = decodeAddressArray(call(new Function(
            "facetAddresses", List.of(), List.of(new TypeReference<DynamicArray<Address>>() {})
        )));
        Map<String, Set<String>> facetSelectors = new LinkedHashMap<>();
        for (String facetAddress : facetAddresses) {
            String normalized = normalizeAddress(facetAddress);
            List<Type> decoded = call(new Function(
                "facetFunctionSelectors",
                List.of(new Address(normalized)),
                List.of(new TypeReference<DynamicArray<Bytes4>>() {})
            ));
            @SuppressWarnings("unchecked")
            DynamicArray<Bytes4> selectors = (DynamicArray<Bytes4>) decoded.get(0);
            facetSelectors.put(
                normalized,
                selectors.getValue().stream()
                    .map(value -> Numeric.toHexString(value.getValue()).toLowerCase(Locale.ROOT))
                    .collect(Collectors.toCollection(TreeSet::new))
            );
        }

        return new ContractSnapshot(
            chainId,
            codeHashes,
            owner,
            defaultAdminRole,
            ownerHasDefaultAdminRole,
            loupeSupported,
            new LinkedHashSet<>(facetAddresses.stream().map(ContractDeploymentVerifier::normalizeAddress).toList()),
            facetSelectors
        );
    }

    private String codeHash(String address) throws IOException {
        EthGetCode response = web3j.ethGetCode(address, DefaultBlockParameterName.LATEST).send();
        if (response == null || response.hasError()) {
            throw verificationFailure("could not read bytecode for " + address);
        }
        String code = response.getCode();
        if (code == null || code.isBlank() || "0x".equalsIgnoreCase(code)) {
            throw verificationFailure("no bytecode at " + address);
        }
        return Numeric.toHexString(Hash.sha3(Numeric.hexStringToByteArray(code))).toLowerCase(Locale.ROOT);
    }

    private List<Type> call(Function function) throws IOException {
        EthCall response = web3j.ethCall(
            Transaction.createEthCallTransaction(null, normalizeAddress(configuredAddress), FunctionEncoder.encode(function)),
            DefaultBlockParameterName.LATEST
        ).send();
        if (response == null || response.hasError()) {
            throw verificationFailure("RPC call reverted for selector " + selectorFor(function.getName()));
        }
        String value = response.getValue();
        if (value == null || value.isBlank() || "0x".equalsIgnoreCase(value)) {
            throw verificationFailure("RPC call returned no data for " + function.getName());
        }
        return FunctionReturnDecoder.decode(value, function.getOutputParameters());
    }

    private static String decodeAddress(List<Type> decoded) {
        return normalizeAddress(((Address) decoded.get(0)).getValue());
    }

    private static String decodeBytes32(List<Type> decoded) {
        return Numeric.toHexString(((Bytes32) decoded.get(0)).getValue()).toLowerCase(Locale.ROOT);
    }

    private static boolean decodeBool(List<Type> decoded) {
        return ((Bool) decoded.get(0)).getValue();
    }

    @SuppressWarnings("unchecked")
    private static List<String> decodeAddressArray(List<Type> decoded) {
        DynamicArray<Address> addresses = (DynamicArray<Address>) decoded.get(0);
        return addresses.getValue().stream().map(Address::getValue).toList();
    }

    private static String sha256(Resource resource) throws IOException {
        try (InputStream input = resource.getInputStream()) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[8192];
            int read;
            while ((read = input.read(buffer)) >= 0) {
                digest.update(buffer, 0, read);
            }
            return Numeric.toHexString(digest.digest()).substring(2).toLowerCase(Locale.ROOT);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    static String selectorFor(String signature) {
        return Hash.sha3String(signature).substring(0, 10).toLowerCase(Locale.ROOT);
    }

    static void validateSnapshot(
        String configuredAddress,
        String activeNetwork,
        String expectedAbiVersion,
        String actualAbiSha256,
        String actualSelectorManifestSha256,
        DeploymentManifest manifest,
        SelectorManifest selectorManifest,
        ContractSnapshot snapshot
    ) {
        requireAddress(configuredAddress, "configured address");
        if (!normalizeAddress(configuredAddress).equals(normalizeAddress(manifest.diamondAddress()))) {
            fail("configured address does not match the deployment manifest");
        }
        if (!Objects.equals(normalizeText(activeNetwork), normalizeText(manifest.network()))) {
            fail("active network does not match the deployment manifest");
        }
        if (!Objects.equals(expectedAbiVersion, manifest.abiVersion())) {
            fail("ABI version does not match the deployment manifest");
        }
        if (!normalizeHash(actualAbiSha256).equals(normalizeHash(manifest.abiSha256()))) {
            fail("local ABI hash does not match the deployment manifest");
        }
        if (!normalizeHash(actualSelectorManifestSha256).equals(normalizeHash(manifest.selectorManifestSha256()))) {
            fail("selector manifest hash does not match the deployment manifest");
        }
        if (selectorManifest.schemaVersion() != manifest.schemaVersion()) {
            fail("selector manifest schema version does not match the deployment manifest");
        }
        if (!"credit-ledger".equalsIgnoreCase(selectorManifest.deploymentModel())) {
            fail("selector manifest deployment model is not credit-ledger");
        }
        if (!manifest.chainId().equals(snapshot.chainId())) {
            fail("RPC chain ID " + snapshot.chainId() + " does not match expected chain ID " + manifest.chainId());
        }
        if (!snapshot.loupeSupported()) {
            fail("Diamond loupe interface is not supported");
        }
        if (!normalizeAddress(manifest.expectedOwner()).equals(normalizeAddress(snapshot.owner()))) {
            fail("Diamond owner does not match the expected admin");
        }
        if (!normalizeHash(manifest.expectedDefaultAdminRole()).equals(normalizeHash(snapshot.defaultAdminRole()))) {
            fail("DEFAULT_ADMIN_ROLE does not match the expected role");
        }
        if (!snapshot.ownerHasDefaultAdminRole()) {
            fail("expected admin does not hold DEFAULT_ADMIN_ROLE");
        }

        for (Map.Entry<String, String> entry : manifest.criticalAddresses().entrySet()) {
            requireAddress(entry.getValue(), "critical address " + entry.getKey());
            if (!snapshot.codeHashes().containsKey(normalizeAddress(entry.getValue()))) {
                fail("critical address was not checked: " + entry.getKey());
            }
        }
        for (Map.Entry<String, String> entry : manifest.criticalCodeHashes().entrySet()) {
            String actualHash = snapshot.codeHashes().get(normalizeAddress(entry.getKey()));
            if (!normalizeHash(entry.getValue()).equals(normalizeHash(actualHash))) {
                fail("bytecode hash mismatch for critical address " + entry.getKey());
            }
        }
        for (FacetExpectation facet : manifest.facets()) {
            requireAddress(facet.address(), "facet " + facet.name());
            String address = normalizeAddress(facet.address());
            if (!normalizeHash(facet.codeHash()).equals(normalizeHash(snapshot.codeHashes().get(address)))) {
                fail("bytecode hash mismatch for facet " + facet.name());
            }
        }
        String expectedDiamondHash = snapshot.codeHashes().get(normalizeAddress(manifest.diamondAddress()));
        if (expectedDiamondHash == null || expectedDiamondHash.isBlank()) {
            fail("Diamond bytecode was not checked");
        }

        Set<String> expectedFacetAddresses = manifest.facets().stream()
            .map(FacetExpectation::address)
            .map(ContractDeploymentVerifier::normalizeAddress)
            .collect(Collectors.toCollection(TreeSet::new));
        Set<String> actualFacetAddresses = snapshot.facetAddresses().stream()
            .map(ContractDeploymentVerifier::normalizeAddress)
            .collect(Collectors.toCollection(TreeSet::new));
        if (!expectedFacetAddresses.equals(actualFacetAddresses)) {
            fail("Diamond loupe facet set does not match the deployment manifest");
        }

        Map<String, Set<String>> expectedSelectorsByFacet = new HashMap<>();
        for (SelectorFacet facet : selectorManifest.facets()) {
            Set<String> selectors = facet.functions().stream()
                .map(ContractDeploymentVerifier::selectorFor)
                .collect(Collectors.toCollection(TreeSet::new));
            if (expectedSelectorsByFacet.put(facet.name(), selectors) != null) {
                fail("selector manifest contains duplicate facet " + facet.name());
            }
        }
        Set<String> manifestFacetNames = manifest.facets().stream().map(FacetExpectation::name).collect(Collectors.toSet());
        if (!manifestFacetNames.equals(expectedSelectorsByFacet.keySet())) {
            fail("selector manifest facets do not match the deployment manifest");
        }
        for (FacetExpectation facet : manifest.facets()) {
            Set<String> actualSelectors = snapshot.facetSelectors().getOrDefault(
                normalizeAddress(facet.address()), Set.of()
            ).stream().map(value -> value.toLowerCase(Locale.ROOT)).collect(Collectors.toCollection(TreeSet::new));
            Set<String> expectedSelectors = expectedSelectorsByFacet.get(facet.name());
            if (!actualSelectors.equals(expectedSelectors)) {
                fail("Diamond loupe selectors do not match the selector manifest for facet " + facet.name());
            }
        }
    }

    private static String normalizeAddress(String value) {
        return value == null ? null : value.trim().toLowerCase(Locale.ROOT);
    }

    private static String normalizeText(String value) {
        return value == null ? null : value.trim().toLowerCase(Locale.ROOT);
    }

    private static String normalizeHash(String value) {
        return value == null ? null : value.trim().toLowerCase(Locale.ROOT).replaceFirst("^0x", "");
    }

    private static void requireAddress(String value, String label) {
        if (value == null || !value.trim().matches("0x[0-9a-fA-F]{40}")) {
            fail(label + " is not a valid Ethereum address");
        }
    }

    private static IllegalStateException verificationFailure(String detail) {
        return new IllegalStateException("Diamond startup verification failed: " + detail);
    }

    private static void fail(String detail) {
        throw verificationFailure(detail);
    }

    public record DeploymentManifest(
        int schemaVersion,
        String network,
        BigInteger chainId,
        String abiVersion,
        String abiSha256,
        String selectorManifestSha256,
        String diamondAddress,
        String expectedOwner,
        String expectedDefaultAdminRole,
        Map<String, String> criticalAddresses,
        Map<String, String> criticalCodeHashes,
        List<FacetExpectation> facets
    ) { }

    public record FacetExpectation(String name, String address, String codeHash) { }

    public record SelectorManifest(
        int schemaVersion,
        String deploymentModel,
        List<SelectorFacet> facets
    ) { }

    public record SelectorFacet(String name, List<String> functions) { }

    public record ContractSnapshot(
        BigInteger chainId,
        Map<String, String> codeHashes,
        String owner,
        String defaultAdminRole,
        boolean ownerHasDefaultAdminRole,
        boolean loupeSupported,
        Set<String> facetAddresses,
        Map<String, Set<String>> facetSelectors
    ) { }
}
