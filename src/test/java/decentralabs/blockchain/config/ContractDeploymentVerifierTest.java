package decentralabs.blockchain.config;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.HexFormat;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

class ContractDeploymentVerifierTest {

    private static final String DIAMOND = "0x1111111111111111111111111111111111111111";
    private static final String OWNER = "0x2222222222222222222222222222222222222222";
    private static final String FACET = "0x3333333333333333333333333333333333333333";
    private static final String CODE_HASH = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private static final String DIAMOND_CODE_HASH = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    private static final String DEFAULT_ADMIN_ROLE =
        "0x0000000000000000000000000000000000000000000000000000000000000000";

    @Test
    void acceptsADeploymentThatMatchesTheConfiguredDiamondAndLoupeSnapshot() {
        ContractDeploymentVerifier.DeploymentManifest manifest = manifest();
        ContractDeploymentVerifier.SelectorManifest selectorManifest = selectorManifest();
        ContractDeploymentVerifier.ContractSnapshot snapshot = snapshot();

        assertThatCode(() -> ContractDeploymentVerifier.validateSnapshot(
            DIAMOND, "sepolia", "credit-ledger-v1", "abi-sha", "selector-sha",
            manifest, selectorManifest, snapshot
        )).doesNotThrowAnyException();
    }

    @Test
    void rejectsAConfiguredDiamondDifferentFromTheDeploymentManifest() {
        assertThatThrownBy(() -> ContractDeploymentVerifier.validateSnapshot(
            "0x4444444444444444444444444444444444444444", "sepolia", "credit-ledger-v1",
            "abi-sha", "selector-sha", manifest(), selectorManifest(), snapshot()
        )).isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("configured address");
    }

    @Test
    void rejectsWrongChainOwnerCodeOrMissingLoupeEvidence() {
        ContractDeploymentVerifier.ContractSnapshot wrongChain = new ContractDeploymentVerifier.ContractSnapshot(
            BigInteger.ONE, snapshot().codeHashes(), OWNER, DEFAULT_ADMIN_ROLE, true, true,
            snapshot().facetAddresses(), snapshot().facetSelectors()
        );

        assertThatThrownBy(() -> ContractDeploymentVerifier.validateSnapshot(
            DIAMOND, "sepolia", "credit-ledger-v1", "abi-sha", "selector-sha",
            manifest(), selectorManifest(), wrongChain
        )).isInstanceOf(IllegalStateException.class).hasMessageContaining("chain ID");

        ContractDeploymentVerifier.ContractSnapshot wrongOwner = new ContractDeploymentVerifier.ContractSnapshot(
            snapshot().chainId(), snapshot().codeHashes(), FACET, DEFAULT_ADMIN_ROLE, true, true,
            snapshot().facetAddresses(), snapshot().facetSelectors()
        );
        assertThatThrownBy(() -> ContractDeploymentVerifier.validateSnapshot(
            DIAMOND, "sepolia", "credit-ledger-v1", "abi-sha", "selector-sha",
            manifest(), selectorManifest(), wrongOwner
        )).isInstanceOf(IllegalStateException.class).hasMessageContaining("owner");

        ContractDeploymentVerifier.ContractSnapshot noLoupe = new ContractDeploymentVerifier.ContractSnapshot(
            snapshot().chainId(), Map.of(DIAMOND, "0xwrong"), OWNER, DEFAULT_ADMIN_ROLE, true, false,
            snapshot().facetAddresses(), snapshot().facetSelectors()
        );
        assertThatThrownBy(() -> ContractDeploymentVerifier.validateSnapshot(
            DIAMOND, "sepolia", "credit-ledger-v1", "abi-sha", "selector-sha",
            manifest(), selectorManifest(), noLoupe
        )).isInstanceOf(IllegalStateException.class).hasMessageContaining("loupe");
    }

    @Test
    void rejectsSelectorManifestMismatch() {
        ContractDeploymentVerifier.ContractSnapshot missingSelector = new ContractDeploymentVerifier.ContractSnapshot(
            snapshot().chainId(), snapshot().codeHashes(), OWNER, DEFAULT_ADMIN_ROLE, true, true,
            snapshot().facetAddresses(), Map.of(FACET, Set.of())
        );

        assertThatThrownBy(() -> ContractDeploymentVerifier.validateSnapshot(
            DIAMOND, "sepolia", "credit-ledger-v1", "abi-sha", "selector-sha",
            manifest(), selectorManifest(), missingSelector
        )).isInstanceOf(IllegalStateException.class).hasMessageContaining("selector");
    }

    @Test
    void productionConfigurationDoesNotProvideAContractAddressFallback() throws IOException {
        Properties properties = new Properties();
        try (var input = Files.newInputStream(Path.of("src/main/resources/application.properties"))) {
            properties.load(input);
        }

        assertThat(properties.getProperty("contract.address")).isEqualTo("${CONTRACT_ADDRESS}");
    }

    @Test
    void sessionStartedAttestationDomainUsesTheCanonicalContractConfiguration() throws IOException {
        Properties properties = new Properties();
        try (var input = Files.newInputStream(Path.of("src/main/resources/application.properties"))) {
            properties.load(input);
        }

        assertThat(properties.getProperty("session.attestation.domain.name"))
            .isEqualTo("DecentraLabsSession");
        assertThat(properties.getProperty("session.attestation.domain.version"))
            .isEqualTo("1");
        assertThat(properties.getProperty("session.attestation.domain.chain-id"))
            .isEqualTo("${INTENT_DOMAIN_CHAIN_ID:11155111}");
        assertThat(properties.getProperty("session.attestation.domain.verifying-contract"))
            .isEqualTo("${contract.address}");
    }

    @Test
    void selectorManifestDeserializesFacetTargets() throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        try (InputStream input = getClass().getResourceAsStream("/contract/selector-manifest.json")) {
            assertThat(input).isNotNull();
            ContractDeploymentVerifier.SelectorManifest manifest = objectMapper.readValue(
                input, ContractDeploymentVerifier.SelectorManifest.class
            );

            assertThat(manifest.facets()).isNotEmpty();
            assertThat(manifest.facets()).allSatisfy(facet -> assertThat(facet.target()).isNotBlank());
            assertThat(manifest.internalRoutingFunctions()).isNotEmpty();
            assertThat(manifest.forbiddenFunctions()).isNotEmpty();
        }
    }

    @Test
    void packagesTheCanonicalDiamondAbiForStartupVerification() throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        ContractDeploymentVerifier.DeploymentManifest deploymentManifest;
        try (InputStream input = getClass().getResourceAsStream("/contract/deployment-manifest.json")) {
            assertThat(input).isNotNull();
            deploymentManifest = objectMapper.readValue(
                input, ContractDeploymentVerifier.DeploymentManifest.class
            );
        }

        try (InputStream input = getClass().getResourceAsStream("/abi/Diamond.json")) {
            assertThat(input).isNotNull();
            String actualHash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(
                input.readAllBytes()
            ));
            assertThat(actualHash).isEqualTo(deploymentManifest.abiSha256());
        }
    }

    private static ContractDeploymentVerifier.DeploymentManifest manifest() {
        return new ContractDeploymentVerifier.DeploymentManifest(
            1, "sepolia", BigInteger.valueOf(11155111), "credit-ledger-v1", "abi-sha", "selector-sha",
            DIAMOND, OWNER, DEFAULT_ADMIN_ROLE,
            Map.of("DiamondInit", FACET), Map.of(DIAMOND, DIAMOND_CODE_HASH),
            List.of(new ContractDeploymentVerifier.FacetExpectation("CoreFacet", FACET, CODE_HASH))
        );
    }

    private static ContractDeploymentVerifier.SelectorManifest selectorManifest() {
        return new ContractDeploymentVerifier.SelectorManifest(
            1, "credit-ledger",
            List.of(new ContractDeploymentVerifier.SelectorFacet(
                "CoreFacet", "contracts/facets/CoreFacet.sol:CoreFacet", List.of("foo()")
            )),
            List.of("foo()"),
            List.of("legacy()"),
            List.of("bar()")
        );
    }

    private static ContractDeploymentVerifier.ContractSnapshot snapshot() {
        String selector = ContractDeploymentVerifier.selectorFor("foo()");
        return new ContractDeploymentVerifier.ContractSnapshot(
            BigInteger.valueOf(11155111),
            Map.of(DIAMOND, DIAMOND_CODE_HASH, FACET, CODE_HASH),
            OWNER, DEFAULT_ADMIN_ROLE, true, true,
            Set.of(FACET), Map.of(FACET, Set.of(selector))
        );
    }
}
