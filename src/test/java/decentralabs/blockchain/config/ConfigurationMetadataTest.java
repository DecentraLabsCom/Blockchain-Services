package decentralabs.blockchain.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ConfigurationMetadataTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void documentsSecuritySensitiveAndAuditProperties() throws Exception {
        Map<String, JsonNode> properties = readProperties();

        assertThat(properties)
            .containsKeys(
                "institutional.checkin.delegation.allow-http",
                "institutional.checkin.delegation.allow-private-networks",
                "access.audit.observation-window-tolerance-seconds",
                "institutional.transaction-outbox.monitor.max-gas-price-wei",
                "institutional.transaction-outbox.monitor.max-multiplier",
                "institutional.transaction-outbox.monitor.max-estimated-transaction-cost-wei"
            );
        assertThat(properties.get("institutional.checkin.delegation.allow-http").path("type").asText())
            .isEqualTo("java.lang.Boolean");
        assertThat(properties.get("institutional.checkin.delegation.allow-http").path("defaultValue").asBoolean())
            .isFalse();
        assertThat(properties.get("institutional.checkin.delegation.allow-private-networks").path("defaultValue").asBoolean())
            .isFalse();
        assertThat(properties.get("access.audit.observation-window-tolerance-seconds").path("defaultValue").asLong())
            .isEqualTo(30L);
        assertThat(properties.get("institutional.transaction-outbox.monitor.max-gas-price-wei")
            .path("defaultValue").asLong()).isEqualTo(100_000_000_000L);
        assertThat(properties.get("institutional.transaction-outbox.monitor.max-multiplier")
            .path("defaultValue").asDouble()).isEqualTo(3.0);
        assertThat(properties.get("institutional.transaction-outbox.monitor.max-estimated-transaction-cost-wei")
            .path("defaultValue").asLong()).isEqualTo(100_000_000_000_000_000L);
    }

    @Test
    void documentsCustomPropertiesUsedByPairingAndMarketplaceAuth() throws Exception {
        Map<String, JsonNode> properties = readProperties();

        assertThat(properties).containsKeys(
            "intent.payload.encryption-key",
            "provider.puc-hash",
            "auth.marketplace-endpoints.audience",
            "auth.marketplace-endpoints.institution-id",
            "auth.marketplace-endpoints.service-subject",
            "auth.marketplace-endpoints.max-ttl-seconds"
        );
    }

    @Test
    void documentsSessionStartedAttestationDomainProperties() throws Exception {
        Map<String, JsonNode> properties = readProperties();

        assertThat(properties).containsKeys(
            "session.attestation.domain.name",
            "session.attestation.domain.version",
            "session.attestation.domain.chain-id",
            "session.attestation.domain.verifying-contract"
        );
        assertThat(properties.get("session.attestation.domain.name").path("defaultValue").asText())
            .isEqualTo("DecentraLabsSession");
        assertThat(properties.get("session.attestation.domain.version").path("defaultValue").asText())
            .isEqualTo("1");
        assertThat(properties.get("session.attestation.domain.chain-id").path("defaultValue").asLong())
            .isEqualTo(11155111L);
        assertThat(properties.get("session.attestation.domain.verifying-contract").path("description").asText())
            .contains("contract.address");
    }

    @Test
    void documentsDeploymentAndStationProperties() throws Exception {
        Map<String, JsonNode> properties = readProperties();

        assertThat(properties).containsKeys(
            "contract.verification.enabled",
            "contract.verification.abi-version",
            "contract.verification.deployment-manifest",
            "contract.verification.selector-manifest",
            "contract.verification.abi-resource",
            "fmu.station.base-url",
            "fmu.station.internal-token",
            "fmu.station.request-timeout-ms",
            "fmu.capacity.required",
            "provider.reservation.availability.lock-timeout.seconds"
        );
        assertThat(properties.get("contract.verification.enabled").path("defaultValue").asBoolean())
            .isTrue();
        assertThat(properties.get("fmu.station.request-timeout-ms").path("defaultValue").asLong())
            .isEqualTo(5000L);
        assertThat(properties.get("fmu.capacity.required").path("defaultValue").asBoolean())
            .isFalse();
        assertThat(properties.get("provider.reservation.availability.lock-timeout.seconds")
            .path("defaultValue").asInt()).isEqualTo(60);
    }

    private Map<String, JsonNode> readProperties() throws Exception {
        try (InputStream input = getClass().getClassLoader()
            .getResourceAsStream("META-INF/additional-spring-configuration-metadata.json")) {
            assertThat(input).isNotNull();
            JsonNode document = objectMapper.readTree(input);
            Map<String, JsonNode> properties = new HashMap<>();
            for (JsonNode property : document.path("properties")) {
                properties.put(property.path("name").asText(), property);
            }
            return properties;
        }
    }
}
