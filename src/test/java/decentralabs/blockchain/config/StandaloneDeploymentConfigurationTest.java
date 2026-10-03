package decentralabs.blockchain.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class StandaloneDeploymentConfigurationTest {

    @Test
    void standaloneComposePublishesDashboardAndPersistsPortableApplicationData() throws IOException {
        String compose = Files.readString(Path.of("docker-compose.yml"), StandardCharsets.UTF_8);
        String environment = Files.readString(Path.of(".env.example"), StandardCharsets.UTF_8);

        assertThat(compose)
            .contains("${BLOCKCHAIN_SERVICES_BIND_ADDRESS:-127.0.0.1}:${BLOCKCHAIN_SERVICES_HOST_PORT:-8080}:8080")
            .contains("${BLOCKCHAIN_DATA_PATH:-./blockchain-data}:/app/data");
        assertThat(environment)
            .contains("BLOCKCHAIN_SERVICES_BIND_ADDRESS=127.0.0.1")
            .contains("BLOCKCHAIN_SERVICES_HOST_PORT=8080")
            .contains("BLOCKCHAIN_DATA_PATH=./blockchain-data");
    }

    @Test
    void walletDashboardTreatsConsumerOnlyAsTheStandaloneInstitutionRole() throws IOException {
        String dashboardScript = Files.readString(
            Path.of("src/main/resources/static/wallet-dashboard/assets/js/admin.js"),
            StandardCharsets.UTF_8
        );

        assertThat(dashboardScript)
            .contains("DashboardState.operatingMode === 'consumer-only'")
            .contains("Fund the institution through the Marketplace")
            .contains("return;");
    }
}
