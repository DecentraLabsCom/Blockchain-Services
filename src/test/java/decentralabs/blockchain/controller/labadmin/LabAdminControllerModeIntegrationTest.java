package decentralabs.blockchain.controller.labadmin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import decentralabs.blockchain.service.auth.JwtService;
import decentralabs.blockchain.service.labadmin.LabAdminService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

class LabAdminControllerModeIntegrationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
        .withUserConfiguration(TestConfiguration.class)
        .withBean(LabAdminService.class, () -> mock(LabAdminService.class))
        .withBean(JwtService.class, () -> mock(JwtService.class));

    @Test
    void providerConsumerModeCreatesTheProviderLabAdminController() {
        contextRunner
            .withPropertyValues(
                "blockchain.services.mode=provider-consumer",
                "features.providers.enabled=false"
            )
            .run(context -> {
                assertThat(context).hasSingleBean(LabAdminController.class);
                assertThat(context).hasSingleBean(LabContentController.class);
            });
    }

    @Test
    void consumerOnlyModeDoesNotCreateTheProviderLabAdminController() {
        contextRunner
            .withPropertyValues(
                "blockchain.services.mode=consumer-only",
                // Explicit mode must remain authoritative over the legacy flag.
                "features.providers.enabled=true"
            )
            .run(context -> {
                assertThat(context).doesNotHaveBean(LabAdminController.class);
                assertThat(context).hasSingleBean(LabContentController.class);
            });
    }

    @Configuration(proxyBeanMethods = false)
    @Import({LabAdminController.class, LabContentController.class})
    static class TestConfiguration {
    }
}
