package decentralabs.blockchain.config;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Validates and records the backend role during application startup. */
@Component
@Slf4j
public class BackendOperatingModeConfiguration {

    @Value("${blockchain.services.mode:}")
    private String configuredMode;

    @Value("${features.providers.enabled:false}")
    private boolean legacyProvidersEnabled;

    private BackendOperatingMode operatingMode;

    @PostConstruct
    void validate() {
        operatingMode = BackendOperatingMode.resolve(configuredMode, legacyProvidersEnabled);
        log.info(
            "Blockchain services backend role: {} (explicit configuration: {})",
            operatingMode.value(),
            configuredMode != null && !configuredMode.isBlank()
        );
    }

    public BackendOperatingMode operatingMode() {
        if (operatingMode == null) {
            operatingMode = BackendOperatingMode.resolve(configuredMode, legacyProvidersEnabled);
        }
        return operatingMode;
    }
}
