package decentralabs.blockchain.service.auth;

import java.util.Map;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.stereotype.Component;

/**
 * Probes the configured SAML metadata endpoints for the actuator readiness group.
 * The probe only validates metadata and certificates; it never changes the trust
 * model or accepts inline assertion certificates.
 */
@Component("samlMetadata")
public class SamlMetadataHealthIndicator implements HealthIndicator {

    private final SamlValidationService samlValidationService;

    public SamlMetadataHealthIndicator(SamlValidationService samlValidationService) {
        this.samlValidationService = samlValidationService;
    }

    @Override
    public Health health() {
        Map<String, Object> details = samlValidationService.metadataHealth();
        Health.Builder builder = "UP".equals(details.get("status"))
            ? Health.up()
            : Health.down();
        details.forEach(builder::withDetail);
        return builder.build();
    }
}
