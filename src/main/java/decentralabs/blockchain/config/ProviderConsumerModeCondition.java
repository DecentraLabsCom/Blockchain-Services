package decentralabs.blockchain.config;

import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

/**
 * Enables provider authentication controllers according to the backend role.
 * The explicit role wins; the legacy provider feature flag remains the
 * fallback for existing deployments that have not added the new setting.
 */
public final class ProviderConsumerModeCondition extends SpringBootCondition {

    @Override
    public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {
        String configuredMode = context.getEnvironment().getProperty("blockchain.services.mode", "");
        boolean legacyProvidersEnabled = context.getEnvironment()
            .getProperty("features.providers.enabled", Boolean.class, false);
        try {
            boolean enabled = BackendOperatingMode.providerConsumer(configuredMode, legacyProvidersEnabled);
            return enabled
                ? ConditionOutcome.match("provider-consumer backend role is enabled")
                : ConditionOutcome.noMatch("consumer-only backend role is enabled");
        } catch (IllegalArgumentException ex) {
            return ConditionOutcome.noMatch(ex.getMessage());
        }
    }
}
