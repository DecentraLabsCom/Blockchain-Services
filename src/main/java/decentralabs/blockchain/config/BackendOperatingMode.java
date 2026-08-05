package decentralabs.blockchain.config;

import java.util.Locale;

/**
 * Role of a blockchain-services process. This is intentionally independent of
 * the Full/Lite access-plane topology selected by the parent gateway.
 */
public enum BackendOperatingMode {
    PROVIDER_CONSUMER("provider-consumer"),
    CONSUMER_ONLY("consumer-only");

    private final String value;

    BackendOperatingMode(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }

    /**
     * Resolves the explicit role, falling back to the historical boolean
     * feature flag when no role has been configured yet.
     */
    public static BackendOperatingMode resolve(String configuredMode, boolean legacyProvidersEnabled) {
        if (configuredMode == null || configuredMode.isBlank()) {
            return legacyProvidersEnabled ? PROVIDER_CONSUMER : CONSUMER_ONLY;
        }

        String normalized = configuredMode.trim().toLowerCase(Locale.ROOT);
        return switch (normalized) {
            case "provider-consumer", "provider_consumer" -> PROVIDER_CONSUMER;
            case "consumer-only", "consumer_only" -> CONSUMER_ONLY;
            default -> throw new IllegalArgumentException(
                "Unsupported blockchain.services.mode '" + configuredMode
                    + "'. Expected 'provider-consumer' or 'consumer-only'."
            );
        };
    }

    public static boolean providerConsumer(String configuredMode, boolean legacyProvidersEnabled) {
        return resolve(configuredMode, legacyProvidersEnabled) == PROVIDER_CONSUMER;
    }
}
