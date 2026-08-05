package decentralabs.blockchain.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class BackendOperatingModeTest {

    @Test
    void explicitConsumerOnlyRoleWinsOverLegacyProviderFlag() {
        assertEquals(
            BackendOperatingMode.CONSUMER_ONLY,
            BackendOperatingMode.resolve("consumer-only", true)
        );
        assertFalse(BackendOperatingMode.providerConsumer("consumer-only", true));
    }

    @Test
    void explicitProviderConsumerRoleWinsOverLegacyConsumerFlag() {
        assertEquals(
            BackendOperatingMode.PROVIDER_CONSUMER,
            BackendOperatingMode.resolve("provider-consumer", false)
        );
        assertTrue(BackendOperatingMode.providerConsumer("provider-consumer", false));
    }

    @Test
    void legacyFlagRemainsFallbackWhenRoleIsNotConfigured() {
        assertEquals(
            BackendOperatingMode.PROVIDER_CONSUMER,
            BackendOperatingMode.resolve("", true)
        );
        assertEquals(
            BackendOperatingMode.CONSUMER_ONLY,
            BackendOperatingMode.resolve(null, false)
        );
    }

    @Test
    void topologyNamesAreNotAcceptedAsBackendRoles() {
        assertThrows(
            IllegalArgumentException.class,
            () -> BackendOperatingMode.resolve("lite", false)
        );
        assertThrows(
            IllegalArgumentException.class,
            () -> BackendOperatingMode.resolve("full", true)
        );
    }
}
