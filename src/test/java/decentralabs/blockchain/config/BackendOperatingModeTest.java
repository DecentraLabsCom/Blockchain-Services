package decentralabs.blockchain.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import decentralabs.blockchain.dto.intent.IntentAction;
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

    @Test
    void consumerOnlyRejectsProviderIntentActionsButKeepsConsumerActions() {
        assertFalse(BackendOperatingMode.CONSUMER_ONLY.allowsIntentAction(IntentAction.LAB_ADD));
        assertFalse(BackendOperatingMode.CONSUMER_ONLY.allowsIntentAction(IntentAction.DIRECT_BOOKING));
        assertTrue(BackendOperatingMode.CONSUMER_ONLY.allowsIntentAction(IntentAction.RESERVATION_REQUEST));
        assertTrue(BackendOperatingMode.CONSUMER_ONLY.allowsIntentAction(IntentAction.CANCEL_BOOKING));
        assertFalse(BackendOperatingMode.CONSUMER_ONLY.allowsIntentAction(null));
    }

    @Test
    void providerConsumerAllowsEveryKnownIntentAction() {
        for (IntentAction action : IntentAction.values()) {
            assertTrue(BackendOperatingMode.PROVIDER_CONSUMER.allowsIntentAction(action));
        }
    }
}
