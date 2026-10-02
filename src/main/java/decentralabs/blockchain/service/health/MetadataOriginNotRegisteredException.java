package decentralabs.blockchain.service.health;

/**
 * Signals that a remote metadata URI is outside the provider's registered
 * metadata origins.
 *
 * <p>This is distinct from a transport or parsing failure so callers that
 * already have an authoritative on-chain URI can apply a narrowly scoped
 * compatibility path without weakening provider publication validation.</p>
 */
final class MetadataOriginNotRegisteredException extends IllegalStateException {

    MetadataOriginNotRegisteredException(String message) {
        super(message);
    }
}
