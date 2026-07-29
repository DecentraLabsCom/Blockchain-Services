package decentralabs.blockchain.config;

/**
 * Classified failure raised while evaluating a provider-side reservation.
 *
 * <p>Only {@link Type#POLICY_REJECTION} is safe to turn into an on-chain
 * denial. The other types mean that the provider could not establish the
 * policy result and must leave the reservation pending.</p>
 */
public final class ReservationProcessingFailure extends IllegalStateException {

    public enum Type {
        POLICY_REJECTION,
        INFRASTRUCTURE_UNAVAILABLE,
        TRANSIENT_RPC_FAILURE
    }

    private final Type type;

    public ReservationProcessingFailure(Type type, String message) {
        super(message);
        this.type = type;
    }

    public ReservationProcessingFailure(Type type, String message, Throwable cause) {
        super(message, cause);
        this.type = type;
    }

    public Type type() {
        return type;
    }
}
