package decentralabs.blockchain.service.auth;

/**
 * Checked dispatch failure with an explicit boundary classification. Only a
 * failure after eth_sendRawTransaction was entered is uncertain; allocator,
 * preparation and persistence failures are safe to retry as a new attempt.
 */
public class InstitutionalWalletDispatchException extends Exception {
    public enum Outcome {
        PRE_BROADCAST_RETRYABLE,
        BROADCAST_OUTCOME_UNKNOWN
    }

    private final Outcome outcome;

    public InstitutionalWalletDispatchException(String message, Throwable cause) {
        this(message, Outcome.BROADCAST_OUTCOME_UNKNOWN, cause);
    }

    public InstitutionalWalletDispatchException(String message, Outcome outcome, Throwable cause) {
        super(message, cause);
        this.outcome = outcome == null ? Outcome.BROADCAST_OUTCOME_UNKNOWN : outcome;
    }

    public Outcome outcome() {
        return outcome;
    }
}
