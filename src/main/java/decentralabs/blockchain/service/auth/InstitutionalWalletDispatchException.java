package decentralabs.blockchain.service.auth;

/**
 * Checked dispatch failure with an explicit boundary classification. Only a
 * failure after eth_sendRawTransaction was entered is uncertain. Before that
 * boundary, nonce contention, transient infrastructure failures and permanent
 * preparation failures are classified separately.
 */
public class InstitutionalWalletDispatchException extends Exception {
    public enum Outcome {
        PRE_BROADCAST_BLOCKED,
        PRE_BROADCAST_TRANSIENT,
        PRE_BROADCAST_PERMANENT,
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
