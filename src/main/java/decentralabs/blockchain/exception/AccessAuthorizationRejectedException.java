package decentralabs.blockchain.exception;

/** A submitted check-in transaction was observed to have failed permanently. */
public class AccessAuthorizationRejectedException extends RuntimeException {
    public AccessAuthorizationRejectedException(String message) {
        super(message);
    }
}
