package decentralabs.blockchain.service.intent;

/** Raised when another backend replica already owns an intent execution claim. */
public class IntentClaimRejectedException extends RuntimeException {
    public IntentClaimRejectedException(String requestId) {
        super("Intent execution already claimed: " + requestId);
    }
}
