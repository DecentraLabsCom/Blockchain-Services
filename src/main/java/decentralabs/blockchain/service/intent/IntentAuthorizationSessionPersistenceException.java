package decentralabs.blockchain.service.intent;

/** Raised when durable WebAuthn authorization session storage is unavailable. */
public class IntentAuthorizationSessionPersistenceException extends RuntimeException {

    public IntentAuthorizationSessionPersistenceException(String message) {
        super(message);
    }

    public IntentAuthorizationSessionPersistenceException(String message, Throwable cause) {
        super(message, cause);
    }
}
