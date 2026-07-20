package decentralabs.blockchain.service.intent;

/**
 * Signals that the durable intent store cannot complete an operation.
 *
 * <p>Intent acceptance must not continue when this exception is raised: an
 * in-memory acknowledgement would otherwise disappear on restart.</p>
 */
public class IntentPersistenceException extends RuntimeException {

    public IntentPersistenceException(String message) {
        super(message);
    }

    public IntentPersistenceException(String message, Throwable cause) {
        super(message, cause);
    }
}
