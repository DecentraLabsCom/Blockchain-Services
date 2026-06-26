package decentralabs.blockchain.exception;

/**
 * Exception thrown when a wallet operation fails
 */
public class WalletOperationException extends RuntimeException {

    private static final long serialVersionUID = 1L;
    
    private final String operation;

    public WalletOperationException(String operation, String message) {
        super(message);
        this.operation = operation;
    }

    public WalletOperationException(String operation, String message, Throwable cause) {
        super(message, cause);
        this.operation = operation;
    }

    public String getOperation() {
        return operation;
    }
}
