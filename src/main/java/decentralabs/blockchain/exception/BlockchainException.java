package decentralabs.blockchain.exception;

/**
 * Exception thrown when blockchain operations fail
 */
public class BlockchainException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public BlockchainException(String message) {
        super(message);
    }

    public BlockchainException(String message, Throwable cause) {
        super(message, cause);
    }
}
