package decentralabs.blockchain.service.provider;

/** Raised when the configured Station cannot prove its execution capacity. */
public class StationCapacityUnavailableException extends RuntimeException {

    public StationCapacityUnavailableException(String message) {
        super(message);
    }

    public StationCapacityUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
