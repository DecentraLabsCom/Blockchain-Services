package decentralabs.blockchain.exception;

/**
 * Raised when an idempotency key is reused for a different transaction payload.
 */
public class IdempotencyKeyPayloadMismatchException extends RuntimeException {
    public static final String CODE = "IDEMPOTENCY_KEY_PAYLOAD_MISMATCH";

    public IdempotencyKeyPayloadMismatchException() {
        super("Idempotency-Key is already associated with a different transaction payload");
    }
}
