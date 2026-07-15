package decentralabs.blockchain.exception;

/** A durable check-in belongs to a different chain or signer context. */
public class AccessAuthorizationContextMismatchException extends RuntimeException {
    private final String reservationKey;
    private final String transactionHash;

    public AccessAuthorizationContextMismatchException(
        String message,
        String reservationKey,
        String transactionHash
    ) {
        super(message);
        this.reservationKey = reservationKey;
        this.transactionHash = transactionHash;
    }

    public String getReservationKey() {
        return reservationKey;
    }

    public String getTransactionHash() {
        return transactionHash;
    }
}
