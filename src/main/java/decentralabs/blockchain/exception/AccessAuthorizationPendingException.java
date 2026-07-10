package decentralabs.blockchain.exception;

/** Raised when a submitted check-in has not reached ACCESS_AUTHORIZED in time. */
public class AccessAuthorizationPendingException extends RuntimeException {
    private final String reservationKey;
    private final String transactionHash;

    public AccessAuthorizationPendingException(String message) {
        this(message, null, null);
    }

    public AccessAuthorizationPendingException(String message, String reservationKey, String transactionHash) {
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
