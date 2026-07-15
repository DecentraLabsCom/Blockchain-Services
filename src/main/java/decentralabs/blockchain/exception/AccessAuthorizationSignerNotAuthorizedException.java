package decentralabs.blockchain.exception;

/** The configured institutional signer cannot publish the requested check-in. */
public class AccessAuthorizationSignerNotAuthorizedException extends RuntimeException {
    private final String reservationKey;
    private final String transactionHash;

    public AccessAuthorizationSignerNotAuthorizedException(
        String message, String reservationKey, String transactionHash
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
