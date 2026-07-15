package decentralabs.blockchain.exception;

/** A durable check-in cannot progress automatically and needs operator action. */
public class AccessAuthorizationManualInterventionException extends RuntimeException {
    private final String reservationKey;
    private final String transactionHash;

    public AccessAuthorizationManualInterventionException(
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
