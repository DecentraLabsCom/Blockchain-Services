package decentralabs.blockchain.notification;

import java.math.BigInteger;
import java.time.Instant;

public record ReservationNotificationData(
    String reservationKey,
    BigInteger labId,
    String labName,
    String renter,
    String payerInstitution,
    Instant start,
    Instant end,
    String transactionHash,
    String gatewayId
) {
    public ReservationNotificationData(
        String reservationKey,
        BigInteger labId,
        String labName,
        String renter,
        String payerInstitution,
        Instant start,
        Instant end,
        String transactionHash
    ) {
        this(reservationKey, labId, labName, renter, payerInstitution, start, end, transactionHash, null);
    }
}
