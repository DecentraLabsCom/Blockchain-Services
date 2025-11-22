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
    String transactionHash
) { }
