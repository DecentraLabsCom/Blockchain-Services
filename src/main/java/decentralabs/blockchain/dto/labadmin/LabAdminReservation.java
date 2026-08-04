package decentralabs.blockchain.dto.labadmin;

import java.util.List;

public record LabAdminReservation(
    String reservationKey,
    String labId,
    String labName,
    String renter,
    String institutionName,
    String institutionAddress,
    int status,
    String statusLabel,
    long start,
    long end,
    String priceRaw,
    String priceCredits,
    String providerShareRaw,
    String providerShareCredits,
    boolean cancellable,
    List<LabAdminCancellationOption> cancellationOptions
) {
}
