package decentralabs.blockchain.dto.labadmin;

public record LabAdminReservation(
    String reservationKey,
    String labId,
    String renter,
    int status,
    String statusLabel,
    long start,
    long end,
    String priceRaw,
    String priceCredits,
    String providerShareRaw,
    String providerShareCredits,
    boolean cancellable
) {
}
