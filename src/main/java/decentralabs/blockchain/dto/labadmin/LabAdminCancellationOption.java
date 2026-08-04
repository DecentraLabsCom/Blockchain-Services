package decentralabs.blockchain.dto.labadmin;

public record LabAdminCancellationOption(
    int reasonCode,
    String label,
    long deadline,
    int reputationPenalty
) {
}
