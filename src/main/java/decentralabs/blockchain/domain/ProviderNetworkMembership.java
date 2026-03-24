package decentralabs.blockchain.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.time.LocalDate;

/**
 * Limited-network provider membership record.
 * Tracks merchant agreement contract dates, status, and suspension reason.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProviderNetworkMembership {

    public enum Status { ACTIVE, SUSPENDED, TERMINATED }

    private Long id;
    private String providerAddress;
    private String contractId;
    /** Merchant agreement version (e.g. "v2.1") — required at activation. */
    private String agreementVersion;
    private LocalDate effectiveDate;
    private LocalDate expiryDate;
    private Status status;
    private String suspensionReason;
    /** Address or identifier of the operator who performed the last status-changing action. */
    private String actionBy;
    private Instant createdAt;
    private Instant updatedAt;
}
