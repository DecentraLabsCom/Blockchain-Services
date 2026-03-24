package decentralabs.blockchain.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.Instant;

/**
 * Approval record for a provider invoice before payout.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProviderApproval {

    private Long id;
    private Long invoiceRecordId;
    private String approvedBy;
    /** Deterministic external approval reference (e.g. "APPROVAL-2026-0042"). */
    private String approvalRef;
    private BigDecimal eurAmount;
    private Instant approvedAt;
}
