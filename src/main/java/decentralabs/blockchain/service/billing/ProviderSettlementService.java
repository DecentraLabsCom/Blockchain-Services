package decentralabs.blockchain.service.billing;

import decentralabs.blockchain.domain.*;
import decentralabs.blockchain.service.persistence.ProviderSettlementPersistenceService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;

/**
 * Manages the full provider settlement lifecycle:
 * accrue → invoice → approve → execute → mark paid.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ProviderSettlementService {

    private final ProviderSettlementPersistenceService persistence;

    /**
     * Submit a provider invoice for settlement of accrued receivables.
     */
    @Transactional
    public ProviderInvoiceRecord submitInvoice(String labId, String providerAddress,
                                                String invoiceRef, BigDecimal eurAmount,
                                                BigDecimal creditAmount) {
        if (invoiceRef == null || invoiceRef.isBlank()) {
            throw new IllegalArgumentException("Invoice reference required");
        }
        if (eurAmount == null || eurAmount.compareTo(BigDecimal.ZERO) <= 0) {
            throw new IllegalArgumentException("EUR amount must be positive");
        }

        ProviderInvoiceRecord record = ProviderInvoiceRecord.builder()
                .labId(labId)
                .providerAddress(providerAddress.toLowerCase())
                .invoiceRef(invoiceRef.trim())
                .eurAmount(eurAmount)
                .creditAmount(creditAmount != null ? creditAmount : BigDecimal.ZERO)
                .status(ProviderInvoiceRecord.Status.SUBMITTED)
                .build();

        record = persistence.createInvoiceRecord(record);
        log.info("Submitted provider invoice {} for lab {} (EUR {})", invoiceRef, labId, eurAmount);
        return record;
    }

    /**
     * Approve a submitted provider invoice for payout.
     */
    @Transactional
    public ProviderApproval approveInvoice(long invoiceId, String approvedBy, String approvalRef, BigDecimal eurAmount) {
        Optional<ProviderInvoiceRecord> opt = persistence.findInvoiceById(invoiceId);
        ProviderInvoiceRecord record = opt.orElseThrow(
                () -> new IllegalArgumentException("Invoice record not found: " + invoiceId));

        if (record.getStatus() != ProviderInvoiceRecord.Status.SUBMITTED) {
            throw new IllegalStateException("Can only approve SUBMITTED invoices, current: " + record.getStatus());
        }

        ProviderApproval approval = ProviderApproval.builder()
                .invoiceRecordId(invoiceId)
                .approvedBy(approvedBy.toLowerCase())
                .approvalRef(approvalRef != null ? approvalRef.trim() : null)
                .eurAmount(eurAmount)
                .build();

        approval = persistence.createApproval(approval);
        persistence.updateInvoiceStatus(invoiceId, ProviderInvoiceRecord.Status.APPROVED);

        log.info("Approved provider invoice {} by {} ref={} (EUR {})", invoiceId, approvedBy, approvalRef, eurAmount);
        return approval;
    }

    /**
     * Record a completed payout with settlement proof references.
     */
    @Transactional
    public ProviderPayout recordPayout(String labId, String providerAddress,
                                        BigDecimal eurAmount, BigDecimal creditAmount,
                                        String bankRef, String eurcTxHash, String usdcTxHash) {
        ProviderPayout payout = ProviderPayout.builder()
                .labId(labId)
                .providerAddress(providerAddress.toLowerCase())
                .eurAmount(eurAmount)
                .creditAmount(creditAmount)
                .bankRef(bankRef)
                .eurcTxHash(eurcTxHash)
                .usdcTxHash(usdcTxHash)
                .build();

        payout = persistence.createPayout(payout);
        log.info("Recorded payout for lab {} provider {} (EUR {})", labId, providerAddress, eurAmount);
        return payout;
    }

    /**
     * Transition invoice status (dispute, cancel, mark paid).
     */
    @Transactional
    public void transitionInvoiceStatus(long invoiceId, ProviderInvoiceRecord.Status newStatus) {
        persistence.updateInvoiceStatus(invoiceId, newStatus);
        log.info("Transitioned provider invoice {} to {}", invoiceId, newStatus);
    }

    public List<ProviderInvoiceRecord> findInvoicesByProvider(String providerAddress) {
        return persistence.findInvoicesByProvider(providerAddress.toLowerCase());
    }

    public List<ProviderInvoiceRecord> findInvoicesByStatus(ProviderInvoiceRecord.Status status) {
        return persistence.findInvoicesByStatus(status);
    }

    public List<ProviderPayout> findPayoutsByProvider(String providerAddress) {
        return persistence.findPayoutsByProvider(providerAddress.toLowerCase());
    }
}
