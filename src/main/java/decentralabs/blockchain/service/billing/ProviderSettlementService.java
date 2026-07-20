package decentralabs.blockchain.service.billing;

import decentralabs.blockchain.domain.*;
import decentralabs.blockchain.service.persistence.ProviderSettlementPersistenceService;
import decentralabs.blockchain.util.LogSanitizer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Manages the full provider settlement lifecycle:
 * accrue → invoice → approve → execute → mark paid.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ProviderSettlementService {

    private static final Pattern BYTES32_PATTERN = Pattern.compile("0x[0-9a-fA-F]{64}");
    private static final String ZERO_BYTES32 = "0x" + "0".repeat(64);

    private final ProviderSettlementPersistenceService persistence;

    /**
     * Submit a provider invoice for settlement of accrued receivables.
     */
    @Transactional
    public ProviderInvoiceRecord submitInvoice(String labId, String providerAddress,
                                                String claimId, String reservationHash,
                                                String invoiceRef, BigDecimal eurAmount,
                                                BigDecimal creditAmount) {
        if (claimId == null || claimId.isBlank() || claimId.trim().length() > 128) {
            throw new IllegalArgumentException("Claim ID required");
        }
        if (reservationHash == null || !BYTES32_PATTERN.matcher(reservationHash.trim()).matches()
                || ZERO_BYTES32.equalsIgnoreCase(reservationHash.trim())) {
            throw new IllegalArgumentException("Reservation hash required and must be bytes32");
        }
        if (invoiceRef == null || invoiceRef.isBlank() || invoiceRef.trim().length() > 256) {
            throw new IllegalArgumentException("Invoice reference required");
        }
        if (eurAmount == null || eurAmount.compareTo(BigDecimal.ZERO) <= 0) {
            throw new IllegalArgumentException("EUR amount must be positive");
        }
        if (providerAddress == null || providerAddress.isBlank()) {
            throw new IllegalArgumentException("Provider address required");
        }
        if (persistence.existsClaimId(claimId.trim())) {
            throw new IllegalArgumentException("Claim ID already used");
        }
        if (persistence.existsInvoiceRef(invoiceRef.trim())) {
            throw new IllegalArgumentException("Invoice reference already used");
        }

        ProviderInvoiceRecord record = ProviderInvoiceRecord.builder()
                .labId(labId)
                .providerAddress(providerAddress.toLowerCase())
                .claimId(claimId.trim())
                .reservationHash(reservationHash.trim().toLowerCase())
                .invoiceRef(invoiceRef.trim())
                .eurAmount(eurAmount)
                .creditAmount(creditAmount != null ? creditAmount : BigDecimal.ZERO)
                .status(ProviderInvoiceRecord.Status.SUBMITTED)
                .build();

        record = persistence.createInvoiceRecord(record);
        // codeql[java/log-injection]
        log.info("Submitted provider invoice (labIdPresent={}, invoiceRefPresent={}, EUR {})",
            labId != null && !labId.isBlank(), !invoiceRef.isBlank(), eurAmount);
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
        if (approvedBy == null || approvedBy.isBlank()) {
            throw new IllegalArgumentException("Approved-by actor required");
        }
        if (approvalRef == null || approvalRef.isBlank() || approvalRef.trim().length() > 64) {
            throw new IllegalArgumentException("Approval reference required");
        }
        if (persistence.existsApprovalRef(approvalRef.trim())) {
            throw new IllegalArgumentException("Approval reference already used");
        }
        if (eurAmount == null || eurAmount.compareTo(BigDecimal.ZERO) <= 0
                || eurAmount.compareTo(record.getEurAmount()) != 0) {
            throw new IllegalArgumentException("Approval EUR amount must match invoice");
        }

        ProviderApproval approval = ProviderApproval.builder()
                .invoiceRecordId(invoiceId)
                .approvedBy(approvedBy.toLowerCase())
                .approvalRef(approvalRef.trim())
                .eurAmount(eurAmount)
                .build();

        approval = persistence.createApproval(approval);
        persistence.updateInvoiceStatus(invoiceId, ProviderInvoiceRecord.Status.APPROVED);

        // codeql[java/log-injection]
        log.info("Approved provider invoice {} (approvedByPresent={}, approvalRefPresent={}, EUR {})", invoiceId,
            !approvedBy.isBlank(), !approvalRef.isBlank(), eurAmount);
        return approval;
    }

    /**
     * Record a completed payout with settlement proof references.
     */
    @Transactional
    public ProviderPayout recordPayout(long invoiceId, String providerAddress, String paidBy,
                                        BigDecimal eurAmount, BigDecimal creditAmount,
                                        String paymentRef, String paymentAttestation,
                                        String bankRef, String eurcTxHash, String usdcTxHash) {
        ProviderInvoiceRecord invoice = persistence.findInvoiceById(invoiceId)
                .orElseThrow(() -> new IllegalArgumentException("Invoice record not found: " + invoiceId));
        if (invoice.getStatus() != ProviderInvoiceRecord.Status.APPROVED) {
            throw new IllegalStateException("Can only pay APPROVED invoices, current: " + invoice.getStatus());
        }
        if (providerAddress == null || !providerAddress.equalsIgnoreCase(invoice.getProviderAddress())) {
            throw new IllegalArgumentException("Payout provider does not match claim");
        }
        if (paidBy == null || paidBy.isBlank()) {
            throw new IllegalArgumentException("Paid-by actor required");
        }
        if (paymentRef == null || paymentRef.isBlank() || paymentRef.trim().length() > 256) {
            throw new IllegalArgumentException("Payment reference required");
        }
        if (paymentAttestation == null || paymentAttestation.isBlank() || paymentAttestation.trim().length() > 256) {
            throw new IllegalArgumentException("Payment attestation required");
        }
        if (eurAmount == null || eurAmount.compareTo(invoice.getEurAmount()) != 0) {
            throw new IllegalArgumentException("Payout EUR amount must match invoice");
        }
        if (persistence.existsPaymentRef(paymentRef.trim())) {
            throw new IllegalArgumentException("Payment reference already used");
        }

        ProviderPayout payout = ProviderPayout.builder()
                .invoiceRecordId(invoiceId)
                .labId(invoice.getLabId())
                .providerAddress(providerAddress.toLowerCase())
                .claimId(invoice.getClaimId())
                .eurAmount(eurAmount)
                .creditAmount(creditAmount != null ? creditAmount : BigDecimal.ZERO)
                .paidBy(paidBy.toLowerCase())
                .paymentRef(paymentRef.trim())
                .paymentAttestation(paymentAttestation.trim())
                .bankRef(bankRef)
                .eurcTxHash(eurcTxHash)
                .usdcTxHash(usdcTxHash)
                .build();

        payout = persistence.createPayout(payout);
        persistence.updateInvoiceStatus(invoiceId, ProviderInvoiceRecord.Status.PAID);
        // codeql[java/log-injection]
        log.info("Recorded payout for lab {} provider {} (EUR {})", LogSanitizer.sanitize(invoice.getLabId()),
            LogSanitizer.maskIdentifier(providerAddress), eurAmount);
        return payout;
    }

    /**
     * Transition invoice status (dispute, cancel, mark paid).
     */
    @Transactional
    public void transitionInvoiceStatus(long invoiceId, ProviderInvoiceRecord.Status newStatus) {
        persistence.updateInvoiceStatus(invoiceId, newStatus);
        log.info("Transitioned provider invoice {} to {}", invoiceId,
            newStatus == null ? "unknown" : newStatus.name());
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
