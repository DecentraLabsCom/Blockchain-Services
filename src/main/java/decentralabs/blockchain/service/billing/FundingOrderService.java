package decentralabs.blockchain.service.billing;

import decentralabs.blockchain.domain.*;
import decentralabs.blockchain.service.persistence.CreditAccountPersistenceService;
import decentralabs.blockchain.service.persistence.FundingOrderPersistenceService;
import decentralabs.blockchain.util.EthereumAddressValidator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Manages the funding order lifecycle:
 * create order → issue invoice → confirm payment → trigger on-chain credit mint.
 *
 * All commercial amounts are kept in EUR; the credit amount is a derived
 * 1:1 mapping at issuance time.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class FundingOrderService {

    private final FundingOrderPersistenceService persistence;
    private final CreditAccountPersistenceService creditPersistence;

    /**
     * Create a new funding order (DRAFT status).
     */
    @Transactional
    public FundingOrder createFundingOrder(String institutionAddress, BigDecimal eurGrossAmount,
                                           BigDecimal creditAmount, String reference, Instant expiresAt) {
        EthereumAddressValidator.validate(institutionAddress, "institutionAddress");
        if (eurGrossAmount == null || eurGrossAmount.compareTo(BigDecimal.ZERO) <= 0) {
            throw new IllegalArgumentException("EUR gross amount must be positive");
        }
        if (creditAmount == null || creditAmount.compareTo(BigDecimal.ZERO) <= 0) {
            throw new IllegalArgumentException("Credit amount must be positive");
        }

        FundingOrder order = FundingOrder.builder()
                .institutionAddress(institutionAddress.toLowerCase())
                .eurGrossAmount(eurGrossAmount)
                .creditAmount(creditAmount)
                .status(FundingOrder.Status.DRAFT)
                .reference(reference)
                .expiresAt(expiresAt)
                .build();

        order = persistence.createFundingOrder(order);
        log.info("Created funding order {} for {} (EUR {} → {} credits)",
                order.getId(), institutionAddress, eurGrossAmount, creditAmount);
        return order;
    }

    /**
     * Issue an invoice for a funding order.
     */
    @Transactional
    public FundingInvoice issueInvoice(long orderId, String invoiceNumber, Instant dueAt) {
        FundingOrder order = persistence.findFundingOrderById(orderId)
                .orElseThrow(() -> new IllegalArgumentException("Funding order not found: " + orderId));

        if (order.getStatus() != FundingOrder.Status.DRAFT) {
            throw new IllegalStateException("Can only invoice DRAFT orders, current: " + order.getStatus());
        }
        if (invoiceNumber == null || invoiceNumber.isBlank()) {
            throw new IllegalArgumentException("Invoice number is required");
        }

        FundingInvoice invoice = FundingInvoice.builder()
                .fundingOrderId(orderId)
                .invoiceNumber(invoiceNumber.trim())
                .eurAmount(order.getEurGrossAmount())
                .issuedAt(Instant.now())
                .dueAt(dueAt)
                .status(FundingInvoice.Status.ISSUED)
                .build();

        invoice = persistence.createFundingInvoice(invoice);
        persistence.updateFundingOrderStatus(orderId, FundingOrder.Status.INVOICED);

        log.info("Issued invoice {} for funding order {}", invoiceNumber, orderId);
        return invoice;
    }

    /**
     * Confirm payment receipt. Records a reconciliation record and advances the order
     * to PAID status. The caller should then trigger on-chain credit minting separately
     * via the existing ISSUE_SERVICE_CREDITS admin operation.
     */
    @Transactional
    public PaymentReconciliation confirmPayment(long orderId, String paymentRef,
                                                 BigDecimal eurAmount, String paymentMethod) {
        FundingOrder order = persistence.findFundingOrderById(orderId)
                .orElseThrow(() -> new IllegalArgumentException("Funding order not found: " + orderId));

        if (order.getStatus() != FundingOrder.Status.INVOICED) {
            throw new IllegalStateException("Can only confirm payment for INVOICED orders, current: " + order.getStatus());
        }
        if (paymentRef == null || paymentRef.isBlank()) {
            throw new IllegalArgumentException("Payment reference is required");
        }
        if (eurAmount == null || eurAmount.compareTo(BigDecimal.ZERO) <= 0) {
            throw new IllegalArgumentException("Payment amount must be positive");
        }

        PaymentReconciliation recon = PaymentReconciliation.builder()
                .fundingOrderId(orderId)
                .paymentRef(paymentRef.trim())
                .eurAmount(eurAmount)
                .paymentMethod(paymentMethod)
                .reconciledAt(Instant.now())
                .build();

        recon = persistence.createReconciliation(recon);
        persistence.updateFundingOrderStatus(orderId, FundingOrder.Status.PAID);

        // Record credit movement for audit trail
        creditPersistence.recordMovement(CreditMovement.builder()
                .accountAddress(order.getInstitutionAddress())
                .movementType(CreditMovement.Type.MINT)
                .amount(order.getCreditAmount())
                .reference("funding-order:" + orderId)
                .build());

        log.info("Confirmed payment {} for funding order {} (EUR {})", paymentRef, orderId, eurAmount);
        return recon;
    }

    /**
     * Mark a funding order as CREDITED after on-chain credit minting tx confirms.
     */
    @Transactional
    public void markCredited(long orderId) {
        persistence.updateFundingOrderStatus(orderId, FundingOrder.Status.CREDITED);
        log.info("Funding order {} marked as CREDITED", orderId);
    }

    /**
     * Cancel a funding order.
     */
    @Transactional
    public void cancelFundingOrder(long orderId) {
        FundingOrder order = persistence.findFundingOrderById(orderId)
                .orElseThrow(() -> new IllegalArgumentException("Funding order not found: " + orderId));

        if (order.getStatus() == FundingOrder.Status.CREDITED) {
            throw new IllegalStateException("Cannot cancel a CREDITED funding order");
        }

        persistence.updateFundingOrderStatus(orderId, FundingOrder.Status.CANCELLED);
        log.info("Cancelled funding order {}", orderId);
    }

    public Optional<FundingOrder> findById(long id) {
        return persistence.findFundingOrderById(id);
    }

    public List<FundingOrder> findByInstitution(String address) {
        return persistence.findFundingOrdersByInstitution(address.toLowerCase());
    }

    public List<FundingOrder> findByStatus(FundingOrder.Status status) {
        return persistence.findFundingOrdersByStatus(status);
    }
}
