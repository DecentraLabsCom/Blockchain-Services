package decentralabs.blockchain.service.billing;

import decentralabs.blockchain.domain.ProviderApproval;
import decentralabs.blockchain.domain.ProviderInvoiceRecord;
import decentralabs.blockchain.domain.ProviderPayout;
import decentralabs.blockchain.domain.ProviderSettlementOperation;
import decentralabs.blockchain.service.persistence.ProviderSettlementPersistenceService;
import decentralabs.blockchain.util.CreditUnitConverter;
import decentralabs.blockchain.util.LogSanitizer;
import decentralabs.blockchain.util.ProviderSettlementReferenceHasher;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.List;
import java.util.Arrays;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Provider settlement application service.
 *
 * The Diamond transition is executed first. SQL contains only the projection
 * created from a successful receipt and the durable domain outbox needed to
 * recover a projection after a process/database failure. On-chain methods
 * suspend ambient SQL transactions so durable preparation is committed before
 * the RPC broadcast and projection can commit independently afterward.
 */
@Service
@Slf4j
public class ProviderSettlementService {

    private static final Pattern BYTES32_PATTERN = Pattern.compile("0x[0-9a-fA-F]{64}");

    private final ProviderSettlementPersistenceService persistence;
    private final ProviderSettlementChainClient chainClient;
    private final TransactionTemplate localTransactionTemplate;

    @Autowired
    public ProviderSettlementService(
        ProviderSettlementPersistenceService persistence,
        ProviderSettlementChainClient chainClient,
        PlatformTransactionManager transactionManager
    ) {
        this.persistence = persistence;
        this.chainClient = chainClient;
        this.localTransactionTemplate = transactionManager == null ? null : new TransactionTemplate(transactionManager);
    }

    /** Test-only/local SQL constructor retained for the billing persistence slice. */
    public ProviderSettlementService(ProviderSettlementPersistenceService persistence) {
        this(persistence, null, null);
    }

    /** Test-only constructor for the on-chain service with a mocked chain client. */
    public ProviderSettlementService(
        ProviderSettlementPersistenceService persistence,
        ProviderSettlementChainClient chainClient
    ) {
        this(persistence, chainClient, null);
    }

    /** Test-only/local SQL constructor with an explicit transaction manager. */
    public ProviderSettlementService(
        ProviderSettlementPersistenceService persistence,
        PlatformTransactionManager transactionManager
    ) {
        this(persistence, null, transactionManager);
    }

    /**
     * On-chain settlement must not hold an ambient SQL transaction across the
     * RPC call. Local-only persistence uses an explicit transaction below.
     */
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public ProviderInvoiceRecord submitInvoice(
        String labId,
        String providerAddress,
        String claimId,
        String batchId,
        String invoiceRef,
        BigDecimal eurAmount,
        BigDecimal creditAmount
    ) {
        validateInvoiceInput(labId, providerAddress, claimId, batchId, invoiceRef, eurAmount);
        BigDecimal canonicalCredits = canonicalCreditAmount(eurAmount, creditAmount);

        if (chainClient == null) {
            return inLocalTransaction(() -> submitLegacy(
                labId, providerAddress, claimId, batchId, invoiceRef, eurAmount, canonicalCredits
            ));
        }

        byte[] claimIdBytes = ProviderSettlementReferenceHasher.claimId(claimId);
        byte[] batchIdBytes = ProviderSettlementReferenceHasher.batchId(batchId);
        byte[] invoiceReferenceHash = ProviderSettlementReferenceHasher.reference(invoiceRef, "invoiceRef");
        String operationKey = operationKey("submit", ProviderSettlementReferenceHasher.hex(claimIdBytes));

        ProviderSettlementOperation operation = persistence.createOrLoadSettlementOperation(
            ProviderSettlementOperation.builder()
                .operationKey(operationKey)
                .action(ProviderSettlementOperation.Action.SUBMIT)
                .status(ProviderSettlementOperation.Status.PREPARED)
                .claimId(claimId.trim())
                .claimIdHash(ProviderSettlementReferenceHasher.hex(claimIdBytes))
                .labId(labId.trim())
                .providerAddress(providerAddress.trim().toLowerCase())
                .batchId(batchId.trim().toLowerCase())
                .invoiceRef(invoiceRef.trim())
                .invoiceReferenceHash(ProviderSettlementReferenceHasher.hex(invoiceReferenceHash))
                .eurAmount(eurAmount)
                .creditAmount(canonicalCredits)
                .requestedByPrincipal(currentPrincipal())
                .build()
        );

        Optional<ProviderInvoiceRecord> projected = projectIfChainAlreadyAdvanced(operation, claimIdBytes);
        if (projected.isPresent()) return projected.get();

        try {
            ProviderSettlementChainClient.ChainReceipt receipt = chainClient.submit(
                claimIdBytes,
                new BigInteger(labId.trim()),
                rawCredits(canonicalCredits),
                batchIdBytes,
                invoiceReferenceHash,
                operationKey
            );
            persistence.markSettlementMined(operationKey, receipt.transactionHash(), receipt.blockNumber(), receipt.blockHash(), receipt.actor());
            persistence.projectSettlementOperation(operationKey, receipt.actor(), receipt.transactionHash(), receipt.blockNumber(), receipt.blockHash());
            return persistence.findInvoiceByClaimId(claimId.trim()).orElseThrow();
        } catch (Exception ex) {
            throw new IllegalStateException("Provider settlement claim was not confirmed on-chain", ex);
        }
    }

    /** Approves only after the Diamond confirms the claim is SUBMITTED. */
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public ProviderApproval approveInvoice(long invoiceId, String approvalRef, BigDecimal eurAmount) {
        if (chainClient == null) {
            return inLocalTransaction(() -> approveInvoiceLocally(invoiceId, approvalRef, eurAmount));
        }
        ProviderInvoiceRecord invoice = invoice(invoiceId);
        validateApproval(invoice, approvalRef, eurAmount);

        byte[] claimIdBytes = ProviderSettlementReferenceHasher.claimId(invoice.getClaimId());
        byte[] approvalReferenceHash = ProviderSettlementReferenceHasher.reference(approvalRef, "approvalRef");
        String operationKey = operationKey("approve", ProviderSettlementReferenceHasher.hex(claimIdBytes));
        ProviderSettlementOperation operation = persistence.createOrLoadSettlementOperation(
            ProviderSettlementOperation.builder()
                .operationKey(operationKey)
                .action(ProviderSettlementOperation.Action.APPROVE)
                .status(ProviderSettlementOperation.Status.PREPARED)
                .claimId(invoice.getClaimId())
                .claimIdHash(ProviderSettlementReferenceHasher.hex(claimIdBytes))
                .invoiceRecordId(invoiceId)
                .labId(invoice.getLabId())
                .providerAddress(invoice.getProviderAddress())
                .batchId(invoice.getBatchId())
                .invoiceRef(invoice.getInvoiceRef())
                .invoiceReferenceHash(ProviderSettlementReferenceHasher.reference(invoice.getInvoiceRef(), "invoiceRef") == null ? null : ProviderSettlementReferenceHasher.hex(ProviderSettlementReferenceHasher.reference(invoice.getInvoiceRef(), "invoiceRef")))
                .approvalRef(approvalRef.trim())
                .approvalReferenceHash(ProviderSettlementReferenceHasher.hex(approvalReferenceHash))
                .eurAmount(eurAmount)
                .creditAmount(invoice.getCreditAmount())
                .requestedByPrincipal(currentPrincipal())
                .build()
        );

        Optional<ProviderApproval> existing = persistence.findApprovalByInvoiceId(invoiceId);
        if (operation.getStatus() == ProviderSettlementOperation.Status.PROJECTED && existing.isPresent()) return existing.get();
        Optional<ProviderApproval> projected = projectIfChainAlreadyAdvancedApproval(operation, claimIdBytes, invoiceId);
        if (projected.isPresent()) return projected.get();

        try {
            ProviderSettlementChainClient.ChainReceipt receipt = chainClient.approve(
                claimIdBytes, approvalReferenceHash, operationKey
            );
            persistence.markSettlementMined(operationKey, receipt.transactionHash(), receipt.blockNumber(), receipt.blockHash(), receipt.actor());
            persistence.projectSettlementOperation(operationKey, receipt.actor(), receipt.transactionHash(), receipt.blockNumber(), receipt.blockHash());
            return persistence.findApprovalByInvoiceId(invoiceId).orElseThrow();
        } catch (Exception ex) {
            throw new IllegalStateException("Provider settlement approval was not confirmed on-chain", ex);
        }
    }

    /** Records payment proof only after the Diamond confirms APPROVED -> PAID. */
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public ProviderPayout recordPayout(
        long invoiceId,
        BigDecimal eurAmount,
        BigDecimal creditAmount,
        String paymentRef,
        String paymentAttestation,
        String bankRef,
        String eurcTxHash,
        String usdcTxHash
    ) {
        if (chainClient == null) {
            return inLocalTransaction(() -> recordPayoutLocally(
                invoiceId, eurAmount, creditAmount, paymentRef, paymentAttestation,
                bankRef, eurcTxHash, usdcTxHash
            ));
        }
        ProviderInvoiceRecord invoice = invoice(invoiceId);
        validatePayment(invoice, eurAmount, paymentRef, paymentAttestation);
        BigDecimal canonicalCredits = canonicalCreditAmount(invoice.getEurAmount(), creditAmount);
        byte[] claimIdBytes = ProviderSettlementReferenceHasher.claimId(invoice.getClaimId());
        byte[] paymentReferenceHash = ProviderSettlementReferenceHasher.reference(paymentRef, "paymentRef");
        byte[] paymentAttestationHash = ProviderSettlementReferenceHasher.reference(paymentAttestation, "paymentAttestation");
        String operationKey = operationKey("pay", ProviderSettlementReferenceHasher.hex(claimIdBytes));

        ProviderSettlementOperation operation = persistence.createOrLoadSettlementOperation(
            ProviderSettlementOperation.builder()
                .operationKey(operationKey)
                .action(ProviderSettlementOperation.Action.PAY)
                .status(ProviderSettlementOperation.Status.PREPARED)
                .claimId(invoice.getClaimId())
                .claimIdHash(ProviderSettlementReferenceHasher.hex(claimIdBytes))
                .invoiceRecordId(invoiceId)
                .labId(invoice.getLabId())
                .providerAddress(invoice.getProviderAddress())
                .batchId(invoice.getBatchId())
                .invoiceRef(invoice.getInvoiceRef())
                .invoiceReferenceHash(ProviderSettlementReferenceHasher.hex(ProviderSettlementReferenceHasher.reference(invoice.getInvoiceRef(), "invoiceRef")))
                .paymentRef(paymentRef.trim())
                .paymentReferenceHash(ProviderSettlementReferenceHasher.hex(paymentReferenceHash))
                .paymentAttestation(paymentAttestation.trim())
                .paymentAttestationHash(ProviderSettlementReferenceHasher.hex(paymentAttestationHash))
                .eurAmount(eurAmount)
                .creditAmount(canonicalCredits)
                .bankRef(bankRef)
                .eurcTxHash(eurcTxHash)
                .usdcTxHash(usdcTxHash)
                .requestedByPrincipal(currentPrincipal())
                .build()
        );

        Optional<ProviderPayout> existing = persistence.findPayoutByInvoiceId(invoiceId);
        if (operation.getStatus() == ProviderSettlementOperation.Status.PROJECTED && existing.isPresent()) return existing.get();
        Optional<ProviderPayout> projected = projectIfChainAlreadyAdvancedPayment(operation, claimIdBytes, invoiceId);
        if (projected.isPresent()) return projected.get();

        try {
            ProviderSettlementChainClient.ChainReceipt receipt = chainClient.pay(
                claimIdBytes, paymentReferenceHash, paymentAttestationHash, operationKey
            );
            persistence.markSettlementMined(operationKey, receipt.transactionHash(), receipt.blockNumber(), receipt.blockHash(), receipt.actor());
            persistence.projectSettlementOperation(operationKey, receipt.actor(), receipt.transactionHash(), receipt.blockNumber(), receipt.blockHash());
            return persistence.findPayoutByInvoiceId(invoiceId).orElseThrow();
        } catch (Exception ex) {
            throw new IllegalStateException("Provider settlement payment was not confirmed on-chain", ex);
        }
    }

    private ProviderApproval approveInvoiceLocally(long invoiceId, String approvalRef, BigDecimal eurAmount) {
        ProviderInvoiceRecord invoice = invoice(invoiceId);
        validateApproval(invoice, approvalRef, eurAmount);
        if (persistence.existsApprovalRef(approvalRef.trim())) throw new IllegalArgumentException("Approval reference already used");
        ProviderApproval approval = persistence.createApproval(
            ProviderApproval.builder()
                .invoiceRecordId(invoiceId)
                .approvedBy(currentPrincipal())
                .approvalRef(approvalRef.trim())
                .eurAmount(eurAmount)
                .build()
        );
        persistence.updateInvoiceStatus(invoiceId, ProviderInvoiceRecord.Status.APPROVED);
        return approval;
    }

    private ProviderPayout recordPayoutLocally(
        long invoiceId,
        BigDecimal eurAmount,
        BigDecimal creditAmount,
        String paymentRef,
        String paymentAttestation,
        String bankRef,
        String eurcTxHash,
        String usdcTxHash
    ) {
        ProviderInvoiceRecord invoice = invoice(invoiceId);
        validatePayment(invoice, eurAmount, paymentRef, paymentAttestation);
        BigDecimal canonicalCredits = canonicalCreditAmount(invoice.getEurAmount(), creditAmount);
        if (persistence.existsPaymentRef(paymentRef.trim())) throw new IllegalArgumentException("Payment reference already used");
        ProviderPayout payout = persistence.createPayout(
            ProviderPayout.builder()
                .invoiceRecordId(invoiceId)
                .labId(invoice.getLabId())
                .providerAddress(invoice.getProviderAddress())
                .claimId(invoice.getClaimId())
                .eurAmount(eurAmount)
                .creditAmount(canonicalCredits)
                .paidBy(currentPrincipal())
                .paymentRef(paymentRef.trim())
                .paymentAttestation(paymentAttestation.trim())
                .bankRef(bankRef)
                .eurcTxHash(eurcTxHash)
                .usdcTxHash(usdcTxHash)
                .build()
        );
        persistence.updateInvoiceStatus(invoiceId, ProviderInvoiceRecord.Status.PAID);
        return payout;
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

    private <T> T inLocalTransaction(Supplier<T> action) {
        if (localTransactionTemplate == null) {
            return action.get();
        }
        return localTransactionTemplate.execute(status -> action.get());
    }

    private Optional<ProviderInvoiceRecord> projectIfChainAlreadyAdvanced(ProviderSettlementOperation operation, byte[] claimId) {
        try {
            DiamondClaimStatus status = claimStatus(claimId);
            if (claimCanSatisfy(operation.getAction(), status.status())
                && operation.getStatus() != ProviderSettlementOperation.Status.PROJECTED
                && claimMatches(operation, status.claim())) {
                persistence.projectSettlementOperation(operation.getOperationKey(), status.actor(), operation.getTransactionHash(), operation.getBlockNumber(), operation.getBlockHash());
                return persistence.findInvoiceByClaimId(operation.getClaimId());
            }
        } catch (Exception ignored) {
            // The transaction manager/outbox remains the source for retry; a
            // temporary RPC read failure must not create a second SQL record.
        }
        return Optional.empty();
    }

    private Optional<ProviderApproval> projectIfChainAlreadyAdvancedApproval(ProviderSettlementOperation operation, byte[] claimId, long invoiceId) {
        try {
            DiamondClaimStatus status = claimStatus(claimId);
            if (claimCanSatisfy(operation.getAction(), status.status()) && claimMatches(operation, status.claim())) {
                persistence.projectSettlementOperation(operation.getOperationKey(), status.actor(), operation.getTransactionHash(), operation.getBlockNumber(), operation.getBlockHash());
                return persistence.findApprovalByInvoiceId(invoiceId);
            }
        } catch (Exception ignored) { }
        return Optional.empty();
    }

    private Optional<ProviderPayout> projectIfChainAlreadyAdvancedPayment(ProviderSettlementOperation operation, byte[] claimId, long invoiceId) {
        try {
            DiamondClaimStatus status = claimStatus(claimId);
            if (claimCanSatisfy(operation.getAction(), status.status()) && claimMatches(operation, status.claim())) {
                persistence.projectSettlementOperation(operation.getOperationKey(), status.actor(), operation.getTransactionHash(), operation.getBlockNumber(), operation.getBlockHash());
                return persistence.findPayoutByInvoiceId(invoiceId);
            }
        } catch (Exception ignored) { }
        return Optional.empty();
    }

    private DiamondClaimStatus claimStatus(byte[] claimId) throws Exception {
        var claim = chainClient.readClaim(claimId);
        String actor = switch (claim.status.intValue()) {
            case 1 -> claim.submittedBy;
            case 2 -> claim.approvedBy;
            case 3 -> claim.paidBy;
            default -> null;
        };
        return new DiamondClaimStatus(claim.status.intValue(), actor, claim);
    }

    private record DiamondClaimStatus(int status, String actor, decentralabs.blockchain.contract.Diamond.ProviderSettlementClaim claim) { }

    private boolean claimMatches(ProviderSettlementOperation operation, decentralabs.blockchain.contract.Diamond.ProviderSettlementClaim claim) throws Exception {
        if (claim == null || claim.status == null || claim.status.intValue() < 1 || claim.status.intValue() > 3) return false;
        if (!new BigInteger(operation.getLabId()).equals(claim.labId)
            || !rawCredits(operation.getCreditAmount()).equals(claim.amount)) return false;
        if (!Arrays.equals(ProviderSettlementReferenceHasher.batchId(operation.getBatchId()), claim.batchId)
            || !Arrays.equals(ProviderSettlementReferenceHasher.reference(operation.getInvoiceRef(), "invoiceRef"), claim.invoiceReferenceHash)) return false;
        if (operation.getAction() == ProviderSettlementOperation.Action.APPROVE) return Arrays.equals(ProviderSettlementReferenceHasher.reference(operation.getApprovalRef(), "approvalRef"), chainClient.readApprovalReferenceHash(ProviderSettlementReferenceHasher.claimId(operation.getClaimId())));
        if (operation.getAction() == ProviderSettlementOperation.Action.PAY) return Arrays.equals(ProviderSettlementReferenceHasher.reference(operation.getPaymentRef(), "paymentRef"), claim.paymentReferenceHash) && Arrays.equals(ProviderSettlementReferenceHasher.reference(operation.getPaymentAttestation(), "paymentAttestation"), claim.paymentAttestationHash);
        return true;
    }

    private boolean claimCanSatisfy(ProviderSettlementOperation.Action action, int status) {
        return switch (action) {
            case SUBMIT -> status >= 1 && status <= 3;
            case APPROVE -> status >= 2 && status <= 3;
            case PAY -> status == 3;
        };
    }

    private ProviderInvoiceRecord submitLegacy(String labId, String providerAddress, String claimId, String batchId, String invoiceRef, BigDecimal eurAmount, BigDecimal creditAmount) {
        if (persistence.existsClaimId(claimId.trim())) throw new IllegalArgumentException("Claim ID already used");
        if (persistence.existsInvoiceRef(invoiceRef.trim())) throw new IllegalArgumentException("Invoice reference already used");
        return persistence.createInvoiceRecord(ProviderInvoiceRecord.builder().labId(labId).providerAddress(providerAddress.toLowerCase()).claimId(claimId.trim()).batchId(batchId.trim().toLowerCase()).invoiceRef(invoiceRef.trim()).eurAmount(eurAmount).creditAmount(creditAmount).status(ProviderInvoiceRecord.Status.SUBMITTED).build());
    }

    private ProviderInvoiceRecord invoice(long invoiceId) {
        return persistence.findInvoiceById(invoiceId).orElseThrow(() -> new IllegalArgumentException("Invoice record not found: " + invoiceId));
    }

    private void validateInvoiceInput(String labId, String providerAddress, String claimId, String batchId, String invoiceRef, BigDecimal eurAmount) {
        if (labId == null || labId.isBlank() || (chainClient != null && new BigInteger(labId.trim()).signum() <= 0)) throw new IllegalArgumentException("Lab ID must be a positive integer");
        if (providerAddress == null || providerAddress.isBlank()) throw new IllegalArgumentException("Provider address required");
        if (claimId == null || claimId.isBlank() || claimId.trim().length() > 128) throw new IllegalArgumentException("Claim ID required");
        if (batchId == null || !BYTES32_PATTERN.matcher(batchId.trim()).matches() || batchId.matches("0x0{64}")) throw new IllegalArgumentException("Settlement batch ID required and must be a non-zero bytes32");
        if (invoiceRef == null || invoiceRef.isBlank() || invoiceRef.trim().length() > 256) throw new IllegalArgumentException("Invoice reference required");
        if (eurAmount == null || eurAmount.compareTo(BigDecimal.ZERO) <= 0) throw new IllegalArgumentException("EUR amount must be positive");
    }

    private BigDecimal canonicalCreditAmount(BigDecimal eurAmount, BigDecimal creditAmount) {
        BigDecimal expected = CreditUnitConverter.creditsFromEur(eurAmount);
        if (creditAmount != null && creditAmount.compareTo(expected) != 0) throw new IllegalArgumentException("Credit amount must equal EUR amount at the canonical 10 credits/EUR rate");
        return expected;
    }

    private BigInteger rawCredits(BigDecimal creditAmount) {
        return creditAmount.multiply(CreditUnitConverter.RAW_PER_CREDIT).toBigIntegerExact();
    }

    private void validateApproval(ProviderInvoiceRecord invoice, String approvalRef, BigDecimal eurAmount) {
        if (invoice.getStatus() != ProviderInvoiceRecord.Status.SUBMITTED) throw new IllegalStateException("Can only approve SUBMITTED invoices, current: " + invoice.getStatus());
        if (approvalRef == null || approvalRef.isBlank() || approvalRef.trim().length() > 256) throw new IllegalArgumentException("Approval reference required");
        if (eurAmount == null || eurAmount.compareTo(invoice.getEurAmount()) != 0) throw new IllegalArgumentException("Approval EUR amount must match invoice");
    }

    private void validatePayment(ProviderInvoiceRecord invoice, BigDecimal eurAmount, String paymentRef, String paymentAttestation) {
        if (invoice.getStatus() != ProviderInvoiceRecord.Status.APPROVED) throw new IllegalStateException("Can only pay APPROVED invoices, current: " + invoice.getStatus());
        if (paymentRef == null || paymentRef.isBlank() || paymentRef.trim().length() > 256) throw new IllegalArgumentException("Payment reference required");
        if (paymentAttestation == null || paymentAttestation.isBlank() || paymentAttestation.trim().length() > 256) throw new IllegalArgumentException("Payment attestation required");
        if (eurAmount == null || eurAmount.compareTo(invoice.getEurAmount()) != 0) throw new IllegalArgumentException("Payout EUR amount must match invoice");
    }

    private String operationKey(String action, String claimHash) {
        return "provider-settlement:" + action + ":" + claimHash;
    }

    private String currentPrincipal() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || authentication.getName() == null || authentication.getName().isBlank()) return "local-internal";
        return LogSanitizer.sanitize(authentication.getName());
    }
}
