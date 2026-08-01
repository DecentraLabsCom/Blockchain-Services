package decentralabs.blockchain.service.billing;

import decentralabs.blockchain.contract.Diamond;
import decentralabs.blockchain.domain.ProviderSettlementOperation;
import decentralabs.blockchain.service.persistence.ProviderSettlementPersistenceService;
import decentralabs.blockchain.util.CreditUnitConverter;
import decentralabs.blockchain.util.ProviderSettlementReferenceHasher;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/** Reconciles durable settlement intentions against the canonical Diamond. */
@Component
@RequiredArgsConstructor
@Slf4j
public class ProviderSettlementReconciliationScheduler {

    private final ProviderSettlementPersistenceService persistence;
    private final ProviderSettlementChainClient chainClient;

    @Value("${billing.provider-settlement.reconcile.batch-size:50}")
    private int batchSize;

    @Scheduled(fixedDelayString = "${billing.provider-settlement.reconcile.interval-ms:60000}")
    public void reconcile() {
        List<ProviderSettlementOperation> pending = persistence.findPendingSettlementOperations(Math.max(1, batchSize));
        for (ProviderSettlementOperation operation : pending) {
            try {
                reconcile(operation);
            } catch (Exception ex) {
                log.warn("Provider settlement reconciliation failed for operation {}: {}", operation.getOperationKey(), ex.getMessage());
            }
        }
    }

    private void reconcile(ProviderSettlementOperation operation) throws Exception {
        Diamond.ProviderSettlementClaim claim = chainClient.readClaim(
            ProviderSettlementReferenceHasher.claimId(operation.getClaimId())
        );
        if (claim == null || claim.status == null) return;
        int status = claim.status.intValue();
        if (!claimCanSatisfy(operation.getAction(), status) || !matches(operation, claim)) return;

        String actor = switch (operation.getAction()) {
            case SUBMIT -> claim.submittedBy;
            case APPROVE -> claim.approvedBy;
            case PAY -> claim.paidBy;
        };
        persistence.projectSettlementOperation(
            operation.getOperationKey(),
            actor,
            operation.getTransactionHash(),
            operation.getBlockNumber(),
            operation.getBlockHash()
        );
    }

    private boolean matches(ProviderSettlementOperation operation, Diamond.ProviderSettlementClaim claim) throws Exception {
        if (claim == null || claim.status == null || claim.status.intValue() < 1 || claim.status.intValue() > 3) return false;
        if (!new BigInteger(operation.getLabId()).equals(claim.labId)
            || !operation.getCreditAmount().multiply(CreditUnitConverter.RAW_PER_CREDIT).toBigIntegerExact().equals(claim.amount)) return false;
        if (!Arrays.equals(
            ProviderSettlementReferenceHasher.batchId(operation.getBatchId()),
            claim.batchId
        )) return false;
        if (!Arrays.equals(
            ProviderSettlementReferenceHasher.reference(operation.getInvoiceRef(), "invoiceRef"),
            claim.invoiceReferenceHash
        )) return false;
        if (operation.getAction() == ProviderSettlementOperation.Action.APPROVE) {
            return Arrays.equals(
                ProviderSettlementReferenceHasher.reference(operation.getApprovalRef(), "approvalRef"),
                chainClient.readApprovalReferenceHash(ProviderSettlementReferenceHasher.claimId(operation.getClaimId()))
            );
        }
        if (operation.getAction() == ProviderSettlementOperation.Action.PAY) {
            return Arrays.equals(
                ProviderSettlementReferenceHasher.reference(operation.getPaymentRef(), "paymentRef"),
                claim.paymentReferenceHash
            ) && Arrays.equals(
                ProviderSettlementReferenceHasher.reference(operation.getPaymentAttestation(), "paymentAttestation"),
                claim.paymentAttestationHash
            );
        }
        return true;
    }

    private boolean claimCanSatisfy(ProviderSettlementOperation.Action action, int status) {
        return switch (action) {
            case SUBMIT -> status >= 1 && status <= 3;
            case APPROVE -> status >= 2 && status <= 3;
            case PAY -> status == 3;
        };
    }
}
