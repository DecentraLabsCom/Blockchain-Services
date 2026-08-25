package decentralabs.blockchain.service.billing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.contract.Diamond;
import decentralabs.blockchain.domain.ProviderSettlementOperation;
import decentralabs.blockchain.service.persistence.ProviderSettlementPersistenceService;
import decentralabs.blockchain.util.CreditUnitConverter;
import decentralabs.blockchain.util.ProviderSettlementReferenceHasher;
import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class ProviderSettlementReconciliationSchedulerTest {
    private static final String BATCH_ID = "0x" + "11".repeat(32);
    private static final BigInteger CLAIM_AMOUNT = BigDecimal.valueOf(250)
        .multiply(CreditUnitConverter.RAW_PER_CREDIT)
        .toBigIntegerExact();

    @Mock
    private ProviderSettlementPersistenceService persistence;

    @Mock
    private ProviderSettlementChainClient chainClient;

    private ProviderSettlementReconciliationScheduler scheduler;

    @BeforeEach
    void setUp() {
        scheduler = new ProviderSettlementReconciliationScheduler(persistence, chainClient);
        ReflectionTestUtils.setField(scheduler, "batchSize", 50);
    }

    @Test
    void projectsMatchingSubmitAndClampsNonPositiveBatchSize() throws Exception {
        ProviderSettlementOperation operation = operation(ProviderSettlementOperation.Action.SUBMIT);
        Diamond.ProviderSettlementClaim claim = matchingClaim(operation, 1);
        ReflectionTestUtils.setField(scheduler, "batchSize", 0);
        when(persistence.findPendingSettlementOperations(1)).thenReturn(List.of(operation));
        when(chainClient.readClaim(any(byte[].class))).thenReturn(claim);

        scheduler.reconcile();

        verify(persistence).findPendingSettlementOperations(1);
        verify(persistence).projectSettlementOperation(
            eq(operation.getOperationKey()),
            eq(claim.submittedBy),
            eq(operation.getTransactionHash()),
            eq(operation.getBlockNumber()),
            eq(operation.getBlockHash())
        );
    }

    @Test
    void projectsApproveAndPayWithActionSpecificActorsAndReferences() throws Exception {
        ProviderSettlementOperation approve = operation(ProviderSettlementOperation.Action.APPROVE);
        approve.setApprovalRef("APPROVAL-1");
        ProviderSettlementOperation pay = operation(ProviderSettlementOperation.Action.PAY);
        pay.setPaymentRef("PAYMENT-1");
        pay.setPaymentAttestation("ATTESTATION-1");

        Diamond.ProviderSettlementClaim approvedClaim = matchingClaim(approve, 2);
        Diamond.ProviderSettlementClaim paidClaim = matchingClaim(pay, 3);
        paidClaim.paymentReferenceHash = ProviderSettlementReferenceHasher.reference(
            pay.getPaymentRef(), "paymentRef"
        );
        paidClaim.paymentAttestationHash = ProviderSettlementReferenceHasher.reference(
            pay.getPaymentAttestation(), "paymentAttestation"
        );

        when(persistence.findPendingSettlementOperations(50)).thenReturn(List.of(approve, pay));
        when(chainClient.readClaim(any(byte[].class))).thenReturn(approvedClaim, paidClaim);
        when(chainClient.readApprovalReferenceHash(any(byte[].class))).thenReturn(
            ProviderSettlementReferenceHasher.reference(approve.getApprovalRef(), "approvalRef")
        );

        scheduler.reconcile();

        verify(persistence).projectSettlementOperation(
            eq(approve.getOperationKey()),
            eq(approvedClaim.approvedBy),
            eq(approve.getTransactionHash()),
            eq(approve.getBlockNumber()),
            eq(approve.getBlockHash())
        );
        verify(persistence).projectSettlementOperation(
            eq(pay.getOperationKey()),
            eq(paidClaim.paidBy),
            eq(pay.getTransactionHash()),
            eq(pay.getBlockNumber()),
            eq(pay.getBlockHash())
        );
        verify(chainClient).readApprovalReferenceHash(any(byte[].class));
    }

    @Test
    void skipsMissingClaimsStatusesAndActionsThatCannotYetBeSatisfied() throws Exception {
        ProviderSettlementOperation missing = operation(ProviderSettlementOperation.Action.SUBMIT);
        ProviderSettlementOperation noStatus = operation(ProviderSettlementOperation.Action.SUBMIT);
        ProviderSettlementOperation submitBeforeMined = operation(ProviderSettlementOperation.Action.SUBMIT);
        ProviderSettlementOperation approveBeforeSubmitted = operation(ProviderSettlementOperation.Action.APPROVE);
        ProviderSettlementOperation payBeforeApproved = operation(ProviderSettlementOperation.Action.PAY);

        Diamond.ProviderSettlementClaim noStatusClaim = matchingClaim(noStatus, 1);
        noStatusClaim.status = null;
        when(persistence.findPendingSettlementOperations(50)).thenReturn(
            List.of(missing, noStatus, submitBeforeMined, approveBeforeSubmitted, payBeforeApproved)
        );
        when(chainClient.readClaim(any(byte[].class))).thenReturn(
            null,
            noStatusClaim,
            matchingClaim(submitBeforeMined, 0),
            matchingClaim(approveBeforeSubmitted, 1),
            matchingClaim(payBeforeApproved, 2)
        );

        scheduler.reconcile();

        verify(persistence, never()).projectSettlementOperation(
            any(String.class), any(String.class), any(String.class), any(BigInteger.class), any(String.class)
        );
        verify(chainClient, never()).readApprovalReferenceHash(any(byte[].class));
    }

    @Test
    void skipsClaimsWithMismatchedSubmitIdentityAndAmounts() throws Exception {
        ProviderSettlementOperation operation = operation(ProviderSettlementOperation.Action.SUBMIT);
        Diamond.ProviderSettlementClaim wrongLab = matchingClaim(operation, 1);
        wrongLab.labId = BigInteger.TWO;
        Diamond.ProviderSettlementClaim wrongAmount = matchingClaim(operation, 1);
        wrongAmount.amount = CLAIM_AMOUNT.add(BigInteger.ONE);
        Diamond.ProviderSettlementClaim wrongBatch = matchingClaim(operation, 1);
        wrongBatch.batchId = ProviderSettlementReferenceHasher.batchId("0x" + "22".repeat(32));
        Diamond.ProviderSettlementClaim wrongInvoice = matchingClaim(operation, 1);
        wrongInvoice.invoiceReferenceHash = ProviderSettlementReferenceHasher.reference("OTHER", "invoiceRef");

        when(persistence.findPendingSettlementOperations(50)).thenReturn(
            List.of(operation, operation, operation, operation)
        );
        when(chainClient.readClaim(any(byte[].class))).thenReturn(
            wrongLab, wrongAmount, wrongBatch, wrongInvoice
        );

        scheduler.reconcile();

        verify(persistence, never()).projectSettlementOperation(
            any(String.class), any(String.class), any(String.class), any(BigInteger.class), any(String.class)
        );
    }

    @Test
    void skipsApproveAndPayWhenTheirReferenceHashesDoNotMatch() throws Exception {
        ProviderSettlementOperation approve = operation(ProviderSettlementOperation.Action.APPROVE);
        approve.setApprovalRef("APPROVAL-1");
        ProviderSettlementOperation pay = operation(ProviderSettlementOperation.Action.PAY);
        pay.setPaymentRef("PAYMENT-1");
        pay.setPaymentAttestation("ATTESTATION-1");

        Diamond.ProviderSettlementClaim approveClaim = matchingClaim(approve, 2);
        Diamond.ProviderSettlementClaim payClaim = matchingClaim(pay, 3);
        payClaim.paymentReferenceHash = ProviderSettlementReferenceHasher.reference("OTHER", "paymentRef");
        payClaim.paymentAttestationHash = ProviderSettlementReferenceHasher.reference(
            pay.getPaymentAttestation(), "paymentAttestation"
        );
        when(persistence.findPendingSettlementOperations(50)).thenReturn(List.of(approve, pay));
        when(chainClient.readClaim(any(byte[].class))).thenReturn(approveClaim, payClaim);
        when(chainClient.readApprovalReferenceHash(any(byte[].class))).thenReturn(
            ProviderSettlementReferenceHasher.reference("OTHER", "approvalRef")
        );

        scheduler.reconcile();

        verify(persistence, never()).projectSettlementOperation(
            any(String.class), any(String.class), any(String.class), any(BigInteger.class), any(String.class)
        );
    }

    @Test
    void continuesReconcilingAfterOneOperationFails() throws Exception {
        ProviderSettlementOperation failed = operation(ProviderSettlementOperation.Action.SUBMIT);
        ProviderSettlementOperation valid = operation(ProviderSettlementOperation.Action.SUBMIT);
        valid.setOperationKey("provider-settlement:submit:valid");
        Diamond.ProviderSettlementClaim validClaim = matchingClaim(valid, 1);

        when(persistence.findPendingSettlementOperations(50)).thenReturn(List.of(failed, valid));
        when(chainClient.readClaim(any(byte[].class)))
            .thenThrow(new IOException("RPC unavailable"))
            .thenReturn(validClaim);

        scheduler.reconcile();

        verify(persistence).projectSettlementOperation(
            eq(valid.getOperationKey()),
            eq(validClaim.submittedBy),
            eq(valid.getTransactionHash()),
            eq(valid.getBlockNumber()),
            eq(valid.getBlockHash())
        );
        verify(persistence, times(1)).projectSettlementOperation(
            any(String.class), any(String.class), any(String.class), any(BigInteger.class), any(String.class)
        );
        assertThat(validClaim.status).isEqualTo(BigInteger.ONE);
    }

    private ProviderSettlementOperation operation(ProviderSettlementOperation.Action action) {
        String suffix = action.name().toLowerCase();
        return ProviderSettlementOperation.builder()
            .operationKey("provider-settlement:" + suffix + ":operation")
            .action(action)
            .status(ProviderSettlementOperation.Status.MINED)
            .claimId("CLAIM-" + suffix)
            .claimIdHash("0x" + "aa".repeat(32))
            .invoiceRecordId(action == ProviderSettlementOperation.Action.SUBMIT ? null : 7L)
            .labId("1")
            .providerAddress("0x1111111111111111111111111111111111111111")
            .batchId(BATCH_ID)
            .invoiceRef("INV-" + suffix)
            .eurAmount(new BigDecimal("25.00"))
            .creditAmount(new BigDecimal("250.0000000"))
            .transactionHash("0xtx-" + suffix)
            .blockNumber(BigInteger.TEN)
            .blockHash("0xblock-" + suffix)
            .build();
    }

    private Diamond.ProviderSettlementClaim matchingClaim(
        ProviderSettlementOperation operation,
        int status
    ) {
        return new Diamond.ProviderSettlementClaim(
            BigInteger.ONE,
            CLAIM_AMOUNT,
            BigInteger.valueOf(status),
            ProviderSettlementReferenceHasher.batchId(operation.getBatchId()),
            ProviderSettlementReferenceHasher.reference(operation.getInvoiceRef(), "invoiceRef"),
            new byte[32],
            new byte[32],
            "0xsubmitter",
            "0xapprover",
            "0xpayer",
            BigInteger.ONE,
            BigInteger.TWO,
            BigInteger.valueOf(3)
        );
    }
}
