package decentralabs.blockchain.service.billing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.domain.ProviderApproval;
import decentralabs.blockchain.domain.ProviderInvoiceRecord;
import decentralabs.blockchain.domain.ProviderSettlementOperation;
import decentralabs.blockchain.service.persistence.ProviderSettlementPersistenceService;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class ProviderSettlementOnChainServiceTest {

    @Mock
    private ProviderSettlementPersistenceService persistence;

    @Mock
    private ProviderSettlementChainClient chainClient;

    @Test
    void submitProjectsOnlyAfterSuccessfulChainReceipt() throws Exception {
        ProviderSettlementOperation operation = operation(ProviderSettlementOperation.Action.SUBMIT);
        ProviderInvoiceRecord invoice = ProviderInvoiceRecord.builder().id(7L).claimId("CLAIM-1").status(ProviderInvoiceRecord.Status.SUBMITTED).build();
        ProviderSettlementChainClient.ChainReceipt receipt = new ProviderSettlementChainClient.ChainReceipt("0xtx", BigInteger.TEN, "0xblock", "0xactor");
        when(persistence.createOrLoadSettlementOperation(any())).thenReturn(operation);
        when(chainClient.readLabOwner(BigInteger.ONE)).thenReturn("0x1111111111111111111111111111111111111111");
        when(chainClient.submit(any(), eq(BigInteger.ONE), eq(BigInteger.valueOf(2_500_000_000L)), any(), any(), anyString())).thenReturn(receipt);
        when(persistence.findInvoiceByClaimId("CLAIM-1")).thenReturn(Optional.of(invoice));

        ProviderInvoiceRecord result = new ProviderSettlementService(persistence, chainClient).submitInvoice(
            "1", "CLAIM-1", "0x" + "11".repeat(32),
            "INV-1", new BigDecimal("25.00"), new BigDecimal("250.0000000")
        );

        assertThat(result).isSameAs(invoice);
        var requestedOperation = org.mockito.ArgumentCaptor.forClass(ProviderSettlementOperation.class);
        verify(persistence).createOrLoadSettlementOperation(requestedOperation.capture());
        assertThat(requestedOperation.getValue().getProviderAddress())
            .isEqualTo("0x1111111111111111111111111111111111111111");
        InOrder order = inOrder(chainClient, persistence);
        order.verify(chainClient).submit(any(), eq(BigInteger.ONE), eq(BigInteger.valueOf(2_500_000_000L)), any(), any(), anyString());
        order.verify(persistence).markSettlementMined(anyString(),
            eq("0xtx"), eq(BigInteger.TEN), eq("0xblock"), eq("0xactor"));
    }

    @Test
    void approvalStoresTheReceiptActorInsteadOfARequestActor() throws Exception {
        ProviderInvoiceRecord invoice = ProviderInvoiceRecord.builder().id(7L).claimId("CLAIM-1").labId("1").providerAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0001").batchId("0x" + "11".repeat(32)).invoiceRef("INV-1").eurAmount(new BigDecimal("25.00")).creditAmount(new BigDecimal("250.0000000")).status(ProviderInvoiceRecord.Status.SUBMITTED).build();
        ProviderSettlementOperation operation = operation(ProviderSettlementOperation.Action.APPROVE);
        ProviderApproval approval = ProviderApproval.builder().id(8L).invoiceRecordId(7L).approvedBy("0x2222222222222222222222222222222222222222").approvalRef("APPROVAL-1").eurAmount(new BigDecimal("25.00")).build();
        ProviderSettlementChainClient.ChainReceipt receipt = new ProviderSettlementChainClient.ChainReceipt("0xtx", BigInteger.TEN, "0xblock", "0x2222222222222222222222222222222222222222");
        when(persistence.findInvoiceById(7L)).thenReturn(Optional.of(invoice));
        when(persistence.createOrLoadSettlementOperation(any())).thenReturn(operation);
        when(persistence.findApprovalByInvoiceId(7L)).thenReturn(Optional.empty()).thenReturn(Optional.of(approval));
        when(chainClient.approve(any(), any(), anyString())).thenReturn(receipt);

        ProviderApproval result = new ProviderSettlementService(persistence, chainClient).approveInvoice(7L, "APPROVAL-1", new BigDecimal("25.00"));

        assertThat(result.getApprovedBy()).isEqualTo(receipt.actor());
        verify(persistence).projectSettlementOperation(anyString(), eq(receipt.actor()), eq("0xtx"), eq(BigInteger.TEN), eq("0xblock"));
    }

    private ProviderSettlementOperation operation(ProviderSettlementOperation.Action action) {
        return ProviderSettlementOperation.builder()
            .operationKey("provider-settlement:" + action.name().toLowerCase() + ":0x" + "aa".repeat(32))
            .action(action)
            .status(ProviderSettlementOperation.Status.PREPARED)
            .claimId("CLAIM-1")
            .claimIdHash("0x" + "aa".repeat(32))
            .invoiceRecordId(action == ProviderSettlementOperation.Action.SUBMIT ? null : 7L)
            .labId("1")
            .providerAddress("0x1111111111111111111111111111111111111111")
            .batchId("0x" + "11".repeat(32))
            .invoiceRef("INV-1")
            .eurAmount(new BigDecimal("25.00"))
            .creditAmount(new BigDecimal("250.0000000"))
            .approvalRef(action == ProviderSettlementOperation.Action.APPROVE ? "APPROVAL-1" : null)
            .build();
    }
}
