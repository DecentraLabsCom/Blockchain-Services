package decentralabs.blockchain.domain;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.Instant;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Durable domain outbox entry for one canonical on-chain settlement transition. */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProviderSettlementOperation {

    public enum Action { SUBMIT, APPROVE, PAY }
    public enum Status { PREPARED, MINED, PROJECTED, RETRYABLE, REJECTED }

    private Long id;
    private String operationKey;
    private Action action;
    private Status status;
    private String claimId;
    private String claimIdHash;
    private Long invoiceRecordId;
    private String labId;
    private String providerAddress;
    private String batchId;
    private String invoiceRef;
    private String invoiceReferenceHash;
    private String approvalRef;
    private String approvalReferenceHash;
    private String paymentRef;
    private String paymentReferenceHash;
    private String paymentAttestation;
    private String paymentAttestationHash;
    private BigDecimal eurAmount;
    private BigDecimal creditAmount;
    private String bankRef;
    private String eurcTxHash;
    private String usdcTxHash;
    private String requestedByPrincipal;
    private String transactionHash;
    private BigInteger blockNumber;
    private String blockHash;
    private String chainActor;
    private Instant updatedAt;
}
