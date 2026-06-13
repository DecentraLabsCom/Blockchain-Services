package decentralabs.blockchain.dto.labadmin;

import java.math.BigInteger;

public record LabAdminTransactionResponse(
    boolean success,
    String action,
    String transactionHash,
    String status,
    BigInteger labId,
    String metadataUrl
) {}
