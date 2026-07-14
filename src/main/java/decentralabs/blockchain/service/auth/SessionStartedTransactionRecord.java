package decentralabs.blockchain.service.auth;

import java.math.BigInteger;
import java.time.Instant;

record SessionStartedTransactionRecord(
    SessionStartedOnChainSubmission submission,
    String status,
    int attempts,
    String walletAddress,
    BigInteger chainId,
    BigInteger transactionNonce,
    String transactionHash,
    Instant submittedAt,
    String signedRawTransaction
) { }
