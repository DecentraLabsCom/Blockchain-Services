package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.dto.auth.CheckInResponse;
import java.math.BigInteger;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * Serializes only nonce allocation, signing, broadcast and tx-hash persistence
 * for one institutional wallet. The database row lock works across replicas.
 */
@Service
@RequiredArgsConstructor
public class InstitutionalWalletNonceDispatcher {
    private final InstitutionalCheckInOutboxService outboxService;
    private final InstitutionalCheckInSubmissionService submissionService;
    private final InstitutionalWalletTransactionDispatcher transactionDispatcher;

    public CheckInResponse dispatch(InstitutionalCheckInOutboxRecord record) throws InstitutionalWalletDispatchException {
        String walletAddress = submissionService.signerAddress();
        BigInteger existingNonce = record.nonce() != null && walletAddress.equalsIgnoreCase(record.walletAddress())
            ? record.nonce() : null;
        final CheckInResponse[] response = new CheckInResponse[1];
        transactionDispatcher.dispatch(
            walletAddress,
            existingNonce,
            nonce -> outboxService.markNonceReserved(record.id(), walletAddress, nonce),
            nonce -> {
                response[0] = submissionService.submit(
                    record.reservationKey(), record.pucHash(), nonce, Math.max(0, record.attempts())
                );
                return response[0] != null ? response[0].getTxHash() : null;
            },
            txHash -> outboxService.markSubmitted(record.id(), txHash)
        );
        return response[0];
    }
}
