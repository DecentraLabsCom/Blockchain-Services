package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.dto.auth.CheckInResponse;
import java.math.BigInteger;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Serializes only nonce allocation, signing, broadcast and tx-hash persistence
 * for one institutional wallet. The database row lock works across replicas.
 */
@Service
@RequiredArgsConstructor
public class InstitutionalWalletNonceDispatcher {
    private final InstitutionalCheckInOutboxService outboxService;
    private final InstitutionalCheckInSubmissionService submissionService;
    private final CheckInOnChainService checkInOnChainService;

    @Transactional(noRollbackFor = InstitutionalWalletDispatchException.class)
    public CheckInResponse dispatch(InstitutionalCheckInOutboxRecord record) throws InstitutionalWalletDispatchException {
        String walletAddress = submissionService.signerAddress();
        BigInteger nonce = record.nonce() != null && walletAddress.equalsIgnoreCase(record.walletAddress())
            ? record.nonce()
            : reserveNonce(record.id(), walletAddress);

        try {
            CheckInResponse response = submissionService.submit(
                record.reservationKey(), record.pucHash(), nonce, Math.max(0, record.attempts())
            );
            if (response == null || response.getTxHash() == null || response.getTxHash().isBlank()) {
                throw new IllegalStateException("Check-in submission returned no transaction hash");
            }
            outboxService.markSubmitted(record.id(), response.getTxHash());
            return response;
        } catch (RuntimeException ex) {
            throw new InstitutionalWalletDispatchException("Check-in broadcast outcome is uncertain", ex);
        }
    }

    private BigInteger reserveNonce(long recordId, String walletAddress) {
        BigInteger nodePendingNonce = checkInOnChainService.pendingNonce(walletAddress);
        BigInteger nonce = outboxService.reserveNextNonce(walletAddress, nodePendingNonce);
        outboxService.markNonceReserved(recordId, walletAddress, nonce);
        return nonce;
    }
}
