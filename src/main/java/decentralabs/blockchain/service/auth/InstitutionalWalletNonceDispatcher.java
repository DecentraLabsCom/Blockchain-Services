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
        if (record == null) {
            throw new InstitutionalWalletDispatchException(
                "Institutional check-in outbox record is required",
                InstitutionalWalletDispatchException.Outcome.PRE_BROADCAST_PERMANENT,
                new IllegalArgumentException("Missing institutional check-in outbox record")
            );
        }
        String walletAddress = submissionService.signerAddress();
        // A stale SUBMITTING row means signing completed but the process may
        // have died before the broadcast/status transition. Resume that exact
        // material first. RETRY rows are handled by the receipt monitor's
        // replacement policy and may deliberately prepare a higher-gas tx.
        if ("SUBMITTING".equalsIgnoreCase(record.status()) && hasPersistedMaterial(record)) {
            if (record.walletAddress() == null || !walletAddress.equalsIgnoreCase(record.walletAddress())) {
                throw new InstitutionalWalletDispatchException(
                    "Persisted institutional transaction belongs to a different wallet",
                    InstitutionalWalletDispatchException.Outcome.PRE_BROADCAST_PERMANENT,
                    new IllegalStateException("Signer and persisted transaction wallet do not match")
                );
            }

            InstitutionalWalletTransactionDispatcher.PreparedTransaction persisted;
            try {
                persisted = new InstitutionalWalletTransactionDispatcher.PreparedTransaction(
                    record.signedRawTransaction(), record.txHash()
                );
            } catch (IllegalArgumentException ex) {
                throw new InstitutionalWalletDispatchException(
                    "Persisted institutional transaction material is incomplete",
                    InstitutionalWalletDispatchException.Outcome.PRE_BROADCAST_PERMANENT,
                    ex
                );
            }
            String txHash = transactionDispatcher.rebroadcastPrepared(persisted);
            outboxService.markSubmitted(record.id(), txHash);
            CheckInResponse response = new CheckInResponse();
            response.setValid(true);
            response.setSigner(walletAddress);
            response.setReservationKey(record.reservationKey());
            response.setTxHash(txHash);
            return response;
        }
        BigInteger existingNonce = record.nonce() != null && walletAddress.equalsIgnoreCase(record.walletAddress())
            ? record.nonce() : null;
        final CheckInResponse[] response = new CheckInResponse[1];
        transactionDispatcher.dispatchPrepared(
            walletAddress,
            record.chainId(),
            existingNonce,
            (chainId, nonce) -> outboxService.markNonceReserved(record.id(), walletAddress, chainId, nonce),
            nonce -> {
                InstitutionalCheckInSubmissionService.PreparedCheckIn prepared = submissionService.prepare(
                    record.reservationKey(), record.pucHash(), nonce, Math.max(0, record.attempts())
                );
                response[0] = prepared.response();
                return prepared.transaction();
            },
            prepared -> outboxService.markPrepared(record.id(), prepared.rawTransaction(), prepared.transactionHash()),
            txHash -> outboxService.markSubmitted(record.id(), txHash)
        );
        return response[0];
    }

    private boolean hasPersistedMaterial(InstitutionalCheckInOutboxRecord record) {
        return hasText(record.signedRawTransaction()) || hasText(record.txHash());
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
