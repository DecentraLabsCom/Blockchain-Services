package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.dto.auth.CheckInResponse;
import java.math.BigInteger;
import java.util.concurrent.atomic.AtomicReference;
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

    public CheckInResponse dispatch(InstitutionalCheckInOutboxClaim claim)
        throws InstitutionalWalletDispatchException {
        return dispatch(claim, false);
    }

    /**
     * Dispatches a claimed row while preserving whether the claim requested a
     * replacement. A row claimed from REPLACEMENT_PENDING must not be treated
     * as a stale crash recovery just because claim() changed its status to
     * SUBMITTING before the row was reloaded.
     */
    public CheckInResponse dispatch(
        InstitutionalCheckInOutboxClaim claim, boolean replacementRequested
    ) throws InstitutionalWalletDispatchException {
        InstitutionalCheckInOutboxRecord record = claim != null ? claim.record() : null;
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
        if (!replacementRequested
            && "SUBMITTING".equalsIgnoreCase(record.status()) && hasPersistedMaterial(record)) {
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
            if (!outboxService.markSubmitted(claim, record, txHash)) {
                throw new IllegalStateException("Check-in persisted transaction submission lost its fencing claim");
            }
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
        AtomicReference<InstitutionalCheckInOutboxRecord> preparedFrom = new AtomicReference<>();
        transactionDispatcher.dispatchPrepared(
            walletAddress,
            record.chainId(),
            existingNonce,
            (chainId, nonce) -> {
                if (!outboxService.markNonceReserved(claim, walletAddress, chainId, nonce)) {
                    throw new IllegalStateException("Check-in nonce reservation lost its fencing claim");
                }
            },
            nonce -> {
                InstitutionalCheckInSubmissionService.PreparedCheckIn prepared = submissionService.prepare(
                    record.reservationKey(), record.pucHash(), nonce,
                    record.originalGasPrice(), record.currentGasPrice(), Math.max(0, record.attempts())
                );
                response[0] = prepared.response();
                return prepared.transaction();
            },
            prepared -> {
                InstitutionalCheckInOutboxRecord current = currentRecord(claim, record);
                preparedFrom.set(current);
                outboxService.markPrepared(claim, current, prepared);
            },
            txHash -> {
                InstitutionalCheckInOutboxRecord current = preparedFrom.get();
                if (current == null) {
                    current = record;
                }
                if (!outboxService.markSubmittedAfterPreparation(claim, current, txHash)) {
                    throw new IllegalStateException("Check-in prepared transaction submission lost its fencing claim");
                }
            }
        );
        return response[0];
    }

    private boolean hasPersistedMaterial(InstitutionalCheckInOutboxRecord record) {
        return hasText(record.signedRawTransaction()) || hasText(record.txHash());
    }

    private InstitutionalCheckInOutboxRecord currentRecord(
        InstitutionalCheckInOutboxClaim claim,
        InstitutionalCheckInOutboxRecord fallback
    ) {
        try {
            InstitutionalCheckInOutboxRecord current = outboxService.findClaimed(claim);
            return current != null ? current : fallback;
        } catch (RuntimeException ex) {
            return fallback;
        }
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
