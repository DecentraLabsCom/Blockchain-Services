package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.dto.auth.CheckInResponse;
import decentralabs.blockchain.dto.auth.InstitutionalCheckInRequest;
import decentralabs.blockchain.dto.auth.SamlAuthRequest;
import decentralabs.blockchain.exception.AccessAuthorizationDelegationException;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.util.PucHashUtil;
import decentralabs.blockchain.util.PucNormalizer;
import java.math.BigInteger;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class InstitutionalAccessCheckInCoordinator {
    private static final BigInteger STATUS_ACCESS_AUTHORIZED = BigInteger.valueOf(2);

    public enum AccessGrantedResult {
        DISPATCHED,
        QUEUED,
        ALREADY_AUTHORIZED,
        CONTEXT_MISMATCH,
        MANUAL_INTERVENTION,
        SIGNER_NOT_AUTHORIZED,
        FAILED
    }

    private final InstitutionalCheckInOutboxService outboxService;
    private final InstitutionalWalletService institutionalWalletService;
    private final InstitutionalCheckInDirectoryService directoryService;
    private final RemoteInstitutionalCheckInClient remoteCheckInClient;
    private final InstitutionalWalletNonceDispatcher nonceDispatcher;
    private final CheckInOnChainService checkInOnChainService;

    @Value("${institutional.checkin.delegation.enabled:true}")
    private boolean delegationEnabled;

    public AccessGrantedResult recordAccessGranted(
        SamlAuthRequest request,
        Map<String, Object> marketplaceClaims,
        Map<String, Object> bookingInfo
    ) {
        // AccessGranted/ACCESS_AUTHORIZED is a payer-side on-chain authorization. It is
        // distinct from the provider-issued JWT/ticket returned by /auth/authorize-and-issue.
        if (isAccessAuthorizedStatus(bookingInfo.get("reservationStatus"))) {
            return AccessGrantedResult.ALREADY_AUTHORIZED;
        }

        String reservationKey = stringValue(bookingInfo.get("reservationKey"));
        String institutionalWallet = stringValue(marketplaceClaims.get("payerInstitutionWallet"));
        String puc = PucNormalizer.normalize(stringValue(marketplaceClaims.get("puc")));
        String labId = stringValue(bookingInfo.get("lab"));
        String accessSessionId = firstNonBlank(
            stringValue(bookingInfo.get("guacSessionId")),
            stringValue(bookingInfo.get("reservationKey"))
        );

        if (!hasText(reservationKey) || !hasText(institutionalWallet)) {
            throw new IllegalStateException("Missing reservation or institution data for check-in outbox");
        }
        if (!hasText(puc)) {
            throw new IllegalStateException("Missing PUC claim for institutional check-in");
        }

        String configuredSigner = normalizeAddress(institutionalWalletService.getInstitutionalWalletAddress());
        if (directoryService.isAuthorizedCheckInSigner(institutionalWallet, configuredSigner)) {
            InstitutionalCheckInOutboxRecord record = outboxService.enqueueAccessGranted(
                reservationKey,
                labId,
                institutionalWallet,
                configuredSigner,
                PucHashUtil.hashPuc(puc),
                accessSessionId
            );
            if ("MANUAL_INTERVENTION".equals(record.status())) {
                return AccessGrantedResult.MANUAL_INTERVENTION;
            }
            if ("MINED_FAILED".equals(record.status())) {
                // MINED_FAILED is terminal evidence that the previous nonce was
                // consumed by a reverted transaction. A new generation is safe
                // even when the active signer or chain has since rotated.
                record = outboxService.restartTerminalFailure(record.id());
            }
            if (outboxService.hasPersistedOnchainContext(record)) {
                BigInteger activeChainId;
                try {
                    activeChainId = checkInOnChainService.connectedChainId();
                } catch (RuntimeException ex) {
                    return AccessGrantedResult.QUEUED;
                }
                if (!outboxService.matchesActiveContext(record, activeChainId, configuredSigner)) {
                    boolean quarantined = outboxService.quarantineContextMismatch(
                        record, activeChainId, configuredSigner
                    );
                    if (quarantined) {
                        return AccessGrantedResult.CONTEXT_MISMATCH;
                    }
                    record = reloadRecord(record);
                    if (record == null) {
                        return AccessGrantedResult.CONTEXT_MISMATCH;
                    }
                    if ("MANUAL_INTERVENTION".equals(record.status())) {
                        return AccessGrantedResult.MANUAL_INTERVENTION;
                    }
                    if ("MINED_SUCCESS".equals(record.status())) {
                        return AccessGrantedResult.ALREADY_AUTHORIZED;
                    }
                    if (!"MINED_FAILED".equals(record.status())
                        && !outboxService.matchesActiveContext(record, activeChainId, configuredSigner)) {
                        return AccessGrantedResult.CONTEXT_MISMATCH;
                    }
                }
            }
            if ("MINED_FAILED".equals(record.status()) || "FAILED".equals(record.status())) {
                // This point is reached only after the provider has performed
                // the full CONFIRMED/window validation for the new request.
                record = outboxService.restartTerminalFailure(record.id());
            }
            return dispatchImmediately(record);
        }

        return delegateSynchronously(request, marketplaceClaims, reservationKey, institutionalWallet, puc, labId);
    }

    private InstitutionalCheckInOutboxRecord reloadRecord(InstitutionalCheckInOutboxRecord record) {
        try {
            return outboxService.findById(record.id());
        } catch (RuntimeException ex) {
            return null;
        }
    }

    private AccessGrantedResult dispatchImmediately(InstitutionalCheckInOutboxRecord record) {
        if (record == null) {
            return AccessGrantedResult.QUEUED;
        }
        boolean replacementRequested = replacementRequested(record);
        InstitutionalCheckInOutboxClaim claim = outboxService.claim(record.id());
        if (claim == null) {
            return AccessGrantedResult.QUEUED;
        }
        InstitutionalCheckInOutboxRecord claimed = claim.record();
        try {
            nonceDispatcher.dispatch(claim, replacementRequested);
            return AccessGrantedResult.DISPATCHED;
        } catch (InstitutionalWalletDispatchException ex) {
            boolean blocked = ex.outcome() == InstitutionalWalletDispatchException.Outcome.PRE_BROADCAST_BLOCKED;
            int attempts = blocked ? claimed.attempts() : claimed.attempts() + 1;
            if (ex.outcome() == InstitutionalWalletDispatchException.Outcome.PRE_BROADCAST_BLOCKED
                || ex.outcome() == InstitutionalWalletDispatchException.Outcome.PRE_BROADCAST_TRANSIENT) {
                boolean retryPersisted = outboxService.markRetry(
                    claim, attempts, Instant.now(),
                    "Initial institutional check-in transaction was not broadcast; retrying"
                );
                if (!retryPersisted) {
                    throw new IllegalStateException("Institutional check-in retry could not be persisted", ex);
                }
                return AccessGrantedResult.QUEUED;
            } else if (ex.outcome() == InstitutionalWalletDispatchException.Outcome.PRE_BROADCAST_PERMANENT) {
                outboxService.markFailed(
                    claim, attempts, "Initial institutional check-in preparation failed permanently"
                );
                return AccessGrantedResult.FAILED;
            } else {
                outboxService.markBroadcastUncertain(
                    claim, attempts,
                    "Initial institutional check-in broadcast outcome is uncertain"
                );
                return AccessGrantedResult.QUEUED;
            }
        } catch (RuntimeException ex) {
            // Non-classified failures happen before the dispatcher can establish
            // a broadcast boundary and are therefore safe to retry.
            boolean retryPersisted = outboxService.markRetry(
                claim, claimed.attempts() + 1, Instant.now(),
                "Initial institutional check-in transaction was not broadcast; retrying"
            );
            if (!retryPersisted) {
                throw new IllegalStateException("Institutional check-in retry could not be persisted", ex);
            }
            return AccessGrantedResult.QUEUED;
        }
    }

    private AccessGrantedResult delegateSynchronously(
        SamlAuthRequest request,
        Map<String, Object> marketplaceClaims,
        String reservationKey,
        String institutionalWallet,
        String puc,
        String resolvedLabId
    ) {
        if (!delegationEnabled) {
            throw new IllegalStateException("Local wallet is not authorized for institution check-in");
        }
        String organization = normalizeOrganization(stringValue(marketplaceClaims.get("affiliation")));
        String backendUrl = directoryService.resolveOrganizationBackendUrl(organization);
        if (!hasText(backendUrl)) {
            throw new IllegalStateException("No institutional backend registered for organization " + organization);
        }

        InstitutionalCheckInRequest checkInRequest = new InstitutionalCheckInRequest();
        checkInRequest.setMarketplaceToken(request.getMarketplaceToken());
        checkInRequest.setSamlAssertion(request.getSamlAssertion());
        checkInRequest.setReservationKey(reservationKey);
        checkInRequest.setLabId(firstNonBlank(request.getLabId(), resolvedLabId));
        checkInRequest.setPayerInstitutionWallet(institutionalWallet);
        checkInRequest.setPuc(puc);

        RemoteInstitutionalCheckInClient.RemoteCheckInResult result =
            remoteCheckInClient.submitDetailed(backendUrl, checkInRequest);
        CheckInResponse response = result == null ? null : result.body();
        String reason = response == null ? null : response.getReason();
        if ("CHECKIN_SIGNER_NOT_AUTHORIZED".equals(reason)) {
            return AccessGrantedResult.SIGNER_NOT_AUTHORIZED;
        }
        if ("CHECKIN_CONTEXT_MISMATCH".equals(reason)) {
            return AccessGrantedResult.CONTEXT_MISMATCH;
        }
        if ("CHECKIN_MANUAL_INTERVENTION".equals(reason)) {
            return AccessGrantedResult.MANUAL_INTERVENTION;
        }
        if (result == null || !result.isHttpSuccessful() || response == null || !response.isValid()) {
            if (result != null && (result.isRetryable() || result.status() == 503)) {
                return AccessGrantedResult.QUEUED;
            }
            throw new AccessAuthorizationDelegationException(result);
        }
        return response.getQueued() != null && response.getQueued()
            ? AccessGrantedResult.QUEUED
            : AccessGrantedResult.DISPATCHED;
    }

    private boolean replacementRequested(InstitutionalCheckInOutboxRecord record) {
        return record != null
            && ("REPLACEMENT_PENDING".equalsIgnoreCase(record.status())
                || ("PENDING".equalsIgnoreCase(record.status()) && hasPersistedMaterial(record)));
    }

    private boolean hasPersistedMaterial(InstitutionalCheckInOutboxRecord record) {
        return record != null
            && ((record.signedRawTransaction() != null && !record.signedRawTransaction().isBlank())
                || (record.txHash() != null && !record.txHash().isBlank()));
    }

    private boolean isAccessAuthorizedStatus(Object value) {
        if (value instanceof BigInteger status) {
            return STATUS_ACCESS_AUTHORIZED.equals(status);
        }
        if (value instanceof Number status) {
            return status.longValue() == STATUS_ACCESS_AUTHORIZED.longValue();
        }
        if (value != null) {
            try {
                return STATUS_ACCESS_AUTHORIZED.equals(new BigInteger(value.toString()));
            } catch (RuntimeException ignored) {
                return false;
            }
        }
        return false;
    }

    private String normalizeAddress(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private String normalizeOrganization(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private String firstNonBlank(String first, String second) {
        return hasText(first) ? first : second;
    }

    private String stringValue(Object value) {
        return value == null ? null : String.valueOf(value);
    }
}
