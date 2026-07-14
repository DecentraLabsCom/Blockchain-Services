package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.dto.auth.CheckInResponse;
import decentralabs.blockchain.dto.auth.InstitutionalCheckInRequest;
import decentralabs.blockchain.dto.auth.SamlAuthRequest;
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

    private final InstitutionalCheckInOutboxService outboxService;
    private final InstitutionalWalletService institutionalWalletService;
    private final InstitutionalCheckInDirectoryService directoryService;
    private final RemoteInstitutionalCheckInClient remoteCheckInClient;
    private final InstitutionalWalletNonceDispatcher nonceDispatcher;

    @Value("${institutional.checkin.delegation.enabled:true}")
    private boolean delegationEnabled;

    public void recordAccessGranted(
        SamlAuthRequest request,
        Map<String, Object> marketplaceClaims,
        Map<String, Object> bookingInfo
    ) {
        // AccessGranted/ACCESS_AUTHORIZED is a payer-side on-chain authorization. It is
        // distinct from the provider-issued JWT/ticket returned by /auth/authorize-and-issue.
        if (isAccessAuthorizedStatus(bookingInfo.get("reservationStatus"))) {
            return;
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
                PucHashUtil.hashPuc(puc),
                accessSessionId
            );
            if ("MINED_FAILED".equals(record.status()) || "FAILED".equals(record.status())) {
                // This point is reached only after the provider has performed
                // the full CONFIRMED/window validation for the new request.
                record = outboxService.restartTerminalFailure(record.id());
            }
            dispatchImmediately(record);
            return;
        }

        delegateSynchronously(request, marketplaceClaims, reservationKey, institutionalWallet, puc, labId);
    }

    private void dispatchImmediately(InstitutionalCheckInOutboxRecord record) {
        if (record == null || !outboxService.claim(record.id())) {
            return;
        }
        try {
            nonceDispatcher.dispatch(record);
        } catch (InstitutionalWalletDispatchException ex) {
            boolean blocked = ex.outcome() == InstitutionalWalletDispatchException.Outcome.PRE_BROADCAST_BLOCKED;
            int attempts = blocked ? record.attempts() : record.attempts() + 1;
            if (ex.outcome() == InstitutionalWalletDispatchException.Outcome.PRE_BROADCAST_BLOCKED
                || ex.outcome() == InstitutionalWalletDispatchException.Outcome.PRE_BROADCAST_TRANSIENT) {
                outboxService.markRetry(
                    record.id(), attempts, Instant.now(),
                    "Initial institutional check-in transaction was not broadcast; retrying"
                );
            } else if (ex.outcome() == InstitutionalWalletDispatchException.Outcome.PRE_BROADCAST_PERMANENT) {
                outboxService.markFailed(
                    record.id(), attempts, "Initial institutional check-in preparation failed permanently"
                );
            } else {
                outboxService.markBroadcastUncertain(
                    record.id(), attempts,
                    "Initial institutional check-in broadcast outcome is uncertain"
                );
            }
        } catch (RuntimeException ex) {
            // Non-classified failures happen before the dispatcher can establish
            // a broadcast boundary and are therefore safe to retry.
            outboxService.markRetry(
                record.id(), record.attempts() + 1, Instant.now(),
                "Initial institutional check-in transaction was not broadcast; retrying"
            );
        }
    }

    private void delegateSynchronously(
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

        CheckInResponse response = remoteCheckInClient.submit(backendUrl, checkInRequest);
        if (response == null || !response.isValid()) {
            String reason = response != null ? response.getReason() : "no response";
            throw new IllegalStateException("Delegated institutional check-in failed: " + reason);
        }
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
