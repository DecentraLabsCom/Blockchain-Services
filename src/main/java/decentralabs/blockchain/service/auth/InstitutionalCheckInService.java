package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.dto.auth.CheckInResponse;
import decentralabs.blockchain.dto.auth.InstitutionalCheckInRequest;
import decentralabs.blockchain.dto.auth.InstitutionalCheckInStatusRequest;
import decentralabs.blockchain.service.wallet.BlockchainBookingService;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.util.LogSanitizer;
import java.nio.charset.StandardCharsets;
import java.math.BigInteger;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import org.web3j.crypto.Hash;
import org.web3j.utils.Numeric;
import decentralabs.blockchain.util.PucNormalizer;

@Service
@RequiredArgsConstructor
@Slf4j
public class InstitutionalCheckInService {
    private static final String ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
    private static final BigInteger STATUS_ACCESS_AUTHORIZED = BigInteger.valueOf(2);

    private static final class MarketplaceIdentityClaims {
        private final String puc;
        private final String payerInstitutionWallet;

        MarketplaceIdentityClaims(String puc, String payerInstitutionWallet) {
            this.puc = puc;
            this.payerInstitutionWallet = payerInstitutionWallet;
        }
    }

    private final SamlValidationService samlValidationService;
    private final MarketplaceEndpointAuthService marketplaceEndpointAuthService;
    private final BlockchainBookingService bookingService;
    private final CheckInOnChainService checkInOnChainService;
    private final InstitutionalWalletService institutionalWalletService;
    private final InstitutionalCheckInDirectoryService directoryService;
    private final RemoteInstitutionalCheckInClient remoteCheckInClient;
    private final InstitutionalCheckInOutboxService outboxService;
    private final InstitutionalWalletNonceDispatcher nonceDispatcher;

    @Value("${institutional.checkin.delegation.enabled:true}")
    private boolean delegationEnabled;

    public CheckInResponse checkIn(InstitutionalCheckInRequest request) {
        validateRequest(request);

        SamlAssertionAttributes saml = validateSaml(request.getSamlAssertion());
        MarketplaceIdentityClaims marketplaceIdentity = validateMarketplaceToken(request, saml);

        String tokenIdentity = PucNormalizer.normalize(marketplaceIdentity.puc);
        if (tokenIdentity == null || tokenIdentity.isBlank()) {
            throw new IllegalArgumentException("Missing institutional user puc");
        }
        String puc = tokenIdentity;

        String requestPuc = PucNormalizer.normalize(request.getPuc());
        if (requestPuc != null && !requestPuc.isBlank() && !requestPuc.equals(puc)) {
            throw new SecurityException("Request puc does not match authenticated user");
        }

        String institutionOrganization = resolveInstitutionOrganization(saml);
        String institutionWallet = resolveInstitutionWallet(request, marketplaceIdentity.payerInstitutionWallet);
        if (institutionWallet == null || institutionWallet.isBlank() || ZERO_ADDRESS.equalsIgnoreCase(institutionWallet)) {
            throw new IllegalArgumentException("Institution wallet could not be resolved");
        }

        Map<String, Object> bookingInfo = bookingService.getCheckInBookingInfo(
            institutionWallet,
            request.getReservationKey(),
            request.getLabId(),
            puc
        );

        String reservationKey = bookingInfo.get("reservationKey") != null
            ? bookingInfo.get("reservationKey").toString()
            : null;
        if (reservationKey == null || reservationKey.isBlank()) {
            throw new IllegalStateException("Reservation key could not be resolved");
        }

        // The reservation status is read from the validated on-chain booking.
        if (isAccessAuthorizedStatus(bookingInfo.get("reservationStatus"))) {
            CheckInResponse response = new CheckInResponse();
            response.setValid(true);
            response.setReservationKey(reservationKey);
            response.setReason("Access already authorized");
            response.setTimestamp(System.currentTimeMillis() / 1000);
            return response;
        }

        String configuredSigner = normalizeAddress(institutionalWalletService.getInstitutionalWalletAddress());
        // configuredSigner is loaded from the institution wallet configuration and
        // the institution wallet was bound to the validated marketplace identity.
        if (!directoryService.isAuthorizedCheckInSigner(institutionWallet, configuredSigner)) {
            return delegateToInstitutionBackend(request, institutionOrganization, institutionWallet);
        }

        InstitutionalCheckInOutboxRecord record = outboxService.enqueueAccessGranted(
            reservationKey,
            request.getLabId(),
            institutionWallet,
            configuredSigner,
            computePucHash(puc),
            reservationKey
        );
        if ("MANUAL_INTERVENTION".equals(record.status())) {
            return manualInterventionResponse(reservationKey, configuredSigner, record.txHash());
        }
        if ("MINED_FAILED".equals(record.status())) {
            // The failed receipt already consumed the old nonce. Restarting a
            // new generation is safe even if the active chain or signer rotated.
            record = outboxService.restartTerminalFailure(record.id());
        }
        if (outboxService.hasPersistedOnchainContext(record)) {
            BigInteger activeChainId;
            try {
                activeChainId = checkInOnChainService.connectedChainId();
            } catch (RuntimeException ex) {
                log.warn("Interactive check-in deferred because active chain context is unavailable: {}",
                    LogSanitizer.sanitize(ex.getMessage()));
                return queuedResponse(
                    reservationKey, configuredSigner, record.txHash(), "CHECKIN_CONTEXT_PENDING"
                );
            }
            if (!outboxService.matchesActiveContext(record, activeChainId, configuredSigner)) {
                boolean quarantined = outboxService.quarantineContextMismatch(
                    record, activeChainId, configuredSigner
                );
                if (quarantined) {
                    return contextMismatchResponse(reservationKey, configuredSigner, record.txHash());
                }
                record = reloadRecord(record);
                if (record == null) {
                    return contextMismatchResponse(reservationKey, configuredSigner, null);
                }
                if ("MANUAL_INTERVENTION".equals(record.status())) {
                    return manualInterventionResponse(reservationKey, configuredSigner, record.txHash());
                }
                if ("MINED_SUCCESS".equals(record.status())) {
                    return minedSuccessResponse(reservationKey, configuredSigner, record.txHash());
                }
                if (!"MINED_FAILED".equals(record.status())
                    && !outboxService.matchesActiveContext(record, activeChainId, configuredSigner)) {
                    return contextMismatchResponse(reservationKey, configuredSigner, record.txHash());
                }
            }
        }
        if ("MINED_FAILED".equals(record.status()) || "FAILED".equals(record.status())) {
            // The booking, payer and institutional identity were fully revalidated above.
            record = outboxService.restartTerminalFailure(record.id());
        }
        boolean replacementRequested = replacementRequested(record);
        InstitutionalCheckInOutboxClaim claim = outboxService.claim(record.id());
        if (claim != null) {
            InstitutionalCheckInOutboxRecord claimed = claim.record();
            try {
                return nonceDispatcher.dispatch(claim, replacementRequested);
            } catch (InstitutionalWalletDispatchException ex) {
                boolean blocked = ex.outcome() == InstitutionalWalletDispatchException.Outcome.PRE_BROADCAST_BLOCKED;
                int attempts = blocked ? claimed.attempts() : claimed.attempts() + 1;
                if (ex.outcome() == InstitutionalWalletDispatchException.Outcome.PRE_BROADCAST_BLOCKED
                    || ex.outcome() == InstitutionalWalletDispatchException.Outcome.PRE_BROADCAST_TRANSIENT) {
                    boolean retryPersisted = outboxService.markRetry(
                        claim, attempts, Instant.now(),
                        "Initial institutional check-in transaction was not broadcast; retrying"
                    );
                    if (retryPersisted) {
                        return queuedResponse(reservationKey, configuredSigner, record.txHash());
                    }
                } else if (ex.outcome() == InstitutionalWalletDispatchException.Outcome.PRE_BROADCAST_PERMANENT) {
                    outboxService.markFailed(
                        claim, attempts, "Initial institutional check-in preparation failed permanently"
                    );
                } else {
                    outboxService.markBroadcastUncertain(
                        claim, attempts, "Initial institutional check-in broadcast outcome is uncertain"
                    );
                }
                throw new IllegalStateException(
                    ex.outcome() == InstitutionalWalletDispatchException.Outcome.PRE_BROADCAST_BLOCKED
                        || ex.outcome() == InstitutionalWalletDispatchException.Outcome.PRE_BROADCAST_TRANSIENT
                        ? "Institutional check-in submission could not be prepared"
                        : "Institutional check-in submission could not be confirmed",
                    ex
                );
            }
        }

        CheckInResponse response = new CheckInResponse();
        response.setValid(true);
        response.setQueued(true);
        response.setRetryable(true);
        response.setReservationKey(reservationKey);
        response.setTxHash(record.txHash());
        response.setTimestamp(System.currentTimeMillis() / 1000);
        response.setReason("Institutional check-in is already queued");
        return response;
    }

    /**
     * Returns the durable consumer-side check-in state for provider-only retries.
     * The marketplace token binds the lookup to the reservation and lab; no SAML
     * assertion is needed because this endpoint does not create or mutate state.
     */
    public CheckInResponse checkInStatus(InstitutionalCheckInStatusRequest request) {
        if (request == null || request.getMarketplaceToken() == null
            || request.getMarketplaceToken().isBlank()
            || request.getReservationKey() == null || request.getReservationKey().isBlank()) {
            throw new IllegalArgumentException("Missing marketplaceToken or reservationKey");
        }
        Map<String, Object> claims;
        try {
            claims = marketplaceEndpointAuthService.enforceToken(request.getMarketplaceToken(), null);
        } catch (ResponseStatusException ex) {
            if (ex.getStatusCode().equals(HttpStatus.UNAUTHORIZED)
                || ex.getStatusCode().equals(HttpStatus.FORBIDDEN)) {
                throw new SecurityException("Invalid marketplace token: " + ex.getReason(), ex);
            }
            throw new IllegalArgumentException("Invalid marketplace token: " + ex.getReason(), ex);
        }
        enforceRequiredClaim(claims, "purpose", "lab_access");
        String effectiveLabId = request.getLabId();
        if (effectiveLabId == null || effectiveLabId.isBlank()) {
            effectiveLabId = firstClaim(claims, "labId");
        }
        enforceOptionalBoundClaim(claims, "reservationKey", request.getReservationKey());
        enforceOptionalBoundClaim(claims, "labId", effectiveLabId);

        String puc = firstClaim(claims, "puc");
        String payerWallet = firstClaim(claims, "payerInstitutionWallet");
        if (puc == null || puc.isBlank() || payerWallet == null || payerWallet.isBlank()) {
            throw new SecurityException("Marketplace token missing required claims");
        }
        Map<String, Object> bookingInfo = bookingService.getCheckInBookingInfo(
            payerWallet,
            request.getReservationKey(),
            effectiveLabId,
            puc
        );
        String canonicalReservationKey = reservationKeyFromBooking(
            bookingInfo, request.getReservationKey()
        );

        InstitutionalCheckInOutboxService.CheckInOutboxState state =
            outboxService.findStateByReservationKeyIfConfigured(canonicalReservationKey);
        if (state == null) {
            CheckInResponse response = new CheckInResponse();
            response.setValid(false);
            response.setQueued(false);
            response.setRetryable(false);
            response.setReservationKey(canonicalReservationKey);
            response.setReason("CHECKIN_NOT_FOUND");
            return response;
        }
        return statusResponse(canonicalReservationKey, state);
    }

    private CheckInResponse statusResponse(
        String reservationKey,
        InstitutionalCheckInOutboxService.CheckInOutboxState state
    ) {
        CheckInResponse response = new CheckInResponse();
        response.setReservationKey(reservationKey);
        response.setTxHash(state.txHash());
        response.setTimestamp(System.currentTimeMillis() / 1000);
        if ("MINED_SUCCESS".equalsIgnoreCase(state.status())) {
            response.setValid(true);
            response.setQueued(false);
            response.setRetryable(false);
            response.setReason("Access already authorized");
        } else if ("MANUAL_INTERVENTION".equalsIgnoreCase(state.status())) {
            response.setValid(false);
            response.setQueued(false);
            response.setRetryable(false);
            response.setReason(state.isContextMismatch()
                ? "CHECKIN_CONTEXT_MISMATCH" : "CHECKIN_MANUAL_INTERVENTION");
        } else if ("FAILED".equalsIgnoreCase(state.status())
            || "MINED_FAILED".equalsIgnoreCase(state.status())) {
            response.setValid(false);
            response.setQueued(false);
            response.setRetryable(false);
            response.setReason("CHECKIN_FAILED");
        } else {
            response.setValid(true);
            response.setQueued(true);
            response.setRetryable(true);
            response.setReason("CHECKIN_QUEUED");
        }
        return response;
    }

    private String reservationKeyFromBooking(Map<String, Object> bookingInfo, String fallback) {
        Object value = bookingInfo == null ? null : bookingInfo.get("reservationKey");
        return value == null || value.toString().isBlank() ? fallback : value.toString();
    }

    private InstitutionalCheckInOutboxRecord reloadRecord(InstitutionalCheckInOutboxRecord record) {
        try {
            return outboxService.findById(record.id());
        } catch (RuntimeException ex) {
            return null;
        }
    }

    private CheckInResponse queuedResponse(String reservationKey, String signer, String txHash) {
        return queuedResponse(reservationKey, signer, txHash, "CHECKIN_QUEUED");
    }

    private CheckInResponse queuedResponse(
        String reservationKey, String signer, String txHash, String reason
    ) {
        CheckInResponse response = new CheckInResponse();
        response.setValid(true);
        response.setQueued(true);
        response.setReservationKey(reservationKey);
        response.setSigner(signer);
        response.setTxHash(txHash);
        response.setTimestamp(System.currentTimeMillis() / 1000);
        response.setReason(reason);
        response.setRetryable(true);
        return response;
    }

    private CheckInResponse contextMismatchResponse(
        String reservationKey, String signer, String txHash
    ) {
        CheckInResponse response = new CheckInResponse();
        response.setValid(false);
        response.setQueued(false);
        response.setRetryable(false);
        response.setReservationKey(reservationKey);
        response.setSigner(signer);
        response.setTxHash(txHash);
        response.setTimestamp(System.currentTimeMillis() / 1000);
        response.setReason("CHECKIN_CONTEXT_MISMATCH");
        return response;
    }

    private CheckInResponse manualInterventionResponse(
        String reservationKey, String signer, String txHash
    ) {
        CheckInResponse response = new CheckInResponse();
        response.setValid(false);
        response.setQueued(false);
        response.setRetryable(false);
        response.setReservationKey(reservationKey);
        response.setSigner(signer);
        response.setTxHash(txHash);
        response.setTimestamp(System.currentTimeMillis() / 1000);
        response.setReason("CHECKIN_MANUAL_INTERVENTION");
        return response;
    }

    private CheckInResponse minedSuccessResponse(
        String reservationKey, String signer, String txHash
    ) {
        CheckInResponse response = new CheckInResponse();
        response.setValid(true);
        response.setQueued(false);
        response.setRetryable(false);
        response.setReservationKey(reservationKey);
        response.setSigner(signer);
        response.setTxHash(txHash);
        response.setTimestamp(System.currentTimeMillis() / 1000);
        response.setReason("Access already authorized");
        return response;
    }

    private void validateRequest(InstitutionalCheckInRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Missing request");
        }
        if (request.getSamlAssertion() == null || request.getSamlAssertion().isBlank()) {
            throw new IllegalArgumentException("Missing samlAssertion");
        }
        if (request.getMarketplaceToken() == null || request.getMarketplaceToken().isBlank()) {
            throw new IllegalArgumentException("Missing marketplaceToken");
        }
        boolean hasReservationKey = request.getReservationKey() != null && !request.getReservationKey().isBlank();
        boolean hasLabId = request.getLabId() != null && !request.getLabId().isBlank();
        if (!hasReservationKey && !hasLabId) {
            throw new IllegalArgumentException("Missing reservationKey or labId");
        }
    }

    private SamlAssertionAttributes validateSaml(String samlAssertion) {
        try {
            return samlValidationService.validateSamlAssertionDetailed(samlAssertion);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid samlAssertion: " + e.getMessage(), e);
        }
    }

    private MarketplaceIdentityClaims validateMarketplaceToken(InstitutionalCheckInRequest request, SamlAssertionAttributes saml) {
        try {
            String marketplaceToken = request.getMarketplaceToken();
            Map<String, Object> claims = marketplaceEndpointAuthService.enforceToken(marketplaceToken, null);
            String claimPuc = firstClaim(claims, "puc");
            // affiliation is validated above but not retained in the return object
            String claimAffiliation = firstClaim(claims, "affiliation", "schacHomeOrganization");

            if (claimPuc == null || claimPuc.isBlank() || claimAffiliation == null || claimAffiliation.isBlank()) {
                throw new IllegalArgumentException("Marketplace token missing required claims");
            }
            String normalizedSamlPuc = PucNormalizer.normalize(saml.puc());
            String normalizedClaimPuc = PucNormalizer.normalize(claimPuc);
            String stableUserIdMode = firstClaim(claims, "stableUserIdMode");
            if (stableUserIdMode != null && !stableUserIdMode.isBlank()) {
                normalizedSamlPuc = PucNormalizer.normalize(
                    samlValidationService.resolveStableUserId(
                        toSamlAttributeMap(saml),
                        stableUserIdMode,
                        null
                    )
                );
            }
            if (normalizedSamlPuc == null
                || normalizedSamlPuc.isBlank()
                || !normalizedSamlPuc.equals(normalizedClaimPuc)) {
                throw new SecurityException("Marketplace token puc mismatch");
            }
            if (saml.affiliation() != null && !saml.affiliation().isBlank() && !claimAffiliation.equals(saml.affiliation())) {
                throw new SecurityException("Marketplace token affiliation mismatch");
            }
            enforceRequiredClaim(claims, "purpose", "lab_access");
            enforceBoundClaim(claims, "reservationKey", request.getReservationKey());
            enforceBoundClaim(claims, "labId", request.getLabId());
            enforceRequiredSamlAssertionHash(claims, request.getSamlAssertion());

            String claimPayerInstitutionWallet = firstClaim(claims, "payerInstitutionWallet");
            return new MarketplaceIdentityClaims(
                claimPuc,
                claimPayerInstitutionWallet
            );
        } catch (ResponseStatusException ex) {
            if (ex.getStatusCode().equals(HttpStatus.UNAUTHORIZED) || ex.getStatusCode().equals(HttpStatus.FORBIDDEN)) {
                throw new SecurityException("Invalid marketplace token: " + ex.getReason(), ex);
            }
            throw new IllegalArgumentException("Invalid marketplace token: " + ex.getReason(), ex);
        } catch (SecurityException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new IllegalArgumentException("Invalid marketplace token: " + ex.getMessage(), ex);
        }
    }

    private String resolveInstitutionWallet(InstitutionalCheckInRequest request, String marketplaceWallet) {
        String boundWallet = normalizeAddress(marketplaceWallet);
        if (boundWallet == null || boundWallet.isBlank()) {
            throw new SecurityException("Marketplace token missing payerInstitutionWallet");
        }

        String requestedWallet = normalizeAddress(request.getPayerInstitutionWallet());
        if (requestedWallet != null && !requestedWallet.equalsIgnoreCase(boundWallet)) {
            throw new SecurityException("Marketplace token payerInstitutionWallet mismatch");
        }

        // The signed marketplace token is the authority for the payer wallet.
        // The request field is only an optional consistency check and never selects
        // which institution is queried on-chain.
        return boundWallet;
    }

    private String resolveInstitutionOrganization(SamlAssertionAttributes saml) {
        String org = null;
        if (saml.schacHomeOrganizations() != null && !saml.schacHomeOrganizations().isEmpty()) {
            org = saml.schacHomeOrganizations().get(0);
        }
        if (org == null || org.isBlank()) {
            org = saml.affiliation();
        }

        if (org == null || org.isBlank()) {
            throw new IllegalArgumentException("Missing institution organization");
        }

        return normalizeOrganization(org);
    }

    private CheckInResponse delegateToInstitutionBackend(
        InstitutionalCheckInRequest request,
        String organization,
        String institutionWallet
    ) {
        if (!delegationEnabled) {
            throw new IllegalStateException("Local wallet is not authorized for institution check-in");
        }
        String backendUrl = directoryService.resolveOrganizationBackendUrl(organization);
        if (backendUrl == null || backendUrl.isBlank()) {
            throw new IllegalStateException("No institutional backend registered for organization "
                + LogSanitizer.sanitize(organization));
        }
        request.setPayerInstitutionWallet(institutionWallet);
        log.info("Delegating institutional check-in for organization {} to registered backend",
            LogSanitizer.sanitize(organization));
        return remoteCheckInClient.submit(backendUrl, request);
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

    private String computePucHash(String puc) {
        if (puc == null || puc.isBlank()) {
            return "0x" + "0".repeat(64);
        }
        byte[] hash = Hash.sha3(puc.getBytes(StandardCharsets.UTF_8));
        return normalizeBytes32(Numeric.toHexString(hash));
    }

    private String normalizeBytes32(String value) {
        String clean = Numeric.cleanHexPrefix(value == null ? "" : value);
        if (clean.length() > 64) {
            clean = clean.substring(clean.length() - 64);
        }
        if (clean.length() < 64) {
            clean = "0".repeat(64 - clean.length()) + clean;
        }
        return "0x" + clean;
    }

    private String normalizeOrganization(String value) {
        if (value == null) {
            return "";
        }
        return value.trim().toLowerCase(Locale.ROOT);
    }

    private String normalizeAddress(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private boolean isAccessAuthorizedStatus(Object value) {
        if (value == null) {
            return false;
        }
        if (value instanceof BigInteger status) {
            return STATUS_ACCESS_AUTHORIZED.equals(status);
        }
        if (value instanceof Number status) {
            return status.longValue() == STATUS_ACCESS_AUTHORIZED.longValue();
        }
        try {
            return STATUS_ACCESS_AUTHORIZED.equals(new BigInteger(value.toString()));
        } catch (RuntimeException ex) {
            log.debug("Unable to parse reservation status", ex);
            return false;
        }
    }

    private void enforceRequiredSamlAssertionHash(Map<String, Object> claims, String samlAssertion) {
        String expectedHash = firstClaim(claims, "samlAssertionHash");
        if (expectedHash == null || expectedHash.isBlank()) {
            throw new SecurityException("Marketplace token samlAssertionHash is required");
        }
        String actualHash = Numeric.toHexString(Hash.sha3(samlAssertion.getBytes(StandardCharsets.UTF_8)));
        if (!expectedHash.equalsIgnoreCase(actualHash)) {
            throw new SecurityException("Marketplace token samlAssertionHash mismatch");
        }
    }

    private void enforceBoundClaim(Map<String, Object> claims, String claim, String expected) {
        if (expected == null || expected.isBlank()) {
            return;
        }
        enforceRequiredClaim(claims, claim, expected);
    }

    private void enforceOptionalBoundClaim(Map<String, Object> claims, String claim, String expected) {
        if (expected == null || expected.isBlank()) {
            return;
        }
        String actual = firstClaim(claims, claim);
        if (actual != null && !actual.isBlank() && !actual.equals(expected)) {
            throw new SecurityException("Marketplace token " + claim + " mismatch");
        }
    }

    private void enforceRequiredClaim(Map<String, Object> claims, String claim, String expected) {
        String value = firstClaim(claims, claim);
        if (value == null || value.isBlank()) {
            throw new SecurityException("Marketplace token " + claim + " is required");
        }
        if (!value.equals(expected)) {
            throw new SecurityException("Marketplace token " + claim + " mismatch");
        }
    }

    private String firstClaim(Map<String, Object> claims, String... keys) {
        for (String key : keys) {
            Object value = claims.get(key);
            if (value != null) {
                return value.toString();
            }
        }
        return null;
    }

    private Map<String, String> toSamlAttributeMap(SamlAssertionAttributes saml) {
        Map<String, String> values = new LinkedHashMap<>();
        putIfPresent(values, "puc", saml.puc());
        putIfPresent(values, "affiliation", saml.affiliation());
        if (saml.attributes() != null) {
            saml.attributes().forEach((key, attributeValues) -> {
                if (attributeValues != null && !attributeValues.isEmpty()) {
                    putIfPresent(values, key, attributeValues.get(0));
                }
            });
        }
        return values;
    }

    private void putIfPresent(Map<String, String> values, String key, String value) {
        if (key == null || value == null || value.isBlank()) {
            return;
        }
        values.put(key, value);
    }

}
