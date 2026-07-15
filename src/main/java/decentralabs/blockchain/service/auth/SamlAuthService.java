package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.dto.auth.AuthResponse;
import decentralabs.blockchain.dto.auth.CheckInResponse;
import decentralabs.blockchain.dto.auth.ProviderAccessCredentialRequest;
import decentralabs.blockchain.dto.auth.SamlAuthRequest;
import decentralabs.blockchain.dto.auth.InstitutionalCheckInStatusRequest;
import decentralabs.blockchain.exception.AccessAuthorizationPendingException;
import decentralabs.blockchain.exception.AccessAuthorizationRejectedException;
import decentralabs.blockchain.exception.AccessAuthorizationContextMismatchException;
import decentralabs.blockchain.exception.AccessAuthorizationManualInterventionException;
import decentralabs.blockchain.exception.AccessAuthorizationSignerNotAuthorizedException;
import decentralabs.blockchain.exception.SamlAuthenticationException;
import decentralabs.blockchain.exception.SamlExpiredAssertionException;
import decentralabs.blockchain.exception.SamlInvalidIssuerException;
import decentralabs.blockchain.exception.SamlMalformedResponseException;
import decentralabs.blockchain.exception.SamlMissingAttributesException;
import decentralabs.blockchain.exception.SamlReplayAttackException;
import decentralabs.blockchain.exception.SamlServiceUnavailableException;
import decentralabs.blockchain.service.wallet.BlockchainBookingService;
import decentralabs.blockchain.util.LogSanitizer;
import decentralabs.blockchain.util.PucNormalizer;
import decentralabs.blockchain.util.PucHashUtil;
import java.util.Collection;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
@Slf4j
@RequiredArgsConstructor
public class SamlAuthService {

    private final BlockchainBookingService blockchainService;
    private final JwtService jwtService;
    private final MarketplaceEndpointAuthService marketplaceEndpointAuthService;
    private final SamlValidationService samlValidationService;
    private final InstitutionalAccessCheckInCoordinator accessCheckInCoordinator;
    private final AccessCredentialDeliveryService accessCredentialDeliveryService;
    private final AccessAuthorizationProvisioningService accessAuthorizationProvisioningService;
    private final CheckInOnChainService checkInOnChainService;
    private final AccessCodeService accessCodeService;
    private final InstitutionalCheckInOutboxService institutionalCheckInOutboxService;
    private final InstitutionalCheckInDirectoryService institutionalCheckInDirectoryService;
    private final RemoteInstitutionalCheckInClient remoteInstitutionalCheckInClient;

    @Value("${auth.saml.require-booking-scope:true}")
    private boolean requireBookingScope;

    @Value("${auth.saml.required-booking-scope:booking:read}")
    private String requiredBookingScope;

    @Value("${auth.access-authorization.wait-timeout-ms:27000}")
    private long accessAuthorizationWaitTimeoutMs;

    @Value("${auth.access-authorization.poll-interval-ms:500}")
    private long accessAuthorizationPollIntervalMs;

    public AuthResponse issueAccessCredential(ProviderAccessCredentialRequest request) {
        validateProviderAccessCredentialRequest(request);

        Map<String, Object> marketplaceJWTClaims = validateMarketplaceJWTBasic(request.getMarketplaceToken());
        enforceBookingInfoEntitlement(marketplaceJWTClaims);
        enforceLabAccessPurpose(marketplaceJWTClaims);
        enforceClaimEquals(marketplaceJWTClaims, "reservationKey", request.getReservationKey());
        enforceClaimEquals(marketplaceJWTClaims, "labId", request.getLabId());

        String payerInstitutionWallet = stringClaim(marketplaceJWTClaims, "payerInstitutionWallet");
        if (payerInstitutionWallet == null || payerInstitutionWallet.isBlank()) {
            throw new SecurityException("Marketplace token missing payerInstitutionWallet");
        }

        Map<String, Object> bookingInfo = null;
        AccessAuthorizationProvisioningService.ProvisioningLease provisionalLease = null;
        String issuedAccessCode = null;
        String canonicalReservationKey = request.getReservationKey();
        try {
            bookingInfo = blockchainService.getBookingInfoForCredentialPreparation(
                payerInstitutionWallet,
                request.getReservationKey(),
                request.getLabId(),
                stringClaim(marketplaceJWTClaims, "puc")
            );
            canonicalReservationKey = reservationKeyFromBooking(bookingInfo, request.getReservationKey());
            if (canonicalReservationKey == null || canonicalReservationKey.isBlank()) {
                throw new IllegalArgumentException("Unable to resolve canonical reservationKey");
            }
            request.setReservationKey(canonicalReservationKey);
            AuthResponse recovered = isAccessAuthorized(bookingInfo)
                ? recoverDeliveredAccess(canonicalReservationKey) : null;
            if (recovered != null) {
                return recovered;
            }
            String puc = stringClaim(marketplaceJWTClaims, "puc");
            String txHash = request.getAccessAuthorizationTxHash();
            if (!isAccessAuthorized(bookingInfo)) {
                enforceConsumerCheckInState(
                    canonicalReservationKey,
                    marketplaceJWTClaims,
                    request.getMarketplaceToken(),
                    request.getLabId()
                );
            }
            if (isAccessAuthorized(bookingInfo)) {
                provisionalLease = provisionAuthorizedGuacamoleAccess(
                    bookingInfo, canonicalReservationKey, payerInstitutionWallet, request.getLabId(), puc, txHash
                );
            } else {
                validatePendingTransaction(txHash);
                provisionalLease = acquireProvisioningLease(canonicalReservationKey, txHash);
                blockchainService.provisionGuacamoleAccess(bookingInfo, false, provisionalLease.fencingToken());
                requireCurrentProvisioningLease(provisionalLease, txHash);
                if (!accessAuthorizationProvisioningService.markWaiting(provisionalLease)) {
                    throw provisioningLeaseLost(provisionalLease, txHash);
                }
                awaitAccessAuthorization(
                    payerInstitutionWallet, canonicalReservationKey, request.getLabId(), puc, bookingInfo, txHash, provisionalLease
                );
                requireCurrentProvisioningLease(provisionalLease, txHash);
                blockchainService.validateAccessAuthorizedReservation(
                    payerInstitutionWallet,
                    canonicalReservationKey,
                    request.getLabId(),
                    puc
                );
                blockchainService.activatePreparedGuacamoleAccess(bookingInfo, provisionalLease.fencingToken());
            }
            if (!accessAuthorizationProvisioningService.markActivated(provisionalLease)) {
                throw provisioningLeaseLost(provisionalLease, txHash);
            }
            bindFmuIdentity(bookingInfo, puc);
            JwtService.IssuedToken issuedToken = jwtService.generateIssuedToken(null, bookingInfo);
            SamlAuthRequest auditRequest = new SamlAuthRequest();
            auditRequest.setMarketplaceToken(request.getMarketplaceToken());
            auditRequest.setReservationKey(canonicalReservationKey);
            auditRequest.setLabId(request.getLabId());
            auditRequest.setTimestamp(System.currentTimeMillis() / 1000);
            AuthResponse response = accessCredentialDeliveryService.deliver(
                issuedToken, auditRequest, marketplaceJWTClaims, bookingInfo, provisionalLease
            );
            issuedAccessCode = response.getAccessCode();
            if (provisionalLease != null && !accessAuthorizationProvisioningService.markDelivered(provisionalLease)) {
                throw provisioningLeaseLost(provisionalLease, txHash);
            }
            return response;
        } catch (AccessAuthorizationPendingException ex) {
            accessCodeService.revoke(issuedAccessCode);
            rollbackPreparedGuacamoleAccess(bookingInfo, canonicalReservationKey, provisionalLease);
            throw ex;
        } catch (RuntimeException ex) {
            accessCodeService.revoke(issuedAccessCode);
            rollbackPreparedGuacamoleAccess(bookingInfo, canonicalReservationKey, provisionalLease);
            throw ex;
        } catch (Exception ex) {
            accessCodeService.revoke(issuedAccessCode);
            rollbackPreparedGuacamoleAccess(bookingInfo, canonicalReservationKey, provisionalLease);
            throw new IllegalStateException("Failed to issue access credential", ex);
        }
    }

    /**
     * Combined same-backend flow. The check-in is queued before the provider
     * prepares the Guacamole user and JWT, but neither credential nor ticket is
     * released until the contract exposes ACCESS_AUTHORIZED.
     */
    public AuthResponse authorizeAndIssue(SamlAuthRequest request) throws SamlAuthenticationException {
        String marketplaceToken = request.getMarketplaceToken();
        String samlAssertion = request.getSamlAssertion();
        auditSAMLAuthentication();
        if (marketplaceToken == null || marketplaceToken.isBlank()) {
            throw new IllegalArgumentException("Missing marketplaceToken");
        }
        if (samlAssertion == null || samlAssertion.isBlank()) {
            throw new IllegalArgumentException("Missing samlAssertion");
        }

        Map<String, Object> marketplaceJWTClaims = validateMarketplaceJWTBasic(marketplaceToken);
        Map<String, String> samlAttributes = validateSAMLAssertion(samlAssertion);
        String jwtPuc = stringClaim(marketplaceJWTClaims, "puc");
        String jwtAffiliation = stringClaim(marketplaceJWTClaims, "affiliation");
        String samlPuc = resolveSamlPucForMarketplaceToken(
            samlAttributes,
            stringClaim(marketplaceJWTClaims, "stableUserIdMode")
        );
        if (!Objects.equals(PucNormalizer.normalize(jwtPuc), PucNormalizer.normalize(samlPuc))
                || normalizeAffiliation(jwtAffiliation) == null
                || !normalizeAffiliation(jwtAffiliation).equals(normalizeAffiliation(samlAttributes.get("affiliation")))) {
            throw new SecurityException("JWT and SAML identity mismatch");
        }
        enforceBookingInfoEntitlement(marketplaceJWTClaims);
        enforceLabAccessPurpose(marketplaceJWTClaims);
        enforceClaimEquals(marketplaceJWTClaims, "reservationKey", request.getReservationKey());
        enforceClaimEquals(marketplaceJWTClaims, "labId", request.getLabId());

        String wallet = stringClaim(marketplaceJWTClaims, "payerInstitutionWallet");
        if (wallet == null || wallet.isBlank()) {
            throw new SecurityException("Marketplace token missing payerInstitutionWallet");
        }

        Map<String, Object> bookingInfo = null;
        AccessAuthorizationProvisioningService.ProvisioningLease provisionalLease = null;
        String issuedAccessCode = null;
        String canonicalReservationKey = request.getReservationKey();
        try {
            bookingInfo = blockchainService.getBookingInfoForCredentialPreparation(wallet, request.getReservationKey(), request.getLabId(), jwtPuc);
            canonicalReservationKey = reservationKeyFromBooking(bookingInfo, request.getReservationKey());
            if (canonicalReservationKey == null || canonicalReservationKey.isBlank()) {
                throw new IllegalArgumentException("Unable to resolve canonical reservationKey");
            }
            request.setReservationKey(canonicalReservationKey);
            AuthResponse recovered = isAccessAuthorized(bookingInfo)
                ? recoverDeliveredAccess(canonicalReservationKey) : null;
            if (recovered != null) {
                return recovered;
            }
            // Persist and immediately broadcast the payer-side authorization before the
            // remote Guacamole provisioning work. The access gate remains
            // ACCESS_AUTHORIZED; this only removes avoidable broadcast delay.
            InstitutionalAccessCheckInCoordinator.AccessGrantedResult checkInResult =
                accessCheckInCoordinator.recordAccessGranted(request, marketplaceJWTClaims, bookingInfo);
            if (checkInResult == InstitutionalAccessCheckInCoordinator.AccessGrantedResult.CONTEXT_MISMATCH) {
                throw new AccessAuthorizationContextMismatchException(
                    "Check-in transaction belongs to a different chain or signer",
                    canonicalReservationKey,
                    null
                );
            }
            if (checkInResult == InstitutionalAccessCheckInCoordinator.AccessGrantedResult.MANUAL_INTERVENTION) {
                throw new AccessAuthorizationManualInterventionException(
                    "Institutional check-in requires manual intervention",
                    canonicalReservationKey,
                    null
                );
            }
            if (checkInResult == InstitutionalAccessCheckInCoordinator.AccessGrantedResult.SIGNER_NOT_AUTHORIZED) {
                throw new AccessAuthorizationSignerNotAuthorizedException(
                    "Institutional check-in signer is not authorized for the payer institution",
                    canonicalReservationKey,
                    null
                );
            }
            if (checkInResult == InstitutionalAccessCheckInCoordinator.AccessGrantedResult.FAILED) {
                throw new AccessAuthorizationRejectedException(
                    "Institutional check-in publication failed permanently"
                );
            }
            if (isAccessAuthorized(bookingInfo)) {
                provisionalLease = provisionAuthorizedGuacamoleAccess(
                    bookingInfo, canonicalReservationKey, wallet, request.getLabId(), jwtPuc, null
                );
            } else {
                provisionalLease = acquireProvisioningLease(canonicalReservationKey, null);
                blockchainService.provisionGuacamoleAccess(bookingInfo, false, provisionalLease.fencingToken());
                requireCurrentProvisioningLease(provisionalLease, null);
                if (!accessAuthorizationProvisioningService.markWaiting(provisionalLease)) {
                    throw provisioningLeaseLost(provisionalLease, null);
                }
                awaitAccessAuthorization(
                    wallet, canonicalReservationKey, request.getLabId(), jwtPuc, bookingInfo, null, provisionalLease
                );
                requireCurrentProvisioningLease(provisionalLease, null);
                blockchainService.validateAccessAuthorizedReservation(
                    wallet,
                    canonicalReservationKey,
                    request.getLabId(),
                    jwtPuc
                );
                blockchainService.activatePreparedGuacamoleAccess(bookingInfo, provisionalLease.fencingToken());
            }
            if (!accessAuthorizationProvisioningService.markActivated(provisionalLease)) {
                throw provisioningLeaseLost(provisionalLease, null);
            }
            bindFmuIdentity(bookingInfo, jwtPuc);
            JwtService.IssuedToken issuedToken = jwtService.generateIssuedToken(null, bookingInfo);
            AuthResponse response = accessCredentialDeliveryService.deliver(
                issuedToken, request, marketplaceJWTClaims, bookingInfo, provisionalLease
            );
            issuedAccessCode = response.getAccessCode();
            if (provisionalLease != null && !accessAuthorizationProvisioningService.markDelivered(provisionalLease)) {
                throw provisioningLeaseLost(provisionalLease, null);
            }
            return response;
        } catch (RuntimeException ex) {
            accessCodeService.revoke(issuedAccessCode);
            rollbackPreparedGuacamoleAccess(bookingInfo, canonicalReservationKey, provisionalLease);
            throw ex;
        } catch (Exception ex) {
            accessCodeService.revoke(issuedAccessCode);
            rollbackPreparedGuacamoleAccess(bookingInfo, canonicalReservationKey, provisionalLease);
            throw new IllegalStateException("Failed to authorize and issue access credential", ex);
        }
    }

    private void awaitAccessAuthorization(
            String wallet,
            String reservationKey,
            String labId,
            String puc,
            Map<String, Object> preparedBookingInfo,
            String txHash,
            AccessAuthorizationProvisioningService.ProvisioningLease provisionalLease) {
        long timeoutMs = Math.max(0L, accessAuthorizationWaitTimeoutMs);
        long pollMs = Math.max(25L, accessAuthorizationPollIntervalMs);
        long deadlineNanos = System.nanoTime() + timeoutMs * 1_000_000L;

        while (true) {
            if (!accessAuthorizationProvisioningService.heartbeat(provisionalLease)) {
                throw provisioningLeaseLost(provisionalLease, txHash);
            }
            validatePendingTransaction(txHash);
            Map<String, Object> state = blockchainService.getAccessAuthorizationState(
                wallet,
                reservationKeyFromBooking(preparedBookingInfo, reservationKey),
                labId,
                puc
            );
            Object status = state.get("reservationStatus");
            if (status instanceof Number number && number.longValue() == 2L) {
                preparedBookingInfo.put("reservationStatus", status);
                return;
            }
            if (isTerminalReservationStatus(status)) {
                throw new AccessAuthorizationRejectedException(
                    "Reservation is no longer eligible for access authorization"
                );
            }
            if (System.nanoTime() >= deadlineNanos) {
                throw new AccessAuthorizationPendingException(
                    "Access authorization was not confirmed on-chain within " + timeoutMs + " ms",
                    reservationKey,
                    txHash
                );
            }
            try {
                Thread.sleep(Math.min(pollMs, Math.max(1L, (deadlineNanos - System.nanoTime()) / 1_000_000L)));
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Interrupted while waiting for access authorization", ex);
            }
        }
    }

    private boolean isAccessAuthorized(Map<String, Object> bookingInfo) {
        Object status = bookingInfo == null ? null : bookingInfo.get("reservationStatus");
        return status instanceof Number number && number.longValue() == 2L;
    }

    private boolean isTerminalReservationStatus(Object status) {
        if (!(status instanceof Number number)) {
            return false;
        }
        long value = number.longValue();
        return value == 3L || value == 4L;
    }

    private String reservationKeyFromBooking(Map<String, Object> bookingInfo, String fallback) {
        Object value = bookingInfo == null ? null : bookingInfo.get("reservationKey");
        return value == null || value.toString().isBlank() ? fallback : value.toString();
    }

    private void enforceConsumerCheckInState(
        String reservationKey,
        Map<String, Object> marketplaceClaims,
        String marketplaceToken,
        String labId
    ) {
        InstitutionalCheckInOutboxService.CheckInOutboxState state =
            institutionalCheckInOutboxService.findStateByReservationKeyIfConfigured(reservationKey);
        if (state != null && state.status() != null) {
            enforceTerminalConsumerCheckInState(reservationKey, state);
            return;
        }

        String affiliation = stringClaim(marketplaceClaims, "affiliation");
        if (affiliation == null || affiliation.isBlank()) {
            return;
        }
        String backendUrl = institutionalCheckInDirectoryService.resolveOrganizationBackendUrl(affiliation);
        if (backendUrl == null || backendUrl.isBlank()) {
            return;
        }
        InstitutionalCheckInStatusRequest statusRequest = new InstitutionalCheckInStatusRequest();
        statusRequest.setMarketplaceToken(marketplaceToken);
        statusRequest.setReservationKey(reservationKey);
        statusRequest.setLabId(labId);
        try {
            RemoteInstitutionalCheckInClient.RemoteCheckInResult remoteState =
                remoteInstitutionalCheckInClient.queryStatus(backendUrl, statusRequest);
            CheckInResponse remoteBody = remoteState == null ? null : remoteState.body();
            if (remoteBody == null || remoteBody.getReason() == null) {
                return;
            }
            String reason = remoteBody.getReason();
            if ("CHECKIN_CONTEXT_MISMATCH".equals(reason)) {
                throw new AccessAuthorizationContextMismatchException(
                    "Consumer institutional check-in belongs to a different chain or signer",
                    reservationKey,
                    remoteBody.getTxHash()
                );
            }
            if ("CHECKIN_MANUAL_INTERVENTION".equals(reason)) {
                throw new AccessAuthorizationManualInterventionException(
                    "Consumer institutional check-in requires manual intervention",
                    reservationKey,
                    remoteBody.getTxHash()
                );
            }
            if ("CHECKIN_FAILED".equals(reason) || "CHECKIN_SIGNER_NOT_AUTHORIZED".equals(reason)) {
                throw new AccessAuthorizationRejectedException(
                    "Consumer institutional check-in publication failed permanently"
                );
            }
        }
        catch (AccessAuthorizationContextMismatchException
            | AccessAuthorizationManualInterventionException
            | AccessAuthorizationRejectedException ex) {
            throw ex;
        } catch (RuntimeException ex) {
            log.debug("Remote consumer check-in status unavailable for {}", reservationKey, ex);
        }
    }

    private void enforceTerminalConsumerCheckInState(
        String reservationKey,
        InstitutionalCheckInOutboxService.CheckInOutboxState state
    ) {
        if ("MANUAL_INTERVENTION".equalsIgnoreCase(state.status())) {
            if (state.isContextMismatch()) {
                throw new AccessAuthorizationContextMismatchException(
                    "Consumer institutional check-in belongs to a different chain or signer",
                    reservationKey,
                    state.txHash()
                );
            }
            throw new AccessAuthorizationManualInterventionException(
                "Consumer institutional check-in requires manual intervention",
                reservationKey,
                state.txHash()
            );
        }
        if ("FAILED".equalsIgnoreCase(state.status()) || "MINED_FAILED".equalsIgnoreCase(state.status())) {
            throw new AccessAuthorizationRejectedException(
                "Consumer institutional check-in publication failed permanently"
            );
        }
    }

    private AccessAuthorizationProvisioningService.ProvisioningLease acquireProvisioningLease(String reservationKey, String txHash) {
        AccessAuthorizationProvisioningService.ProvisioningLease lease = accessAuthorizationProvisioningService.tryStart(reservationKey);
        if (lease != null) {
            return lease;
        }
        throw new AccessAuthorizationPendingException(
            "Access authorization provisioning is already in progress",
            reservationKey,
            txHash
        );
    }

    private void validatePendingTransaction(String txHash) {
        if (txHash == null || txHash.isBlank()) {
            return;
        }
        if (checkInOnChainService.transactionState(txHash) == CheckInOnChainService.TransactionState.FAILED) {
            throw new AccessAuthorizationRejectedException("Access authorization transaction reverted on-chain");
        }
    }

    private void requireCurrentProvisioningLease(
        AccessAuthorizationProvisioningService.ProvisioningLease lease,
        String txHash
    ) {
        if (!accessAuthorizationProvisioningService.isCurrent(lease)) {
            throw provisioningLeaseLost(lease, txHash);
        }
    }

    private AuthResponse recoverDeliveredAccess(String reservationKey) {
        var provisioning = accessAuthorizationProvisioningService.recoverableProvisioning(reservationKey);
        if (provisioning == null) return null;
        var delivery = accessCodeService.recoverDelivery(reservationKey, provisioning.generation());
        if (delivery == null) {
            accessAuthorizationProvisioningService.revokeExpiredDelivery(
                reservationKey, provisioning.generation()
            );
            return null;
        }
        if (!accessAuthorizationProvisioningService.promoteRecoveredDelivery(
            reservationKey, provisioning.generation()
        )) {
            throw new AccessAuthorizationPendingException(
                "Access delivery recovery lost its provisioning generation", reservationKey, null
            );
        }
        return AuthResponse.opaqueAccess(
            delivery.getAccessCode(), delivery.getLabURL(), delivery.getResourceType(), reservationKey
        );
    }

    /**
     * ACCESS_AUTHORIZED can be observed while a former request is still
     * cleaning up a provisional user. Use the same fenced lease in this fast
     * path so the two requests never share a Guacamole identity.
     */
    private AccessAuthorizationProvisioningService.ProvisioningLease provisionAuthorizedGuacamoleAccess(
        Map<String, Object> bookingInfo,
        String reservationKey,
        String wallet,
        String labId,
        String puc,
        String txHash
    ) {
        if (!"lab".equals(bookingInfo.get("resourceType"))) {
            AccessAuthorizationProvisioningService.ProvisioningLease lease = acquireProvisioningLease(reservationKey, txHash);
            blockchainService.provisionGuacamoleAccess(bookingInfo);
            return lease;
        }
        AccessAuthorizationProvisioningService.ProvisioningLease lease = acquireProvisioningLease(reservationKey, txHash);
        blockchainService.provisionGuacamoleAccess(bookingInfo, false, lease.fencingToken());
        requireCurrentProvisioningLease(lease, txHash);
        blockchainService.validateAccessAuthorizedReservation(
            wallet,
            reservationKeyFromBooking(bookingInfo, reservationKey),
            labId,
            puc
        );
        if (!accessAuthorizationProvisioningService.heartbeat(lease)) {
            throw provisioningLeaseLost(lease, txHash);
        }
        blockchainService.activatePreparedGuacamoleAccess(bookingInfo, lease.fencingToken());
        return lease;
    }

    private AccessAuthorizationPendingException provisioningLeaseLost(
        AccessAuthorizationProvisioningService.ProvisioningLease lease,
        String txHash
    ) {
        return new AccessAuthorizationPendingException(
            "Access authorization provisioning lease was superseded",
            lease.reservationKey(),
            txHash
        );
    }

    private void rollbackPreparedGuacamoleAccess(
        Map<String, Object> bookingInfo,
        String reservationKey,
        AccessAuthorizationProvisioningService.ProvisioningLease provisionalLease
    ) {
        if (bookingInfo == null || !"lab".equals(bookingInfo.get("resourceType"))) {
            if (provisionalLease != null) {
                accessAuthorizationProvisioningService.markFailed(provisionalLease);
            }
            return;
        }
        try {
            if (provisionalLease != null && !accessAuthorizationProvisioningService.beginRollback(provisionalLease)) {
                return;
            }
            blockchainService.deletePreparedGuacamoleAccess(bookingInfo);
            if (provisionalLease != null) {
                accessAuthorizationProvisioningService.markRolledBack(provisionalLease);
            }
        } catch (RuntimeException cleanupError) {
            if (provisionalLease != null) {
                accessAuthorizationProvisioningService.markFailed(provisionalLease);
            }
            log.error("Failed to clean up the unissued Guacamole user", cleanupError);
        }
    }

    private Map<String, Object> validateMarketplaceJWTBasic(String marketplaceToken) {
        try {
            return marketplaceEndpointAuthService.enforceToken(marketplaceToken, null);
        } catch (ResponseStatusException e) {
            log.error("Marketplace JWT validation failed: {}", LogSanitizer.sanitize(e.getReason()), e);
            throw new SecurityException("Invalid marketplace token: " + e.getReason(), e);
        } catch (Exception e) {
            log.error("Marketplace JWT validation failed: {}", LogSanitizer.sanitize(e.getMessage()), e);
            throw new SecurityException("Invalid marketplace token: " + e.getMessage(), e);
        }
    }

    private Map<String, String> validateSAMLAssertion(String samlAssertion) throws SamlAuthenticationException {
        try {
            Map<String, String> attributes = samlValidationService.validateSamlAssertionWithSignature(samlAssertion);
            log.info("SAML assertion validated WITH SIGNATURE.");
            return attributes;
        } catch (Exception e) {
            String errorMessage = e.getMessage();
            if (errorMessage != null) {
                if (errorMessage.contains("expired") || errorMessage.contains("not valid")) {
                    throw new SamlExpiredAssertionException("SAML assertion has expired: " + errorMessage, e);
                }
                if (errorMessage.contains("not in trusted list") || errorMessage.contains("unknown-idp")) {
                    throw new SamlInvalidIssuerException("Issuer not trusted: " + errorMessage, e);
                }
                if (errorMessage.contains("signature is INVALID") || errorMessage.contains("Could not validate")) {
                    throw new SamlMalformedResponseException("Invalid SAML response format: " + errorMessage, e);
                }
                if (errorMessage.contains("missing")
                    && (errorMessage.contains("PUC") || errorMessage.contains("puc") || errorMessage.contains("affiliation"))) {
                    throw new SamlMissingAttributesException(
                        "SAML assertion missing required attributes: " + errorMessage,
                        e
                    );
                }
                if (errorMessage.contains("replay") || errorMessage.contains("already used")) {
                    throw new SamlReplayAttackException(
                        "SAML assertion already used (replay attack detected): " + errorMessage,
                        e
                    );
                }
                if (errorMessage.contains("unavailable") || errorMessage.contains("Could not retrieve")) {
                    throw new SamlServiceUnavailableException(
                        "IdP metadata service unavailable: " + errorMessage,
                        e
                    );
                }
            }
            throw new SamlMalformedResponseException("Invalid SAML response format: " + errorMessage, e);
        }
    }

    private String resolveSamlPucForMarketplaceToken(
        Map<String, String> samlAttributes,
        String stableUserIdMode
    ) {
        if (stableUserIdMode == null || stableUserIdMode.isBlank()) {
            return samlAttributes == null ? null : samlAttributes.get("puc");
        }
        return samlValidationService.resolveStableUserId(samlAttributes, stableUserIdMode, null);
    }

    private void auditSAMLAuthentication() {
        log.info("SAML Authentication attempt recorded");
    }

    private void enforceBookingInfoEntitlement(Map<String, Object> marketplaceClaims) {
        if (!requireBookingScope) {
            return;
        }
        if (Boolean.TRUE.equals(marketplaceClaims.get("bookingInfoAllowed"))) {
            return;
        }
        Object scopeClaim = marketplaceClaims.getOrDefault("scope", marketplaceClaims.get("scopes"));
        if (scopeClaim != null && scopeContainsRequiredScope(scopeClaim)) {
            return;
        }
        log.warn("Booking info request denied - missing required scope");
        throw new SecurityException(
            "Marketplace token missing required scope '" + requiredBookingScope + "' for booking info"
        );
    }

    private void validateProviderAccessCredentialRequest(ProviderAccessCredentialRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Missing request");
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

    private void enforceLabAccessPurpose(Map<String, Object> marketplaceClaims) {
        String purpose = stringClaim(marketplaceClaims, "purpose");
        if (!"lab_access".equals(purpose)) {
            throw new SecurityException("Marketplace token purpose is not lab_access");
        }
    }

    private void enforceClaimEquals(Map<String, Object> marketplaceClaims, String claim, String expected) {
        if (expected == null || expected.isBlank()) {
            return;
        }
        String value = stringClaim(marketplaceClaims, claim);
        if (value == null || !expected.equals(value)) {
            throw new SecurityException("Marketplace token " + claim + " mismatch");
        }
    }

    private String stringClaim(Map<String, Object> claims, String key) {
        if (claims == null || key == null || !claims.containsKey(key)) {
            return null;
        }
        Object value = claims.get(key);
        return value == null ? null : value.toString();
    }

    private void bindFmuIdentity(Map<String, Object> bookingInfo, String puc) {
        if (bookingInfo == null || !"fmu".equalsIgnoreCase(String.valueOf(bookingInfo.get("resourceType")))) {
            return;
        }
        String normalizedPuc = PucNormalizer.normalize(puc);
        if (normalizedPuc == null || normalizedPuc.isBlank()) {
            throw new SecurityException("FMU credential requires an institutional user identity");
        }
        String pucHash = PucHashUtil.hashPuc(normalizedPuc);
        bookingInfo.put("pucHash", pucHash);
        bookingInfo.put("sub", "fmu-user:" + pucHash);
    }

    private boolean scopeContainsRequiredScope(Object scopeClaim) {
        if (scopeClaim instanceof String scopeText) {
            return Stream.of(scopeText.split("[\\s,]+"))
                .anyMatch(token -> token.equals(requiredBookingScope));
        }
        if (scopeClaim instanceof Collection<?> collection) {
            return collection.stream()
                .filter(Objects::nonNull)
                .map(token -> token.toString())
                .anyMatch(token -> token.equals(requiredBookingScope));
        }
        return false;
    }

    private String normalizeAffiliation(String affiliation) {
        if (affiliation == null || affiliation.isBlank()) {
            return null;
        }
        String normalized = affiliation.trim().toLowerCase();
        if (normalized.contains("@")) {
            String[] parts = normalized.split("@");
            if (parts.length == 2) {
                return parts[1];
            }
        }
        return normalized;
    }
}
