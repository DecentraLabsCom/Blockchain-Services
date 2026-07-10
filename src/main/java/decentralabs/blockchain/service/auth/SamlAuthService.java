package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.dto.auth.AuthResponse;
import decentralabs.blockchain.dto.auth.ProviderAccessCredentialRequest;
import decentralabs.blockchain.dto.auth.SamlAuthRequest;
import decentralabs.blockchain.exception.AccessAuthorizationPendingException;
import decentralabs.blockchain.exception.AccessAuthorizationRejectedException;
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
    private final AccessCredentialAuditService accessCredentialAuditService;
    private final AccessAuthorizationProvisioningService accessAuthorizationProvisioningService;
    private final CheckInOnChainService checkInOnChainService;

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
        boolean provisionalLease = false;
        try {
            bookingInfo = blockchainService.getBookingInfoForCredentialPreparation(
                payerInstitutionWallet,
                request.getReservationKey(),
                request.getLabId(),
                stringClaim(marketplaceJWTClaims, "puc")
            );
            String puc = stringClaim(marketplaceJWTClaims, "puc");
            String txHash = request.getAccessAuthorizationTxHash();
            if (isAccessAuthorized(bookingInfo)) {
                blockchainService.provisionGuacamoleAccess(bookingInfo);
            } else {
                validatePendingTransaction(txHash);
                provisionalLease = acquireProvisioningLease(request.getReservationKey(), txHash);
                blockchainService.provisionGuacamoleAccess(bookingInfo, false);
                accessAuthorizationProvisioningService.markWaiting(request.getReservationKey());
                awaitAccessAuthorization(payerInstitutionWallet, request.getReservationKey(), request.getLabId(), puc, bookingInfo, txHash);
                blockchainService.validateAccessAuthorizedReservation(
                    payerInstitutionWallet,
                    reservationKeyFromBooking(bookingInfo, request.getReservationKey()),
                    request.getLabId(),
                    puc
                );
                blockchainService.activatePreparedGuacamoleAccess(bookingInfo);
            }
            JwtService.IssuedToken issuedToken = jwtService.generateIssuedToken(null, bookingInfo);
            SamlAuthRequest auditRequest = new SamlAuthRequest();
            auditRequest.setMarketplaceToken(request.getMarketplaceToken());
            auditRequest.setReservationKey(request.getReservationKey());
            auditRequest.setLabId(request.getLabId());
            auditRequest.setTimestamp(System.currentTimeMillis() / 1000);
            accessCredentialAuditService.recordJwtIssued(auditRequest, marketplaceJWTClaims, bookingInfo, issuedToken);
            if (provisionalLease) {
                accessAuthorizationProvisioningService.markDelivered(request.getReservationKey());
            }
            return new AuthResponse(issuedToken.token(), (String) bookingInfo.get("labURL"));
        } catch (AccessAuthorizationPendingException ex) {
            rollbackPreparedGuacamoleAccess(bookingInfo, request.getReservationKey(), provisionalLease);
            throw ex;
        } catch (RuntimeException ex) {
            rollbackPreparedGuacamoleAccess(bookingInfo, request.getReservationKey(), provisionalLease);
            throw ex;
        } catch (Exception ex) {
            rollbackPreparedGuacamoleAccess(bookingInfo, request.getReservationKey(), provisionalLease);
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
        boolean provisionalLease = false;
        try {
            bookingInfo = blockchainService.getBookingInfoForCredentialPreparation(wallet, request.getReservationKey(), request.getLabId(), jwtPuc);
            if (isAccessAuthorized(bookingInfo)) {
                blockchainService.provisionGuacamoleAccess(bookingInfo);
            } else {
                provisionalLease = acquireProvisioningLease(request.getReservationKey(), null);
                blockchainService.provisionGuacamoleAccess(bookingInfo, false);
                accessCheckInCoordinator.recordAccessGranted(request, marketplaceJWTClaims, bookingInfo);
                accessAuthorizationProvisioningService.markWaiting(request.getReservationKey());
                awaitAccessAuthorization(wallet, request.getReservationKey(), request.getLabId(), jwtPuc, bookingInfo, null);
                blockchainService.validateAccessAuthorizedReservation(
                    wallet,
                    reservationKeyFromBooking(bookingInfo, request.getReservationKey()),
                    request.getLabId(),
                    jwtPuc
                );
                blockchainService.activatePreparedGuacamoleAccess(bookingInfo);
            }
            JwtService.IssuedToken issuedToken = jwtService.generateIssuedToken(null, bookingInfo);
            accessCredentialAuditService.recordJwtIssued(request, marketplaceJWTClaims, bookingInfo, issuedToken);
            if (provisionalLease) {
                accessAuthorizationProvisioningService.markDelivered(request.getReservationKey());
            }
            return new AuthResponse(issuedToken.token(), (String) bookingInfo.get("labURL"));
        } catch (RuntimeException ex) {
            rollbackPreparedGuacamoleAccess(bookingInfo, request.getReservationKey(), provisionalLease);
            throw ex;
        } catch (Exception ex) {
            rollbackPreparedGuacamoleAccess(bookingInfo, request.getReservationKey(), provisionalLease);
            throw new IllegalStateException("Failed to authorize and issue access credential", ex);
        }
    }

    private void awaitAccessAuthorization(
            String wallet,
            String reservationKey,
            String labId,
            String puc,
            Map<String, Object> preparedBookingInfo,
            String txHash) {
        long timeoutMs = Math.max(0L, accessAuthorizationWaitTimeoutMs);
        long pollMs = Math.max(25L, accessAuthorizationPollIntervalMs);
        long deadlineNanos = System.nanoTime() + timeoutMs * 1_000_000L;

        while (true) {
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

    private boolean acquireProvisioningLease(String reservationKey, String txHash) {
        if (accessAuthorizationProvisioningService.tryStart(reservationKey)) {
            return true;
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

    private void rollbackPreparedGuacamoleAccess(Map<String, Object> bookingInfo, String reservationKey, boolean provisionalLease) {
        if (bookingInfo == null || !"lab".equals(bookingInfo.get("resourceType"))) {
            if (provisionalLease) {
                accessAuthorizationProvisioningService.markFailed(reservationKey);
            }
            return;
        }
        try {
            blockchainService.deletePreparedGuacamoleAccess(bookingInfo);
            if (provisionalLease) {
                accessAuthorizationProvisioningService.markRolledBack(reservationKey);
            }
        } catch (RuntimeException cleanupError) {
            if (provisionalLease) {
                accessAuthorizationProvisioningService.markFailed(reservationKey);
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
