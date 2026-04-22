package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.dto.auth.AuthResponse;
import decentralabs.blockchain.dto.auth.SamlAuthRequest;
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

    @Value("${auth.saml.require-booking-scope:true}")
    private boolean requireBookingScope;

    @Value("${auth.saml.required-booking-scope:booking:read}")
    private String requiredBookingScope;

    public AuthResponse handleAuthentication(SamlAuthRequest request, boolean includeBookingInfo)
            throws SamlAuthenticationException {
        String marketplaceToken = request.getMarketplaceToken();
        String samlAssertion = request.getSamlAssertion();

        auditSAMLAuthentication();

        if (marketplaceToken == null || marketplaceToken.isEmpty()) {
            throw new IllegalArgumentException("Missing marketplaceToken");
        }
        if (samlAssertion == null || samlAssertion.isEmpty()) {
            throw new IllegalArgumentException("Missing samlAssertion");
        }

        Map<String, Object> marketplaceJWTClaims = validateMarketplaceJWTBasic(marketplaceToken);
        Map<String, String> samlAttributes = validateSAMLAssertion(samlAssertion);

        String jwtUserId = (String) marketplaceJWTClaims.get("userid");
        String jwtAffiliation = (String) marketplaceJWTClaims.get("affiliation");
        String samlUserId = samlAttributes.get("userid");
        String samlAffiliation = samlAttributes.get("affiliation");

        String normalizedJwtUserId = PucNormalizer.normalize(jwtUserId);
        String normalizedSamlUserId = PucNormalizer.normalize(samlUserId);
        if (normalizedJwtUserId == null || !normalizedJwtUserId.equals(normalizedSamlUserId)) {
            throw new SecurityException("JWT and SAML userid mismatch");
        }

        String normalizedJwtAffiliation = normalizeAffiliation(jwtAffiliation);
        String normalizedSamlAffiliation = normalizeAffiliation(samlAffiliation);
        if (normalizedJwtAffiliation == null || !normalizedJwtAffiliation.equals(normalizedSamlAffiliation)) {
            throw new SecurityException("JWT and SAML affiliation mismatch");
        }

        enforceBookingInfoAccess(includeBookingInfo, marketplaceJWTClaims, jwtUserId);
        if (includeBookingInfo) {
            return buildBookingInfoResponse(
                marketplaceJWTClaims,
                request.getReservationKey(),
                request.getLabId()
            );
        }
        return buildJwtOnlyResponse(jwtUserId, jwtAffiliation);
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
                    && (errorMessage.contains("userid") || errorMessage.contains("affiliation"))) {
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

    private AuthResponse buildBookingInfoResponse(
        Map<String, Object> marketplaceJWTClaims,
        String reservationKey,
        String labId
    ) {
        try {
            String institutionalProviderWallet = (String) marketplaceJWTClaims.get("institutionalProviderWallet");
            String puc = (String) marketplaceJWTClaims.get("puc");
            Map<String, Object> bookingInfo = blockchainService.getBookingInfo(
                institutionalProviderWallet,
                reservationKey,
                labId,
                puc
            );
            String token = jwtService.generateToken(null, bookingInfo);
            return new AuthResponse(token, (String) bookingInfo.get("labURL"));
        } catch (RuntimeException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to generate booking authentication token", ex);
        }
    }

    private AuthResponse buildJwtOnlyResponse(String jwtUserId, String jwtAffiliation) {
        try {
            Map<String, Object> claims = Map.of(
                "userid", jwtUserId,
                "affiliation", jwtAffiliation
            );
            String token = jwtService.generateToken(claims, null);
            return new AuthResponse(token);
        } catch (RuntimeException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to generate SAML authentication token", ex);
        }
    }

    private void auditSAMLAuthentication() {
        log.info("SAML Authentication attempt recorded");
    }

    private void enforceBookingInfoEntitlement(Map<String, Object> marketplaceClaims, String userId) {
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

    private void enforceBookingInfoAccess(
        boolean bookingInfoRequested,
        Map<String, Object> marketplaceClaims,
        String userId
    ) {
        if (!bookingInfoRequested) {
            return;
        }
        enforceBookingInfoEntitlement(marketplaceClaims, userId);
    }

    private boolean scopeContainsRequiredScope(Object scopeClaim) {
        if (scopeClaim instanceof String scopeText) {
            return Stream.of(scopeText.split("[\\s,]+"))
                .anyMatch(token -> token.equals(requiredBookingScope));
        }
        if (scopeClaim instanceof Collection<?> collection) {
            return collection.stream()
                .filter(Objects::nonNull)
                .map(Object::toString)
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
