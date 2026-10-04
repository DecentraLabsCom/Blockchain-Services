package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.dto.auth.IdentitySessionRequest;
import decentralabs.blockchain.dto.auth.InstitutionalSessionResponse;
import decentralabs.blockchain.service.accesspolicy.InstitutionalIdentityContextPersistenceService;
import java.util.Locale;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/**
 * Converts a signed Marketplace identity envelope into a backend-owned
 * institutional session credential. External provider claims are never trusted
 * directly by downstream intent or access services.
 */
@Service
public class InstitutionalIdentitySessionService {

    private final InstitutionalSessionCredentialService credentialService;
    private final ExternalOidcTokenValidationService externalOidcTokenValidationService;
    private InstitutionalIdentityContextPersistenceService identityContextPersistenceService;

    public InstitutionalIdentitySessionService(InstitutionalSessionCredentialService credentialService) {
        this(credentialService, null);
    }

    @org.springframework.beans.factory.annotation.Autowired
    public InstitutionalIdentitySessionService(
        InstitutionalSessionCredentialService credentialService,
        ExternalOidcTokenValidationService externalOidcTokenValidationService
    ) {
        this.credentialService = credentialService;
        this.externalOidcTokenValidationService = externalOidcTokenValidationService;
    }

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setIdentityContextPersistenceService(InstitutionalIdentityContextPersistenceService service) {
        this.identityContextPersistenceService = service;
    }

    public InstitutionalSessionResponse create(
        IdentitySessionRequest request,
        Map<String, Object> marketplaceClaims,
        boolean marketplaceBindingRequired
    ) {
        try {
            String protocol = requiredClaim(marketplaceClaims, "identityProtocol").toLowerCase(Locale.ROOT);
            if (!SetSupport.IDENTITY_PROTOCOLS.contains(protocol)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "unsupported_identity_protocol");
            }
            String provider = requiredClaim(marketplaceClaims, "identityProvider").toLowerCase(Locale.ROOT);
            String issuer = requiredClaim(marketplaceClaims, "identityIssuer");
            String subject = requiredClaim(marketplaceClaims, "identitySubject");
            String stableUserId = requiredClaimOrFallback(marketplaceClaims, "stableUserId", "puc");
            String evidenceHash = requiredClaim(marketplaceClaims, "identityEvidenceHash");
            String evidenceHashVersion = requiredClaim(marketplaceClaims, "identityEvidenceHashVersion");
            String identityNonce = requiredClaim(marketplaceClaims, "identityNonce");
            if ("oidc".equals(protocol)
                && !InstitutionalSessionCredentialService.OIDC_ID_TOKEN_HASH_VERSION.equals(evidenceHashVersion)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "unsupported_identity_evidence_hash_version");
            }
            String institutionId = normalizeInstitution(requiredClaimOrFallback(
                marketplaceClaims,
                "affiliation",
                "institutionId"
            ));
            String marketplacePuc = requiredClaimOrFallback(marketplaceClaims, "puc", "stableUserId");
            if (marketplaceBindingRequired && !marketplacePuc.equals(stableUserId)) {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "institutional_identity_mismatch");
            }

            ExternalOidcTokenValidationService.ValidatedToken validatedExternalToken = null;
            if ("oidc".equals(protocol)) {
                String externalIdToken = request == null ? null : request.getExternalIdToken();
                if (externalOidcTokenValidationService == null || externalIdToken == null || externalIdToken.isBlank()) {
                    throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "external_oidc_token_required");
                }
                validatedExternalToken = externalOidcTokenValidationService.validate(
                    provider,
                    externalIdToken,
                    issuer,
                    subject,
                    evidenceHash,
                    identityNonce
                );
            }

            String stableUserIdMode = request != null && request.getStableUserIdMode() != null
                && !request.getStableUserIdMode().isBlank()
                ? request.getStableUserIdMode().trim()
                : requiredClaimOrFallback(marketplaceClaims, "stableUserIdMode", "identityProtocol");

            var issued = credentialService.issueIdentity(
                institutionId,
                stableUserId,
                stableUserIdMode,
                protocol,
                provider,
                issuer,
                subject,
                evidenceHash,
                evidenceHashVersion
            );
            if (validatedExternalToken != null && identityContextPersistenceService != null) {
                identityContextPersistenceService.upsertOidc(
                    institutionId,
                    stableUserId,
                    provider,
                    validatedExternalToken.issuer(),
                    validatedExternalToken.claims(),
                    issued.expiresAt()
                );
            }
            return InstitutionalSessionResponse.builder()
                .sessionToken(issued.token())
                .expiresAt(issued.expiresAt())
                .reauthenticationAt(issued.expiresAt())
                .samlAssertionHash(issued.samlAssertionHash())
                .samlAssertionHashVersion(issued.samlAssertionHashVersion())
                .identityProtocol(issued.identityProtocol())
                .identityProvider(issued.identityProvider())
                .identityIssuer(issued.identityIssuer())
                .identitySubject(issued.identitySubject())
                .identityEvidenceHash(issued.identityEvidenceHash())
                .identityEvidenceHashVersion(issued.identityEvidenceHashVersion())
                .build();
        } catch (ResponseStatusException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_identity_evidence", ex);
        }
    }

    private String requiredClaimOrFallback(Map<String, Object> claims, String primary, String fallback) {
        String value = textClaim(claims, primary);
        return value == null ? requiredClaim(claims, fallback) : value;
    }

    private String requiredClaim(Map<String, Object> claims, String name) {
        String value = textClaim(claims, name);
        if (value == null) {
            String reason = "identityEvidenceHash".equals(name)
                ? "missing_identity_evidence_hash"
                : "missing_" + name;
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, reason);
        }
        return value;
    }

    private String textClaim(Map<String, Object> claims, String name) {
        Object value = claims == null ? null : claims.get(name);
        if (value == null) return null;
        String text = String.valueOf(value).trim();
        return text.isBlank() ? null : text;
    }

    private String normalizeInstitution(String value) {
        String normalized = value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
        if (!normalized.matches("[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_institution_id");
        }
        return normalized;
    }

    private static final class SetSupport {
        // VC credentials remain a reserved credential format until a concrete
        // EBSI/EUDI proof verifier is enabled at this boundary.
        private static final java.util.Set<String> IDENTITY_PROTOCOLS = java.util.Set.of("oidc");

        private SetSupport() {}
    }
}
