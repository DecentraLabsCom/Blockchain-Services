package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.dto.auth.InstitutionalSessionRequest;
import decentralabs.blockchain.dto.auth.InstitutionalSessionResponse;
import decentralabs.blockchain.util.PucHashUtil;
import decentralabs.blockchain.util.PucNormalizer;
import java.util.Map;
import java.util.Objects;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
public class InstitutionalSamlSessionService {

    private final SamlValidationService samlValidationService;
    private final InstitutionalSessionCredentialService credentialService;

    public InstitutionalSessionResponse create(
        InstitutionalSessionRequest request,
        Map<String, Object> marketplaceClaims,
        boolean marketplaceBindingRequired
    ) {
        try {
            SamlAssertionAttributes validated = samlValidationService
                .validateSamlAssertionDetailed(request.getSamlAssertion());
            Map<String, String> attributes = samlValidationService.toIdentityAttributeMap(validated);
            String marketplacePuc = marketplaceBindingRequired
                ? requireMarketplacePuc(marketplaceClaims)
                : null;
            String stableUserId = PucNormalizer.normalize(samlValidationService.resolveStableUserId(
                attributes,
                request.getStableUserIdMode(),
                marketplacePuc == null ? null : PucHashUtil.hashPuc(marketplacePuc)
            ));
            String institutionId = marketplaceBindingRequired
                ? requireMatchingInstitution(
                    stringClaim(marketplaceClaims, "affiliation"),
                    attributes.get("affiliation")
                )
                : requireSamlInstitution(attributes.get("affiliation"));
            if (marketplaceBindingRequired && !Objects.equals(marketplacePuc, stableUserId)) {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "institutional_identity_mismatch");
            }

            var issued = credentialService.issue(
                institutionId,
                stableUserId,
                request.getStableUserIdMode(),
                validated.assertionHash(),
                validated.assertionHashVersion()
            );
            return InstitutionalSessionResponse.builder()
                .sessionToken(issued.token())
                .expiresAt(issued.expiresAt())
                .reauthenticationAt(issued.expiresAt())
                .samlAssertionHash(issued.samlAssertionHash())
                .samlAssertionHashVersion(issued.samlAssertionHashVersion())
                .build();
        } catch (ResponseStatusException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_saml", ex);
        }
    }

    private String requireMarketplacePuc(Map<String, Object> marketplaceClaims) {
        String puc = PucNormalizer.normalize(stringClaim(marketplaceClaims, "puc"));
        if (puc == null || puc.isBlank()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "institutional_identity_mismatch");
        }
        return puc;
    }

    private String requireMatchingInstitution(String marketplaceInstitution, String samlInstitution) {
        String marketplace = normalizeInstitution(marketplaceInstitution);
        String saml = normalizeInstitution(samlInstitution);
        if (marketplace == null || saml == null || !marketplace.equals(saml)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "institutional_identity_mismatch");
        }
        return marketplace;
    }

    private String requireSamlInstitution(String samlInstitution) {
        String saml = normalizeInstitution(samlInstitution);
        if (saml == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_saml");
        }
        return saml;
    }

    private String normalizeInstitution(String value) {
        if (value == null || value.isBlank()) return null;
        return value.trim().toLowerCase();
    }

    private String stringClaim(Map<String, Object> claims, String key) {
        Object value = claims == null ? null : claims.get(key);
        return value == null ? null : String.valueOf(value).trim();
    }
}
