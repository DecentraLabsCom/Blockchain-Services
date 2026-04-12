package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.dto.identity.IdentityEvidenceDTO;
import decentralabs.blockchain.dto.identity.IdentityEvidenceMetadata;
import decentralabs.blockchain.dto.identity.NormalizedClaims;
import decentralabs.blockchain.dto.identity.ValidatedIdentity;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * Adapts legacy SAML validation to the unified identity envelope.
 */
@Service
@RequiredArgsConstructor
public class SamlEvidenceValidationService implements IdentityValidationStrategy {

    private final SamlValidationService samlValidationService;
    private final IdentityEvidenceHashService hashService;

    @Override
    public boolean supports(String type) {
        return "saml".equalsIgnoreCase(type);
    }

    @Override
    public ValidatedIdentity validate(IdentityEvidenceDTO evidence) {
        if (evidence == null) {
            throw new IllegalArgumentException("Missing identity evidence");
        }
        if (evidence.rawEvidence() == null || evidence.rawEvidence().isBlank()) {
            throw new IllegalArgumentException("Missing raw SAML evidence");
        }

        Map<String, String> samlAttributes;
        try {
            samlAttributes = samlValidationService.validateSamlAssertionWithSignature(evidence.rawEvidence());
        } catch (Exception ex) {
            throw new IllegalArgumentException("Invalid SAML evidence: " + ex.getMessage(), ex);
        }

        NormalizedClaims claims = evidence.normalizedClaims() != null
            ? evidence.normalizedClaims()
            : new NormalizedClaims(
                samlAttributes.get("userid"),
                samlAttributes.get("affiliation"),
                samlAttributes.get("role"),
                samlAttributes.get("scopedRole"),
                samlAttributes.get("puc"),
                samlAttributes.get("email"),
                samlAttributes.get("name")
            );

        IdentityEvidenceMetadata metadata = new IdentityEvidenceMetadata(
            evidence.issuer() != null ? evidence.issuer() : samlAttributes.get("issuer"),
            evidence.issuedAt() != null ? evidence.issuedAt() : Instant.now(),
            evidence.expiresAt(),
            evidence.nonce(),
            evidence.audience() != null ? List.copyOf(evidence.audience()) : null,
            true,
            evidence.format() != null ? evidence.format() : "saml2-base64"
        );

        String evidenceHash = evidence.evidenceHash();
        if (evidenceHash == null || evidenceHash.isBlank()) {
            evidenceHash = hashService.computeCanonicalHash(Map.of(
                "type", evidence.type(),
                "format", evidence.format(),
                "claims", claims,
                "metadata", metadata
            ));
        }

        return new ValidatedIdentity(
            evidence.type(),
            evidence.format(),
            claims,
            metadata,
            evidenceHash
        );
    }
}
