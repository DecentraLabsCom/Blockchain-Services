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
 * Minimal VC validator scaffold for the transition period.
 */
@Service
@RequiredArgsConstructor
public class VcValidationService implements IdentityValidationStrategy {

    private final IdentityEvidenceHashService hashService;

    @Override
    public boolean supports(String type) {
        return "openid4vp".equalsIgnoreCase(type)
            || "sd-jwt-vc".equalsIgnoreCase(type)
            || "mso_mdoc".equalsIgnoreCase(type);
    }

    @Override
    public ValidatedIdentity validate(IdentityEvidenceDTO evidence) {
        if (evidence == null) {
            throw new IllegalArgumentException("Missing identity evidence");
        }
        if (!supports(evidence.type())) {
            throw new IllegalArgumentException("Unsupported identity evidence type: " + evidence.type());
        }

        NormalizedClaims claims = evidence.normalizedClaims();
        if (claims == null) {
            throw new IllegalArgumentException("VC evidence missing normalized claims");
        }

        IdentityEvidenceMetadata metadata = new IdentityEvidenceMetadata(
            evidence.issuer(),
            evidence.issuedAt() != null ? evidence.issuedAt() : Instant.now(),
            evidence.expiresAt(),
            evidence.nonce(),
            evidence.audience() != null ? List.copyOf(evidence.audience()) : null,
            true,
            evidence.format()
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
