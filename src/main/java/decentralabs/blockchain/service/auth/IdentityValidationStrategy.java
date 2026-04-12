package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.dto.identity.IdentityEvidenceDTO;
import decentralabs.blockchain.dto.identity.ValidatedIdentity;

/**
 * Strategy interface for evidence validation.
 */
public interface IdentityValidationStrategy {
    boolean supports(String type);

    ValidatedIdentity validate(IdentityEvidenceDTO evidence);
}
