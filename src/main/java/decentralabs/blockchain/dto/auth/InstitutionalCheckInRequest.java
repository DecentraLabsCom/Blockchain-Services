package decentralabs.blockchain.dto.auth;

import decentralabs.blockchain.dto.identity.IdentityEvidenceDTO;
import decentralabs.blockchain.dto.identity.NormalizedClaims;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class InstitutionalCheckInRequest {
    private String marketplaceToken;
    // XXX: Legacy SAML assertion kept for compatibility while Marketplace transitions.
    private String samlAssertion;
    private IdentityEvidenceDTO identityEvidence;
    private NormalizedClaims normalizedClaims;
    private String evidenceHash;
    private String reservationKey;
    private String labId;
    private String institutionalProviderWallet;
    private String puc;
}
