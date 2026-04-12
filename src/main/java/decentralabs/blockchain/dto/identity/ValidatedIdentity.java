package decentralabs.blockchain.dto.identity;

import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.Builder;

/**
 * Validated identity state ready for business checks.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@Builder(toBuilder = true)
public record ValidatedIdentity(
    String type,
    String format,
    NormalizedClaims claims,
    IdentityEvidenceMetadata metadata,
    String evidenceHash
) {}
