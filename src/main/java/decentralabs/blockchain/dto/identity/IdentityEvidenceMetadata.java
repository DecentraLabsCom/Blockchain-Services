package decentralabs.blockchain.dto.identity;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.time.Instant;
import java.util.List;

/**
 * Structured validation metadata for identity evidence.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record IdentityEvidenceMetadata(
    String issuer,
    Instant issuedAt,
    Instant expiresAt,
    String nonce,
    List<String> audience,
    boolean verified,
    String validationType
) {}
