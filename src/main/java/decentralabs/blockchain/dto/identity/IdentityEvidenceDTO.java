package decentralabs.blockchain.dto.identity;

import com.fasterxml.jackson.annotation.JsonInclude;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.Builder;
import lombok.extern.jackson.Jacksonized;

import java.time.Instant;
import java.util.List;

/**
 * Neutral identity evidence envelope shared by SAML and VC-style flows.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@Jacksonized
@Builder(toBuilder = true)
public record IdentityEvidenceDTO(
    @NotBlank
    String type,
    String format,
    String rawEvidence,
    @Valid NormalizedClaims normalizedClaims,
    String evidenceHash,
    String issuer,
    Instant issuedAt,
    Instant expiresAt,
    String nonce,
    List<String> audience
) {}
