package decentralabs.blockchain.dto.identity;

import com.fasterxml.jackson.annotation.JsonInclude;

import jakarta.validation.constraints.NotBlank;
import lombok.Builder;
import lombok.extern.jackson.Jacksonized;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Jacksonized
@Builder(toBuilder = true)
public record NormalizedClaims(
    @NotBlank String stableUserId,
    @NotBlank String institutionId,
    String role,
    String scopedRole,
    @NotBlank String puc,
    String email,
    String name
) {}

