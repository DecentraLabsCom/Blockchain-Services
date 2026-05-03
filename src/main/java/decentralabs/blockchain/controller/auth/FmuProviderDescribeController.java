package decentralabs.blockchain.controller.auth;

import decentralabs.blockchain.service.auth.JwtService;
import decentralabs.blockchain.service.auth.MarketplaceEndpointAuthService;
import java.math.BigInteger;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Issues a short-lived JWT that authorises a single FMU describe call.
 *
 * <p>Intended for the provider dashboard "Add Lab" flow where a provider wants to
 * auto-detect FMU metadata before a reservation exists. No SAML assertion is required;
 * authentication is proved by a valid Marketplace JWT in the Authorization header.
 *
 * <p>POST /auth/fmu/provider-describe-token
 * Body: { "fmuFileName": "Dahlquist.fmu" }
 * Returns: { "token": "...", "expiresIn": 60 }
 */
@RestController
@RequestMapping("/auth/fmu/provider-describe-token")
@ConditionalOnProperty(value = "features.providers.enabled", havingValue = "true", matchIfMissing = true)
@RequiredArgsConstructor
@Slf4j
public class FmuProviderDescribeController {

    private final MarketplaceEndpointAuthService marketplaceEndpointAuthService;
    private final JwtService jwtService;

    @Value("${auth.fmu.provider-describe-token.ttl-seconds:60}")
    private int ttlSeconds;

    @PostMapping
    public ResponseEntity<?> issue(
            @RequestHeader(value = "Authorization", required = false) String authorization,
            @RequestBody(required = false) Map<String, String> body
    ) {
        try {
            marketplaceEndpointAuthService.enforceAuthorization(authorization, null);

            String fmuFileName = body == null ? null : body.get("fmuFileName");
            if (fmuFileName == null || fmuFileName.isBlank()) {
                return ResponseEntity.badRequest().body(Map.of("error", "Missing fmuFileName"));
            }
            String trimmed = fmuFileName.strip();
            if (!trimmed.toLowerCase().endsWith(".fmu")) {
                return ResponseEntity.badRequest().body(Map.of("error", "fmuFileName must end with .fmu"));
            }

            long now = Instant.now().getEpochSecond();
            Map<String, Object> claims = new HashMap<>();
            claims.put("accessKey", trimmed);
            claims.put("resourceType", "fmu");
            claims.put("exp", BigInteger.valueOf(now + ttlSeconds));

            String token = jwtService.generateToken(claims, null);
            return ResponseEntity.ok(Map.of("token", token, "expiresIn", ttlSeconds));

        } catch (ResponseStatusException ex) {
            return ResponseEntity.status(ex.getStatusCode()).body(Map.of("error", ex.getReason()));
        } catch (Exception ex) {
            log.error("Failed to issue FMU provider describe token", ex);
            return ResponseEntity.internalServerError().body(Map.of("error", "Internal server error"));
        }
    }
}
