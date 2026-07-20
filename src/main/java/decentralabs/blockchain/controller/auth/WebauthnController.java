package decentralabs.blockchain.controller.auth;

import decentralabs.blockchain.dto.auth.WebauthnRevokeRequest;
import decentralabs.blockchain.service.auth.MarketplaceEndpointAuthService;
import decentralabs.blockchain.service.auth.WebauthnCredentialService;
import jakarta.validation.Valid;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/webauthn")
public class WebauthnController {

    private final WebauthnCredentialService credentialService;
    private final MarketplaceEndpointAuthService marketplaceEndpointAuthService;

    public WebauthnController(
        WebauthnCredentialService credentialService,
        MarketplaceEndpointAuthService marketplaceEndpointAuthService
    ) {
        this.credentialService = credentialService;
        this.marketplaceEndpointAuthService = marketplaceEndpointAuthService;
    }

    @PostMapping("/revoke")
    public ResponseEntity<Void> revoke(
        @RequestHeader(value = "Authorization", required = false) String authorizationHeader,
        @Valid @RequestBody WebauthnRevokeRequest request
    ) {
        Map<String, Object> claims = marketplaceEndpointAuthService.enforceAuthorization(
            authorizationHeader,
            "webauthn:manage"
        );
        enforceUserScope(claims, request.getPuc());
        credentialService.revoke(request.getPuc(), request.getCredentialId());
        return ResponseEntity.ok().build();
    }

    private void enforceUserScope(Map<String, Object> claims, String expectedUserId) {
        if (claims == null || claims.isEmpty() || expectedUserId == null || expectedUserId.isBlank()) {
            return;
        }
        String claimPuc = firstClaim(claims, "puc");
        if (claimPuc == null || claimPuc.isBlank()) {
            return;
        }
        if (!claimPuc.trim().equals(expectedUserId.trim())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "marketplace_puc_mismatch");
        }
    }

    private String firstClaim(Map<String, Object> claims, String... keys) {
        for (String key : keys) {
            Object value = claims.get(key);
            if (value != null) {
                return value.toString();
            }
        }
        return null;
    }
}
