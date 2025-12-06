package decentralabs.blockchain.controller.auth;

import decentralabs.blockchain.dto.auth.WebauthnRegisterRequest;
import decentralabs.blockchain.dto.auth.WebauthnRevokeRequest;
import decentralabs.blockchain.service.auth.WebauthnCredentialService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/webauthn")
public class WebauthnController {

    private final WebauthnCredentialService credentialService;

    public WebauthnController(WebauthnCredentialService credentialService) {
        this.credentialService = credentialService;
    }

    @PostMapping("/register")
    public ResponseEntity<Void> register(@Valid @RequestBody WebauthnRegisterRequest request) {
        credentialService.register(
            request.getPuc(),
            request.getCredentialId(),
            request.getPublicKey(),
            request.getAaguid(),
            request.getSignCount()
        );
        return ResponseEntity.ok().build();
    }

    @PostMapping("/revoke")
    public ResponseEntity<Void> revoke(@Valid @RequestBody WebauthnRevokeRequest request) {
        credentialService.revoke(request.getPuc(), request.getCredentialId());
        return ResponseEntity.ok().build();
    }
}
