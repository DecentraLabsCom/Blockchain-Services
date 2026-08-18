package decentralabs.blockchain.controller.auth;

import decentralabs.blockchain.dto.auth.InstitutionalSessionRequest;
import decentralabs.blockchain.dto.auth.InstitutionalSessionResponse;
import decentralabs.blockchain.service.auth.InstitutionalSamlSessionService;
import decentralabs.blockchain.service.intent.IntentAuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth/saml")
@RequiredArgsConstructor
public class InstitutionalSamlSessionController {

    private final InstitutionalSamlSessionService sessionService;
    private final IntentAuthService intentAuthService;

    @PostMapping("/session")
    public ResponseEntity<InstitutionalSessionResponse> createSession(
        @Valid @RequestBody InstitutionalSessionRequest request,
        @RequestHeader(value = "Authorization", required = false) String authorizationHeader
    ) {
        IntentAuthService.SessionAuthorization authorization = intentAuthService
            .enforceSessionAuthorization(authorizationHeader);
        return ResponseEntity.ok(sessionService.create(
            request,
            authorization.claims(),
            authorization.marketplaceBindingRequired()
        ));
    }
}
