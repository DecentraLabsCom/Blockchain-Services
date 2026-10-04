package decentralabs.blockchain.controller.auth;

import decentralabs.blockchain.dto.auth.IdentitySessionRequest;
import decentralabs.blockchain.dto.auth.InstitutionalSessionResponse;
import decentralabs.blockchain.service.auth.InstitutionalIdentitySessionService;
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
@RequestMapping("/auth/identity")
@RequiredArgsConstructor
public class InstitutionalIdentitySessionController {

    private final InstitutionalIdentitySessionService sessionService;
    private final IntentAuthService intentAuthService;

    @PostMapping("/session")
    public ResponseEntity<InstitutionalSessionResponse> createSession(
        @Valid @RequestBody IdentitySessionRequest request,
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
