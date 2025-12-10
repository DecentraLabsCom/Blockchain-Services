package decentralabs.blockchain.controller.auth;

import decentralabs.blockchain.dto.auth.WebauthnOnboardingCompleteRequest;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingCompleteResponse;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingOptionsRequest;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingOptionsResponse;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingStatusResponse;
import decentralabs.blockchain.service.auth.WebauthnOnboardingService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for WebAuthn credential registration during user onboarding.
 * 
 * This implements the dedicated onboarding endpoint described in the
 * Federated SSO Architecture specification where:
 * 
 * 1. The SP sends user identity from the federated assertion to request options
 * 2. The WIB (this service) generates a challenge and returns credential creation options
 * 3. The SP redirects the browser to perform the WebAuthn ceremony
 * 4. The browser sends the attestation directly to the WIB
 * 5. The WIB verifies and stores the credential binding
 * 
 * Endpoints:
 * - POST /onboarding/webauthn/options - Request credential creation options (challenge)
 * - POST /onboarding/webauthn/complete - Submit attestation response
 * 
 * Security:
 * - Challenges are single-use and time-limited
 * - Origin verification is performed on attestation
 * - Credentials are bound to stable user identifiers from federated assertions
 * - The SP does not see or relay the challenge or user signature
 */
@RestController
@RequestMapping("/onboarding/webauthn")
@RequiredArgsConstructor
@Slf4j
public class WebauthnOnboardingController {

    private final WebauthnOnboardingService onboardingService;

    /**
     * Request WebAuthn credential creation options.
     * 
     * Called by the SP after validating the federated assertion.
     * Returns a challenge and options for navigator.credentials.create().
     * 
     * @param request Contains stable user ID and institution from assertion
     * @return Credential creation options including challenge
     */
    @PostMapping("/options")
    public ResponseEntity<WebauthnOnboardingOptionsResponse> getOptions(
            @Valid @RequestBody WebauthnOnboardingOptionsRequest request) {
        log.debug("WebAuthn options requested for institution: {}", request.getInstitutionId());
        WebauthnOnboardingOptionsResponse response = onboardingService.generateOptions(request);
        return ResponseEntity.ok(response);
    }

    /**
     * Complete WebAuthn credential registration.
     * 
     * Called by the browser after navigator.credentials.create() completes.
     * Verifies the attestation and stores the credential binding.
     * 
     * @param request Contains attestation response from authenticator
     * @return Success status
     */
    @PostMapping("/complete")
    public ResponseEntity<WebauthnOnboardingCompleteResponse> complete(
            @Valid @RequestBody WebauthnOnboardingCompleteRequest request) {
        log.debug("WebAuthn attestation received for session: {}", request.getSessionId());
        WebauthnOnboardingCompleteResponse response = onboardingService.completeOnboarding(request);
        return ResponseEntity.ok(response);
    }

    /**
     * Get the status of a WebAuthn onboarding session.
     * 
     * This endpoint allows the SP to poll for the onboarding result if callback
     * delivery failed or wasn't configured. Status can be:
     * - PENDING: Browser hasn't completed the ceremony yet
     * - SUCCESS: Credential was registered successfully
     * - FAILED: Registration failed (error details included)
     * 
     * @param sessionId The session ID returned from /options
     * @return Status of the onboarding session
     */
    @GetMapping("/status/{sessionId}")
    public ResponseEntity<WebauthnOnboardingStatusResponse> getStatus(
            @PathVariable String sessionId) {
        log.debug("WebAuthn status check for session: {}", sessionId);
        WebauthnOnboardingStatusResponse response = onboardingService.getStatus(sessionId);
        return ResponseEntity.ok(response);
    }
}
