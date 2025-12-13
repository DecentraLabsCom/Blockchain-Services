package decentralabs.blockchain.controller.auth;

import decentralabs.blockchain.dto.auth.UserKeyStatusResponse;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingCompleteRequest;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingCompleteResponse;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingOptionsRequest;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingOptionsResponse;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingStatusResponse;
import decentralabs.blockchain.service.auth.WebauthnCredentialService;
import decentralabs.blockchain.service.auth.WebauthnOnboardingService;
import jakarta.validation.Valid;
import java.time.Instant;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
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
    private final WebauthnCredentialService credentialService;

    /**
     * Check if a user has registered WebAuthn credentials.
     * 
     * Called by the SP to determine if onboarding is needed before requesting an action.
     * This allows the SP to skip the onboarding flow for users who already have credentials.
     * 
     * @param stableUserId The stable user identifier (e.g., SAML NameID, uid)
     * @param institutionId Optional institution filter (for future multi-institution support)
     * @return Key status including whether credentials exist and count
     */
    @GetMapping("/key-status/{stableUserId}")
    public ResponseEntity<UserKeyStatusResponse> getKeyStatus(
            @PathVariable String stableUserId,
            @RequestParam(required = false) String institutionId) {
        log.debug("Key status check for user: {}, institution: {}", stableUserId, institutionId);
        
        WebauthnCredentialService.KeyStatus keyStatus = credentialService.getKeyStatus(stableUserId);
        
        UserKeyStatusResponse response = UserKeyStatusResponse.builder()
            .hasCredential(keyStatus.isHasCredential())
            .credentialCount(keyStatus.getCredentialCount())
            .stableUserId(stableUserId)
            .institutionId(institutionId)
            .lastRegistered(keyStatus.getLastRegisteredEpoch() != null 
                ? Instant.ofEpochSecond(keyStatus.getLastRegisteredEpoch()) 
                : null)
            .hasRevokedCredentials(keyStatus.isHasRevokedCredentials())
            .build();
        
        return ResponseEntity.ok(response);
    }

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

    /**
     * Serve the WebAuthn ceremony page.
     * 
     * The SP redirects the browser here after receiving the onboardingUrl from /options.
     * This page executes navigator.credentials.create() and submits the result to /complete.
     * 
     * The IB serves this page so that it is the WebAuthn Relying Party, ensuring
     * the credential is bound to the IB's origin (rpId).
     * 
     * @param sessionId The session ID from the onboarding URL
     * @return HTML page that performs the WebAuthn ceremony
     */
    @GetMapping(value = "/ceremony/{sessionId}", produces = "text/html")
    public ResponseEntity<String> getCeremonyPage(@PathVariable String sessionId) {
        log.debug("WebAuthn ceremony page requested for session: {}", sessionId);
        
        // Validate session exists and is not expired
        WebauthnOnboardingOptionsResponse options = onboardingService.getSessionOptions(sessionId);
        
        // Generate the HTML page with embedded options
        String html = generateCeremonyHtml(options);
        return ResponseEntity.ok(html);
    }

    /**
     * Generate the HTML page for the WebAuthn ceremony.
     * This page includes all necessary JavaScript to perform the credential creation.
     */
    private String generateCeremonyHtml(WebauthnOnboardingOptionsResponse options) {
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Credential Registration - DecentraLabs</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%%, #16213e 100%%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #fff;
        }
        .container {
            background: rgba(255,255,255,0.05);
            backdrop-filter: blur(10px);
            border-radius: 16px;
            padding: 48px;
            max-width: 480px;
            width: 90%%;
            text-align: center;
            border: 1px solid rgba(255,255,255,0.1);
        }
        .logo { font-size: 48px; margin-bottom: 24px; }
        h1 { font-size: 24px; margin-bottom: 8px; }
        .subtitle { color: #888; margin-bottom: 32px; }
        .user-info {
            background: rgba(255,255,255,0.05);
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 32px;
        }
        .user-info .label { font-size: 12px; color: #888; text-transform: uppercase; }
        .user-info .value { font-size: 16px; margin-top: 4px; word-break: break-all; }
        .status {
            padding: 16px;
            border-radius: 8px;
            margin-bottom: 24px;
        }
        .status.pending { background: rgba(255,193,7,0.2); color: #ffc107; }
        .status.success { background: rgba(76,175,80,0.2); color: #4caf50; }
        .status.error { background: rgba(244,67,54,0.2); color: #f44336; }
        .spinner {
            width: 40px; height: 40px;
            border: 3px solid rgba(255,255,255,0.1);
            border-top-color: #ffc107;
            border-radius: 50%%;
            animation: spin 1s linear infinite;
            margin: 0 auto 16px;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        button {
            background: #4f46e5;
            color: white;
            border: none;
            padding: 16px 32px;
            font-size: 16px;
            border-radius: 8px;
            cursor: pointer;
            transition: background 0.2s;
        }
        button:hover { background: #4338ca; }
        button:disabled { background: #666; cursor: not-allowed; }
        .hidden { display: none; }
        .close-msg { margin-top: 24px; font-size: 14px; color: #888; }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">🔐</div>
        <h1>Credential Registration</h1>
        <p class="subtitle">Create a secure passkey for your account</p>
        
        <div class="user-info">
            <div class="label">Account</div>
            <div class="value" id="userName">%s</div>
        </div>
        
        <div id="statusPending" class="status pending">
            <div class="spinner"></div>
            <div>Waiting for authenticator...</div>
        </div>
        
        <div id="statusSuccess" class="status success hidden">
            <div style="font-size: 32px; margin-bottom: 8px;">✓</div>
            <div>Registration successful!</div>
        </div>
        
        <div id="statusError" class="status error hidden">
            <div style="font-size: 32px; margin-bottom: 8px;">✗</div>
            <div id="errorMessage">Registration failed</div>
        </div>
        
        <button id="retryBtn" class="hidden" onclick="startCeremony()">Try Again</button>
        <p id="closeMsg" class="close-msg hidden">You can close this window.</p>
    </div>

    <script>
        const options = %s;
        
        function base64UrlToArrayBuffer(base64url) {
            const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
            const padding = '='.repeat((4 - base64.length %% 4) %% 4);
            const binary = atob(base64 + padding);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
            return bytes.buffer;
        }
        
        function arrayBufferToBase64Url(buffer) {
            const bytes = new Uint8Array(buffer);
            let binary = '';
            for (let i = 0; i < bytes.length; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return btoa(binary).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=/g, '');
        }
        
        function showStatus(status, message) {
            document.getElementById('statusPending').classList.add('hidden');
            document.getElementById('statusSuccess').classList.add('hidden');
            document.getElementById('statusError').classList.add('hidden');
            document.getElementById('retryBtn').classList.add('hidden');
            document.getElementById('closeMsg').classList.add('hidden');
            
            if (status === 'pending') {
                document.getElementById('statusPending').classList.remove('hidden');
            } else if (status === 'success') {
                document.getElementById('statusSuccess').classList.remove('hidden');
                document.getElementById('closeMsg').classList.remove('hidden');
            } else if (status === 'error') {
                document.getElementById('statusError').classList.remove('hidden');
                document.getElementById('errorMessage').textContent = message || 'Registration failed';
                document.getElementById('retryBtn').classList.remove('hidden');
            }
        }
        
        async function startCeremony() {
            showStatus('pending');
            
            try {
                const publicKeyOptions = {
                    challenge: base64UrlToArrayBuffer(options.challenge),
                    rp: options.rp,
                    user: {
                        id: base64UrlToArrayBuffer(options.user.id),
                        name: options.user.name,
                        displayName: options.user.displayName
                    },
                    pubKeyCredParams: options.pubKeyCredParams,
                    timeout: options.timeout,
                    attestation: options.attestation,
                    authenticatorSelection: options.authenticatorSelection
                };
                
                const credential = await navigator.credentials.create({ publicKey: publicKeyOptions });
                
                const attestationResponse = {
                    sessionId: options.sessionId,
                    id: credential.id,
                    rawId: arrayBufferToBase64Url(credential.rawId),
                    type: credential.type,
                    response: {
                        clientDataJSON: arrayBufferToBase64Url(credential.response.clientDataJSON),
                        attestationObject: arrayBufferToBase64Url(credential.response.attestationObject)
                    }
                };
                
                const response = await fetch('/onboarding/webauthn/complete', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(attestationResponse)
                });
                
                if (response.ok) {
                    showStatus('success');
                } else {
                    const error = await response.json();
                    showStatus('error', error.message || 'Server rejected the credential');
                }
            } catch (err) {
                console.error('WebAuthn error:', err);
                if (err.name === 'NotAllowedError') {
                    showStatus('error', 'You cancelled the operation or it timed out');
                } else if (err.name === 'InvalidStateError') {
                    showStatus('error', 'A credential already exists for this account');
                } else {
                    showStatus('error', err.message || 'Unknown error occurred');
                }
            }
        }
        
        // Auto-start the ceremony
        startCeremony();
    </script>
</body>
</html>
""".formatted(
            escapeHtml(options.getUser().getDisplayName()),
            serializeOptionsToJson(options)
        );
    }

    private String escapeHtml(String input) {
        if (input == null) return "";
        return input
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#39;");
    }

    private String serializeOptionsToJson(WebauthnOnboardingOptionsResponse options) {
        try {
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            return mapper.writeValueAsString(options);
        } catch (Exception e) {
            log.error("Failed to serialize options to JSON", e);
            throw new RuntimeException("Failed to serialize options", e);
        }
    }
}
