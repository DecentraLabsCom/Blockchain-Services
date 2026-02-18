package decentralabs.blockchain.controller.intent;

import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.dto.intent.IntentAckResponse;
import decentralabs.blockchain.dto.intent.IntentAuthorizationCompleteRequest;
import decentralabs.blockchain.dto.intent.IntentAuthorizationRequest;
import decentralabs.blockchain.dto.intent.IntentAuthorizationSessionResponse;
import decentralabs.blockchain.dto.intent.IntentAuthorizationStatusResponse;
import decentralabs.blockchain.service.intent.IntentAuthService;
import decentralabs.blockchain.service.intent.IntentAuthorizationService;
import jakarta.validation.Valid;
import java.util.HashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("${endpoint.intents:/intents}")
@RequiredArgsConstructor
@Slf4j
public class IntentAuthorizationController {

    private static final long DEFAULT_TIMEOUT_MS = 90_000L;

    private final IntentAuthorizationService authorizationService;
    private final IntentAuthService intentAuthService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @PostMapping("/authorize")
    public ResponseEntity<IntentAuthorizationSessionResponse> authorizeIntent(
        @RequestBody @Valid IntentAuthorizationRequest request,
        @RequestHeader(value = "Authorization", required = false) String authorizationHeader
    ) {
        intentAuthService.enforceSubmitAuthorization(authorizationHeader);
        IntentAuthorizationService.AuthorizationSession session = authorizationService.createSession(request);
        IntentAuthorizationSessionResponse response = IntentAuthorizationSessionResponse.builder()
            .sessionId(session.getSessionId())
            .ceremonyUrl(authorizationService.buildCeremonyUrl(session.getSessionId()))
            .requestId(session.getSubmission().getMeta().getRequestId())
            .expiresAt(session.getExpiresAt())
            .build();
        return ResponseEntity.ok(response);
    }

    @GetMapping("/authorize/status/{sessionId}")
    public ResponseEntity<IntentAuthorizationStatusResponse> getStatus(
        @PathVariable String sessionId,
        @RequestHeader(value = "Authorization", required = false) String authorizationHeader
    ) {
        intentAuthService.enforceStatusAuthorization(authorizationHeader);
        return ResponseEntity.ok(authorizationService.getStatus(sessionId));
    }

    @GetMapping(value = "/authorize/ceremony/{sessionId}", produces = "text/html")
    public ResponseEntity<String> getCeremonyPage(@PathVariable String sessionId) {
        IntentAuthorizationService.AuthorizationSession session = authorizationService.getSession(sessionId);
        String html = generateCeremonyHtml(session);
        return ResponseEntity.ok(html);
    }

    @PostMapping("/authorize/complete")
    public ResponseEntity<IntentAckResponse> completeAuthorization(
        @RequestBody @Valid IntentAuthorizationCompleteRequest request
    ) {
        IntentAckResponse response = authorizationService.completeAuthorization(request);
        return ResponseEntity.ok(response);
    }

    private String generateCeremonyHtml(IntentAuthorizationService.AuthorizationSession session) {
        Map<String, Object> options = new HashMap<>();
        options.put("sessionId", session.getSessionId());
        options.put("challenge", session.getChallenge());
        options.put("allowCredentials", session.getCredentialIds());
        options.put("rpId", authorizationService.getRelyingPartyId());
        options.put("timeout", DEFAULT_TIMEOUT_MS);
        options.put("userVerification", "required");
        options.put("returnUrl", session.getReturnUrl());
        options.put("requestId", session.getSubmission().getMeta().getRequestId());

        return """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Intent Authorization - DecentraLabs</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: Arial, Helvetica, sans-serif;
      background: #0f172a;
      color: #e2e8f0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }
    .card {
      width: 100%%;
      max-width: 420px;
      background: #111827;
      border: 1px solid #1f2937;
      border-radius: 12px;
      padding: 32px;
      text-align: center;
      box-shadow: 0 10px 30px rgba(15, 23, 42, 0.5);
    }
    h1 { font-size: 20px; margin-bottom: 8px; }
    p { font-size: 14px; color: #94a3b8; margin-bottom: 24px; }
    .status {
      padding: 14px;
      border-radius: 8px;
      margin-bottom: 16px;
    }
    .pending { background: rgba(59, 130, 246, 0.15); color: #93c5fd; }
    .success { background: rgba(16, 185, 129, 0.15); color: #6ee7b7; }
    .error { background: rgba(239, 68, 68, 0.15); color: #fca5a5; }
    .hidden { display: none; }
    button {
      background: #2563eb;
      color: #fff;
      border: none;
      padding: 12px 20px;
      border-radius: 8px;
      font-size: 14px;
      cursor: pointer;
    }
    button:disabled { background: #475569; cursor: not-allowed; }
    .meta {
      font-size: 12px;
      color: #64748b;
      word-break: break-all;
      margin-top: 16px;
    }
  </style>
</head>
<body>
  <div class="card">
    <h1>Authorize Intent</h1>
    <p>Confirm this action with your security key or passkey.</p>

    <div id="statusPending" class="status pending">Waiting for confirmation...</div>
    <div id="statusSuccess" class="status success hidden">Authorization complete.</div>
    <div id="statusError" class="status error hidden">Authorization failed.</div>

    <button id="retryBtn" class="hidden" onclick="startCeremony()">Try Again</button>
    <div class="meta" id="metaText"></div>
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

    function showStatus(kind, message) {
      document.getElementById('statusPending').classList.add('hidden');
      document.getElementById('statusSuccess').classList.add('hidden');
      document.getElementById('statusError').classList.add('hidden');
      document.getElementById('retryBtn').classList.add('hidden');

      if (kind === 'pending') {
        document.getElementById('statusPending').classList.remove('hidden');
      } else if (kind === 'success') {
        document.getElementById('statusSuccess').classList.remove('hidden');
      } else if (kind === 'error') {
        document.getElementById('statusError').classList.remove('hidden');
        if (message) {
          document.getElementById('statusError').textContent = message;
        }
        document.getElementById('retryBtn').classList.remove('hidden');
      }
    }

    let authorizationNotified = false;

    function notifyParent(status, message) {
      try {
        if (window.opener && !window.opener.closed) {
          const payload = {
            type: 'intent-authorization',
            status,
            requestId: options.requestId || null,
            sessionId: options.sessionId || null,
            error: message || null,
          };
          let targetOrigin = '*';
          if (options.returnUrl) {
            try {
              targetOrigin = new URL(options.returnUrl).origin;
            } catch {
              targetOrigin = '*';
            }
          }
          window.opener.postMessage(payload, targetOrigin);
          authorizationNotified = true;
        }
      } catch (err) {
        // ignore postMessage errors
      }
    }

    function notifyCancelledOnClose() {
      if (authorizationNotified) return;
      notifyParent('CANCELLED', 'Authorization window closed');
    }

    function closeOrFallbackAfterSuccess() {
      if (window.opener && !window.opener.closed) {
        // Browser will only allow this for script-opened windows.
        setTimeout(() => { window.close(); }, 700);
        return;
      }
      if (options.returnUrl) {
        setTimeout(() => { window.location.href = options.returnUrl; }, 700);
      } else {
        setTimeout(() => { window.close(); }, 800);
      }
    }

        async function startCeremony() {
          showStatus('pending');

          try {
            const allowCredentialIds = Array.isArray(options.allowCredentials)
              ? options.allowCredentials
              : [];
            if (!allowCredentialIds.length) {
              throw new Error('No credential available for this authorization session');
            }
            const publicKey = {
              challenge: base64UrlToArrayBuffer(options.challenge),
              rpId: options.rpId,
              allowCredentials: allowCredentialIds.map((credentialId) => ({
                id: base64UrlToArrayBuffer(credentialId),
                type: 'public-key',
              })),
              userVerification: options.userVerification || 'required',
              timeout: options.timeout || 90000,
            };

        const assertion = await navigator.credentials.get({ publicKey });
        const payload = {
          sessionId: options.sessionId,
          credentialId: assertion.id,
          clientDataJSON: arrayBufferToBase64Url(assertion.response.clientDataJSON),
          authenticatorData: arrayBufferToBase64Url(assertion.response.authenticatorData),
          signature: arrayBufferToBase64Url(assertion.response.signature),
        };

        const response = await fetch('/intents/authorize/complete', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });

        if (response.ok) {
          showStatus('success');
          notifyParent('SUCCESS');
          closeOrFallbackAfterSuccess();
        } else {
          const error = await response.json().catch(() => ({}));
          const message = error.message || error.error || 'Authorization failed';
          showStatus('error', message);
          notifyParent('FAILED', message);
        }
      } catch (err) {
        if (err && err.name === 'NotAllowedError') {
          const message = 'You cancelled the request or it timed out';
          showStatus('error', message);
          notifyParent('CANCELLED', message);
        } else {
          const message = err?.message || 'Authorization failed';
          showStatus('error', message);
          notifyParent('FAILED', message);
        }
      }
    }

    if (options.requestId) {
      const metaText = document.getElementById('metaText');
      metaText.textContent = 'Request ID: ' + options.requestId;
    }

    window.addEventListener('beforeunload', notifyCancelledOnClose);
    window.addEventListener('pagehide', notifyCancelledOnClose);

    startCeremony();
  </script>
</body>
</html>
""".formatted(serializeOptionsToJson(options));
    }

    private String serializeOptionsToJson(Map<String, Object> options) {
        try {
            String json = objectMapper.writeValueAsString(options);
            return json.replace("</", "<\\/");
        } catch (Exception e) {
            log.error("Failed to serialize intent authorization options", e);
            throw new RuntimeException("Failed to serialize intent authorization options", e);
        }
    }
}
