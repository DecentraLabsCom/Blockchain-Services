package decentralabs.blockchain.dto.intent;

import jakarta.validation.constraints.NotBlank;

/**
 * Request payload submitted by the browser after WebAuthn assertion.
 */
public class IntentAuthorizationCompleteRequest {

    @NotBlank
    private String sessionId;

    @NotBlank
    private String credentialId;

    @NotBlank
    private String clientDataJSON;

    @NotBlank
    private String authenticatorData;

    @NotBlank
    private String signature;

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    public String getCredentialId() {
        return credentialId;
    }

    public void setCredentialId(String credentialId) {
        this.credentialId = credentialId;
    }

    public String getClientDataJSON() {
        return clientDataJSON;
    }

    public void setClientDataJSON(String clientDataJSON) {
        this.clientDataJSON = clientDataJSON;
    }

    public String getAuthenticatorData() {
        return authenticatorData;
    }

    public void setAuthenticatorData(String authenticatorData) {
        this.authenticatorData = authenticatorData;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }
}
