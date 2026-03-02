package decentralabs.blockchain.dto.auth;

import jakarta.validation.constraints.NotBlank;

public class WebauthnRegisterRequest {
    private String puc;
    private String userId;

    @NotBlank
    private String credentialId;

    @NotBlank
    private String publicKey;

    private String aaguid;

    private Long signCount;

    /**
     * Optional: authenticator attachment type ("platform" or "cross-platform").
     */
    private String authenticatorAttachment;

    /**
     * Optional: whether the credential is resident (discoverable).
     */
    private Boolean residentKey;

    /**
     * Optional: comma-separated transports (usb, nfc, ble, internal, hybrid, etc.).
     */
    private String transports;

    public String getPuc() {
        return puc;
    }

    public void setPuc(String puc) {
        this.puc = puc;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    /**
     * Returns the effective user identifier for credential binding.
     * Supports both legacy `puc` and the newer `userId` field.
     */
    public String getEffectiveUserId() {
        if (userId != null && !userId.isBlank()) {
            return userId;
        }
        return puc;
    }

    public String getCredentialId() {
        return credentialId;
    }

    public void setCredentialId(String credentialId) {
        this.credentialId = credentialId;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getAaguid() {
        return aaguid;
    }

    public void setAaguid(String aaguid) {
        this.aaguid = aaguid;
    }

    public Long getSignCount() {
        return signCount;
    }

    public void setSignCount(Long signCount) {
        this.signCount = signCount;
    }

    public String getAuthenticatorAttachment() {
        return authenticatorAttachment;
    }

    public void setAuthenticatorAttachment(String authenticatorAttachment) {
        this.authenticatorAttachment = authenticatorAttachment;
    }

    public Boolean getResidentKey() {
        return residentKey;
    }

    public void setResidentKey(Boolean residentKey) {
        this.residentKey = residentKey;
    }

    public String getTransports() {
        return transports;
    }

    public void setTransports(String transports) {
        this.transports = transports;
    }
}
