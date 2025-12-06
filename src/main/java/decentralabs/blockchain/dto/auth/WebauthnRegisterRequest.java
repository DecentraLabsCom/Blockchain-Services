package decentralabs.blockchain.dto.auth;

import jakarta.validation.constraints.NotBlank;

public class WebauthnRegisterRequest {
    @NotBlank
    private String puc;

    @NotBlank
    private String credentialId;

    @NotBlank
    private String publicKey;

    private String aaguid;

    private Long signCount;

    public String getPuc() {
        return puc;
    }

    public void setPuc(String puc) {
        this.puc = puc;
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
}
