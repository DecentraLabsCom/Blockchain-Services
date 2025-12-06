package decentralabs.blockchain.dto.auth;

import jakarta.validation.constraints.NotBlank;

public class WebauthnRevokeRequest {
    @NotBlank
    private String puc;

    @NotBlank
    private String credentialId;

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
}
