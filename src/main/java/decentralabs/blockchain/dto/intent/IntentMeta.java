package decentralabs.blockchain.dto.intent;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/**
 * Mirrors the IntentMeta struct in LibIntent.
 */
public class IntentMeta {

    @NotBlank
    private String requestId;   // bytes32 hex

    @NotBlank
    private String signer;      // address

    @NotBlank
    private String executor;    // address (must equal signer on-chain today)

    @NotNull
    private Integer action;     // uint8 discriminator

    @NotBlank
    private String payloadHash; // bytes32 hex

    @NotNull
    private Long nonce;         // uint256 (fits in signed long in practice)

    @NotNull
    private Long requestedAt;   // uint64

    @NotNull
    private Long expiresAt;     // uint64

    public String getRequestId() {
        return requestId;
    }

    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }

    public String getSigner() {
        return signer;
    }

    public void setSigner(String signer) {
        this.signer = signer;
    }

    public String getExecutor() {
        return executor;
    }

    public void setExecutor(String executor) {
        this.executor = executor;
    }

    public Integer getAction() {
        return action;
    }

    public void setAction(Integer action) {
        this.action = action;
    }

    public String getPayloadHash() {
        return payloadHash;
    }

    public void setPayloadHash(String payloadHash) {
        this.payloadHash = payloadHash;
    }

    public Long getNonce() {
        return nonce;
    }

    public void setNonce(Long nonce) {
        this.nonce = nonce;
    }

    public Long getRequestedAt() {
        return requestedAt;
    }

    public void setRequestedAt(Long requestedAt) {
        this.requestedAt = requestedAt;
    }

    public Long getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Long expiresAt) {
        this.expiresAt = expiresAt;
    }
}
