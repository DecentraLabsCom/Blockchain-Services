package decentralabs.blockchain.service.intent;

import java.time.Instant;
import java.util.Map;

import decentralabs.blockchain.dto.intent.ActionIntentPayload;
import decentralabs.blockchain.dto.intent.IntentAction;
import decentralabs.blockchain.dto.intent.IntentStatus;
import decentralabs.blockchain.dto.intent.ReservationIntentPayload;

public class IntentRecord {
    private final String requestId;
    private IntentStatus status;
    private String txHash;
    private Long blockNumber;
    private String labId;
    private String reservationKey;
    private String error;
    private final String action;
    private final String provider;
    private Instant updatedAt;
    private Instant createdAt;
    private String reason;
    private Long expiresAt;
    private Long nonce;
    private Map<String, Object> data;
    private String payloadJson;
    private String puc;
    private String signer;
    private String executor;
    private Integer actionId;
    private String payloadHash;
    private Long requestedAt;
    private String signature;
    private ActionIntentPayload actionPayload;
    private ReservationIntentPayload reservationPayload;

    public IntentRecord(String requestId, String action, String provider) {
        this.requestId = requestId;
        this.action = action;
        this.provider = provider;
        this.status = IntentStatus.QUEUED;
        this.createdAt = Instant.now();
        this.updatedAt = this.createdAt;
    }

    public String getRequestId() {
        return requestId;
    }

    public IntentStatus getStatus() {
        return status;
    }

    public void setStatus(IntentStatus status) {
        this.status = status;
        this.updatedAt = Instant.now();
    }

    public String getTxHash() {
        return txHash;
    }

    public void setTxHash(String txHash) {
        this.txHash = txHash;
    }

    public Long getBlockNumber() {
        return blockNumber;
    }

    public void setBlockNumber(Long blockNumber) {
        this.blockNumber = blockNumber;
    }

    public String getLabId() {
        return labId;
    }

    public void setLabId(String labId) {
        this.labId = labId;
    }

    public String getReservationKey() {
        return reservationKey;
    }

    public void setReservationKey(String reservationKey) {
        this.reservationKey = reservationKey;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public String getAction() {
        return action;
    }

    public String getProvider() {
        return provider;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public Long getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Long expiresAt) {
        this.expiresAt = expiresAt;
    }

    public Long getNonce() {
        return nonce;
    }

    public void setNonce(Long nonce) {
        this.nonce = nonce;
    }

    public void setUpdatedAt(Instant updatedAt) {
        this.updatedAt = updatedAt;
    }

    public Map<String, Object> getData() {
        return data;
    }

    public void setData(Map<String, Object> data) {
        this.data = data;
    }

    public String getPayloadJson() {
        return payloadJson;
    }

    public void setPayloadJson(String payloadJson) {
        this.payloadJson = payloadJson;
    }

    public String getPuc() {
        return puc;
    }

    public void setPuc(String puc) {
        this.puc = puc;
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

    public Integer getActionId() {
        return actionId;
    }

    public void setActionId(Integer actionId) {
        this.actionId = actionId;
    }

    public String getPayloadHash() {
        return payloadHash;
    }

    public void setPayloadHash(String payloadHash) {
        this.payloadHash = payloadHash;
    }

    public Long getRequestedAt() {
        return requestedAt;
    }

    public void setRequestedAt(Long requestedAt) {
        this.requestedAt = requestedAt;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public ActionIntentPayload getActionPayload() {
        return actionPayload;
    }

    public void setActionPayload(ActionIntentPayload actionPayload) {
        this.actionPayload = actionPayload;
    }

    public ReservationIntentPayload getReservationPayload() {
        return reservationPayload;
    }

    public void setReservationPayload(ReservationIntentPayload reservationPayload) {
        this.reservationPayload = reservationPayload;
    }

    public IntentAction getIntentAction() {
        return IntentAction.fromId(actionId).orElse(null);
    }
}
