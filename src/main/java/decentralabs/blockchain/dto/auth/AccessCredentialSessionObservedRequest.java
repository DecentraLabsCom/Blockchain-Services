package decentralabs.blockchain.dto.auth;

public class AccessCredentialSessionObservedRequest {
    private String reservationKey;
    private String credentialHash;
    private String jwtJti;
    private String fmuTicketId;
    private String sessionId;
    private String gatewayId;
    private String accessType;
    private Long observedAt;
    private Long reportedAt;
    private String clientProofHash;

    public String getReservationKey() {
        return reservationKey;
    }

    public void setReservationKey(String reservationKey) {
        this.reservationKey = reservationKey;
    }

    public String getCredentialHash() {
        return credentialHash;
    }

    public void setCredentialHash(String credentialHash) {
        this.credentialHash = credentialHash;
    }

    public String getJwtJti() {
        return jwtJti;
    }

    public void setJwtJti(String jwtJti) {
        this.jwtJti = jwtJti;
    }

    public String getFmuTicketId() {
        return fmuTicketId;
    }

    public void setFmuTicketId(String fmuTicketId) {
        this.fmuTicketId = fmuTicketId;
    }

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    public String getGatewayId() {
        return gatewayId;
    }

    public void setGatewayId(String gatewayId) {
        this.gatewayId = gatewayId;
    }

    public String getAccessType() {
        return accessType;
    }

    public void setAccessType(String accessType) {
        this.accessType = accessType;
    }

    public Long getObservedAt() {
        return observedAt;
    }

    public void setObservedAt(Long observedAt) {
        this.observedAt = observedAt;
    }

    public Long getReportedAt() {
        return reportedAt;
    }

    public void setReportedAt(Long reportedAt) {
        this.reportedAt = reportedAt;
    }

    public String getClientProofHash() {
        return clientProofHash;
    }

    public void setClientProofHash(String clientProofHash) {
        this.clientProofHash = clientProofHash;
    }
}
