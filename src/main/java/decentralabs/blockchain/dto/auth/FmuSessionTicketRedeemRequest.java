package decentralabs.blockchain.dto.auth;

public class FmuSessionTicketRedeemRequest {
    private String sessionTicket;
    private String labId;
    private String reservationKey;
    private String sessionId;
    private String gatewayId;
    private Long observedAt;

    public String getSessionTicket() {
        return sessionTicket;
    }

    public void setSessionTicket(String sessionTicket) {
        this.sessionTicket = sessionTicket;
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

    public Long getObservedAt() {
        return observedAt;
    }

    public void setObservedAt(Long observedAt) {
        this.observedAt = observedAt;
    }
}
