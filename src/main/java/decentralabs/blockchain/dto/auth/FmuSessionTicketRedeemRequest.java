package decentralabs.blockchain.dto.auth;

public class FmuSessionTicketRedeemRequest {
    private String sessionTicket;
    private String labId;
    private String reservationKey;

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
}
