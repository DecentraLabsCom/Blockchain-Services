package decentralabs.blockchain.dto.intent;

import java.math.BigInteger;

import com.fasterxml.jackson.annotation.JsonInclude;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/**
 * Mirrors ReservationIntentPayload in the contract.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ReservationIntentPayload {

    @NotBlank
    private String executor;

    private String schacHomeOrganization;
    private String pucHash; // bytes32 hex
    private String assertionHash; // bytes32 hex

    @NotNull
    private BigInteger labId;

    @NotNull
    private Long start; // uint32

    @NotNull
    private Long end;   // uint32

    private BigInteger price; // uint96
    private String reservationKey; // bytes32

    public String getExecutor() {
        return executor;
    }

    public void setExecutor(String executor) {
        this.executor = executor;
    }

    public String getSchacHomeOrganization() {
        return schacHomeOrganization;
    }

    public void setSchacHomeOrganization(String schacHomeOrganization) {
        this.schacHomeOrganization = schacHomeOrganization;
    }

    public String getPucHash() {
        return pucHash;
    }

    public void setPucHash(String pucHash) {
        this.pucHash = pucHash;
    }

    public String getAssertionHash() {
        return assertionHash;
    }

    public void setAssertionHash(String assertionHash) {
        this.assertionHash = assertionHash;
    }

    public BigInteger getLabId() {
        return labId;
    }

    public void setLabId(BigInteger labId) {
        this.labId = labId;
    }

    public Long getStart() {
        return start;
    }

    public void setStart(Long start) {
        this.start = start;
    }

    public Long getEnd() {
        return end;
    }

    public void setEnd(Long end) {
        this.end = end;
    }

    public BigInteger getPrice() {
        return price;
    }

    public void setPrice(BigInteger price) {
        this.price = price;
    }

    public String getReservationKey() {
        return reservationKey;
    }

    public void setReservationKey(String reservationKey) {
        this.reservationKey = reservationKey;
    }
}
