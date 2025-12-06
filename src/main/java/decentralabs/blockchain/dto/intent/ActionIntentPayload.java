package decentralabs.blockchain.dto.intent;

import java.math.BigInteger;

import com.fasterxml.jackson.annotation.JsonInclude;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/**
 * Mirrors ActionIntentPayload in the contract.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ActionIntentPayload {

    @NotBlank
    private String executor;

    private String schacHomeOrganization;
    private String puc;
    private String assertionHash; // bytes32 hex

    @NotNull
    private BigInteger labId;

    private String reservationKey; // bytes32 hex
    private String uri;
    private BigInteger price;      // uint96
    private BigInteger maxBatch;   // uint96 (only for REQUEST_FUNDS intent)
    private String auth;
    private String accessURI;
    private String accessKey;
    private String tokenURI;

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

    public String getPuc() {
        return puc;
    }

    public void setPuc(String puc) {
        this.puc = puc;
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

    public String getReservationKey() {
        return reservationKey;
    }

    public void setReservationKey(String reservationKey) {
        this.reservationKey = reservationKey;
    }

    public String getUri() {
        return uri;
    }

    public void setUri(String uri) {
        this.uri = uri;
    }

    public BigInteger getPrice() {
        return price;
    }

    public void setPrice(BigInteger price) {
        this.price = price;
    }
    public BigInteger getMaxBatch() {
        return maxBatch;
    }

    public void setMaxBatch(BigInteger maxBatch) {
        this.maxBatch = maxBatch;
    }

    public String getAuth() {
        return auth;
    }

    public void setAuth(String auth) {
        this.auth = auth;
    }

    public String getAccessURI() {
        return accessURI;
    }

    public void setAccessURI(String accessURI) {
        this.accessURI = accessURI;
    }

    public String getAccessKey() {
        return accessKey;
    }

    public void setAccessKey(String accessKey) {
        this.accessKey = accessKey;
    }

    public String getTokenURI() {
        return tokenURI;
    }

    public void setTokenURI(String tokenURI) {
        this.tokenURI = tokenURI;
    }
}
