package decentralabs.blockchain.dto.intent;

import com.fasterxml.jackson.annotation.JsonValue;

public enum IntentStatus {
    QUEUED("queued"),
    AUTHORIZED_PENDING_REGISTRATION("authorized_pending_registration"),
    IN_PROGRESS("in_progress"),
    EXECUTED("executed"),
    FAILED("failed"),
    REJECTED("rejected");

    private final String wireValue;

    IntentStatus(String wireValue) {
        this.wireValue = wireValue;
    }

    @JsonValue
    public String getWireValue() {
        return wireValue;
    }
}
