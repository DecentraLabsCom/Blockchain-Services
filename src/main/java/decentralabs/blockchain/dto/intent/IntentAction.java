package decentralabs.blockchain.dto.intent;

import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;

/**
 * Enumerates the intent actions supported on-chain.
 * Action ids must match the uint8 discriminators in LibIntent.
 */
public enum IntentAction {
    LAB_ADD(1, "LAB_ADD", false),
    LAB_ADD_AND_LIST(2, "LAB_ADD_AND_LIST", false),
    LAB_SET_URI(3, "LAB_SET_URI", false),
    LAB_UPDATE(4, "LAB_UPDATE", false),
    LAB_DELETE(5, "LAB_DELETE", false),
    LAB_LIST(6, "LAB_LIST", false),
    LAB_UNLIST(7, "LAB_UNLIST", false),
    RESERVATION_REQUEST(8, "RESERVATION_REQUEST", true),
    CANCEL_RESERVATION_REQUEST(9, "CANCEL_RESERVATION_REQUEST", true),
    CANCEL_BOOKING(10, "CANCEL_BOOKING", false),
    REQUEST_FUNDS(11, "REQUEST_FUNDS", false);

    private final int id;
    private final String wireValue;
    private final boolean reservationPayload;

    IntentAction(int id, String wireValue, boolean reservationPayload) {
        this.id = id;
        this.wireValue = wireValue;
        this.reservationPayload = reservationPayload;
    }

    public int getId() {
        return id;
    }

    public String getWireValue() {
        return wireValue;
    }

    public boolean usesReservationPayload() {
        return reservationPayload;
    }

    public static Optional<IntentAction> fromId(Integer id) {
        if (id == null) {
            return Optional.empty();
        }
        return Arrays.stream(values())
            .filter(a -> a.id == id)
            .findFirst();
    }

    public static Optional<IntentAction> fromWireValue(String value) {
        if (value == null || value.isBlank()) {
            return Optional.empty();
        }
        String normalized = value.trim().toUpperCase(Locale.ROOT);
        return Arrays.stream(values())
            .filter(a -> a.wireValue.equalsIgnoreCase(normalized))
            .findFirst();
    }
}
