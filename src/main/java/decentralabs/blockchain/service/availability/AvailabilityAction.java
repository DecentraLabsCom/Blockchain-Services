package decentralabs.blockchain.service.availability;

/**
 * Actions that can be taken automatically when a reservation event is received.
 */
public enum AvailabilityAction {
    AUTO_APPROVE,
    AUTO_DENY,
    MANUAL;

    public static AvailabilityAction fromMode(String mode) {
        if (mode == null) {
            return MANUAL;
        }
        return switch (mode.trim().toLowerCase()) {
            case "auto-approve", "autoapprove" -> AUTO_APPROVE;
            case "auto-deny", "autodeny", "deny" -> AUTO_DENY;
            default -> MANUAL;
        };
    }
}
