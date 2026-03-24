package decentralabs.blockchain.dto.wallet;

public final class PayoutRequestSimulationResult {

    private final boolean canRequestPayout;
    private final String reason;

    public PayoutRequestSimulationResult(boolean canRequestPayout, String reason) {
        this.canRequestPayout = canRequestPayout;
        this.reason = reason;
    }

    public boolean canRequestPayout() {
        return canRequestPayout;
    }

    public String reason() {
        return reason;
    }
}
