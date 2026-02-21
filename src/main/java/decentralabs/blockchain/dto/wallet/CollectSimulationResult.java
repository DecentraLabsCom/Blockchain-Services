package decentralabs.blockchain.dto.wallet;

public final class CollectSimulationResult {

    private final boolean canCollect;
    private final String reason;

    public CollectSimulationResult(boolean canCollect, String reason) {
        this.canCollect = canCollect;
        this.reason = reason;
    }

    public boolean canCollect() {
        return canCollect;
    }

    public String reason() {
        return reason;
    }
}
