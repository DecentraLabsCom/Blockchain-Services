package decentralabs.blockchain.dto.wallet;

import java.math.BigInteger;

public final class LabPayoutStatus {

    private final BigInteger walletPayout;
    private final BigInteger institutionalPayout;
    private final BigInteger totalPayout;
    private final BigInteger institutionalCollectorCount;

    public LabPayoutStatus(
        BigInteger walletPayout,
        BigInteger institutionalPayout,
        BigInteger totalPayout,
        BigInteger institutionalCollectorCount
    ) {
        this.walletPayout = walletPayout;
        this.institutionalPayout = institutionalPayout;
        this.totalPayout = totalPayout;
        this.institutionalCollectorCount = institutionalCollectorCount;
    }

    public BigInteger walletPayout() {
        return walletPayout;
    }

    public BigInteger institutionalPayout() {
        return institutionalPayout;
    }

    public BigInteger totalPayout() {
        return totalPayout;
    }

    public BigInteger institutionalCollectorCount() {
        return institutionalCollectorCount;
    }
}
