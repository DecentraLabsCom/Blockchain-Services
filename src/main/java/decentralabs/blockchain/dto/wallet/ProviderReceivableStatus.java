package decentralabs.blockchain.dto.wallet;

import java.math.BigInteger;

public final class ProviderReceivableStatus {

    private final BigInteger providerReceivable;
    private final BigInteger deferredInstitutionalReceivable;
    private final BigInteger totalReceivable;
    private final BigInteger eligibleReservationCount;
    private final BigInteger accruedReceivable;
    private final BigInteger settlementQueued;
    private final BigInteger invoicedReceivable;
    private final BigInteger approvedReceivable;
    private final BigInteger paidReceivable;
    private final BigInteger reversedReceivable;
    private final BigInteger disputedReceivable;
    private final BigInteger lastAccruedAt;

    public ProviderReceivableStatus(
        BigInteger providerReceivable,
        BigInteger deferredInstitutionalReceivable,
        BigInteger totalReceivable,
        BigInteger eligibleReservationCount
    ) {
        this(
            providerReceivable,
            deferredInstitutionalReceivable,
            totalReceivable,
            eligibleReservationCount,
            BigInteger.ZERO,
            BigInteger.ZERO,
            BigInteger.ZERO,
            BigInteger.ZERO,
            BigInteger.ZERO,
            BigInteger.ZERO,
            BigInteger.ZERO,
            BigInteger.ZERO
        );
    }

    public ProviderReceivableStatus(
        BigInteger providerReceivable,
        BigInteger deferredInstitutionalReceivable,
        BigInteger totalReceivable,
        BigInteger eligibleReservationCount,
        BigInteger accruedReceivable,
        BigInteger settlementQueued,
        BigInteger invoicedReceivable,
        BigInteger approvedReceivable,
        BigInteger paidReceivable,
        BigInteger reversedReceivable,
        BigInteger disputedReceivable,
        BigInteger lastAccruedAt
    ) {
        this.providerReceivable = providerReceivable;
        this.deferredInstitutionalReceivable = deferredInstitutionalReceivable;
        this.totalReceivable = totalReceivable;
        this.eligibleReservationCount = eligibleReservationCount;
        this.accruedReceivable = accruedReceivable;
        this.settlementQueued = settlementQueued;
        this.invoicedReceivable = invoicedReceivable;
        this.approvedReceivable = approvedReceivable;
        this.paidReceivable = paidReceivable;
        this.reversedReceivable = reversedReceivable;
        this.disputedReceivable = disputedReceivable;
        this.lastAccruedAt = lastAccruedAt;
    }

    public BigInteger providerReceivable() {
        return providerReceivable;
    }

    public BigInteger deferredInstitutionalReceivable() {
        return deferredInstitutionalReceivable;
    }

    public BigInteger totalReceivable() {
        return totalReceivable;
    }

    public BigInteger eligibleReservationCount() {
        return eligibleReservationCount;
    }

    public BigInteger accruedReceivable() {
        return accruedReceivable;
    }

    public BigInteger settlementQueued() {
        return settlementQueued;
    }

    public BigInteger invoicedReceivable() {
        return invoicedReceivable;
    }

    public BigInteger approvedReceivable() {
        return approvedReceivable;
    }

    public BigInteger paidReceivable() {
        return paidReceivable;
    }

    public BigInteger reversedReceivable() {
        return reversedReceivable;
    }

    public BigInteger disputedReceivable() {
        return disputedReceivable;
    }

    public BigInteger lastAccruedAt() {
        return lastAccruedAt;
    }
}
