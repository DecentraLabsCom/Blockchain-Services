package decentralabs.blockchain.dto.wallet;

import java.math.BigInteger;

public final class ProviderReceivableStatus {

    private final BigInteger providerReceivable;
    private final BigInteger totalReceivable;
    private final BigInteger eligibleReservationCount;
    private final BigInteger attestedSessionPayout;
    private final BigInteger potentialNoShowFee;
    private final BigInteger pendingGraceReservationCount;
    private final BigInteger existingAccruedReceivable;
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
        BigInteger totalReceivable,
        BigInteger eligibleReservationCount
    ) {
        this(
            providerReceivable,
            totalReceivable,
            eligibleReservationCount,
            BigInteger.ZERO,
            BigInteger.ZERO,
            BigInteger.ZERO,
            providerReceivable,
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
        this(
            providerReceivable,
            totalReceivable,
            eligibleReservationCount,
            BigInteger.ZERO,
            BigInteger.ZERO,
            BigInteger.ZERO,
            providerReceivable,
            accruedReceivable,
            settlementQueued,
            invoicedReceivable,
            approvedReceivable,
            paidReceivable,
            reversedReceivable,
            disputedReceivable,
            lastAccruedAt
        );
    }

    public ProviderReceivableStatus(
        BigInteger providerReceivable,
        BigInteger totalReceivable,
        BigInteger eligibleReservationCount,
        BigInteger attestedSessionPayout,
        BigInteger potentialNoShowFee,
        BigInteger pendingGraceReservationCount,
        BigInteger existingAccruedReceivable,
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
        this.totalReceivable = totalReceivable;
        this.eligibleReservationCount = eligibleReservationCount;
        this.attestedSessionPayout = attestedSessionPayout;
        this.potentialNoShowFee = potentialNoShowFee;
        this.pendingGraceReservationCount = pendingGraceReservationCount;
        this.existingAccruedReceivable = existingAccruedReceivable;
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

    public BigInteger totalReceivable() {
        return totalReceivable;
    }

    public BigInteger eligibleReservationCount() {
        return eligibleReservationCount;
    }

    public BigInteger attestedSessionPayout() {
        return attestedSessionPayout;
    }

    public BigInteger potentialNoShowFee() {
        return potentialNoShowFee;
    }

    public BigInteger pendingGraceReservationCount() {
        return pendingGraceReservationCount;
    }

    public BigInteger existingAccruedReceivable() {
        return existingAccruedReceivable;
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
