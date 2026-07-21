package decentralabs.blockchain.dto.billing;

import java.math.BigInteger;
import java.util.List;

/**
 * Read-only snapshot of the service-credit ledger returned by the Diamond.
 *
 * <p>The values in this DTO use the raw on-chain credit unit scale. The
 * billing projection converts them to decimal credits before persistence.</p>
 */
public record CreditLedgerSnapshot(
    BigInteger available,
    BigInteger locked,
    List<Lot> lots,
    List<Movement> movements
) {

    public CreditLedgerSnapshot {
        available = available == null ? BigInteger.ZERO : available;
        locked = locked == null ? BigInteger.ZERO : locked;
        lots = lots == null ? List.of() : List.copyOf(lots);
        movements = movements == null ? List.of() : List.copyOf(movements);
    }

    public record Lot(
        int index,
        BigInteger lotId,
        String fundingOrderReference,
        BigInteger creditAmount,
        BigInteger remaining,
        BigInteger eurGrossAmountCents,
        BigInteger issuedAtEpochSeconds,
        BigInteger expiresAtEpochSeconds,
        boolean expired
    ) {
        public Lot {
            lotId = lotId == null ? BigInteger.ZERO : lotId;
            creditAmount = creditAmount == null ? BigInteger.ZERO : creditAmount;
            remaining = remaining == null ? BigInteger.ZERO : remaining;
            eurGrossAmountCents = eurGrossAmountCents == null ? BigInteger.ZERO : eurGrossAmountCents;
            issuedAtEpochSeconds = issuedAtEpochSeconds == null ? BigInteger.ZERO : issuedAtEpochSeconds;
            expiresAtEpochSeconds = expiresAtEpochSeconds == null ? BigInteger.ZERO : expiresAtEpochSeconds;
        }
    }

    public record Movement(
        String type,
        BigInteger amount,
        String reference,
        BigInteger timestampEpochSeconds,
        int index
    ) {
        public Movement {
            type = type == null ? "ADJUST" : type;
            amount = amount == null ? BigInteger.ZERO : amount;
            timestampEpochSeconds = timestampEpochSeconds == null ? BigInteger.ZERO : timestampEpochSeconds;
        }
    }
}
