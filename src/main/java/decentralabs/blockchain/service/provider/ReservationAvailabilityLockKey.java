package decentralabs.blockchain.service.provider;

import java.math.BigInteger;
import java.util.Locale;

/** Identifies the on-chain reservation-capacity namespace that must be serialized. */
public record ReservationAvailabilityLockKey(
    BigInteger chainId,
    String contractAddress,
    BigInteger labId
) {

    public ReservationAvailabilityLockKey {
        if (chainId == null || chainId.signum() <= 0) {
            throw new IllegalArgumentException("chainId must be positive");
        }
        if (contractAddress == null || contractAddress.isBlank()) {
            throw new IllegalArgumentException("contractAddress is required");
        }
        if (labId == null || labId.signum() <= 0) {
            throw new IllegalArgumentException("labId must be positive");
        }
        contractAddress = contractAddress.trim().toLowerCase(Locale.ROOT);
    }
}
