package decentralabs.blockchain.util;

import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.regex.Pattern;
import org.web3j.crypto.Hash;
import org.web3j.utils.Numeric;

/**
 * Canonical encoding shared by the SQL settlement outbox and the Diamond.
 * Human-facing references are hashed as UTF-8; existing bytes32 references
 * (reservation sets and explicit claim ids) are retained as-is.
 */
public final class ProviderSettlementReferenceHasher {

    private static final Pattern BYTES32 = Pattern.compile("0x[0-9a-fA-F]{64}");
    private static final String ZERO_BYTES32 = "0x" + "0".repeat(64);

    private ProviderSettlementReferenceHasher() {
    }

    public static byte[] claimId(String value) {
        return bytes32OrKeccak(value, "claimId");
    }

    public static byte[] reservationHash(String value) {
        String normalized = requireText(value, "reservationHash");
        if (!BYTES32.matcher(normalized).matches() || ZERO_BYTES32.equalsIgnoreCase(normalized)) {
            throw new IllegalArgumentException("reservationHash must be a non-zero bytes32 value");
        }
        return Numeric.hexStringToByteArray(normalized);
    }

    public static byte[] reference(String value, String fieldName) {
        return keccak(requireText(value, fieldName));
    }

    public static String hex(byte[] value) {
        return Numeric.toHexString(value).toLowerCase(Locale.ROOT);
    }

    private static byte[] bytes32OrKeccak(String value, String fieldName) {
        String normalized = requireText(value, fieldName);
        if (BYTES32.matcher(normalized).matches() && !ZERO_BYTES32.equalsIgnoreCase(normalized)) {
            return Numeric.hexStringToByteArray(normalized);
        }
        return keccak(normalized);
    }

    private static byte[] keccak(String value) {
        return Hash.sha3(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String requireText(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " is required");
        }
        return value.trim();
    }
}
