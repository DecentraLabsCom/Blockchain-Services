package decentralabs.blockchain.util;

import java.nio.charset.StandardCharsets;
import org.web3j.crypto.Hash;
import org.web3j.utils.Numeric;

public final class PucHashUtil {
    private PucHashUtil() {
    }

    public static String hashPuc(String puc) {
        if (puc == null || puc.isBlank()) {
            return zeroHash();
        }
        return normalizeBytes32(Numeric.toHexString(Hash.sha3(puc.getBytes(StandardCharsets.UTF_8))));
    }

    public static String normalizeBytes32(String value) {
        String clean = Numeric.cleanHexPrefix(value == null ? "" : value.trim());
        if (clean.length() > 64) {
            clean = clean.substring(clean.length() - 64);
        }
        if (clean.length() < 64) {
            clean = "0".repeat(64 - clean.length()) + clean;
        }
        return "0x" + clean;
    }

    public static String zeroHash() {
        return "0x" + "0".repeat(64);
    }
}
