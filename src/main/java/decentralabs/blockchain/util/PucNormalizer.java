package decentralabs.blockchain.util;

import java.util.Locale;

/**
 * Canonical PUC normalization shared across Marketplace and blockchain-services.
 *
 * For SCHAC personalUniqueCode URNs, returns the trailing non-empty segment.
 * Example: urn:schac:personalUniqueCode:es:dni:12345678A -> 12345678A
 */
public final class PucNormalizer {

    private PucNormalizer() {
    }

    public static String normalize(String value) {
        if (value == null) {
            return null;
        }

        String trimmed = value.trim();
        if (trimmed.isEmpty()) {
            return "";
        }

        String lower = trimmed.toLowerCase(Locale.ROOT);
        if (!lower.contains("personaluniquecode") && !lower.contains("schacpersonaluniquecode")) {
            return trimmed;
        }

        String[] segments = trimmed.split(":");
        for (int i = segments.length - 1; i >= 0; i--) {
            String segment = segments[i] == null ? "" : segments[i].trim();
            if (!segment.isEmpty()) {
                return segment;
            }
        }

        return trimmed;
    }
}

