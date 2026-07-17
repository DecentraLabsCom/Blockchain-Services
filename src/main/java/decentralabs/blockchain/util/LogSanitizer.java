package decentralabs.blockchain.util;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Utility helpers to make sure user controlled values are safe for logging.
 * Removes control characters to prevent log injection and allows masking
 * of identifiers such as wallet addresses or reservation keys.
 */
public final class LogSanitizer {

    private static final Pattern CONTROL_CHARS = Pattern.compile("[\\r\\n\\t]+");

    private LogSanitizer() {
        // Utility class
    }

    /**
     * Removes control characters that could be abused for log injection.
     *
     * @param value User provided value
     * @return Sanitized value safe for log statements
     */
    public static String sanitize(String value) {
        if (value == null) {
            return "";
        }
        return CONTROL_CHARS.matcher(value).replaceAll("_");
    }

    /**
     * Sanitizes enum and other value-object fields without overloading the
     * string-specific sanitizer.
     */
    public static String sanitizeValue(Object value) {
        return sanitize(value == null ? null : String.valueOf(value));
    }

    /**
     * Masks identifiers (wallets, reservation keys, etc.) while keeping
     * enough context for debugging.
     *
     * @param identifier Sensitive identifier
     * @return Short masked representation safe for logs
     */
    public static String maskIdentifier(String identifier) {
        String sanitized = sanitize(identifier);
        if (sanitized.isEmpty()) {
            return "";
        }
        if (sanitized.length() == 1) {
            return "*";
        }
        if (sanitized.length() <= 4) {
            return sanitized.charAt(0) + "***";
        }
        int prefixLength = Math.min(6, sanitized.length() / 2);
        int suffixLength = Math.min(4, Math.max(1, sanitized.length() - prefixLength));
        return sanitized.substring(0, prefixLength) + "..." + sanitized.substring(sanitized.length() - suffixLength);
    }

    /** Masks an identifier represented by a value object. */
    public static String maskIdentifierValue(Object identifier) {
        return maskIdentifier(identifier == null ? null : String.valueOf(identifier));
    }

    /**
     * Returns the sanitized string or a fallback when it is null.
     */
    public static String sanitizeOrDefault(String value, String defaultValue) {
        if (value == null) {
            return Objects.requireNonNullElse(defaultValue, "");
        }
        return sanitize(value);
    }
}
