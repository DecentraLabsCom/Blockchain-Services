package decentralabs.blockchain.util;

import java.net.URI;
import java.util.Locale;
import org.springframework.util.StringUtils;

public final class GatewayIdentity {
    private GatewayIdentity() { }

    public static String fromAccessUri(String accessUri) {
        if (!StringUtils.hasText(accessUri)) {
            return null;
        }
        try {
            URI uri = URI.create(accessUri.trim());
            String host = uri.getHost();
            if (!StringUtils.hasText(host)) {
                return null;
            }
            String normalizedHost = host.toLowerCase(Locale.ROOT);
            if (normalizedHost.contains(":")) {
                normalizedHost = "[" + normalizedHost + "]";
            }
            String scheme = StringUtils.hasText(uri.getScheme())
                ? uri.getScheme().toLowerCase(Locale.ROOT)
                : "https";
            int port = uri.getPort();
            boolean defaultPort = port < 0
                || ("https".equals(scheme) && port == 443)
                || ("http".equals(scheme) && port == 80);
            return defaultPort ? normalizedHost : normalizedHost + ":" + port;
        } catch (RuntimeException ex) {
            return null;
        }
    }

    public static String normalizeGatewayId(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        if (normalized.contains("://") || normalized.contains("/")
            || normalized.contains("?") || normalized.contains("#")
            || normalized.chars().anyMatch(Character::isWhitespace)) {
            return null;
        }
        if (!normalized.startsWith("[") && normalized.endsWith(".")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized.isBlank() ? null : normalized;
    }
}