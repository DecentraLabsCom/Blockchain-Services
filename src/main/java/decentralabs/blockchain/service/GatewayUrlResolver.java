package decentralabs.blockchain.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

/**
 * Resolves the external base domain used for issuer URLs and metadata.
 * <p>
 * Resolution order:
 * <ol>
 *     <li>Explicit {@code BASE_DOMAIN} environment/property (trimmed, trailing slashes removed)</li>
 *     <li>{@code SERVER_NAME} + {@code HTTPS_PORT} (defaults to HTTPS scheme, omits :443)</li>
 *     <li>{@code SERVER_NAME} + {@code HTTP_PORT} (falls back to {@code server.port} or 8080)</li>
 *     <li>Ultimately {@code http://localhost:8080} if nothing else is provided</li>
 * </ol>
 * This keeps standalone blockchain-services behavior identical to the gateway deployment.
 */
@Service
public class GatewayUrlResolver {

    private final String configuredBaseDomain;
    private final String serverName;
    private final String httpsPort;
    private final String httpPort;
    private final String applicationPort;

    public GatewayUrlResolver(
        @Value("${base.domain:}") String configuredBaseDomain,
        @Value("${SERVER_NAME:}") String serverName,
        @Value("${HTTPS_PORT:}") String httpsPort,
        @Value("${HTTP_PORT:}") String httpPort,
        @Value("${server.port:8080}") String applicationPort
    ) {
        this.configuredBaseDomain = configuredBaseDomain;
        this.serverName = serverName;
        this.httpsPort = httpsPort;
        this.httpPort = httpPort;
        this.applicationPort = applicationPort;
    }

    /**
     * Returns the normalized base domain (scheme + host + optional port).
     */
    public String resolveBaseDomain() {
        String explicit = normalize(configuredBaseDomain);
        if (StringUtils.hasText(explicit)) {
            return explicit;
        }

        String host = StringUtils.hasText(serverName) ? serverName.trim() : "localhost";
        boolean httpsAvailable = StringUtils.hasText(httpsPort);
        String scheme = httpsAvailable ? "https" : "http";
        String port = httpsAvailable ? httpsPort.trim() : fallbackHttpPort();

        if (!StringUtils.hasText(port)) {
            port = httpsAvailable ? "443" : "80";
        }

        boolean omitPort = ("https".equals(scheme) && "443".equals(port))
            || ("http".equals(scheme) && "80".equals(port));

        StringBuilder builder = new StringBuilder(scheme).append("://").append(host.trim());
        if (!omitPort) {
            builder.append(":").append(port);
        }
        return builder.toString();
    }

    /**
     * Builds the issuer URL by appending the auth base path.
     */
    public String resolveIssuer(String authPath) {
        String path = (authPath == null || authPath.isBlank()) ? "/auth" : authPath;
        if (!path.startsWith("/")) {
            path = "/" + path;
        }
        return resolveBaseDomain() + path;
    }

    private String fallbackHttpPort() {
        if (StringUtils.hasText(httpPort)) {
            return httpPort.trim();
        }
        return applicationPort;
    }

    private String normalize(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        String sanitized = value.trim();
        while (sanitized.endsWith("/")) {
            sanitized = sanitized.substring(0, sanitized.length() - 1);
        }
        return sanitized;
    }
}
