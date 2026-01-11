package decentralabs.blockchain.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "gateway.server")
public class ServerProperties {

    /** Server name (hostname) used for URL resolution. Can be set via env SERVER_NAME. */
    private String name;

    /** Default HTTPS port (as string to preserve ':' formatting and allow empty). */
    private String httpsPort = "443";

    /** Default HTTP port. */
    private String httpPort = "80";
}
