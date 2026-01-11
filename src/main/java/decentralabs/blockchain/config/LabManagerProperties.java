package decentralabs.blockchain.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "gateway.lab-manager")
public class LabManagerProperties {

    /** Token value used by lab manager clients. */
    private String token;

    /** HTTP header name for the lab manager token. */
    private String tokenHeader = "X-Lab-Manager-Token";
}
