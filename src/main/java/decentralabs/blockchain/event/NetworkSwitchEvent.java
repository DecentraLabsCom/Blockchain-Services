package decentralabs.blockchain.event;

import lombok.Getter;
import org.springframework.context.ApplicationEvent;

/**
 * Event published when the blockchain network is switched.
 * This event triggers reconfiguration of all network-dependent components.
 */
@Getter
public class NetworkSwitchEvent extends ApplicationEvent {
    
    private final String oldNetwork;
    private final String newNetwork;
    
    public NetworkSwitchEvent(Object source, String oldNetwork, String newNetwork) {
        super(source);
        this.oldNetwork = oldNetwork;
        this.newNetwork = newNetwork;
    }
}
