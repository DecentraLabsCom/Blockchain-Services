package decentralabs.blockchain.service.auth;

import java.util.Collections;
import java.util.List;
import java.util.Map;

public record SamlAssertionAttributes(
    String issuer,
    String userid,
    String affiliation,
    String email,
    String displayName,
    List<String> schacHomeOrganizations,
    Map<String, List<String>> attributes
) {
    public SamlAssertionAttributes {
        schacHomeOrganizations = schacHomeOrganizations == null
            ? Collections.emptyList()
            : List.copyOf(schacHomeOrganizations);
        attributes = attributes == null
            ? Collections.emptyMap()
            : Collections.unmodifiableMap(attributes);
    }
}
