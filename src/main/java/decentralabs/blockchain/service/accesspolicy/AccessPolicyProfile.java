package decentralabs.blockchain.service.accesspolicy;

import java.util.List;

public record AccessPolicyProfile(
    String institutionId,
    String name,
    int version,
    boolean enabled,
    AccessPolicyDecision defaultDecision,
    List<AccessPolicyGroup> groups,
    List<AccessPolicyOverride> overrides
) {
    public AccessPolicyProfile {
        defaultDecision = defaultDecision == null ? AccessPolicyDecision.DENY : defaultDecision;
        groups = groups == null ? List.of() : List.copyOf(groups);
        overrides = overrides == null ? List.of() : List.copyOf(overrides);
    }
}
