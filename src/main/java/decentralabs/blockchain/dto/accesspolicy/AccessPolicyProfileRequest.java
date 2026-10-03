package decentralabs.blockchain.dto.accesspolicy;

import decentralabs.blockchain.service.accesspolicy.AccessPolicyDecision;
import decentralabs.blockchain.service.accesspolicy.AccessPolicyGroup;
import decentralabs.blockchain.service.accesspolicy.AccessPolicyOverride;
import java.util.List;

public record AccessPolicyProfileRequest(
    String name,
    AccessPolicyDecision defaultDecision,
    Boolean enabled,
    List<AccessPolicyGroup> groups,
    List<AccessPolicyOverride> overrides
) {}
