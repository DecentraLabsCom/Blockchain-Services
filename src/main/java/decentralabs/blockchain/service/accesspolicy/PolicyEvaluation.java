package decentralabs.blockchain.service.accesspolicy;

import java.util.List;

public record PolicyEvaluation(
    boolean allowed,
    AccessPolicyDecision decision,
    String policyId,
    int policyVersion,
    boolean policyEnabled,
    List<String> matchedGroupIds,
    List<String> matchedCategories,
    String reasonCode,
    String displayMessage
) {
    public static PolicyEvaluation allow(String policyId, int version, boolean enabled, String reason) {
        return new PolicyEvaluation(true, AccessPolicyDecision.ALLOW, policyId, version, enabled,
            List.of(), List.of(), reason, null);
    }
}
