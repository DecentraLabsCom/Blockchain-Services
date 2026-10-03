package decentralabs.blockchain.dto.accesspolicy;

import java.util.List;

public record AccessPolicyBatchRequest(
    String institutionalSessionToken,
    List<AccessPolicyEvaluateRequest> evaluations
) {}
