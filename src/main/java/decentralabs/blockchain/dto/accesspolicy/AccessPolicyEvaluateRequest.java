package decentralabs.blockchain.dto.accesspolicy;

import java.math.BigInteger;
import java.util.List;

public record AccessPolicyEvaluateRequest(
    String institutionalSessionToken,
    BigInteger labId,
    BigInteger price,
    List<String> categories
) {}
