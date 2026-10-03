package decentralabs.blockchain.dto.accesspolicy;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

public record AccessPolicyTestRequest(
    Map<String, List<String>> attributes,
    BigInteger price,
    List<String> categories
) {}
