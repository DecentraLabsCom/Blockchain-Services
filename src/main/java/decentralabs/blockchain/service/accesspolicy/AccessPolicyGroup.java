package decentralabs.blockchain.service.accesspolicy;

import java.util.List;
import java.util.Map;

public record AccessPolicyGroup(
    String id,
    String label,
    Map<String, List<String>> matchers,
    List<String> allowedCategories,
    List<String> deniedCategories
) {}
