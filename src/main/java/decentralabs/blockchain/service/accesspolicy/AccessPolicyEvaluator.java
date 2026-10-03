package decentralabs.blockchain.service.accesspolicy;

import java.math.BigInteger;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class AccessPolicyEvaluator {
    public PolicyEvaluation evaluate(
        AccessPolicyProfile profile,
        InstitutionalIdentityContext context,
        BigInteger price,
        List<String> rawCategories
    ) {
        String policyId = profile == null ? null : profile.institutionId();
        int version = profile == null ? 0 : profile.version();
        boolean enabled = profile != null && profile.enabled();
        if (price == null || price.signum() <= 0) return PolicyEvaluation.allow(policyId, version, enabled, "ALLOW_ZERO_PRICE");
        if (profile == null || !profile.enabled()) return PolicyEvaluation.allow(policyId, version, false, "ALLOW_NO_POLICY");

        List<String> categories = LabCategoryNormalizer.recognized(rawCategories);
        AccessPolicyDecision defaultDecision = profile.defaultDecision();
        if (categories.isEmpty()) {
            return result(profile, defaultDecision, "NO_MATCH_LAB_CATEGORY", List.of(), List.of());
        }
        if (context == null || !context.hasAttributes()) {
            return result(profile, defaultDecision, "NO_MATCH_USER_DISCIPLINE", List.of(), categories);
        }

        List<AccessPolicyGroup> matchedGroups = profile.groups().stream()
            .filter(group -> matches(group, context.attributes()))
            .toList();
        LinkedHashSet<String> matchedIds = new LinkedHashSet<>();
        LinkedHashSet<String> allows = new LinkedHashSet<>();
        LinkedHashSet<String> denies = new LinkedHashSet<>();
        matchedGroups.forEach(group -> {
            if (group.id() != null) matchedIds.add(group.id());
            allows.addAll(LabCategoryNormalizer.normalize(group.allowedCategories()));
            denies.addAll(LabCategoryNormalizer.normalize(group.deniedCategories()));
        });
        profile.overrides().forEach(override -> {
            String category = LabCategoryNormalizer.canonical(override.category());
            if (category == null) return;
            if (override.decision() == AccessPolicyDecision.ALLOW) allows.add(category);
            if (override.decision() == AccessPolicyDecision.DENY) denies.add(category);
        });
        List<String> matchingAllows = categories.stream().filter(allows::contains).toList();
        List<String> matchingDenies = categories.stream().filter(denies::contains).toList();
        if (!matchingAllows.isEmpty()) return result(profile, AccessPolicyDecision.ALLOW, "ALLOW_POLICY_MATCH", List.copyOf(matchedIds), matchingAllows);
        if (!matchingDenies.isEmpty()) return result(profile, AccessPolicyDecision.DENY, "DENY_POLICY_MATCH", List.copyOf(matchedIds), matchingDenies);
        return result(profile, defaultDecision, "NO_MATCH_USER_DISCIPLINE", List.copyOf(matchedIds), categories);
    }

    private boolean matches(AccessPolicyGroup group, Map<String, List<String>> attributes) {
        if (group == null || group.matchers() == null || group.matchers().isEmpty()) return false;
        return group.matchers().entrySet().stream().allMatch(entry -> {
            List<String> actual = findValues(attributes, entry.getKey());
            return entry.getValue() != null && entry.getValue().stream().anyMatch(expected ->
                actual.stream().anyMatch(value -> wildcardEquals(expected, value)));
        });
    }

    private List<String> findValues(Map<String, List<String>> attributes, String requestedKey) {
        if (requestedKey == null) return List.of();
        String target = requestedKey.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
        return attributes.entrySet().stream()
            .filter(entry -> entry.getKey() != null
                && entry.getKey().toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "").equals(target))
            .flatMap(entry -> entry.getValue() == null ? java.util.stream.Stream.empty() : entry.getValue().stream())
            .toList();
    }

    private boolean wildcardEquals(String expected, String actual) {
        if (expected == null || actual == null) return false;
        String left = expected.trim().toLowerCase(Locale.ROOT);
        String right = actual.trim().toLowerCase(Locale.ROOT);
        if ("*".equals(left)) return true;
        if (left.endsWith("*")) return right.startsWith(left.substring(0, left.length() - 1));
        return left.equals(right);
    }

    private PolicyEvaluation result(AccessPolicyProfile profile, AccessPolicyDecision decision, String reason,
        List<String> matchedGroups, List<String> categories) {
        boolean allowed = decision == AccessPolicyDecision.ALLOW;
        return new PolicyEvaluation(allowed, decision, profile.institutionId(), profile.version(), profile.enabled(),
            matchedGroups, categories, reason, allowed ? null : "This lab is restricted by your institution's access policy.");
    }
}
