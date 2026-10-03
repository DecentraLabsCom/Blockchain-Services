package decentralabs.blockchain.service.accesspolicy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AccessPolicyEvaluatorTest {

    private final AccessPolicyEvaluator evaluator = new AccessPolicyEvaluator();

    @Test
    void freeLabAlwaysAllowsBeforePolicyEvaluation() {
        var profile = profile(AccessPolicyDecision.DENY);

        var result = evaluator.evaluate(profile, context("student"), BigInteger.ZERO, List.of("Cybersecurity"));

        assertTrue(result.allowed());
        assertEquals("ALLOW_ZERO_PRICE", result.reasonCode());
    }

    @Test
    void paidLabWithoutActivePolicyAllowsWithoutIdentityAttributes() {
        var result = evaluator.evaluate(profile(AccessPolicyDecision.DENY, false), null,
            BigInteger.ONE, List.of("Cybersecurity"));

        assertTrue(result.allowed());
        assertEquals("ALLOW_NO_POLICY", result.reasonCode());
    }

    @Test
    void defaultDecisionAppliesWhenUserDoesNotMatchAnyGroup() {
        var profile = new AccessPolicyProfile(
            "uni.example", "Policy", 4, true, AccessPolicyDecision.DENY,
            List.of(new AccessPolicyGroup("engineering", "Engineering", Map.of(
                "eduPersonEntitlement", List.of("urn:example:engineering")
            ), List.of("Computer Science"), List.of())), List.of());

        var result = evaluator.evaluate(profile, context("student"), BigInteger.TEN, List.of("Computer Science"));

        assertEquals(AccessPolicyDecision.DENY, result.decision());
        assertEquals("NO_MATCH_USER_DISCIPLINE", result.reasonCode());
    }

    @Test
    void allowWinsOverDenyForSameCategory() {
        var profile = new AccessPolicyProfile(
            "uni.example", "Policy", 4, true, AccessPolicyDecision.DENY,
            List.of(
                new AccessPolicyGroup("staff", "Staff", Map.of("role", List.of("staff")), List.of(), List.of("Cybersecurity")),
                new AccessPolicyGroup("security", "Security", Map.of("role", List.of("staff")), List.of("Cybersecurity"), List.of())
            ), List.of());

        var result = evaluator.evaluate(profile, context("staff"), BigInteger.TEN, List.of("Cybersecurity"));

        assertTrue(result.allowed());
        assertEquals("ALLOW_POLICY_MATCH", result.reasonCode());
        assertEquals(List.of("staff", "security"), result.matchedGroupIds());
    }

    @Test
    void unknownCategoriesUseDefaultDecision() {
        var result = evaluator.evaluate(profile(AccessPolicyDecision.ALLOW), context("student"),
            BigInteger.TEN, List.of("Secret discipline"));

        assertTrue(result.allowed());
        assertEquals("NO_MATCH_LAB_CATEGORY", result.reasonCode());
    }

    @Test
    void categoryNormalizerAcceptsMetadataArraysAndAliases() {
        var categories = LabCategoryNormalizer.normalize(List.of("AI/ML", "computer-science", "AI/ML"));

        assertEquals(List.of("Artificial Intelligence & Machine Learning", "Computer Science"), categories);
    }

    private AccessPolicyProfile profile(AccessPolicyDecision decision) {
        return profile(decision, true);
    }

    private AccessPolicyProfile profile(AccessPolicyDecision decision, boolean enabled) {
        return new AccessPolicyProfile("uni.example", "Policy", 1, enabled, decision, List.of(), List.of());
    }

    private InstitutionalIdentityContext context(String role) {
        return new InstitutionalIdentityContext("uni.example", "0xabc", "saml", "https://idp.example",
            Map.of("role", List.of(role)), null, null);
    }
}
