package decentralabs.blockchain.controller.accesspolicy;

import decentralabs.blockchain.dto.accesspolicy.AccessPolicyProfileRequest;
import decentralabs.blockchain.dto.accesspolicy.AccessPolicyTestRequest;
import decentralabs.blockchain.service.accesspolicy.AccessPolicyDecision;
import decentralabs.blockchain.service.accesspolicy.AccessPolicyEvaluator;
import decentralabs.blockchain.service.accesspolicy.AccessPolicyProfile;
import decentralabs.blockchain.service.accesspolicy.InstitutionalIdentityContext;
import decentralabs.blockchain.service.accesspolicy.LabCategoryAccessPolicyService;
import decentralabs.blockchain.service.accesspolicy.PolicyEvaluation;
import decentralabs.blockchain.service.organization.ProviderConfigurationPersistenceService;
import java.math.BigInteger;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/wallet-admin/access-policies")
@RequiredArgsConstructor
@PreAuthorize("@walletDashboardAuthorizationService.canManageInstitutionPolicies()")
public class WalletAccessPolicyAdminController {
    private final LabCategoryAccessPolicyService service;
    private final ProviderConfigurationPersistenceService configuration;
    private final AccessPolicyEvaluator evaluator = new AccessPolicyEvaluator();

    @GetMapping
    public Map<String, Object> get() { return envelope(currentProfile()); }

    @GetMapping("/effective")
    public Map<String, Object> effective() { return envelope(currentProfile()); }

    @GetMapping("/{institutionId}")
    public Map<String, Object> getForInstitution(@PathVariable String institutionId) {
        requireInstitution(institutionId);
        return envelope(currentProfile());
    }

    @PutMapping
    public Map<String, Object> update(@RequestBody AccessPolicyProfileRequest request) {
        String institution = currentInstitution();
        AccessPolicyProfile current = currentProfile();
        AccessPolicyProfile next = new AccessPolicyProfile(institution,
            textOrDefault(request == null ? null : request.name(), current.name()),
            current.version() + 1,
            request != null && Boolean.TRUE.equals(request.enabled()),
            request == null || request.defaultDecision() == null ? current.defaultDecision() : request.defaultDecision(),
            request == null ? current.groups() : request.groups(), request == null ? current.overrides() : request.overrides());
        service.save(next, "wallet-dashboard", "UPDATED");
        return envelope(next);
    }

    @PutMapping("/{institutionId}")
    public Map<String, Object> updateForInstitution(@PathVariable String institutionId, @RequestBody AccessPolicyProfileRequest request) {
        requireInstitution(institutionId);
        return update(request);
    }

    @PostMapping("/activate")
    public Map<String, Object> activate() { return setEnabled(true); }

    @PostMapping("/deactivate")
    public Map<String, Object> deactivate() { return setEnabled(false); }

    @PostMapping("/{institutionId}/activate")
    public Map<String, Object> activateForInstitution(@PathVariable String institutionId) {
        requireInstitution(institutionId);
        return setEnabled(true);
    }

    @PostMapping("/{institutionId}/deactivate")
    public Map<String, Object> deactivateForInstitution(@PathVariable String institutionId) {
        requireInstitution(institutionId);
        return setEnabled(false);
    }

    @PostMapping("/test")
    public PolicyEvaluation test(@RequestBody AccessPolicyTestRequest request) {
        AccessPolicyProfile profile = currentProfile();
        InstitutionalIdentityContext context = new InstitutionalIdentityContext(currentInstitution(), "test", "dashboard", "dashboard",
            request == null ? Map.of() : request.attributes(), Instant.now(), null);
        return evaluator.evaluate(profile, context, request == null ? BigInteger.ZERO : request.price(), request == null ? List.of() : request.categories());
    }

    @PostMapping("/{institutionId}/test")
    public PolicyEvaluation testForInstitution(@PathVariable String institutionId, @RequestBody AccessPolicyTestRequest request) {
        requireInstitution(institutionId);
        return test(request);
    }

    @GetMapping("/export")
    public AccessPolicyProfile export() { return currentProfile(); }

    @PostMapping("/import")
    public Map<String, Object> importPolicy(@RequestBody AccessPolicyProfile imported) {
        if (imported == null) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_access_policy");
        AccessPolicyProfile current = new AccessPolicyProfile(currentInstitution(), imported.name(), currentProfile().version() + 1,
            imported.enabled(), imported.defaultDecision(), imported.groups(), imported.overrides());
        service.save(current, "wallet-dashboard", "IMPORTED");
        return envelope(current);
    }

    @PostMapping("/{institutionId}/import")
    public Map<String, Object> importForInstitution(@PathVariable String institutionId, @RequestBody AccessPolicyProfile imported) {
        requireInstitution(institutionId);
        return importPolicy(imported);
    }

    @GetMapping("/audit")
    public List<Map<String, Object>> audit(@RequestParam(defaultValue = "50") int limit) {
        return service.audit(currentInstitution(), limit);
    }

    private Map<String, Object> setEnabled(boolean enabled) {
        AccessPolicyProfile current = currentProfile();
        AccessPolicyProfile next = new AccessPolicyProfile(current.institutionId(), current.name(), current.version() + 1, enabled,
            current.defaultDecision(), current.groups(), current.overrides());
        service.save(next, "wallet-dashboard", enabled ? "ACTIVATED" : "DEACTIVATED");
        return envelope(next);
    }

    private Map<String, Object> envelope(AccessPolicyProfile profile) {
        return Map.of("institutionId", profile.institutionId(), "policy", profile,
            "audit", service.audit(profile.institutionId(), 20));
    }

    private AccessPolicyProfile currentProfile() {
        String institution = currentInstitution();
        AccessPolicyProfile profile = service.profile(institution);
        return profile == null ? new AccessPolicyProfile(institution, "Institutional access policy", 0, false,
            AccessPolicyDecision.DENY, List.of(), List.of()) : profile;
    }

    private String currentInstitution() {
        Properties properties = configuration.loadConfigurationSafe();
        String value = properties.getProperty("provider.organization", "");
        if (value.isBlank()) throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "institution_not_configured");
        return value.trim().toLowerCase();
    }

    private void requireInstitution(String institutionId) {
        if (institutionId == null || !currentInstitution().equalsIgnoreCase(institutionId.trim())) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "access_policy_not_found");
        }
    }

    private String textOrDefault(String value, String fallback) { return value == null || value.isBlank() ? fallback : value.trim(); }
}
