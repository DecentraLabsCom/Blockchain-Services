package decentralabs.blockchain.controller.accesspolicy;

import decentralabs.blockchain.dto.accesspolicy.AccessPolicyBatchRequest;
import decentralabs.blockchain.dto.accesspolicy.AccessPolicyEvaluateRequest;
import decentralabs.blockchain.service.accesspolicy.LabCategoryAccessPolicyService;
import decentralabs.blockchain.service.accesspolicy.PolicyEvaluation;
import decentralabs.blockchain.service.auth.InstitutionalSessionCredentialService;
import decentralabs.blockchain.service.auth.MarketplaceEndpointAuthService;
import java.math.BigInteger;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/access-policy/labs")
@RequiredArgsConstructor
public class AccessPolicyController {
    private final MarketplaceEndpointAuthService marketplaceAuth;
    private final InstitutionalSessionCredentialService credentialService;
    private final LabCategoryAccessPolicyService accessPolicyService;
    @PostMapping("/evaluate")
    public PolicyEvaluation evaluate(
        @RequestHeader(value = "Authorization", required = false) String authorization,
        @RequestBody AccessPolicyEvaluateRequest request
    ) {
        marketplaceAuth.enforceServiceAuthorization(authorization, "access-policy:evaluate");
        AccessPolicyEvaluateRequest validRequest = requireRequest(request);
        var credential = validateCredential(validRequest.institutionalSessionToken());
        requireLab(validRequest.labId());
        return accessPolicyService.evaluate(credential, validRequest.labId(), validRequest.price(), validRequest.categories());
    }

    @GetMapping("/{labId}/eligibility")
    public PolicyEvaluation eligibility(
        @RequestHeader(value = "Authorization", required = false) String authorization,
        @RequestHeader(value = "X-Institutional-Session", required = false) String sessionToken,
        @PathVariable BigInteger labId,
        @RequestParam(required = false) List<String> categories,
        @RequestParam(required = false) String price
    ) {
        marketplaceAuth.enforceServiceAuthorization(authorization, "access-policy:evaluate");
        var credential = validateCredential(sessionToken);
        requireLab(labId);
        return accessPolicyService.evaluate(credential, labId, parsePrice(price),
            categories == null ? List.of() : categories);
    }

    @PostMapping("/eligibility:batch")
    public List<PolicyEvaluation> batch(
        @RequestHeader(value = "Authorization", required = false) String authorization,
        @RequestBody AccessPolicyBatchRequest request
    ) {
        marketplaceAuth.enforceServiceAuthorization(authorization, "access-policy:evaluate");
        if (request == null || request.evaluations() == null || request.evaluations().size() > 100) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_access_policy_batch");
        }
        var credential = validateCredential(request.institutionalSessionToken());
        return request.evaluations().stream().map(item -> {
            requireLab(item.labId());
            return accessPolicyService.evaluate(credential, item.labId(), item.price(), item.categories());
        }).toList();
    }

    private InstitutionalSessionCredentialService.Credential validateCredential(String token) {
        if (token == null || token.isBlank()) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "missing_institutional_session");
        return credentialService.validate(token);
    }

    private AccessPolicyEvaluateRequest requireRequest(AccessPolicyEvaluateRequest request) {
        if (request == null) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "missing_access_policy_request");
        return request;
    }

    private void requireLab(BigInteger labId) {
        if (labId == null || labId.signum() <= 0) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_lab_id");
    }

    private BigInteger parsePrice(String value) {
        if (value == null || value.isBlank()) return BigInteger.ONE;
        try { return new BigInteger(value); } catch (NumberFormatException ex) { return BigInteger.ONE; }
    }
}
