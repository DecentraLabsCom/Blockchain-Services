package decentralabs.blockchain.service.accesspolicy;

import decentralabs.blockchain.dto.health.LabMetadata;
import decentralabs.blockchain.dto.intent.ReservationIntentPayload;
import decentralabs.blockchain.service.auth.InstitutionalSessionCredentialService.Credential;
import decentralabs.blockchain.service.health.LabMetadataService;
import decentralabs.blockchain.service.intent.IntentRecord;
import decentralabs.blockchain.util.PucHashUtil;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
public class LabCategoryAccessPolicyService {
    private final AccessPolicyPersistenceService policyPersistence;
    private final InstitutionalIdentityContextPersistenceService identityPersistence;
    private final LabMetadataService labMetadataService;
    private final AccessPolicyEvaluator evaluator = new AccessPolicyEvaluator();

    public PolicyEvaluation evaluate(Credential credential, BigInteger labId, BigInteger price, List<String> categoryHint) {
        if (credential == null) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "missing_institutional_session");
        AccessPolicyProfile profile = policyPersistence.find(credential.institutionId());
        List<String> categories = categoryHint == null ? List.of() : categoryHint;
        if (profile != null && profile.enabled()) {
            LabMetadata metadata = labMetadataService.getLabMetadataForLab(labId);
            categories = new ArrayList<>();
            if (metadata.getCategory() != null) categories.add(metadata.getCategory());
            if (metadata.getCategories() != null) categories.addAll(metadata.getCategories());
        }
        InstitutionalIdentityContext context = identityPersistence.find(credential.institutionId(), PucHashUtil.hashPuc(credential.puc()));
        if (profile != null && profile.enabled() && context == null) {
            return new PolicyEvaluation(false, AccessPolicyDecision.DENY, profile.institutionId(), profile.version(), true,
                List.of(), List.of(), "IDENTITY_CONTEXT_UNAVAILABLE",
                "Institutional identity could not be resolved.");
        }
        return evaluator.evaluate(profile, context, price, categories);
    }

    public void enforce(Credential credential, BigInteger labId, BigInteger price, List<String> categoryHint) {
        PolicyEvaluation result;
        try {
            result = evaluate(credential, labId, price, categoryHint);
        } catch (ResponseStatusException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "access_policy_unavailable", ex);
        }
        if (!result.allowed()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "LAB_CATEGORY_ACCESS_DENIED");
        }
    }

    /**
     * Re-checks a durable reservation immediately before submitting its
     * on-chain transaction. The record contains only the institutional hash;
     * no raw PUC or session token is needed at execution time.
     */
    public void enforceStored(IntentRecord record) {
        if (record == null) throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "access_policy_unavailable");
        ReservationIntentPayload payload = record.getReservationPayload();
        String institutionId = record.getInstitutionId();
        if ((institutionId == null || institutionId.isBlank()) && payload != null) {
            institutionId = payload.getSchacHomeOrganization();
        }
        BigInteger labId = parseBigInteger(record.getLabId(), payload == null ? null : payload.getLabId());
        BigInteger price = payload == null ? null : payload.getPrice();
        PolicyEvaluation result = evaluateByIdentityReference(institutionId, record.getPucHash(), labId, price, List.of());
        if (!result.allowed()) throw new ResponseStatusException(HttpStatus.FORBIDDEN, "LAB_CATEGORY_ACCESS_DENIED");
    }

    private PolicyEvaluation evaluateByIdentityReference(
        String institutionId,
        String identityReference,
        BigInteger labId,
        BigInteger price,
        List<String> categoryHint
    ) {
        AccessPolicyProfile profile = policyPersistence.find(institutionId);
        List<String> categories = categoryHint == null ? List.of() : categoryHint;
        if (profile != null && profile.enabled()) {
            LabMetadata metadata = labMetadataService.getLabMetadataForLab(labId);
            categories = new ArrayList<>();
            if (metadata.getCategory() != null) categories.add(metadata.getCategory());
            if (metadata.getCategories() != null) categories.addAll(metadata.getCategories());
        }
        InstitutionalIdentityContext context = identityPersistence.find(institutionId, identityReference);
        if (profile != null && profile.enabled() && context == null) {
            return new PolicyEvaluation(false, AccessPolicyDecision.DENY, profile.institutionId(), profile.version(), true,
                List.of(), List.of(), "IDENTITY_CONTEXT_UNAVAILABLE",
                "Institutional identity could not be resolved.");
        }
        return evaluator.evaluate(profile, context, price, categories);
    }

    private BigInteger parseBigInteger(String raw, BigInteger fallback) {
        if (raw == null || raw.isBlank()) return fallback;
        try {
            return new BigInteger(raw);
        } catch (NumberFormatException ex) {
            return fallback;
        }
    }

    public AccessPolicyProfile profile(String institutionId) { return policyPersistence.find(institutionId); }
    public void save(AccessPolicyProfile profile, String actor, String event) { policyPersistence.save(profile, actor, event); }
    public List<java.util.Map<String, Object>> audit(String institutionId, int limit) { return policyPersistence.audit(institutionId, limit); }
}
