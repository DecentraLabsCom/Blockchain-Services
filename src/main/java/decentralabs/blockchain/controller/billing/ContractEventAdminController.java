package decentralabs.blockchain.controller.billing;

import decentralabs.blockchain.security.AdminNetworkAccessPolicy;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import jakarta.servlet.http.HttpServletRequest;

/** Read-only operator view of contract-event dead letters and reorg evidence. */
@RestController
@RequestMapping("/billing/admin/contract-events")
@RequiredArgsConstructor
public class ContractEventAdminController {

    private final ObjectProvider<JdbcTemplate> jdbcTemplateProvider;
    private final AdminNetworkAccessPolicy adminNetworkAccessPolicy;

    @Value("${security.access-token:}")
    private String accessToken;

    @Value("${security.access-token-header:X-Access-Token}")
    private String accessTokenHeader;

    @Value("${security.access-token-cookie:access_token}")
    private String accessTokenCookie;

    @Value("${security.access-token.required:true}")
    private boolean accessTokenRequired;

    @GetMapping("/dead-letter")
    public ResponseEntity<?> deadLetters(
        HttpServletRequest request,
        @RequestParam(defaultValue = "100") int limit
    ) {
        if (!adminNetworkAccessPolicy.isRequestAllowed(request, () -> hasValidAccessToken(request))) {
            return ResponseEntity.status(403).body(Map.of("success", false, "error", "Access denied"));
        }
        JdbcTemplate jdbcTemplate = jdbcTemplateProvider.getIfAvailable();
        if (jdbcTemplate == null) {
            return ResponseEntity.status(503).body(Map.of("success", false, "error", "Database unavailable"));
        }
        int boundedLimit = Math.max(1, Math.min(500, limit));
        List<Map<String, Object>> rows = jdbcTemplate.queryForList(
            "SELECT chain_id, contract_address, event_signature, transaction_hash, log_index, block_number, "
                + "block_hash, confirmations, canonical_status, event_name, status, attempts, last_error, "
                + "first_seen_at, updated_at FROM contract_event_journal "
                + "WHERE status='DEAD_LETTER' ORDER BY updated_at DESC LIMIT " + boundedLimit
        );
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("success", true);
        response.put("count", rows.size());
        response.put("events", rows);
        return ResponseEntity.ok(response);
    }

    private boolean hasValidAccessToken(HttpServletRequest request) {
        if (!accessTokenRequired) {
            return true;
        }
        if (accessToken == null || accessToken.isBlank()) {
            return false;
        }
        String headerToken = request.getHeader(accessTokenHeader);
        if (headerToken != null && accessToken.equals(headerToken.trim())) {
            return true;
        }
        if (request.getCookies() != null) {
            for (var cookie : request.getCookies()) {
                if (accessTokenCookie.equals(cookie.getName()) && accessToken.equals(cookie.getValue())) {
                    return true;
                }
            }
        }
        return false;
    }
}
