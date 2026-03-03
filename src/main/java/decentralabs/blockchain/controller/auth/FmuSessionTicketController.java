package decentralabs.blockchain.controller.auth;

import decentralabs.blockchain.dto.auth.FmuSessionTicketIssueRequest;
import decentralabs.blockchain.dto.auth.FmuSessionTicketIssueResponse;
import decentralabs.blockchain.dto.auth.FmuSessionTicketRedeemRequest;
import decentralabs.blockchain.dto.auth.FmuSessionTicketRedeemResponse;
import decentralabs.blockchain.service.auth.FmuSessionTicketService;
import decentralabs.blockchain.service.auth.SessionTicketException;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth/fmu/session-ticket")
@ConditionalOnProperty(value = "features.providers.enabled", havingValue = "true", matchIfMissing = true)
@RequiredArgsConstructor
@Slf4j
public class FmuSessionTicketController {

    private final FmuSessionTicketService sessionTicketService;

    @PostMapping("/issue")
    public ResponseEntity<?> issue(
        @RequestHeader(value = "Authorization", required = false) String authorization,
        @RequestBody(required = false) FmuSessionTicketIssueRequest request
    ) {
        try {
            FmuSessionTicketIssueResponse response = sessionTicketService.issue(authorization, request);
            return ResponseEntity.ok(response);
        } catch (SessionTicketException ex) {
            return ResponseEntity.status(ex.getStatus()).body(Map.of(
                "code", ex.getCode(),
                "error", ex.getMessage()
            ));
        } catch (Exception ex) {
            log.error("Failed to issue FMU session ticket", ex);
            return ResponseEntity.internalServerError().body(Map.of(
                "code", "INTERNAL_ERROR",
                "error", "Internal server error"
            ));
        }
    }

    @PostMapping("/redeem")
    public ResponseEntity<?> redeem(@RequestBody(required = false) FmuSessionTicketRedeemRequest request) {
        try {
            FmuSessionTicketRedeemResponse response = sessionTicketService.redeem(request);
            return ResponseEntity.ok(response);
        } catch (SessionTicketException ex) {
            return ResponseEntity.status(ex.getStatus()).body(Map.of(
                "code", ex.getCode(),
                "error", ex.getMessage()
            ));
        } catch (Exception ex) {
            log.error("Failed to redeem FMU session ticket", ex);
            return ResponseEntity.internalServerError().body(Map.of(
                "code", "INTERNAL_ERROR",
                "error", "Internal server error"
            ));
        }
    }
}
