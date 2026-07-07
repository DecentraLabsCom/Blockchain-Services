package decentralabs.blockchain.security;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LocalhostFilterTestController {

    @PostMapping("/wallet/test")
    public ResponseEntity<String> wallet() {
        return ResponseEntity.ok("ok");
    }

    @GetMapping("/wallet/health")
    public ResponseEntity<String> walletHealth() {
        return ResponseEntity.ok("ok");
    }

    @GetMapping("/wallet-dashboard/index.html")
    public ResponseEntity<String> walletDashboard() {
        return ResponseEntity.ok("ok");
    }

    @PostMapping("/onboarding/token/apply")
    public ResponseEntity<String> onboarding() {
        return ResponseEntity.ok("ok");
    }

    @GetMapping("/lab-admin/status")
    public ResponseEntity<String> labAdminStatus() {
        return ResponseEntity.ok("ok");
    }

    @PostMapping("/access-audit/internal/session-observed")
    public ResponseEntity<String> accessAuditSessionObserved() {
        return ResponseEntity.ok("ok");
    }
}
