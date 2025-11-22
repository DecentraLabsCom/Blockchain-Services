package decentralabs.blockchain.controller.treasury;

import decentralabs.blockchain.notification.NotificationConfigService;
import decentralabs.blockchain.notification.NotificationUpdateRequest;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/treasury/admin/notifications")
@RequiredArgsConstructor
@Slf4j
public class NotificationAdminController {

    private final NotificationConfigService notificationConfigService;

    @Value("${admin.dashboard.local-only:true}")
    private boolean adminDashboardLocalOnly;

    @Value("${admin.dashboard.allow-private:true}")
    private boolean adminDashboardAllowPrivate;

    private static final Set<String> LOOPBACK_ADDRESSES = Set.of(
        "127.0.0.1",
        "0:0:0:0:0:0:0:1",
        "::1"
    );

    @GetMapping
    public ResponseEntity<?> getConfig(HttpServletRequest request) {
        if (!isLocalhostRequest(request)) {
            return forbidden();
        }
        return ResponseEntity.ok(Map.of(
            "success", true,
            "config", notificationConfigService.getPublicConfig()
        ));
    }

    @PostMapping
    public ResponseEntity<?> updateConfig(
        @RequestBody NotificationUpdateRequest request,
        HttpServletRequest httpRequest
    ) {
        if (!isLocalhostRequest(httpRequest)) {
            return forbidden();
        }
        try {
            return ResponseEntity.ok(Map.of(
                "success", true,
                "config", notificationConfigService.updateMailConfig(request)
            ));
        } catch (Exception ex) {
            log.error("Failed to update notification config: {}", ex.getMessage(), ex);
            return ResponseEntity.internalServerError().body(Map.of(
                "success", false,
                "error", "Failed to update notification config: " + ex.getMessage()
            ));
        }
    }

    private ResponseEntity<?> forbidden() {
        return ResponseEntity.status(403).body(Map.of(
            "success", false,
            "error", "Access denied: administrative endpoints only accessible from localhost"
        ));
    }

    private boolean isLocalhostRequest(HttpServletRequest request) {
        if (!adminDashboardLocalOnly) {
            return true;
        }
        String candidate = extractClientIp(request);
        boolean allowed = candidate == null
            || LOOPBACK_ADDRESSES.contains(candidate)
            || candidate.startsWith("127.")
            || (adminDashboardAllowPrivate && isPrivateAddress(candidate));
        if (!allowed) {
            log.warn("Blocked administrative notification access from non-local address.");
        }
        return allowed;
    }

    private boolean isPrivateAddress(String address) {
        if (address == null || address.isBlank()) {
            return false;
        }
        return address.startsWith("10.")
            || address.startsWith("192.168.")
            || (address.startsWith("172.") && isInRange(address, 16, 31))
            || address.startsWith("169.254.");
    }

    private boolean isInRange(String address, int start, int end) {
        try {
            String[] parts = address.split("\\.");
            if (parts.length < 2) {
                return false;
            }
            int second = Integer.parseInt(parts[1]);
            return second >= start && second <= end;
        } catch (NumberFormatException ex) {
            return false;
        }
    }

    private String extractClientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
