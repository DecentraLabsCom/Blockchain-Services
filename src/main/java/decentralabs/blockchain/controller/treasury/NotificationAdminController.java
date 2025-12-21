package decentralabs.blockchain.controller.treasury;

import decentralabs.blockchain.notification.MailSenderAdapter;
import decentralabs.blockchain.notification.MailSenderFactory;
import decentralabs.blockchain.notification.NotificationConfigService;
import decentralabs.blockchain.notification.NotificationMessage;
import decentralabs.blockchain.notification.NotificationProperties;
import decentralabs.blockchain.notification.NotificationUpdateRequest;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
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
    private final MailSenderFactory mailSenderFactory;

    @Value("${admin.dashboard.local-only:true}")
    private boolean adminDashboardLocalOnly;

    @Value("${admin.dashboard.allow-private:true}")
    private boolean adminDashboardAllowPrivate;

    @Value("${security.allow-private-networks:false}")
    private boolean allowPrivateNetworks;

    @Value("${security.internal-token:}")
    private String internalToken;

    @Value("${security.internal-token-header:X-Internal-Token}")
    private String internalTokenHeader;

    @Value("${security.internal-token-cookie:internal_token}")
    private String internalTokenCookie;

    @Value("${security.internal-token.required:true}")
    private boolean internalTokenRequired;

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
            var errors = notificationConfigService.validateUpdate(request);
            if (!errors.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", String.join("; ", errors)
                ));
            }
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

    @PostMapping("/test")
    public ResponseEntity<?> sendTest(HttpServletRequest httpRequest) {
        if (!isLocalhostRequest(httpRequest)) {
            return forbidden();
        }
        NotificationProperties.Mail mail = notificationConfigService.getMailConfig();
        var validation = notificationConfigService.validateMailConfig();
        if (!validation.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                "success", false,
                "error", String.join("; ", validation)
            ));
        }
        if (mail.getDefaultTo().isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                "success", false,
                "error", "No recipients configured (defaultTo is empty)"
            ));
        }
        try {
            MailSenderAdapter sender = mailSenderFactory.resolve();
            sender.send(new NotificationMessage(
                mail.getDefaultTo(),
                "Lab Gateway notification test",
                "Test message from Lab Gateway",
                "<p>Test message from Lab Gateway</p>",
                null,
                null
            ));
            return ResponseEntity.ok(Map.of("success", true));
        } catch (Exception ex) {
            log.error("Failed to send test notification: {}", ex.getMessage(), ex);
            return ResponseEntity.internalServerError().body(Map.of(
                "success", false,
                "error", "Failed to send test notification: " + ex.getMessage()
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

        String candidate = request.getRemoteAddr();
        boolean allowed = isLoopback(candidate)
            || (adminDashboardAllowPrivate
                && allowPrivateNetworks
                && isPrivateAddress(candidate)
                && (!internalTokenRequired || hasValidInternalToken(request)));

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

    private boolean isLoopback(String address) {
        if (address == null || address.isBlank()) {
            return false;
        }
        return address.equals("127.0.0.1")
            || address.startsWith("127.")
            || address.equals("0:0:0:0:0:0:0:1")
            || address.equals("::1");
    }

    private boolean hasValidInternalToken(HttpServletRequest request) {
        if (internalToken == null || internalToken.isBlank()) {
            return false;
        }
        String headerToken = request.getHeader(internalTokenHeader);
        if (headerToken != null && !headerToken.isBlank()) {
            return internalToken.equals(headerToken.trim());
        }
        String authorization = request.getHeader("Authorization");
        if (authorization != null) {
            String lower = authorization.toLowerCase();
            if (lower.startsWith("bearer ")) {
                String bearer = authorization.substring("bearer ".length()).trim();
                return internalToken.equals(bearer);
            }
        }
        if (request.getCookies() != null) {
            for (var cookie : request.getCookies()) {
                if (internalTokenCookie.equals(cookie.getName())) {
                    return internalToken.equals(cookie.getValue());
                }
            }
        }
        return false;
    }
}
