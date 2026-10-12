package decentralabs.blockchain.controller.billing;

import decentralabs.blockchain.config.ProviderConsumerModeCondition;
import decentralabs.blockchain.notification.MailSenderAdapter;
import decentralabs.blockchain.notification.MailSenderFactory;
import decentralabs.blockchain.notification.MailSendResult;
import decentralabs.blockchain.notification.NotificationConfigService;
import decentralabs.blockchain.notification.NotificationMessage;
import decentralabs.blockchain.notification.NotificationProperties;
import decentralabs.blockchain.notification.NotificationUpdateRequest;
import decentralabs.blockchain.security.AdminNetworkAccessPolicy;
import decentralabs.blockchain.security.LabAdminGatewayScope;
import decentralabs.blockchain.util.GatewayIdentity;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Conditional;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Gateway-scoped notification settings and delivery for Lab Manager. */
@RestController
@RequestMapping("/lab-admin/notifications")
@Conditional(ProviderConsumerModeCondition.class)
@RequiredArgsConstructor
@Slf4j
public class NotificationAdminController {

    private final NotificationConfigService notificationConfigService;
    private final MailSenderFactory mailSenderFactory;
    private final AdminNetworkAccessPolicy adminNetworkAccessPolicy;

    @GetMapping
    public ResponseEntity<?> getConfig(
        HttpServletRequest request,
        @RequestAttribute(value = LabAdminGatewayScope.REQUEST_ATTRIBUTE, required = false)
        LabAdminGatewayScope gatewayScope
    ) {
        String gatewayId = authorizedGateway(request, gatewayScope);
        if (gatewayId == null) return forbidden();
        return ResponseEntity.ok(Map.of(
            "success", true,
            "config", notificationConfigService.getPublicConfig(gatewayId)
        ));
    }

    @PutMapping
    public ResponseEntity<?> updateConfig(
        @RequestBody NotificationUpdateRequest config,
        HttpServletRequest request,
        @RequestAttribute(value = LabAdminGatewayScope.REQUEST_ATTRIBUTE, required = false)
        LabAdminGatewayScope gatewayScope
    ) {
        String gatewayId = authorizedGateway(request, gatewayScope);
        if (gatewayId == null) return forbidden();
        try {
            List<String> errors = notificationConfigService.validateUpdate(gatewayId, config);
            if (!errors.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", String.join("; ", errors)
                ));
            }
            notificationConfigService.updateMailConfig(gatewayId, config);
            return ResponseEntity.ok(Map.of(
                "success", true,
                "config", notificationConfigService.getPublicConfig(gatewayId)
            ));
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest().body(Map.of("success", false, "error", ex.getMessage()));
        } catch (Exception ex) {
            log.error("Failed to update notification config for Gateway {}: {}", gatewayId, ex.getMessage(), ex);
            return ResponseEntity.internalServerError().body(Map.of(
                "success", false,
                "error", "Failed to update notification config"
            ));
        }
    }

    @PostMapping("/test")
    public ResponseEntity<?> sendTest(
        HttpServletRequest request,
        @RequestAttribute(value = LabAdminGatewayScope.REQUEST_ATTRIBUTE, required = false)
        LabAdminGatewayScope gatewayScope
    ) {
        String gatewayId = authorizedGateway(request, gatewayScope);
        if (gatewayId == null) return forbidden();
        NotificationProperties.Mail mail = notificationConfigService.getMailConfig(gatewayId);
        List<String> validation = notificationConfigService.validateMailConfig(gatewayId);
        if (!validation.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of(
                "success", false,
                "error", String.join("; ", validation)
            ));
        }
        if (mail.getDefaultTo() == null || mail.getDefaultTo().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of(
                "success", false,
                "error", "No recipients configured (defaultTo is empty)"
            ));
        }
        try {
            MailSenderAdapter sender = mailSenderFactory.resolve(mail);
            MailSendResult result = sender.send(new NotificationMessage(
                mail.getDefaultTo(),
                "Lab Gateway notification test",
                "Test message from Lab Gateway",
                "<p>Test message from Lab Gateway</p>",
                null,
                null
            ));
            return deliveryResponse(result, "test notification");
        } catch (Exception ex) {
            log.error("Failed to send test notification for Gateway {}: {}", gatewayId, ex.getMessage(), ex);
            return ResponseEntity.internalServerError().body(Map.of(
                "success", false,
                "error", "Failed to send test notification"
            ));
        }
    }

    @PostMapping("/send")
    public ResponseEntity<?> sendNotification(
        @RequestBody NotificationMessage message,
        HttpServletRequest request,
        @RequestAttribute(value = LabAdminGatewayScope.REQUEST_ATTRIBUTE, required = false)
        LabAdminGatewayScope gatewayScope
    ) {
        String gatewayId = authorizedGateway(request, gatewayScope);
        if (gatewayId == null) return forbidden();
        if (message == null) {
            return ResponseEntity.badRequest().body(Map.of(
                "success", false,
                "error", "Notification message is required"
            ));
        }

        NotificationProperties.Mail mail = notificationConfigService.getMailConfig(gatewayId);
        if (!mail.isEnabled()) {
            return ResponseEntity.badRequest().body(Map.of(
                "success", false,
                "error", "Notification service is disabled"
            ));
        }

        List<String> recipients = message.recipients();
        if (recipients == null || recipients.isEmpty()) recipients = mail.getDefaultTo();
        if (recipients == null || recipients.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of(
                "success", false,
                "error", "No recipients provided and no defaultTo configured"
            ));
        }

        List<String> validation = notificationConfigService.validateMailConfig(gatewayId);
        if (!validation.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of(
                "success", false,
                "error", String.join("; ", validation)
            ));
        }

        try {
            MailSenderAdapter sender = mailSenderFactory.resolve(mail);
            MailSendResult result = sender.send(new NotificationMessage(
                recipients,
                message.subject(),
                message.textBody(),
                message.htmlBody(),
                message.icsContent(),
                message.icsFileName()
            ));
            return deliveryResponse(result, "notification");
        } catch (Exception ex) {
            log.error("Failed to send notification for Gateway {}: {}", gatewayId, ex.getMessage(), ex);
            return ResponseEntity.internalServerError().body(Map.of(
                "success", false,
                "error", "Failed to send notification"
            ));
        }
    }

    private String authorizedGateway(HttpServletRequest request, LabAdminGatewayScope scope) {
        if (scope == null || scope.institutionWide()) return null;
        String gatewayId = GatewayIdentity.normalizeGatewayId(scope.gatewayId());
        if (gatewayId == null) return null;
        // LocalhostOnlyFilter has already established the trust-bundle-backed
        // Gateway scope. Recheck the network policy at this controller boundary.
        return adminNetworkAccessPolicy.isRequestAllowed(request, () -> true) ? gatewayId : null;
    }

    private ResponseEntity<?> forbidden() {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
            "success", false,
            "error", "A Gateway-scoped Lab Manager credential is required"
        ));
    }

    private ResponseEntity<?> deliveryResponse(MailSendResult result, String operation) {
        if (result != null && result.status() == MailSendResult.Status.SENT) {
            return ResponseEntity.ok(Map.of("success", true));
        }
        if (result == null) {
            log.error("Mail sender returned no delivery result for {}", operation);
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(Map.of(
                "success", false,
                "error", "Mail sender did not confirm delivery"
            ));
        }
        String error = result.message() != null && !result.message().isBlank()
            ? result.message()
            : "Notification was not sent";
        HttpStatus status = result.status() == MailSendResult.Status.FAILED
            ? HttpStatus.BAD_GATEWAY
            : HttpStatus.BAD_REQUEST;
        return ResponseEntity.status(status).body(Map.of("success", false, "error", error));
    }
}
