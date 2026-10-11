package decentralabs.blockchain.controller.labadmin;

import decentralabs.blockchain.config.ProviderConsumerModeCondition;
import decentralabs.blockchain.security.LabAdminGatewayScope;
import decentralabs.blockchain.service.billing.ProviderIncomeAccountingService;
import decentralabs.blockchain.util.GatewayIdentity;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Conditional;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Read-only billing views for the authenticated Lab Manager Gateway. */
@RestController
@RequestMapping("/lab-admin/billing")
@Conditional(ProviderConsumerModeCondition.class)
@RequiredArgsConstructor
public class LabAdminBillingController {

    private final ProviderIncomeAccountingService providerIncomeAccountingService;

    @GetMapping("/provider-income")
    public ResponseEntity<?> providerIncome(
        @RequestAttribute(value = LabAdminGatewayScope.REQUEST_ATTRIBUTE, required = false)
        LabAdminGatewayScope gatewayScope
    ) {
        String gatewayId = gatewayScope == null || gatewayScope.institutionWide()
            ? null
            : GatewayIdentity.normalizeGatewayId(gatewayScope.gatewayId());
        if (gatewayId == null) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                "success", false,
                "error", "A Gateway-scoped Lab Manager credential is required"
            ));
        }
        return ResponseEntity.ok(providerIncomeAccountingService.getReportForGateway(gatewayId));
    }
}
