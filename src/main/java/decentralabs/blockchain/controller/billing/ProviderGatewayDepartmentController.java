package decentralabs.blockchain.controller.billing;

import decentralabs.blockchain.config.ProviderConsumerModeCondition;
import decentralabs.blockchain.dto.billing.UpdateGatewayDepartmentRequest;
import decentralabs.blockchain.service.billing.ProviderGatewayDepartmentService;
import jakarta.validation.Valid;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Conditional;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Read and maintain display names for the Lites registered with this provider backend. */
@RestController
@RequestMapping("/billing/provider-gateways")
@RequiredArgsConstructor
@Conditional(ProviderConsumerModeCondition.class)
public class ProviderGatewayDepartmentController {

    private final ProviderGatewayDepartmentService departmentService;

    @GetMapping
    @PreAuthorize("@walletDashboardAuthorizationService.canManageProviderNetwork()")
    public ResponseEntity<?> listGateways() {
        return ResponseEntity.ok(Map.of(
            "success", true,
            "gateways", departmentService.listConfiguredGateways()
        ));
    }

    @PutMapping("/{gatewayId}")
    @PreAuthorize("@walletDashboardAuthorizationService.canManageProviderNetwork()")
    public ResponseEntity<?> updateDepartmentName(
        @PathVariable String gatewayId,
        @Valid @RequestBody UpdateGatewayDepartmentRequest request
    ) {
        return ResponseEntity.ok(Map.of(
            "success", true,
            "gateway", departmentService.updateDepartmentName(gatewayId, request.departmentName())
        ));
    }
}
