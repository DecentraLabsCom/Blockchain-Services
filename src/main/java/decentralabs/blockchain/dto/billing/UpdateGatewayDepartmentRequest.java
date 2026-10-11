package decentralabs.blockchain.dto.billing;

import jakarta.validation.constraints.Size;

public record UpdateGatewayDepartmentRequest(
    @Size(max = 120) String departmentName
) { }
