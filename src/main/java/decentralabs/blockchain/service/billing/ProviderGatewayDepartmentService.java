package decentralabs.blockchain.service.billing;

import decentralabs.blockchain.security.LabAdminGatewayCredentialService;
import decentralabs.blockchain.security.LabAdminGatewayCredentialService.ConfiguredGateway;
import decentralabs.blockchain.util.GatewayIdentity;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

/** Institution-managed display names for the Lite Gateways registered by this provider backend. */
@Service
public class ProviderGatewayDepartmentService {

    private final JdbcTemplate jdbcTemplate;
    private final LabAdminGatewayCredentialService gatewayCredentials;

    public ProviderGatewayDepartmentService(
        ObjectProvider<JdbcTemplate> jdbcTemplateProvider,
        LabAdminGatewayCredentialService gatewayCredentials
    ) {
        this.jdbcTemplate = jdbcTemplateProvider.getIfAvailable();
        this.gatewayCredentials = gatewayCredentials;
    }

    @Transactional(readOnly = true)
    public List<GatewayDepartment> listConfiguredGateways() {
        Map<String, String> departmentNames = departmentNames();
        List<GatewayDepartment> gateways = new ArrayList<>();
        for (ConfiguredGateway gateway : gatewayCredentials.configuredGateways()) {
            gateways.add(new GatewayDepartment(
                gateway.gatewayId(),
                gateway.accessUri(),
                departmentNames.getOrDefault(gateway.gatewayId(), "")
            ));
        }
        return List.copyOf(gateways);
    }

    @Transactional
    public GatewayDepartment updateDepartmentName(String gatewayId, String requestedName) {
        String normalizedGatewayId = GatewayIdentity.normalizeGatewayId(gatewayId);
        if (normalizedGatewayId == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid Gateway ID");
        }
        ConfiguredGateway gateway = findConfiguredGateway(normalizedGatewayId)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Gateway is not registered"));
        JdbcTemplate jdbc = requireJdbcTemplate();
        String departmentName = requestedName == null ? "" : requestedName.trim();
        if (departmentName.isEmpty()) {
            jdbc.update("DELETE FROM provider_gateway_departments WHERE gateway_id = ?", normalizedGatewayId);
            return new GatewayDepartment(gateway.gatewayId(), gateway.accessUri(), "");
        }

        jdbc.update(
            """
            INSERT INTO provider_gateway_departments (gateway_id, department_name)
            VALUES (?, ?)
            ON DUPLICATE KEY UPDATE department_name=VALUES(department_name), updated_at=CURRENT_TIMESTAMP
            """,
            gateway.gatewayId(),
            departmentName
        );
        return new GatewayDepartment(gateway.gatewayId(), gateway.accessUri(), departmentName);
    }

    @Transactional(readOnly = true)
    public Map<String, String> departmentNames() {
        JdbcTemplate jdbc = requireJdbcTemplate();
        Map<String, String> names = new HashMap<>();
        jdbc.query(
            "SELECT gateway_id, department_name FROM provider_gateway_departments",
            (ResultSet rs) -> {
                names.put(rs.getString("gateway_id"), rs.getString("department_name"));
            }
        );
        return Map.copyOf(names);
    }

    private Optional<ConfiguredGateway> findConfiguredGateway(String gatewayId) {
        return gatewayCredentials.configuredGateways().stream()
            .filter(gateway -> gateway.gatewayId().equals(gatewayId))
            .findFirst();
    }

    private JdbcTemplate requireJdbcTemplate() {
        if (jdbcTemplate == null) {
            throw new ResponseStatusException(
                HttpStatus.SERVICE_UNAVAILABLE,
                "Gateway department storage is unavailable without a configured database"
            );
        }
        return jdbcTemplate;
    }

    public record GatewayDepartment(String gatewayId, String accessUri, String departmentName) { }
}
