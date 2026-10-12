package decentralabs.blockchain.service.billing;

import decentralabs.blockchain.security.LabAdminGatewayCredentialService;
import decentralabs.blockchain.security.LabAdminGatewayCredentialService.ConfiguredGateway;
import decentralabs.blockchain.service.BackendUrlResolver;
import decentralabs.blockchain.util.GatewayIdentity;
import java.sql.ResultSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

/** Institution-managed display names for the provider's Lite Gateways and local Full Gateway. */
@Service
public class ProviderGatewayDepartmentService {

    private static final String FULL_GATEWAY_TYPE = "FULL";
    private static final String LITE_GATEWAY_TYPE = "LITE";

    private final JdbcTemplate jdbcTemplate;
    private final LabAdminGatewayCredentialService gatewayCredentials;
    private final BackendUrlResolver backendUrlResolver;
    private final String issuer;

    public ProviderGatewayDepartmentService(
        ObjectProvider<JdbcTemplate> jdbcTemplateProvider,
        LabAdminGatewayCredentialService gatewayCredentials,
        BackendUrlResolver backendUrlResolver,
        @Value("${ISSUER:}") String issuer
    ) {
        this.jdbcTemplate = jdbcTemplateProvider.getIfAvailable();
        this.gatewayCredentials = gatewayCredentials;
        this.backendUrlResolver = backendUrlResolver;
        this.issuer = issuer;
    }

    @Transactional(readOnly = true)
    public List<GatewayDepartment> listConfiguredGateways() {
        Map<String, String> departmentNames = departmentNames();
        return configuredGatewayEntries().values().stream()
            .map(gateway -> toGatewayDepartment(
                gateway,
                departmentNames.getOrDefault(gateway.gatewayId(), "")
            ))
            .toList();
    }

    @Transactional
    public GatewayDepartment updateDepartmentName(String gatewayId, String requestedName) {
        String normalizedGatewayId = GatewayIdentity.normalizeGatewayId(gatewayId);
        if (normalizedGatewayId == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid Gateway ID");
        }
        ManagedGateway gateway = configuredGatewayEntries().get(normalizedGatewayId);
        if (gateway == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Gateway is not registered");
        }
        JdbcTemplate jdbc = requireJdbcTemplate();
        String departmentName = requestedName == null ? "" : requestedName.trim();
        if (departmentName.isEmpty()) {
            jdbc.update("DELETE FROM provider_gateway_departments WHERE gateway_id = ?", normalizedGatewayId);
            return toGatewayDepartment(gateway, "");
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
        return toGatewayDepartment(gateway, departmentName);
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

    private Map<String, ManagedGateway> configuredGatewayEntries() {
        List<ConfiguredGateway> liteGateways = gatewayCredentials.configuredGateways();
        Map<String, ManagedGateway> gateways = new TreeMap<>();
        for (ConfiguredGateway gateway : liteGateways) {
            gateways.put(gateway.gatewayId(), new ManagedGateway(
                gateway.gatewayId(), gateway.accessUri(), LITE_GATEWAY_TYPE
            ));
        }

        if (!liteGateways.isEmpty() && (issuer == null || issuer.isBlank())) {
            String accessUri = backendUrlResolver.resolveBaseDomain();
            String gatewayId = GatewayIdentity.fromAccessUri(accessUri);
            if (gatewayId != null) {
                gateways.putIfAbsent(gatewayId, new ManagedGateway(
                    gatewayId, accessUri, FULL_GATEWAY_TYPE
                ));
            }
        }
        return gateways;
    }

    private GatewayDepartment toGatewayDepartment(ManagedGateway gateway, String departmentName) {
        return new GatewayDepartment(
            gateway.gatewayId(), gateway.accessUri(), gateway.gatewayType(), departmentName
        );
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

    public record GatewayDepartment(
        String gatewayId,
        String accessUri,
        String gatewayType,
        String departmentName
    ) { }

    private record ManagedGateway(String gatewayId, String accessUri, String gatewayType) { }
}
