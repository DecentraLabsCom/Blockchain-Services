package decentralabs.blockchain.security;

/** Request scope established by the backend authentication boundary for lab administration. */
public record LabAdminGatewayScope(String gatewayId, boolean institutionWide) {
    public static final String REQUEST_ATTRIBUTE = LabAdminGatewayScope.class.getName();

    public static LabAdminGatewayScope forGateway(String gatewayId) {
        return new LabAdminGatewayScope(gatewayId, false);
    }

    public static LabAdminGatewayScope forInstitution() {
        return new LabAdminGatewayScope(null, true);
    }
}
