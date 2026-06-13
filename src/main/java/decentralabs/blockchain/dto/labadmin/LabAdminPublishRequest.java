package decentralabs.blockchain.dto.labadmin;

import java.math.BigInteger;
import java.util.Map;

public record LabAdminPublishRequest(
    String setupMode,
    Boolean listImmediately,
    String metadataUrl,
    Map<String, Object> metadata,
    BigInteger price,
    String accessURI,
    String accessKey,
    Integer resourceType
) {}
