package decentralabs.blockchain.dto.labadmin;

public record LabAdminAssetResponse(
    boolean success,
    String contentId,
    String path,
    String url,
    String contentType,
    long size
) {}
