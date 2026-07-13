package decentralabs.blockchain.service.organization;

import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import java.util.Locale;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class InstitutionOnChainStatusService {
    private static final String ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

    private final WalletService walletService;
    private final InstitutionalWalletService institutionalWalletService;

    public Status inspect(String organization, String expectedBackendUrl, boolean providerMode) {
        String wallet = trimToNull(institutionalWalletService.getInstitutionalWalletAddress());
        String normalizedOrganization = normalizeOrganization(organization);
        if (wallet == null || normalizedOrganization == null) {
            return Status.unavailable(wallet);
        }
        try {
            boolean providerRole = walletService.isLabProvider(wallet);
            boolean institutionRole = walletService.isInstitution(wallet);
            String owner = trimToNull(
                walletService.resolveInstitutionWalletForOrganization(normalizedOrganization)
            );
            String backendUrl = trimToNull(
                walletService.getOrganizationBackendUrl(normalizedOrganization)
            );
            String authorizedBackend = trimToNull(
                walletService.getAuthorizedInstitutionalBackend(wallet)
            );
            int networkStatusValue = walletService.getProviderNetworkStatus(wallet);
            String networkStatus = networkStatusName(networkStatusValue);

            boolean organizationMatches = addressMatches(wallet, owner);
            boolean backendMatches = normalizeUrl(expectedBackendUrl).equals(normalizeUrl(backendUrl));
            boolean backendAuthorized = authorizedBackend != null
                && !ZERO_ADDRESS.equalsIgnoreCase(authorizedBackend);
            boolean providerReady = !providerMode || (providerRole && networkStatusValue == 1);
            boolean fullyOperational = institutionRole
                && organizationMatches
                && backendMatches
                && backendAuthorized
                && providerReady;

            return new Status(
                true, wallet, providerRole, institutionRole, owner, backendUrl,
                authorizedBackend, networkStatus, fullyOperational
            );
        } catch (Exception ex) {
            log.warn("Unable to inspect institution registration on-chain: {}", ex.getMessage());
            return Status.unavailable(wallet);
        }
    }

    private String normalizeOrganization(String value) {
        String normalized = trimToNull(value);
        return normalized == null ? null : normalized.toLowerCase(Locale.ROOT);
    }

    private String normalizeUrl(String value) {
        String normalized = trimToNull(value);
        if (normalized == null) return "";
        while (normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized.toLowerCase(Locale.ROOT);
    }

    private boolean addressMatches(String left, String right) {
        return left != null && right != null && left.equalsIgnoreCase(right)
            && !ZERO_ADDRESS.equalsIgnoreCase(left);
    }

    private String trimToNull(String value) {
        if (value == null || value.isBlank()) return null;
        return value.trim();
    }

    private String networkStatusName(int status) {
        return switch (status) {
            case 1 -> "ACTIVE";
            case 2 -> "SUSPENDED";
            case 3 -> "TERMINATED";
            default -> "NONE";
        };
    }

    public record Status(
        boolean onChainStatusAvailable,
        String walletAddress,
        boolean providerRoleOnChain,
        boolean institutionRoleOnChain,
        String organizationOwner,
        String backendUrlOnChain,
        String authorizedBackendOnChain,
        String providerNetworkStatus,
        boolean fullyOperational
    ) {
        public static Status unavailable() {
            return unavailable(null);
        }

        public static Status unavailable(String walletAddress) {
            return new Status(
                false, walletAddress, false, false, null, null, null, "UNKNOWN", false
            );
        }
    }
}
