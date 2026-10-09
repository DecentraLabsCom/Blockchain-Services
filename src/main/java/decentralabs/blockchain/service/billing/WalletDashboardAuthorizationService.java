package decentralabs.blockchain.service.billing;

import decentralabs.blockchain.config.BackendOperatingMode;
import decentralabs.blockchain.config.BackendOperatingModeConfiguration;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import decentralabs.blockchain.util.EthereumAddressValidator;
import java.math.BigInteger;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * Authorization decisions for the local wallet dashboard are based on the
 * configured institutional wallet's on-chain roles and the backend's explicit
 * capability mode. The network/token filter remains an outer access boundary.
 */
@Component("walletDashboardAuthorizationService")
@RequiredArgsConstructor
public class WalletDashboardAuthorizationService {

    private final BackendOperatingModeConfiguration operatingMode;
    private final InstitutionalWalletService institutionalWalletService;
    private final WalletService walletService;

    public boolean canManageInstitutionPolicies() {
        String address = institutionalAddress();
        return address != null
            && (walletService.isInstitution(address) || walletService.isDefaultAdmin(address));
    }

    public boolean canManageProviderNetwork() {
        String address = institutionalAddress();
        return providerModeEnabled() && address != null && walletService.isDefaultAdmin(address);
    }

    public boolean canReviewProviderSettlements() {
        String address = institutionalAddress();
        return providerModeEnabled() && address != null && walletService.isDefaultAdmin(address);
    }

    public boolean canReadProviderPayouts(String providerAddress) {
        String address = institutionalAddress();
        if (!providerModeEnabled() || address == null || providerAddress == null || providerAddress.isBlank()) {
            return false;
        }
        if (walletService.isDefaultAdmin(address)) {
            return true;
        }
        return walletService.isLabProvider(address) && address.equalsIgnoreCase(providerAddress.trim());
    }

    public boolean canSubmitProviderInvoice(String labId) {
        String address = institutionalAddress();
        if (!providerModeEnabled() || address == null || !walletService.isLabProvider(address)) {
            return false;
        }
        try {
            BigInteger parsedLabId = EthereumAddressValidator.parseBigInteger(labId, "labId");
            return walletService.isLabOwnedByProvider(address, parsedLabId);
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    private boolean providerModeEnabled() {
        return operatingMode.operatingMode() == BackendOperatingMode.PROVIDER_CONSUMER;
    }

    private String institutionalAddress() {
        String address = institutionalWalletService.getInstitutionalWalletAddress();
        return address == null || address.isBlank() ? null : address.trim();
    }
}
