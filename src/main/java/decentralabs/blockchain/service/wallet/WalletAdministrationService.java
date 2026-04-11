package decentralabs.blockchain.service.wallet;

import decentralabs.blockchain.dto.wallet.WalletImportRequest;
import decentralabs.blockchain.dto.wallet.WalletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * Coordinates wallet lifecycle operations that also need to update the
 * institutional wallet runtime configuration.
 */
@Service
@RequiredArgsConstructor
public class WalletAdministrationService {

    private final WalletService walletService;
    private final InstitutionalWalletService institutionalWalletService;

    public WalletResponse createAndConfigureInstitutionalWallet(String password) {
        WalletResponse response = walletService.createWallet(password);
        configureInstitutionalWallet(response, password);
        return response;
    }

    public WalletResponse importAndConfigureInstitutionalWallet(WalletImportRequest request) {
        WalletResponse response = walletService.importWallet(request);
        configureInstitutionalWallet(response, request.getPassword());
        return response;
    }

    private void configureInstitutionalWallet(WalletResponse response, String password) {
        if (!response.isSuccess() || response.getAddress() == null || response.getAddress().isBlank()) {
            return;
        }

        institutionalWalletService.saveConfigToFile(response.getAddress(), password);
        institutionalWalletService.initializeInstitutionalWallet();
    }
}
