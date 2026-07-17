package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.contract.Diamond;
import decentralabs.blockchain.service.wallet.WalletService;
import java.math.BigInteger;
import java.util.Locale;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.web3j.tx.ReadonlyTransactionManager;
import org.web3j.tx.gas.StaticGasProvider;

@Service
@RequiredArgsConstructor
@Slf4j
public class InstitutionalCheckInDirectoryService {
    private static final String ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

    private final WalletService walletService;

    @Value("${contract.address}")
    private String contractAddress;

    public boolean isAuthorizedCheckInSigner(String institutionWallet, String signer) {
        String institution = normalizeAddress(institutionWallet);
        String candidate = normalizeAddress(signer);
        if (institution == null || candidate == null) {
            return false;
        }
        if (candidate.equalsIgnoreCase(institution)) {
            return true;
        }

        // The backend address is read from the deployed contract before it is
        // compared with the configured institutional signer.
        // codeql[java/user-controlled-bypass]

        String backend = resolveAuthorizedBackend(institution);
        return backend != null && candidate.equalsIgnoreCase(backend);
    }

    public String resolveOrganizationBackendUrl(String organization) {
        String normalized = normalizeOrganization(organization);
        if (normalized.isBlank()) {
            return null;
        }
        try {
            String backendUrl = loadReadonlyDiamond().getSchacHomeOrganizationBackend(normalized).send();
            return backendUrl == null || backendUrl.isBlank() ? null : backendUrl.trim();
        } catch (Exception ex) {
            log.warn("Unable to resolve check-in backend for organization {}: {}", normalized, ex.getMessage());
            return null;
        }
    }

    private String resolveAuthorizedBackend(String institutionWallet) {
        try {
            String backend = loadReadonlyDiamond().getAuthorizedBackend(institutionWallet).send();
            String normalized = normalizeAddress(backend);
            return ZERO_ADDRESS.equalsIgnoreCase(normalized) ? null : normalized;
        } catch (Exception ex) {
            log.warn("Unable to resolve authorized backend for institution {}: {}", institutionWallet, ex.getMessage());
            return null;
        }
    }

    private Diamond loadReadonlyDiamond() {
        var web3j = walletService.getWeb3jInstance();
        return Diamond.load(
            contractAddress,
            web3j,
            new ReadonlyTransactionManager(web3j, ZERO_ADDRESS),
            new StaticGasProvider(BigInteger.ZERO, BigInteger.ZERO)
        );
    }

    private String normalizeOrganization(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    private String normalizeAddress(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isBlank() ? null : trimmed;
    }
}
